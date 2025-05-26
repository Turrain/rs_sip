use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering};
use std::net::SocketAddr;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::{RwLock, mpsc};
use tokio::time::{interval, Duration, Instant};

use crate::{
    CallId, Event, Logger, MediaCapabilities, MediaDirection, MediaEvent, MediaPortId, MediaType, Result, SipError
};

// RTP Header structure
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct RtpHeader {
    pub flags: u8,      // V(2), P(1), X(1), CC(4)
    pub marker_pt: u8,  // M(1), PT(7)
    pub sequence: u16,
    pub timestamp: u32,
    pub ssrc: u32,
}

impl RtpHeader {
    pub fn new(payload_type: u8, sequence: u16, timestamp: u32, ssrc: u32, marker: bool) -> Self {
        let flags = 0x80; // Version 2, no padding, no extension, no CSRCs
        let marker_pt = if marker { 0x80 | payload_type } else { payload_type };
        
        RtpHeader {
            flags,
            marker_pt,
            sequence: sequence.to_be(),
            timestamp: timestamp.to_be(),
            ssrc: ssrc.to_be(),
        }
    }

    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 12 {
            return None;
        }
        
        unsafe {
            Some(std::ptr::read_unaligned(data.as_ptr() as *const RtpHeader))
        }
    }

    pub fn to_bytes(&self) -> [u8; 12] {
        unsafe {
            std::mem::transmute_copy(self)
        }
    }

    pub fn version(&self) -> u8 {
        (self.flags >> 6) & 0x03
    }

    pub fn padding(&self) -> bool {
        (self.flags & 0x20) != 0
    }

    pub fn extension(&self) -> bool {
        (self.flags & 0x10) != 0
    }

    pub fn csrc_count(&self) -> u8 {
        self.flags & 0x0F
    }

    pub fn marker(&self) -> bool {
        (self.marker_pt & 0x80) != 0
    }

    pub fn payload_type(&self) -> u8 {
        self.marker_pt & 0x7F
    }

    pub fn sequence_number(&self) -> u16 {
        u16::from_be(self.sequence)
    }

    pub fn timestamp_value(&self) -> u32 {
        u32::from_be(self.timestamp)
    }

    pub fn ssrc_value(&self) -> u32 {
        u32::from_be(self.ssrc)
    }
}

// RTCP packet types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RtcpPacketType {
    SR = 200,   // Sender Report
    RR = 201,   // Receiver Report
    SDES = 202, // Source Description
    BYE = 203,  // Goodbye
    APP = 204,  // Application-defined
}

// Media statistics
#[derive(Debug, Clone, Default)]
pub struct MediaStatistics {
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_lost: u64,
    pub jitter: f64,
    pub rtt: f64,
}

// Media Port implementation
pub struct MediaPort {
    pub id: MediaPortId,
    rtp_socket: Arc<UdpSocket>,
    rtcp_socket: Option<Arc<UdpSocket>>,
    local_addr: SocketAddr,
    remote_addr: Arc<RwLock<Option<SocketAddr>>>,
    direction: Arc<RwLock<MediaDirection>>,
    ssrc: u32,
    statistics: Arc<RwLock<MediaStatistics>>,
    logger: Arc<dyn Logger>,
    running: Arc<RwLock<bool>>,
    command_tx: mpsc::Sender<MediaPortCommand>,
}

#[derive(Debug)]
enum MediaPortCommand {
    SetRemoteAddr(SocketAddr),
    SetDirection(MediaDirection),
    SendRtp(Vec<u8>),
    Stop,
}

impl MediaPort {
    pub async fn new(
        id: MediaPortId,
        local_addr: SocketAddr,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let rtp_socket = UdpSocket::bind(local_addr).await
            .map_err(|e| SipError::MediaError(format!("Failed to bind RTP socket: {}", e)))?;
        
        let actual_addr = rtp_socket.local_addr()
            .map_err(|e| SipError::MediaError(format!("Failed to get local address: {}", e)))?;
        
        // Bind RTCP socket (RTP port + 1)
        let rtcp_addr = SocketAddr::new(actual_addr.ip(), actual_addr.port() + 1);
        let rtcp_socket = match UdpSocket::bind(rtcp_addr).await {
            Ok(socket) => Some(Arc::new(socket)),
            Err(e) => {
                logger.warn(&format!("Failed to bind RTCP socket: {}", e));
                None
            }
        };

        let (command_tx, command_rx) = mpsc::channel(100);

        let ssrc = generate_ssrc();

        let port = Arc::new(MediaPort {
            id,
            rtp_socket: Arc::new(rtp_socket),
            rtcp_socket,
            local_addr: actual_addr,
            remote_addr: Arc::new(RwLock::new(None)),
            direction: Arc::new(RwLock::new(MediaDirection::SendRecv)),
            ssrc,
            statistics: Arc::new(RwLock::new(MediaStatistics::default())),
            logger,
            running: Arc::new(RwLock::new(false)),
            command_tx,
        });

        // Start command handler
        let port_clone = port.clone();
        tokio::spawn(async move {
            port_clone.run_command_handler(command_rx).await;
        });

        Ok(port)
    }

    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        *running = true;

        // Start RTP receiver
        let port_id = self.id.clone();
        let socket = self.rtp_socket.clone();
        let logger = self.logger.clone();
        let running = self.running.clone();
        let direction = self.direction.clone();
        let statistics = self.statistics.clone();
        
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 2048];
            
            loop {
                if !*running.read().await {
                    break;
                }

                match socket.recv_from(&mut buffer).await {
                    Ok((size, source)) => {
                        if size >= 12 {
                            if let Some(header) = RtpHeader::from_bytes(&buffer[..size]) {
                                if header.version() == 2 {
                                    let dir = *direction.read().await;
                                    if dir != MediaDirection::SendOnly && dir != MediaDirection::Inactive {
                                        let mut stats = statistics.write().await;
                                        stats.packets_received += 1;
                                        stats.bytes_received += size as u64;

                                        logger.debug(&format!(
                                            "Received RTP packet: PT={}, Seq={}, TS={}, SSRC={:08x}, Size={}",
                                            header.payload_type(),
                                            header.sequence_number(),
                                            header.timestamp_value(),
                                            header.ssrc_value(),
                                            size
                                        ));
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        logger.error(&format!("RTP receive error: {}", e));
                    }
                }
            }
            
            logger.info(&format!("Media port {} RTP receiver stopped", port_id.0));
        });

        // Start RTCP handler
        if let Some(rtcp_socket) = self.rtcp_socket.clone() {
            let port_id = self.id.clone();
            let logger = self.logger.clone();
            let running = self.running.clone();
            let remote_addr = self.remote_addr.clone();
            let ssrc = self.ssrc;
            let statistics = self.statistics.clone();
            
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 1024];
                let mut ticker = interval(Duration::from_secs(5));
                
                loop {
                    tokio::select! {
                        _ = ticker.tick() => {
                            if !*running.read().await {
                                break;
                            }
                            // Send RTCP SR/RR
                            if let Some(remote) = *remote_addr.read().await {
                                let stats = statistics.read().await;
                                let rtcp_packet = create_rtcp_report(ssrc, &stats);
                                let rtcp_addr = SocketAddr::new(remote.ip(), remote.port() + 1);
                                let _ = rtcp_socket.send_to(&rtcp_packet, rtcp_addr).await;
                            }
                        }
                        result = rtcp_socket.recv_from(&mut buffer) => {
                            if let Ok((size, source)) = result {
                                if size >= 8 {
                                    let packet_type = buffer[1];
                                    
                                    logger.debug(&format!(
                                        "Received RTCP packet type {} from {}, size {}",
                                        packet_type, source, size
                                    ));
                                }
                            }
                        }
                    }
                }
                
                logger.info(&format!("Media port {} RTCP handler stopped", port_id.0));
            });
        }

        self.logger.info(&format!("Media port {} started on {}", self.id.0, self.local_addr));
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        *running = false;

        let _ = self.command_tx.send(MediaPortCommand::Stop).await;
        
        self.logger.info(&format!("Media port {} stopped", self.id.0));
        Ok(())
    }

    pub async fn set_remote_endpoint(&self, addr: SocketAddr) -> Result<()> {
        *self.remote_addr.write().await = Some(addr);
        let _ = self.command_tx.send(MediaPortCommand::SetRemoteAddr(addr)).await;
        Ok(())
    }

    pub async fn set_direction(&self, direction: MediaDirection) -> Result<()> {
        *self.direction.write().await = direction;
        let _ = self.command_tx.send(MediaPortCommand::SetDirection(direction)).await;
        Ok(())
    }

    pub async fn send_rtp_packet(&self, payload: Vec<u8>, payload_type: u8, timestamp: u32, marker: bool) -> Result<()> {
        let direction = *self.direction.read().await;
        if direction == MediaDirection::RecvOnly || direction == MediaDirection::Inactive {
            return Ok(());
        }

        let sequence = self.get_next_sequence();
        let header = RtpHeader::new(payload_type, sequence, timestamp, self.ssrc, marker);
        
        let mut packet = Vec::with_capacity(12 + payload.len());
        packet.extend_from_slice(&header.to_bytes());
        packet.extend_from_slice(&payload);

        let _ = self.command_tx.send(MediaPortCommand::SendRtp(packet)).await;
        Ok(())
    }

    pub async fn get_statistics(&self) -> MediaStatistics {
        self.statistics.read().await.clone()
    }

    pub fn get_local_port(&self) -> u16 {
        self.local_addr.port()
    }

    pub fn get_ssrc(&self) -> u32 {
        self.ssrc
    }

    async fn run_command_handler(&self, mut rx: mpsc::Receiver<MediaPortCommand>) {
        while let Some(command) = rx.recv().await {
            match command {
                MediaPortCommand::SetRemoteAddr(addr) => {
                    self.logger.debug(&format!("Media port {} remote endpoint set to {}", self.id.0, addr));
                }
                MediaPortCommand::SetDirection(direction) => {
                    self.logger.debug(&format!("Media port {} direction set to {:?}", self.id.0, direction));
                }
                MediaPortCommand::SendRtp(packet) => {
                    if let Some(remote) = *self.remote_addr.read().await {
                        if let Err(e) = self.rtp_socket.send_to(&packet, remote).await {
                            self.logger.error(&format!("Failed to send RTP packet: {}", e));
                        } else {
                            let mut stats = self.statistics.write().await;
                            stats.packets_sent += 1;
                            stats.bytes_sent += packet.len() as u64;
                        }
                    }
                }
                MediaPortCommand::Stop => break,
            }
        }
    }

    fn get_next_sequence(&self) -> u16 {
        static SEQUENCE: AtomicU16 = AtomicU16::new(0);
        SEQUENCE.fetch_add(1, Ordering::SeqCst)
    }
}

// Media Stream
pub struct MediaStream {
    pub media_type: MediaType,
    pub port: Arc<MediaPort>,
    pub payload_type: u8,
    pub clock_rate: u32,
    pub ptime: u32, // Packetization time in ms
    encoder: RwLock<Option<Box<dyn AudioEncoder>>>,
    decoder: RwLock<Option<Box<dyn AudioDecoder>>>,
    jitter_buffer: Arc<JitterBuffer>,
    timestamp: AtomicU32,
    logger: Arc<dyn Logger>,
}

// Audio encoder trait
pub trait AudioEncoder: Send + Sync {
    fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>>;
    fn samples_per_frame(&self) -> usize;
}

// Audio decoder trait
pub trait AudioDecoder: Send + Sync {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>>;
}

// Jitter buffer
pub struct JitterBuffer {
    buffer: RwLock<HashMap<u16, JitterBufferEntry>>,
    max_size: usize,
    target_delay: Duration,
}

struct JitterBufferEntry {
    data: Vec<u8>,
    timestamp: u32,
    received_at: Instant,
}

impl JitterBuffer {
    pub fn new(max_size: usize, target_delay: Duration) -> Self {
        JitterBuffer {
            buffer: RwLock::new(HashMap::new()),
            max_size,
            target_delay,
        }
    }

    pub async fn insert(&self, sequence: u16, data: Vec<u8>, timestamp: u32) {
        let mut buffer = self.buffer.write().await;
        
        if buffer.len() >= self.max_size {
            // Remove oldest entry
            if let Some(min_seq) = buffer.keys().min().copied() {
                buffer.remove(&min_seq);
            }
        }

        buffer.insert(sequence, JitterBufferEntry {
            data,
            timestamp,
            received_at: Instant::now(),
        });
    }

    pub async fn get(&self, sequence: u16) -> Option<Vec<u8>> {
        let buffer = self.buffer.read().await;
        buffer.get(&sequence).map(|entry| entry.data.clone())
    }

    pub async fn get_ready_packets(&self) -> Vec<(u16, Vec<u8>)> {
        let now = Instant::now();
        let buffer = self.buffer.read().await;
        
        let mut ready_packets = Vec::new();
        for (seq, entry) in buffer.iter() {
            if now.duration_since(entry.received_at) >= self.target_delay {
                ready_packets.push((*seq, entry.data.clone()));
            }
        }
        
        ready_packets.sort_by_key(|(seq, _)| *seq);
        ready_packets
    }
}

impl MediaStream {
    pub fn new(
        media_type: MediaType,
        port: Arc<MediaPort>,
        payload_type: u8,
        clock_rate: u32,
        ptime: u32,
        logger: Arc<dyn Logger>,
    ) -> Self {
        MediaStream {
            media_type,
            port,
            payload_type,
            clock_rate,
            ptime,
            encoder: RwLock::new(None),
            decoder: RwLock::new(None),
            jitter_buffer: Arc::new(JitterBuffer::new(100, Duration::from_millis(50))),
            timestamp: AtomicU32::new(0),
            logger,
        }
    }

    pub async fn send_audio(&self, _pcm_data: &[i16]) -> Result<()> {
        let encoder = self.encoder.read().await;
        if let Some(ref _enc) = *encoder {
            // Encode audio
            // In real implementation, would encode PCM data
            let encoded = vec![0u8; 160]; // Placeholder
            
            // Send RTP packet
            let timestamp = self.timestamp.fetch_add(
                (self.ptime * self.clock_rate / 1000) as u32,
                Ordering::SeqCst
            );
            
            self.port.send_rtp_packet(encoded, self.payload_type, timestamp, false).await?;
        }
        
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        self.port.start().await?;
        
        // Start audio processing tasks
        // In real implementation, would start audio capture/playback
        
        self.logger.info(&format!("Media stream started on port {}", self.port.get_local_port()));
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        self.port.stop().await?;
        
        self.logger.info("Media stream stopped");
        Ok(())
    }
}

// Generate random SSRC
fn generate_ssrc() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    (now.as_secs() as u32) ^ (now.subsec_nanos() as u32)
}

// Create RTCP report
fn create_rtcp_report(ssrc: u32, stats: &MediaStatistics) -> Vec<u8> {
    // Create simplified RTCP SR (Sender Report)
    let mut packet = Vec::new();
    
    // RTCP header
    packet.push(0x80); // V=2, P=0, RC=0
    packet.push(200);  // PT=SR
    packet.extend_from_slice(&0u16.to_be_bytes()); // Length (placeholder)
    packet.extend_from_slice(&ssrc.to_be_bytes()); // SSRC
    
    // NTP timestamp (simplified - use current time)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    packet.extend_from_slice(&now.as_secs().to_be_bytes());
    
    // RTP timestamp
    packet.extend_from_slice(&0u32.to_be_bytes());
    
    // Packet count
    packet.extend_from_slice(&(stats.packets_sent as u32).to_be_bytes());
    
    // Octet count
    packet.extend_from_slice(&(stats.bytes_sent as u32).to_be_bytes());
    
    // Update length field
    let length = ((packet.len() - 4) / 4) as u16;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    
    packet
}

// PCMU codec (G.711 μ-law)
pub struct PcmuCodec;

impl AudioEncoder for PcmuCodec {
    fn encode(&mut self, pcm: &[i16]) -> Result<Vec<u8>> {
        // Simplified μ-law encoding
        let mut encoded = Vec::with_capacity(pcm.len());
        for &sample in pcm {
            encoded.push(linear_to_ulaw(sample));
        }
        Ok(encoded)
    }

    fn samples_per_frame(&self) -> usize {
        160 // 20ms at 8kHz
    }
}

impl AudioDecoder for PcmuCodec {
    fn decode(&mut self, data: &[u8]) -> Result<Vec<i16>> {
        // Simplified μ-law decoding
        let mut decoded = Vec::with_capacity(data.len());
        for &byte in data {
            decoded.push(ulaw_to_linear(byte));
        }
        Ok(decoded)
    }
}

// μ-law encoding/decoding functions (simplified)
fn linear_to_ulaw(sample: i16) -> u8 {
    // Simplified implementation
    // Real implementation would follow ITU-T G.711 specification
    ((sample >> 8) as u8) ^ 0x80
}

fn ulaw_to_linear(ulaw: u8) -> i16 {
    // Simplified implementation
    // Real implementation would follow ITU-T G.711 specification
    ((ulaw ^ 0x80) as i8 as i16) << 8
}

// Media Manager for a call
pub struct CallMediaManager {
    streams: RwLock<HashMap<MediaType, Arc<MediaStream>>>,
    capabilities: MediaCapabilities,
    logger: Arc<dyn Logger>,
}

impl CallMediaManager {
    pub fn new(local_address: String, logger: Arc<dyn Logger>) -> Self {
        CallMediaManager {
            streams: RwLock::new(HashMap::new()),
            capabilities: MediaCapabilities::new(local_address),
            logger,
        }
    }

    pub async fn create_audio_stream(&self, port: u16, payload_type: u8, clock_rate: u32) -> Result<Arc<MediaStream>> {
        let addr = format!("{}:{}", self.capabilities.local_address, port).parse()
            .map_err(|_| SipError::MediaError("Invalid address".to_string()))?;
        
        let media_port = MediaPort::new(
            MediaPortId(format!("audio-{}", port)),
            addr,
            self.logger.clone(),
        ).await?;

        let stream = Arc::new(MediaStream::new(
            MediaType::Audio,
            media_port,
            payload_type,
            clock_rate,
            20, // 20ms ptime
            self.logger.clone(),
        ));

        let mut streams = self.streams.write().await;
        streams.insert(MediaType::Audio, stream.clone());

        Ok(stream)
    }

    pub async fn start_all_streams(&self) -> Result<()> {
        let streams = self.streams.read().await;
        for stream in streams.values() {
            stream.start().await?;
        }
        Ok(())
    }

    pub async fn stop_all_streams(&self) -> Result<()> {
        let streams = self.streams.read().await;
        for stream in streams.values() {
            stream.stop().await?;
        }
        Ok(())
    }

    pub async fn get_stream(&self, media_type: MediaType) -> Option<Arc<MediaStream>> {
        let streams = self.streams.read().await;
        streams.get(&media_type).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rtp_header() {
        let header = RtpHeader::new(0, 1234, 567890, 0x12345678, false);
        assert_eq!(header.version(), 2);
        assert_eq!(header.payload_type(), 0);
        assert_eq!(header.sequence_number(), 1234);
        assert_eq!(header.timestamp_value(), 567890);
        assert_eq!(header.ssrc_value(), 0x12345678);
        assert!(!header.marker());

        let bytes = header.to_bytes();
        let parsed = RtpHeader::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.version(), 2);
        assert_eq!(parsed.payload_type(), 0);
        assert_eq!(parsed.sequence_number(), 1234);
    }

    #[test]
    fn test_pcmu_codec() {
        let mut codec = PcmuCodec;
        let pcm = vec![0i16, 1000, -1000, 32767, -32768];
        let encoded = codec.encode(&pcm).unwrap();
        assert_eq!(encoded.len(), pcm.len());
        
        let decoded = codec.decode(&encoded).unwrap();
        assert_eq!(decoded.len(), encoded.len());
    }
}