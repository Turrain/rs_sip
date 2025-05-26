use std::collections::HashMap;
use std::fmt;
use crate::{Result, SipError, MediaType, MediaDirection, Session, SessionOrigin, 
    ConnectionData, TimingInfo, MediaDescription};

// SDP Parser
pub struct SdpParser;

impl SdpParser {
    pub fn parse(sdp: &str) -> Result<Session> {
        let lines = sdp.lines();
        let mut session = Session {
            version: 0,
            origin: SessionOrigin {
                username: "-".to_string(),
                session_id: "0".to_string(),
                session_version: "0".to_string(),
                network_type: "IN".to_string(),
                address_type: "IP4".to_string(),
                address: "0.0.0.0".to_string(),
            },
            name: "-".to_string(),
            connection: None,
            timing: vec![],
            media: vec![],
            attributes: HashMap::new(),
        };

        let mut current_media: Option<MediaDescription> = None;
        let mut in_media_section = false;

        for line in lines {
            if line.len() < 2 || !line.contains('=') {
                continue;
            }

            let type_char = line.chars().next().unwrap();
            let value = &line[2..];

            match type_char {
                'v' => {
                    session.version = value.parse()
                        .map_err(|_| SipError::ParseError("Invalid SDP version".to_string()))?;
                }
                'o' => {
                    session.origin = Self::parse_origin(value)?;
                }
                's' => {
                    if !in_media_section {
                        session.name = value.to_string();
                    }
                }
                'c' => {
                    let connection = Self::parse_connection(value)?;
                    if in_media_section {
                        if let Some(ref mut media) = current_media {
                            media.connection = Some(connection);
                        }
                    } else {
                        session.connection = Some(connection);
                    }
                }
                't' => {
                    let timing = Self::parse_timing(value)?;
                    session.timing.push(timing);
                }
                'm' => {
                    // Save previous media section if exists
                    if let Some(media) = current_media.take() {
                        session.media.push(media);
                    }
                    
                    current_media = Some(Self::parse_media(value)?);
                    in_media_section = true;
                }
                'a' => {
                    let (attr_name, attr_value) = Self::parse_attribute(value)?;
                    
                    if in_media_section {
                        if let Some(ref mut media) = current_media {
                            // Handle media-specific attributes
                            match attr_name.as_str() {
                                "sendrecv" => media.direction = MediaDirection::SendRecv,
                                "sendonly" => media.direction = MediaDirection::SendOnly,
                                "recvonly" => media.direction = MediaDirection::RecvOnly,
                                "inactive" => media.direction = MediaDirection::Inactive,
                                _ => {
                                    media.attributes.insert(attr_name, attr_value);
                                }
                            }
                        }
                    } else {
                        session.attributes.insert(attr_name, attr_value);
                    }
                }
                _ => {
                    // Ignore unknown lines
                }
            }
        }

        // Save last media section
        if let Some(media) = current_media {
            session.media.push(media);
        }

        // Validate session
        if session.media.is_empty() && session.timing.is_empty() {
            session.timing.push(TimingInfo { start: 0, stop: 0 });
        }

        Ok(session)
    }

    fn parse_origin(value: &str) -> Result<SessionOrigin> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 6 {
            return Err(SipError::ParseError("Invalid origin line".to_string()));
        }

        Ok(SessionOrigin {
            username: parts[0].to_string(),
            session_id: parts[1].to_string(),
            session_version: parts[2].to_string(),
            network_type: parts[3].to_string(),
            address_type: parts[4].to_string(),
            address: parts[5].to_string(),
        })
    }

    fn parse_connection(value: &str) -> Result<ConnectionData> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 3 {
            return Err(SipError::ParseError("Invalid connection line".to_string()));
        }

        Ok(ConnectionData {
            network_type: parts[0].to_string(),
            address_type: parts[1].to_string(),
            address: parts[2].to_string(),
        })
    }

    fn parse_timing(value: &str) -> Result<TimingInfo> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(SipError::ParseError("Invalid timing line".to_string()));
        }

        Ok(TimingInfo {
            start: parts[0].parse()
                .map_err(|_| SipError::ParseError("Invalid start time".to_string()))?,
            stop: parts[1].parse()
                .map_err(|_| SipError::ParseError("Invalid stop time".to_string()))?,
        })
    }

    fn parse_media(value: &str) -> Result<MediaDescription> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 4 {
            return Err(SipError::ParseError("Invalid media line".to_string()));
        }

        let media_type = match parts[0] {
            "audio" => MediaType::Audio,
            "video" => MediaType::Video,
            "application" => MediaType::Application,
            "text" => MediaType::Text,
            "message" => MediaType::Message,
            _ => return Err(SipError::ParseError(format!("Unknown media type: {}", parts[0]))),
        };

        let (port, port_count) = if parts[1].contains('/') {
            let port_parts: Vec<&str> = parts[1].split('/').collect();
            let port = port_parts[0].parse()
                .map_err(|_| SipError::ParseError("Invalid port".to_string()))?;
            let count = port_parts[1].parse()
                .map_err(|_| SipError::ParseError("Invalid port count".to_string()))?;
            (port, Some(count))
        } else {
            let port = parts[1].parse()
                .map_err(|_| SipError::ParseError("Invalid port".to_string()))?;
            (port, None)
        };

        let protocol = parts[2].to_string();
        let formats = parts[3..].iter().map(|s| s.to_string()).collect();

        Ok(MediaDescription {
            media_type,
            port,
            port_count,
            protocol,
            formats,
            connection: None,
            attributes: HashMap::new(),
            direction: MediaDirection::SendRecv, // Default
        })
    }

    fn parse_attribute(value: &str) -> Result<(String, Option<String>)> {
        if let Some(colon_pos) = value.find(':') {
            let name = value[..colon_pos].to_string();
            let attr_value = value[colon_pos + 1..].to_string();
            Ok((name, Some(attr_value)))
        } else {
            Ok((value.to_string(), None))
        }
    }
}

// SDP Builder
pub struct SdpBuilder {
    session: Session,
}

impl SdpBuilder {
    pub fn new() -> Self {
        SdpBuilder {
            session: Session {
                version: 0,
                origin: SessionOrigin {
                    username: "-".to_string(),
                    session_id: Self::generate_session_id(),
                    session_version: "1".to_string(),
                    network_type: "IN".to_string(),
                    address_type: "IP4".to_string(),
                    address: "0.0.0.0".to_string(),
                },
                name: "-".to_string(),
                connection: None,
                timing: vec![TimingInfo { start: 0, stop: 0 }],
                media: vec![],
                attributes: HashMap::new(),
            },
        }
    }

    fn generate_session_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
        format!("{}", now.as_secs())
    }

    pub fn origin(mut self, username: &str, address: &str) -> Self {
        self.session.origin.username = username.to_string();
        self.session.origin.address = address.to_string();
        self
    }

    pub fn session_name(mut self, name: &str) -> Self {
        self.session.name = name.to_string();
        self
    }

    pub fn connection(mut self, address: &str) -> Self {
        self.session.connection = Some(ConnectionData {
            network_type: "IN".to_string(),
            address_type: if address.contains(':') { "IP6" } else { "IP4" }.to_string(),
            address: address.to_string(),
        });
        self
    }

    pub fn add_media(mut self, media: MediaDescription) -> Self {
        self.session.media.push(media);
        self
    }

    pub fn add_audio_media(mut self, port: u16, codecs: Vec<RtpCodec>) -> Self {
        let mut media = MediaDescription {
            media_type: MediaType::Audio,
            port,
            port_count: None,
            protocol: "RTP/AVP".to_string(),
            formats: codecs.iter().map(|c| c.payload_type.to_string()).collect(),
            connection: None,
            attributes: HashMap::new(),
            direction: MediaDirection::SendRecv,
        };

        // Add codec attributes
        for codec in codecs {
            media.attributes.insert(
                format!("rtpmap:{}", codec.payload_type),
                Some(format!("{}/{}{}", 
                    codec.encoding_name, 
                    codec.clock_rate,
                    if codec.channels > 1 { format!("/{}", codec.channels) } else { String::new() }
                )),
            );

            if !codec.parameters.is_empty() {
                media.attributes.insert(
                    format!("fmtp:{}", codec.payload_type),
                    Some(codec.parameters.clone()),
                );
            }
        }

        self.session.media.push(media);
        self
    }

    pub fn add_video_media(mut self, port: u16, codecs: Vec<RtpCodec>) -> Self {
        let mut media = MediaDescription {
            media_type: MediaType::Video,
            port,
            port_count: None,
            protocol: "RTP/AVP".to_string(),
            formats: codecs.iter().map(|c| c.payload_type.to_string()).collect(),
            connection: None,
            attributes: HashMap::new(),
            direction: MediaDirection::SendRecv,
        };

        // Add codec attributes
        for codec in codecs {
            media.attributes.insert(
                format!("rtpmap:{}", codec.payload_type),
                Some(format!("{}/{}", codec.encoding_name, codec.clock_rate)),
            );

            if !codec.parameters.is_empty() {
                media.attributes.insert(
                    format!("fmtp:{}", codec.payload_type),
                    Some(codec.parameters.clone()),
                );
            }
        }

        self.session.media.push(media);
        self
    }

    pub fn attribute(mut self, name: &str, value: Option<&str>) -> Self {
        self.session.attributes.insert(name.to_string(), value.map(|v| v.to_string()));
        self
    }

    pub fn build(self) -> Session {
        self.session
    }
}

// RTP Codec representation
#[derive(Debug, Clone)]
pub struct RtpCodec {
    pub payload_type: u8,
    pub encoding_name: String,
    pub clock_rate: u32,
    pub channels: u8,
    pub parameters: String,
}

impl RtpCodec {
    pub fn new(payload_type: u8, encoding_name: &str, clock_rate: u32) -> Self {
        RtpCodec {
            payload_type,
            encoding_name: encoding_name.to_string(),
            clock_rate,
            channels: 1,
            parameters: String::new(),
        }
    }

    pub fn with_channels(mut self, channels: u8) -> Self {
        self.channels = channels;
        self
    }

    pub fn with_parameters(mut self, parameters: &str) -> Self {
        self.parameters = parameters.to_string();
        self
    }
}

// Common codecs
impl RtpCodec {
    pub fn pcmu() -> Self {
        RtpCodec::new(0, "PCMU", 8000)
    }

    pub fn pcma() -> Self {
        RtpCodec::new(8, "PCMA", 8000)
    }

    pub fn g722() -> Self {
        RtpCodec::new(9, "G722", 8000)
    }

    pub fn opus() -> Self {
        RtpCodec::new(111, "opus", 48000).with_channels(2)
    }

    pub fn telephone_event() -> Self {
        RtpCodec::new(101, "telephone-event", 8000)
            .with_parameters("0-15")
    }

    pub fn h264() -> Self {
        RtpCodec::new(96, "H264", 90000)
            .with_parameters("profile-level-id=42e01e")
    }

    pub fn vp8() -> Self {
        RtpCodec::new(100, "VP8", 90000)
    }
}

// Session formatting (to SDP string)
impl Session {
    pub fn to_sdp(&self) -> String {
        let mut sdp = String::new();

        // Version
        sdp.push_str(&format!("v={}\r\n", self.version));

        // Origin
        sdp.push_str(&format!("o={} {} {} {} {} {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.network_type,
            self.origin.address_type,
            self.origin.address
        ));

        // Session name
        sdp.push_str(&format!("s={}\r\n", self.name));

        // Connection (session-level)
        if let Some(ref conn) = self.connection {
            sdp.push_str(&format!("c={} {} {}\r\n",
                conn.network_type,
                conn.address_type,
                conn.address
            ));
        }

        // Timing
        for timing in &self.timing {
            sdp.push_str(&format!("t={} {}\r\n", timing.start, timing.stop));
        }

        // Session attributes
        for (name, value) in &self.attributes {
            if let Some(val) = value {
                sdp.push_str(&format!("a={}:{}\r\n", name, val));
            } else {
                sdp.push_str(&format!("a={}\r\n", name));
            }
        }

        // Media sections
        for media in &self.media {
            sdp.push_str(&media.to_sdp());
        }

        sdp
    }
}

impl MediaDescription {
    pub fn to_sdp(&self) -> String {
        let mut sdp = String::new();

        // Media line
        let media_type = match self.media_type {
            MediaType::Audio => "audio",
            MediaType::Video => "video",
            MediaType::Application => "application",
            MediaType::Text => "text",
            MediaType::Message => "message",
        };

        let port_str = if let Some(count) = self.port_count {
            format!("{}/{}", self.port, count)
        } else {
            self.port.to_string()
        };

        sdp.push_str(&format!("m={} {} {} {}\r\n",
            media_type,
            port_str,
            self.protocol,
            self.formats.join(" ")
        ));

        // Connection (media-level)
        if let Some(ref conn) = self.connection {
            sdp.push_str(&format!("c={} {} {}\r\n",
                conn.network_type,
                conn.address_type,
                conn.address
            ));
        }

        // Direction attribute
        let direction_str = match self.direction {
            MediaDirection::SendRecv => "sendrecv",
            MediaDirection::SendOnly => "sendonly",
            MediaDirection::RecvOnly => "recvonly",
            MediaDirection::Inactive => "inactive",
        };
        sdp.push_str(&format!("a={}\r\n", direction_str));

        // Media attributes
        for (name, value) in &self.attributes {
            if let Some(val) = value {
                sdp.push_str(&format!("a={}:{}\r\n", name, val));
            } else {
                sdp.push_str(&format!("a={}\r\n", name));
            }
        }

        sdp
    }
}

// SDP negotiation
pub struct SdpNegotiator;

impl SdpNegotiator {
    pub fn create_answer(offer: &Session, capabilities: &MediaCapabilities) -> Result<Session> {
        let mut answer = SdpBuilder::new()
            .origin("-", &capabilities.local_address)
            .connection(&capabilities.local_address)
            .session_name("-")
            .build();

        // Process each media in the offer
        for offered_media in &offer.media {
            let answer_media = Self::negotiate_media(offered_media, capabilities)?;
            answer.media.push(answer_media);
        }

        Ok(answer)
    }

    fn negotiate_media(
        offered: &MediaDescription,
        capabilities: &MediaCapabilities,
    ) -> Result<MediaDescription> {
        let supported_codecs = match offered.media_type {
            MediaType::Audio => &capabilities.audio_codecs,
            MediaType::Video => &capabilities.video_codecs,
            _ => return Err(SipError::InvalidState("Unsupported media type".to_string())),
        };

        // Find common codecs
        let mut selected_formats = Vec::new();
        let mut selected_attributes = HashMap::new();

        for format in &offered.formats {
            if let Ok(pt) = format.parse::<u8>() {
                if supported_codecs.iter().any(|c| c.payload_type == pt) {
                    selected_formats.push(format.clone());
                    
                    // Copy relevant attributes
                    let rtpmap_key = format!("rtpmap:{}", pt);
                    if let Some(rtpmap) = offered.attributes.get(&rtpmap_key) {
                        selected_attributes.insert(rtpmap_key, rtpmap.clone());
                    }
                    
                    let fmtp_key = format!("fmtp:{}", pt);
                    if let Some(fmtp) = offered.attributes.get(&fmtp_key) {
                        selected_attributes.insert(fmtp_key, fmtp.clone());
                    }
                }
            }
        }

        if selected_formats.is_empty() {
            // No common codecs - reject media
            return Ok(MediaDescription {
                media_type: offered.media_type,
                port: 0, // Port 0 means rejected
                port_count: None,
                protocol: offered.protocol.clone(),
                formats: vec![],
                connection: None,
                attributes: HashMap::new(),
                direction: MediaDirection::Inactive,
            });
        }

        // Allocate port for this media
        let port = capabilities.allocate_port(offered.media_type)?;

        Ok(MediaDescription {
            media_type: offered.media_type,
            port,
            port_count: None,
            protocol: offered.protocol.clone(),
            formats: selected_formats,
            connection: None,
            attributes: selected_attributes,
            direction: offered.direction,
        })
    }
}

// Media capabilities
pub struct MediaCapabilities {
    pub local_address: String,
    pub audio_codecs: Vec<RtpCodec>,
    pub video_codecs: Vec<RtpCodec>,
    pub port_range: (u16, u16),
    allocated_ports: std::sync::RwLock<Vec<u16>>,
}

impl MediaCapabilities {
    pub fn new(local_address: String) -> Self {
        MediaCapabilities {
            local_address,
            audio_codecs: vec![
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
                RtpCodec::opus(),
                RtpCodec::telephone_event(),
            ],
            video_codecs: vec![
                RtpCodec::vp8(),
                RtpCodec::h264(),
            ],
            port_range: (10000, 20000),
            allocated_ports: std::sync::RwLock::new(Vec::new()),
        }
    }

    fn allocate_port(&self, _media_type: MediaType) -> Result<u16> {
        let mut allocated = self.allocated_ports.write().unwrap();
        
        // Find an even port number in the range
        for port in (self.port_range.0..self.port_range.1).step_by(2) {
            if !allocated.contains(&port) {
                allocated.push(port);
                allocated.push(port + 1); // Reserve RTCP port too
                return Ok(port);
            }
        }
        
        Err(SipError::MediaError("No available ports".to_string()))
    }

    pub fn release_port(&self, port: u16) {
        let mut allocated = self.allocated_ports.write().unwrap();
        allocated.retain(|&p| p != port && p != port + 1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdp_parsing() {
        let sdp = "v=0\r\n\
                   o=alice 2890844526 2890844526 IN IP4 host.atlanta.com\r\n\
                   s=-\r\n\
                   c=IN IP4 host.atlanta.com\r\n\
                   t=0 0\r\n\
                   m=audio 49170 RTP/AVP 0 8 97\r\n\
                   a=rtpmap:0 PCMU/8000\r\n\
                   a=rtpmap:8 PCMA/8000\r\n\
                   a=rtpmap:97 iLBC/8000\r\n\
                   a=sendrecv\r\n";

        let session = SdpParser::parse(sdp).unwrap();
        assert_eq!(session.version, 0);
        assert_eq!(session.origin.username, "alice");
        assert_eq!(session.media.len(), 1);
        assert_eq!(session.media[0].port, 49170);
        assert_eq!(session.media[0].formats.len(), 3);
    }

    #[test]
    fn test_sdp_builder() {
        let sdp = SdpBuilder::new()
            .origin("test", "192.168.1.100")
            .connection("192.168.1.100")
            .add_audio_media(5004, vec![
                RtpCodec::pcmu(),
                RtpCodec::pcma(),
            ])
            .build();

        let sdp_str = sdp.to_sdp();
        assert!(sdp_str.contains("v=0"));
        assert!(sdp_str.contains("o=test"));
        assert!(sdp_str.contains("c=IN IP4 192.168.1.100"));
        assert!(sdp_str.contains("m=audio 5004 RTP/AVP 0 8"));
    }
}