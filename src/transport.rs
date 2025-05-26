use std::net::SocketAddr;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, RwLock, oneshot};
use tokio::time::{sleep, Duration, timeout};
use std::fmt;

use crate::{Result, SipError, SipMessage, SipParser, TransportKey, Logger, ConsoleLogger};

// Transport trait defining common interface
pub trait Transport: Send + Sync {
    fn send<'a>(&'a self, message: &'a SipMessage, target: SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn send_response<'a>(&'a self, message: &'a SipMessage, target: SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn start<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn stop<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;
    fn local_addr(&self) -> SocketAddr;
    fn protocol(&self) -> &str;
}

// Message handler trait
pub trait MessageHandler: Send + Sync {
    fn handle_message<'a>(&'a self, message: SipMessage, source: SocketAddr, transport: Arc<dyn Transport>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

// Transport event types
#[derive(Debug)]
pub enum TransportCommand {
    Send { message: SipMessage, target: SocketAddr, response_tx: oneshot::Sender<Result<()>> },
    Stop,
}

// UDP Transport implementation
pub struct UdpTransport {
    socket: Arc<UdpSocket>,
    local_addr: SocketAddr,
    buffer_size: usize,
    message_handler: Arc<dyn MessageHandler>,
    command_tx: mpsc::Sender<TransportCommand>,
    command_rx: Arc<RwLock<mpsc::Receiver<TransportCommand>>>,
    logger: Arc<dyn Logger>,
    running: Arc<RwLock<bool>>,
}

impl Clone for UdpTransport {
    fn clone(&self) -> Self {
        panic!("UdpTransport should not be cloned directly - use Arc<UdpTransport>");
    }
}

impl UdpTransport {
    pub async fn new(
        local_addr: SocketAddr,
        message_handler: Arc<dyn MessageHandler>,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let socket = UdpSocket::bind(local_addr).await
            .map_err(|e| SipError::IoError(format!("Failed to bind UDP socket: {}", e)))?;
        
        let actual_addr = socket.local_addr()
            .map_err(|e| SipError::IoError(format!("Failed to get local address: {}", e)))?;

        let (command_tx, command_rx) = mpsc::channel(100);

        logger.info(&format!("UDP transport bound to {}", actual_addr));

        let transport = Arc::new(UdpTransport {
            socket: Arc::new(socket),
            local_addr: actual_addr,
            buffer_size: 65535,
            message_handler,
            command_tx,
            command_rx: Arc::new(RwLock::new(command_rx)),
            logger,
            running: Arc::new(RwLock::new(false)),
        });

        Ok(transport)
    }

    pub async fn start_tasks(self: Arc<Self>) {
        // Spawn receiver task
        let receiver = self.clone();
        tokio::spawn(async move {
            receiver.run_receiver().await;
        });

        // Spawn sender task
        let sender = self.clone();
        tokio::spawn(async move {
            sender.run_sender().await;
        });
    }

    async fn run_receiver(self: Arc<Self>) {
        let mut buffer = vec![0u8; self.buffer_size];
        
        loop {
            let running = *self.running.read().await;
            if !running {
                break;
            }

            // Use timeout to periodically check if we should stop
            match timeout(Duration::from_secs(1), self.socket.recv_from(&mut buffer)).await {
                Ok(Ok((size, source))) => {
                    self.logger.debug(&format!("Received {} bytes from {}", size, source));
                    
                    match SipParser::parse(&buffer[..size]) {
                        Ok((message, _)) => {
                            self.logger.debug(&format!("Parsed SIP message from {}", source));
                            let transport = self.clone() as Arc<dyn Transport>;
                            self.message_handler.handle_message(message, source, transport).await;
                        }
                        Err(e) => {
                            self.logger.error(&format!("Failed to parse SIP message from {}: {}", source, e));
                        }
                    }
                }
                Ok(Err(e)) => {
                    self.logger.error(&format!("UDP receive error: {}", e));
                }
                Err(_) => {
                    // Timeout - check if we should continue
                    continue;
                }
            }
        }
        
        self.logger.info("UDP receiver stopped");
    }

    async fn run_sender(self: Arc<Self>) {
        let mut command_rx = self.command_rx.write().await;
        
        while let Some(command) = command_rx.recv().await {
            match command {
                TransportCommand::Send { message, target, response_tx } => {
                    let data = message.to_bytes();
                    let result = self.socket.send_to(&data, target).await
                        .map(|_| ())
                        .map_err(|e| SipError::TransportError(format!("UDP send error: {}", e)));
                    
                    if result.is_ok() {
                        self.logger.debug(&format!("Sent {} bytes to {}", data.len(), target));
                    } else {
                        self.logger.error(&format!("Failed to send to {}: {:?}", target, result));
                    }
                    
                    let _ = response_tx.send(result);
                }
                TransportCommand::Stop => {
                    break;
                }
            }
        }
        
        self.logger.info("UDP sender stopped");
    }
}

impl Transport for UdpTransport {
    fn send<'a>(&'a self, message: &'a SipMessage, target: SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let (response_tx, response_rx) = oneshot::channel();
            
            self.command_tx.send(TransportCommand::Send {
                message: message.clone(),
                target,
                response_tx,
            }).await.map_err(|_| SipError::TransportError("Failed to send command".to_string()))?;
            
            response_rx.await.map_err(|_| SipError::TransportError("Failed to get send response".to_string()))?
        })
    }

    fn send_response<'a>(&'a self, message: &'a SipMessage, target: SocketAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        self.send(message, target)
    }

    fn start<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut running = self.running.write().await;
            if *running {
                return Ok(());
            }
            *running = true;
            
            self.logger.info(&format!("UDP transport started on {}", self.local_addr));
            Ok(())
        })
    }

    fn stop<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        Box::pin(async move {
            let mut running = self.running.write().await;
            if !*running {
                return Ok(());
            }
            *running = false;

            // Send stop command
            let _ = self.command_tx.send(TransportCommand::Stop).await;
            
            self.logger.info("UDP transport stopped");
            Ok(())
        })
    }

    fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    fn protocol(&self) -> &str {
        "UDP"
    }
}

// Transport Manager
pub struct TransportManager {
    transports: Arc<RwLock<HashMap<TransportKey, Arc<dyn Transport>>>>,
    logger: Arc<dyn Logger>,
}

impl TransportManager {
    pub fn new(logger: Arc<dyn Logger>) -> Self {
        TransportManager {
            transports: Arc::new(RwLock::new(HashMap::new())),
            logger,
        }
    }

    pub async fn add_transport(&self, transport: Arc<dyn Transport>) -> Result<()> {
        let key = TransportKey {
            protocol: transport.protocol().to_string(),
            local_addr: transport.local_addr(),
        };

        let mut transports = self.transports.write().await;
        transports.insert(key.clone(), transport.clone());
        
        self.logger.info(&format!("Added {} transport on {}", key.protocol, key.local_addr));
        
        transport.start().await?;
        Ok(())
    }

    pub async fn remove_transport(&self, key: &TransportKey) -> Result<()> {
        let mut transports = self.transports.write().await;
        if let Some(transport) = transports.remove(key) {
            transport.stop().await?;
            self.logger.info(&format!("Removed {} transport on {}", key.protocol, key.local_addr));
        }
        Ok(())
    }

    pub async fn get_transport(&self, protocol: &str, local_addr: Option<SocketAddr>) -> Option<Arc<dyn Transport>> {
        let transports = self.transports.read().await;
        
        if let Some(addr) = local_addr {
            let key = TransportKey {
                protocol: protocol.to_string(),
                local_addr: addr,
            };
            transports.get(&key).cloned()
        } else {
            // Find first transport with matching protocol
            transports.values()
                .find(|t| t.protocol() == protocol)
                .cloned()
        }
    }

    pub async fn find_transport_for_target(&self, target: SocketAddr, protocol: &str) -> Option<Arc<dyn Transport>> {
        let transports = self.transports.read().await;
        
        // For now, just return the first transport with matching protocol
        // In a real implementation, we'd consider network interfaces, routing, etc.
        transports.values()
            .find(|t| t.protocol() == protocol)
            .cloned()
    }

    pub async fn stop_all(&self) -> Result<()> {
        let transports = self.transports.read().await;
        for transport in transports.values() {
            transport.stop().await?;
        }
        Ok(())
    }
}

// DNS Resolution helper
pub struct DnsResolver {
    logger: Arc<dyn Logger>,
}

impl DnsResolver {
    pub fn new(logger: Arc<dyn Logger>) -> Self {
        DnsResolver { logger }
    }

    pub async fn resolve(&self, host: &str, port: Option<u16>) -> Result<Vec<SocketAddr>> {
        let port = port.unwrap_or(5060);
        
        // First try to parse as IP address
        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        // Resolve hostname
        let addr_str = format!("{}:{}", host, port);
        match tokio::net::lookup_host(&addr_str).await {
            Ok(addrs) => {
                let addresses: Vec<SocketAddr> = addrs.collect();
                if addresses.is_empty() {
                    Err(SipError::TransportError(format!("No addresses found for {}", host)))
                } else {
                    self.logger.debug(&format!("Resolved {} to {:?}", host, addresses));
                    Ok(addresses)
                }
            }
            Err(e) => Err(SipError::TransportError(format!("DNS resolution failed for {}: {}", host, e)))
        }
    }

    pub async fn resolve_target(&self, uri: &crate::SipUri) -> Result<Vec<SocketAddr>> {
        self.resolve(&uri.host, uri.port).await
    }
}

// Retransmission timer for reliable transmission
pub struct RetransmissionTimer {
    timer_t1: Duration,
    timer_t2: Duration,
    max_retries: u32,
}

impl Default for RetransmissionTimer {
    fn default() -> Self {
        RetransmissionTimer {
            timer_t1: Duration::from_millis(500),
            timer_t2: Duration::from_secs(4),
            max_retries: 7,
        }
    }
}

impl RetransmissionTimer {
    pub fn new(timer_t1: Duration, timer_t2: Duration, max_retries: u32) -> Self {
        RetransmissionTimer {
            timer_t1,
            timer_t2,
            max_retries,
        }
    }

    pub async fn run_with_retransmission<F, Fut>(
        &self,
        transport: Arc<dyn Transport>,
        message: SipMessage,
        target: SocketAddr,
        is_invite: bool,
        mut on_response: F,
    ) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = Option<()>>,
    {
        let mut retry_count = 0;
        let mut current_interval = if is_invite { self.timer_t1 } else { self.timer_t1 };

        loop {
            // Send the message
            transport.send(&message, target).await?;

            // Wait for response or timeout
            match timeout(current_interval, on_response()).await {
                Ok(Some(_)) => {
                    // Response received
                    return Ok(());
                }
                Ok(None) => {
                    // Continue waiting
                }
                Err(_) => {
                    // Timeout - retry
                    retry_count += 1;
                    if retry_count >= self.max_retries {
                        return Err(SipError::TransactionTimeout);
                    }

                    // Calculate next interval
                    if is_invite {
                        current_interval = std::cmp::min(current_interval * 2, self.timer_t2);
                    } else {
                        current_interval = std::cmp::min(current_interval * 2, self.timer_t2);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{SipMethod, SipUri};

    struct TestMessageHandler;

    impl MessageHandler for TestMessageHandler {
        fn handle_message<'a>(&'a self, _message: SipMessage, _source: SocketAddr, _transport: Arc<dyn Transport>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                // Test implementation
            })
        }
    }

    #[tokio::test]
    async fn test_udp_transport() {
        let logger = Arc::new(ConsoleLogger);
        let handler = Arc::new(TestMessageHandler);
        let addr = "127.0.0.1:0".parse().unwrap();
        
        let transport = UdpTransport::new(addr, handler, logger).await.unwrap();
        transport.start().await.unwrap();
        
        assert_eq!(transport.protocol(), "UDP");
        
        transport.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_dns_resolver() {
        let logger = Arc::new(ConsoleLogger);
        let resolver = DnsResolver::new(logger);
        
        // Test IP address parsing
        let addrs = resolver.resolve("127.0.0.1", Some(5060)).await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "127.0.0.1:5060".parse().unwrap());
        
        // Test localhost resolution
        let addrs = resolver.resolve("localhost", Some(5060)).await.unwrap();
        assert!(!addrs.is_empty());
    }
}