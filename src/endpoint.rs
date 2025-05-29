use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::{RwLock, mpsc};

use crate::{
    call, generate_branch, generate_call_id, AccountId, CSeqHeader, CallId, ConsoleLogger, ContactHeader, DialogManager, DnsResolver, EndpointConfig, Event, Logger, MessageHandler, Result, SipError, SipMessage, SipMethod, SipParser, SipUri, TransactionEvent, TransactionEventHandler, TransactionId, TransactionManager, Transport, TransportEvent, TransportKey, TransportManager, UdpTransport, ViaHeader
};

// Component Registry
#[derive(Clone)]
pub struct ComponentRegistry {
    pub transport_manager: Arc<TransportManager>,
    pub transaction_manager: Arc<TransactionManager>,
    pub dialog_manager: Arc<DialogManager>,
    pub dns_resolver: Arc<DnsResolver>,
}

// Event dispatcher
pub struct EventDispatcher {
    handlers: Arc<RwLock<Vec<Box<dyn EventHandler>>>>,
    event_tx: mpsc::Sender<Event>,
    event_rx: Arc<RwLock<mpsc::Receiver<Event>>>,
}

// Event handler trait
pub trait EventHandler: Send + Sync {
    fn on_event<'a>(&'a self, event: Event) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

impl EventDispatcher {
    pub fn new() -> Self {
        let (event_tx, event_rx) = mpsc::channel(1000);
        EventDispatcher {
            handlers: Arc::new(RwLock::new(Vec::new())),
            event_tx,
            event_rx: Arc::new(RwLock::new(event_rx)),
        }
    }

    pub async fn add_handler(&self, handler: Box<dyn EventHandler>) {
        let mut handlers = self.handlers.write().await;
        handlers.push(handler);
    }

    pub async fn dispatch(&self, event: Event) {
        let _ = self.event_tx.send(event).await;
    }

    pub async fn start(self: Arc<Self>) {
        let handlers = self.handlers.clone();
        let event_rx = self.event_rx.clone();
        
        tokio::spawn(async move {
            let mut rx = event_rx.write().await;
            while let Some(event) = rx.recv().await {
                let handlers = handlers.read().await;
                for handler in handlers.iter() {
                    handler.on_event(event.clone()).await;
                }
            }
        });
    }
}

// Main Endpoint structure
pub struct Endpoint {
    config: EndpointConfig,
    accounts: Arc<RwLock<HashMap<AccountId, Arc<crate::Account>>>>,
    calls: Arc<RwLock<HashMap<CallId, Arc<crate::Call>>>>,
    registry: ComponentRegistry,
    event_dispatcher: Arc<EventDispatcher>,
    logger: Arc<dyn Logger>,
    running: Arc<RwLock<bool>>,
    message_handler: Arc<EndpointMessageHandler>,
}

// Endpoint builder
pub struct EndpointBuilder {
    config: EndpointConfig,
    logger: Option<Arc<dyn Logger>>,
}

impl EndpointBuilder {
    pub fn new() -> Self {
        EndpointBuilder {
            config: EndpointConfig::default(),
            logger: None,
        }
    }

    pub fn user_agent(mut self, user_agent: &str) -> Self {
        self.config.user_agent = user_agent.to_string();
        self
    }

    pub fn max_calls(mut self, max_calls: usize) -> Self {
        self.config.max_calls = max_calls;
        self
    }

    pub fn max_accounts(mut self, max_accounts: usize) -> Self {
        self.config.max_accounts = max_accounts;
        self
    }

    pub fn nat_enabled(mut self, enabled: bool) -> Self {
        self.config.nat_enabled = enabled;
        self
    }

    pub fn stun_servers(mut self, servers: Vec<String>) -> Self {
        self.config.stun_servers = servers;
        self
    }

    pub fn logger(mut self, logger: Arc<dyn Logger>) -> Self {
        self.logger = Some(logger);
        self
    }

    pub fn udp_port(mut self, port: u16) -> Self {
        self.config.transport_config.udp_port = port;
        self
    }

    pub async fn build(self) -> Result<Arc<Endpoint>> {
        let logger = self.logger.unwrap_or_else(|| Arc::new(ConsoleLogger));
        
        // Create event dispatcher
        let event_dispatcher = Arc::new(EventDispatcher::new());
        event_dispatcher.clone().start().await;
        
        // Create core components
        let transport_manager = Arc::new(TransportManager::new(logger.clone()));
        let dialog_manager = Arc::new(DialogManager::new(logger.clone()));
        let dns_resolver = Arc::new(DnsResolver::new(logger.clone()));
        
        // Create a placeholder for transaction event handler
        let transaction_event_handler = Arc::new(EndpointTransactionHandler {
            event_dispatcher: event_dispatcher.clone(),
            logger: logger.clone(),
        });
        
        let transaction_manager = Arc::new(TransactionManager::new(
            logger.clone(),
            transaction_event_handler,
        ));
        
        let registry = ComponentRegistry {
            transport_manager,
            transaction_manager,
            dialog_manager,
            dns_resolver,
        };
        
        // Create message handler
        let message_handler = Arc::new(EndpointMessageHandler {
            endpoint: RwLock::new(None),
            logger: logger.clone(),
        });
        
        let endpoint = Arc::new(Endpoint {
            config: self.config,
            accounts: Arc::new(RwLock::new(HashMap::new())),
            calls: Arc::new(RwLock::new(HashMap::new())),
            registry,
            event_dispatcher,
            logger,
            running: Arc::new(RwLock::new(false)),
            message_handler,
        });
        
        // Set the actual endpoint in message handler
        {
            let mut handler = endpoint.message_handler.endpoint.write().await;
            *handler = Some(endpoint.clone());
        }
        
        Ok(endpoint)
    }
}

impl Endpoint {
    pub fn builder() -> EndpointBuilder {
        EndpointBuilder::new()
    }

    pub async fn start(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if *running {
            return Ok(());
        }
        
        self.logger.info("Starting SIP endpoint");
        
        // Create default UDP transport
        let local_addr: SocketAddr = format!("0.0.0.0:{}", self.config.transport_config.udp_port)
            .parse()
            .map_err(|e| SipError::InvalidState(format!("Invalid address: {}", e)))?;
        
        let udp_transport = UdpTransport::new(
            local_addr,
            self.message_handler.clone(),
            self.logger.clone(),
        ).await?;
        
        // Start the transport tasks
        udp_transport.clone().start_tasks().await;
        
        self.registry.transport_manager.add_transport(udp_transport).await?;
        
        *running = true;
        self.logger.info("SIP endpoint started");
        
        Ok(())
    }

    pub async fn stop(&self) -> Result<()> {
        let mut running = self.running.write().await;
        if !*running {
            return Ok(());
        }
        
        self.logger.info("Stopping SIP endpoint");
        
        // Stop all transports
        self.registry.transport_manager.stop_all().await?;
        
        // Unregister all accounts
        let accounts = self.accounts.read().await;
        for account in accounts.values() {
            let _ = account.unregister().await;
        }
        
        // Terminate all calls
        let calls = self.calls.read().await;
        for call in calls.values() {
            let _ = call.hangup().await;
        }
        
        *running = false;
        self.logger.info("SIP endpoint stopped");
        
        Ok(())
    }

    pub async fn add_transport(&self, transport: Arc<dyn Transport>) -> Result<()> {
        self.registry.transport_manager.add_transport(transport).await
    }

    pub async fn create_account(&self, config: crate::AccountConfig) -> Result<Arc<crate::Account>> {
        let accounts = self.accounts.read().await;
        if accounts.len() >= self.config.max_accounts {
            return Err(SipError::InvalidState("Maximum accounts reached".to_string()));
        }
        drop(accounts);

        let account_id = AccountId(format!("{}@{}", config.username, config.domain));
        
        let account = crate::Account::new(
            account_id.clone(),
            config,
            self.registry.clone(),
            self.event_dispatcher.clone(),
            self.logger.clone(),
        ).await?;
        
        let mut accounts = self.accounts.write().await;
        accounts.insert(account_id, account.clone());
        
        Ok(account)
    }

    pub async fn get_account(&self, id: &AccountId) -> Option<Arc<crate::Account>> {
        let accounts = self.accounts.read().await;
        accounts.get(id).cloned()
    }

    pub async fn remove_account(&self, id: &AccountId) -> Result<()> {
        let mut accounts = self.accounts.write().await;
        if let Some(account) = accounts.remove(id) {
            account.unregister().await?;
        }
        Ok(())
    }

    pub async fn add_event_handler(&self, handler: Box<dyn EventHandler>) {
        self.event_dispatcher.add_handler(handler).await;
    }

    pub async fn make_call(
        &self,
        account_id: &AccountId,
        uri: SipUri,
        sdp: Option<crate::Session>,
    ) -> Result<Arc<crate::Call>> {
        let calls = self.calls.read().await;
        if calls.len() >= self.config.max_calls {
            return Err(SipError::InvalidState("Maximum calls reached".to_string()));
        }
        drop(calls);

        let account = self.get_account(account_id).await
            .ok_or_else(|| SipError::AccountNotFound)?;
        
        let call = account.make_call(uri, sdp).await?;
        
        let mut calls = self.calls.write().await;
        calls.insert(call.id.clone(), call.clone());
        
        Ok(call)
    }

    pub async fn get_call(&self, id: &CallId) -> Option<Arc<crate::Call>> {
        let calls = self.calls.read().await;
        calls.get(id).cloned()
    }

    pub(crate) async fn add_call(&self, call: Arc<crate::Call>) -> Result<()> {
        let mut calls = self.calls.write().await;
        if calls.len() >= self.config.max_calls {
            return Err(SipError::InvalidState("Maximum calls reached".to_string()));
        }
        calls.insert(call.id.clone(), call);
        Ok(())
    }

    pub(crate) async fn remove_call(&self, id: &CallId) {
        let mut calls = self.calls.write().await;
        calls.remove(id);
    }

    pub(crate) async fn handle_incoming_request(
        &self,
        request: SipMessage,
        source: SocketAddr,
        transport: Arc<dyn Transport>,
    ) -> Result<()> {
        // Check for existing server transaction first
        let method = request.method().unwrap_or(&SipMethod::Options);
        let via = request.get_via();
        
        if let Some(via_header) = via {
            let transaction_id = TransactionId::from_message(method, &via_header.branch);
            
            // Check if this is a retransmission
            if let Some(existing_txn) = self.registry.transaction_manager
                .find_transaction(&transaction_id).await {
                
                // Handle retransmission
                let _ = existing_txn.event_tx.send(
                    TransactionEvent::ReceivedRequest(request, source)
                ).await;
                return Ok(());
            }
        }
        
        // Create new server transaction
        let transaction = self.registry.transaction_manager
            .create_server_transaction(request.clone(), transport.clone(), source)
            .await?;
        
        // Route based on method
        match request.method() {
            Some(SipMethod::Invite) => {
                self.handle_incoming_invite(request, source, transport, transaction).await?;
            }
            Some(SipMethod::Register) => {
                self.handle_incoming_register(request, source, transport, transaction).await?;
            }
            Some(SipMethod::Options) => {
                self.handle_incoming_options(request, source, transport, transaction).await?;
            }
            _ => {
                // Send 501 Not Implemented
                let response = SipMessage::new_response(501, "Not Implemented");
                transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
                    .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
            }
        }
        
        Ok(())
    }

    async fn handle_incoming_invite(
        &self,
        request: SipMessage,
        source: SocketAddr,
        transport: Arc<dyn Transport>,
        transaction: Arc<crate::Transaction>,
    ) -> Result<()> {
        // Find account based on To header
        let to_header = request.get_to()
            .ok_or_else(|| SipError::InvalidHeader("Missing To header".to_string()))?;
        
        let to_uri = ContactHeader::parse(to_header)?.uri;
        let account_id = AccountId(format!("{}@{}", 
            to_uri.user.as_ref().unwrap_or(&"unknown".to_string()), 
            to_uri.host
        ));
        
        if let Some(account) = self.get_account(&account_id).await {
            // Create incoming call
            let from_header = request.get_from()
                .ok_or_else(|| SipError::InvalidHeader("Missing From header".to_string()))?;
            let from_uri = ContactHeader::parse(from_header)?.uri;
            
            let call = account.handle_incoming_call(request, from_uri, source, transport, transaction).await?;
            
            // Add to calls
            self.add_call(call).await?;
        } else {
            // Send 404 Not Found
            let response = call::create_response(&request, 404, "Not Found")?;
            transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
                .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
        }
        
        Ok(())
    }

    async fn handle_incoming_register(
        &self,
        request: SipMessage,
        source: SocketAddr,
        transport: Arc<dyn Transport>,
        transaction: Arc<crate::Transaction>,
    ) -> Result<()> {
        // For now, just send 200 OK
        // In a real implementation, this would handle registrations
        let response = call::create_response(&request, 200, "OK")?;
        transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
            .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
        
        Ok(())
    }

    async fn handle_incoming_options(
        &self,
        request: SipMessage,
        source: SocketAddr,
        transport: Arc<dyn Transport>,
        transaction: Arc<crate::Transaction>,
    ) -> Result<()> {
        let mut response = call::create_response(&request, 200, "OK")?;
        
        // Add supported methods
        response.headers.set(
            crate::HeaderName::new(crate::HeaderName::ALLOW),
            "INVITE, ACK, BYE, CANCEL, OPTIONS, REGISTER".to_string(),
        );
        
        // Add supported features
        response.headers.set(
            crate::HeaderName::new(crate::HeaderName::SUPPORTED),
            "replaces, timer".to_string(),
        );
        
        transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
            .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
        
        Ok(())
    }
}

// Message handler for the endpoint
struct EndpointMessageHandler {
    endpoint: RwLock<Option<Arc<Endpoint>>>,
    logger: Arc<dyn Logger>,
}

impl MessageHandler for EndpointMessageHandler {
    fn handle_message<'a>(&'a self, message: SipMessage, source: SocketAddr, transport: Arc<dyn Transport>) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let endpoint = self.endpoint.read().await;
            if let Some(ref ep) = *endpoint {
                self.logger.debug(&format!("Received {} from {}", 
                    message.method().map(|m| m.as_str()).unwrap_or("response"),
                    source
                ));
                
                if message.is_request() {
                    // Handle request
                    if let Err(e) = ep.handle_incoming_request(message, source, transport).await {
                        self.logger.error(&format!("Failed to handle incoming request: {}", e));
                    }
                } else {
                    // Response - find matching client transaction
                    if let Some(transaction_id) = TransactionId::from_response(&message) {
                        if let Some(transaction) = ep.registry.transaction_manager
                            .find_transaction(&transaction_id).await {
                            let _ = transaction.event_tx.send(
                                TransactionEvent::ReceivedResponse(message)
                            ).await;
                        } else {
                            self.logger.warn(&format!(
                                "Received response without matching transaction: {}", 
                                transaction_id.0
                            ));
                        }
                    } else {
                        self.logger.warn("Could not extract transaction ID from response");
                    }
                }
            }
        })
    }
}

// Transaction event handler
struct EndpointTransactionHandler {
    event_dispatcher: Arc<EventDispatcher>,
    logger: Arc<dyn Logger>,
}

impl TransactionEventHandler for EndpointTransactionHandler {
    fn handle_transaction_event<'a>(&'a self, transaction_id: TransactionId, event: TransactionEvent) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match event {
                TransactionEvent::ReceivedResponse(response) => {
                    self.logger.debug(&format!("Transaction {} received response {}", 
                        transaction_id.0,
                        response.status_code().unwrap_or(0)
                    ));
                }
                TransactionEvent::TimerFired(timer) => {
                    self.logger.debug(&format!("Transaction {} timer {:?} fired", 
                        transaction_id.0, timer
                    ));
                }
                _ => {}
            }
        })
    }
}

// Helper function to create response from request
fn create_response(request: &SipMessage, status_code: u16, reason_phrase: &str) -> Result<SipMessage> {
    let mut response = SipMessage::new_response(status_code, reason_phrase);
    
    // Copy headers from request
    if let Some(via) = request.get_via() {
        response.add_via(via);
    }
    
    if let Some(from) = request.get_from() {
        response.headers.set(crate::HeaderName::new(crate::HeaderName::FROM), from.clone());
    }
    
    if let Some(to) = request.get_to() {
        response.headers.set(crate::HeaderName::new(crate::HeaderName::TO), to.clone());
    }
    
    if let Some(call_id) = request.get_call_id() {
        response.headers.set(crate::HeaderName::new(crate::HeaderName::CALL_ID), call_id.clone());
    }
    
    if let Some(cseq) = request.get_cseq() {
        response.headers.set(crate::HeaderName::new(crate::HeaderName::CSEQ), cseq.to_string());
    }
    
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    // Helper function to find an available port
    async fn get_available_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[tokio::test]
    async fn test_endpoint_creation() {
        let endpoint = Endpoint::builder()
            .user_agent("TestSIP/1.0")
            .max_calls(10)
            .build()
            .await
            .unwrap();
        
        assert_eq!(endpoint.config.user_agent, "TestSIP/1.0");
        assert_eq!(endpoint.config.max_calls, 10);
    }

    #[tokio::test]
    async fn test_endpoint_start_stop() {
        let port = get_available_port().await;
        let endpoint = Endpoint::builder()
            .udp_port(port)
            .build()
            .await
            .unwrap();
        
        endpoint.start().await.unwrap();
        assert!(*endpoint.running.read().await);
        
        endpoint.stop().await.unwrap();
        assert!(!*endpoint.running.read().await);
    }
}