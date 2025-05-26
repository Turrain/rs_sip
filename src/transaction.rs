use std::sync::Arc;
use std::collections::HashMap;
use std::net::SocketAddr;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{sleep, Duration, Instant, timeout};

use crate::{
    Result, SipError, SipMessage, SipMethod, TransactionId, DialogId,
    Transport, Logger, TimerType, ViaHeader, CSeqHeader,
    generate_branch, MessageHandler,
};

// Transaction states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionState {
    // Client states
    Calling,
    Proceeding,
    Completed,
    Terminated,
    
    // Server states
    Trying,
    Confirmed,
}

// Transaction types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionType {
    ClientInvite,
    ClientNonInvite,
    ServerInvite,
    ServerNonInvite,
}

// Transaction events
#[derive(Debug, Clone)]
pub enum TransactionEvent {
    SendRequest(SipMessage, SocketAddr),
    SendResponse(SipMessage, SocketAddr),
    ReceivedRequest(SipMessage, SocketAddr),
    ReceivedResponse(SipMessage),
    TimerFired(TimerType),
    Terminate,
}

// Transaction callback
pub type TransactionCallback = Box<dyn Fn(TransactionEvent) + Send + Sync>;

// Transaction structure
pub struct Transaction {
    pub id: TransactionId,
    pub transaction_type: TransactionType,
    pub state: RwLock<TransactionState>,
    pub request: SipMessage,
    pub response: RwLock<Option<SipMessage>>,
    pub transport: Arc<dyn Transport>,
    pub remote_addr: SocketAddr,
    pub branch: String,
    pub created_at: Instant,
    pub last_activity: RwLock<Instant>,
    pub retransmit_count: RwLock<u32>,
    pub timers: RwLock<HashMap<TimerType, oneshot::Sender<()>>>,
    pub event_tx: mpsc::Sender<TransactionEvent>,
    pub logger: Arc<dyn Logger>,
}

impl Transaction {
    pub fn new_client(
        request: SipMessage,
        transport: Arc<dyn Transport>,
        remote_addr: SocketAddr,
        event_tx: mpsc::Sender<TransactionEvent>,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let method = request.method()
            .ok_or_else(|| SipError::InvalidState("Request has no method".to_string()))?;
        
        let via = request.get_via()
            .ok_or_else(|| SipError::InvalidHeader("No Via header".to_string()))?;
        
        let transaction_type = if *method == SipMethod::Invite {
            TransactionType::ClientInvite
        } else {
            TransactionType::ClientNonInvite
        };

        let id = TransactionId::from_message(method, &via.branch);
        
        Ok(Arc::new(Transaction {
            id: id.clone(),
            transaction_type,
            state: RwLock::new(TransactionState::Calling),
            request,
            response: RwLock::new(None),
            transport,
            remote_addr,
            branch: via.branch.clone(),
            created_at: Instant::now(),
            last_activity: RwLock::new(Instant::now()),
            retransmit_count: RwLock::new(0),
            timers: RwLock::new(HashMap::new()),
            event_tx,
            logger,
        }))
    }

    pub fn new_server(
        request: SipMessage,
        transport: Arc<dyn Transport>,
        remote_addr: SocketAddr,
        event_tx: mpsc::Sender<TransactionEvent>,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let method = request.method()
            .ok_or_else(|| SipError::InvalidState("Request has no method".to_string()))?;
        
        let via = request.get_via()
            .ok_or_else(|| SipError::InvalidHeader("No Via header".to_string()))?;
        
        let transaction_type = if *method == SipMethod::Invite {
            TransactionType::ServerInvite
        } else {
            TransactionType::ServerNonInvite
        };

        let id = TransactionId::from_message(method, &via.branch);
        
        Ok(Arc::new(Transaction {
            id: id.clone(),
            transaction_type,
            state: RwLock::new(TransactionState::Trying),
            request,
            response: RwLock::new(None),
            transport,
            remote_addr,
            branch: via.branch.clone(),
            created_at: Instant::now(),
            last_activity: RwLock::new(Instant::now()),
            retransmit_count: RwLock::new(0),
            timers: RwLock::new(HashMap::new()),
            event_tx,
            logger,
        }))
    }

    pub async fn handle_event(self: Arc<Self>, event: TransactionEvent) -> Result<()> {
        match self.transaction_type {
            TransactionType::ClientInvite => self.handle_client_invite_event(event).await,
            TransactionType::ClientNonInvite => self.handle_client_non_invite_event(event).await,
            TransactionType::ServerInvite => self.handle_server_invite_event(event).await,
            TransactionType::ServerNonInvite => self.handle_server_non_invite_event(event).await,
        }
    }

    async fn handle_client_invite_event(self: Arc<Self>, event: TransactionEvent) -> Result<()> {
        let current_state = *self.state.read().await;
        
        match (current_state, event) {
            (TransactionState::Calling, TransactionEvent::SendRequest(msg, addr)) => {
                // Send request and start Timer A and Timer B
                self.transport.send(&msg, addr).await?;
                self.start_timer(TimerType::TimerA).await;
                self.start_timer(TimerType::TimerB).await;
            }
            
            (TransactionState::Calling, TransactionEvent::ReceivedResponse(response)) => {
                let status = response.status_code().unwrap_or(0);
                
                if status >= 100 && status < 200 {
                    // Provisional response
                    self.cancel_timer(TimerType::TimerA).await;
                    self.cancel_timer(TimerType::TimerB).await;
                    *self.state.write().await = TransactionState::Proceeding;
                } else if status >= 200 && status < 300 {
                    // 2xx response
                    self.cancel_timer(TimerType::TimerA).await;
                    self.cancel_timer(TimerType::TimerB).await;
                    *self.state.write().await = TransactionState::Terminated;
                } else if status >= 300 {
                    // Final response
                    self.cancel_timer(TimerType::TimerA).await;
                    self.cancel_timer(TimerType::TimerB).await;
                    
                    // Send ACK for non-2xx
                    self.send_ack_for_response(&response).await?;
                    
                    *self.state.write().await = TransactionState::Completed;
                    self.start_timer(TimerType::TimerD).await;
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Calling, TransactionEvent::TimerFired(TimerType::TimerA)) => {
                // Retransmit request
                let mut count = self.retransmit_count.write().await;
                *count += 1;
                
                self.transport.send(&self.request, self.remote_addr).await?;
                
                // Restart Timer A with exponential backoff
                let duration = Duration::from_millis(500 * (1 << *count));
                self.start_timer_with_duration(TimerType::TimerA, duration).await;
            }
            
            (TransactionState::Calling, TransactionEvent::TimerFired(TimerType::TimerB)) => {
                // Timeout
                *self.state.write().await = TransactionState::Terminated;
                return Err(SipError::TransactionTimeout);
            }
            
            (TransactionState::Proceeding, TransactionEvent::ReceivedResponse(response)) => {
                let status = response.status_code().unwrap_or(0);
                
                if status >= 200 && status < 300 {
                    // 2xx response
                    *self.state.write().await = TransactionState::Terminated;
                } else if status >= 300 {
                    // Final response
                    self.send_ack_for_response(&response).await?;
                    *self.state.write().await = TransactionState::Completed;
                    self.start_timer(TimerType::TimerD).await;
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Completed, TransactionEvent::TimerFired(TimerType::TimerD)) => {
                *self.state.write().await = TransactionState::Terminated;
            }
            
            (TransactionState::Completed, TransactionEvent::ReceivedResponse(response)) => {
                // Retransmit ACK
                self.send_ack_for_response(&response).await?;
            }
            
            _ => {
                self.logger.debug(&format!("Unhandled event in state {:?}", current_state));
            }
        }
        
        Ok(())
    }

    async fn handle_client_non_invite_event(self: Arc<Self>, event: TransactionEvent) -> Result<()> {
        let current_state = *self.state.read().await;
        
        match (current_state, event) {
            (TransactionState::Calling, TransactionEvent::SendRequest(msg, addr)) => {
                // Send request and start Timer E and Timer F
                self.transport.send(&msg, addr).await?;
                self.start_timer(TimerType::TimerE).await;
                self.start_timer(TimerType::TimerF).await;
            }
            
            (TransactionState::Calling, TransactionEvent::ReceivedResponse(response)) => {
                let status = response.status_code().unwrap_or(0);
                
                if status >= 100 && status < 200 {
                    // Provisional response
                    *self.state.write().await = TransactionState::Proceeding;
                } else {
                    // Final response
                    self.cancel_timer(TimerType::TimerE).await;
                    self.cancel_timer(TimerType::TimerF).await;
                    *self.state.write().await = TransactionState::Completed;
                    
                    if self.is_unreliable_transport() {
                        self.start_timer(TimerType::TimerK).await;
                    } else {
                        *self.state.write().await = TransactionState::Terminated;
                    }
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Calling, TransactionEvent::TimerFired(TimerType::TimerE)) => {
                // Retransmit request
                let mut count = self.retransmit_count.write().await;
                *count += 1;
                
                self.transport.send(&self.request, self.remote_addr).await?;
                
                // Restart Timer E with exponential backoff
                let duration = std::cmp::min(
                    Duration::from_millis(500 * (1 << *count)),
                    Duration::from_secs(4)
                );
                self.start_timer_with_duration(TimerType::TimerE, duration).await;
            }
            
            (TransactionState::Calling, TransactionEvent::TimerFired(TimerType::TimerF)) => {
                // Timeout
                *self.state.write().await = TransactionState::Terminated;
                return Err(SipError::TransactionTimeout);
            }
            
            (TransactionState::Proceeding, TransactionEvent::ReceivedResponse(response)) => {
                let status = response.status_code().unwrap_or(0);
                
                if status >= 200 {
                    // Final response
                    self.cancel_timer(TimerType::TimerE).await;
                    self.cancel_timer(TimerType::TimerF).await;
                    *self.state.write().await = TransactionState::Completed;
                    
                    if self.is_unreliable_transport() {
                        self.start_timer(TimerType::TimerK).await;
                    } else {
                        *self.state.write().await = TransactionState::Terminated;
                    }
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Completed, TransactionEvent::TimerFired(TimerType::TimerK)) => {
                *self.state.write().await = TransactionState::Terminated;
            }
            
            _ => {
                self.logger.debug(&format!("Unhandled event in state {:?}", current_state));
            }
        }
        
        Ok(())
    }

    async fn handle_server_invite_event(self: Arc<Self>, event: TransactionEvent) -> Result<()> {
        let current_state = *self.state.read().await;
        
        match (current_state, event) {
            (TransactionState::Trying, TransactionEvent::SendResponse(response, addr)) => {
                let status = response.status_code().unwrap_or(0);
                
                if status >= 100 && status < 200 {
                    // Provisional response
                    self.transport.send_response(&response, addr).await?;
                    *self.state.write().await = TransactionState::Proceeding;
                } else if status >= 200 && status < 300 {
                    // 2xx response
                    self.transport.send_response(&response, addr).await?;
                    *self.state.write().await = TransactionState::Terminated;
                } else {
                    // Error response
                    self.transport.send_response(&response, addr).await?;
                    *self.state.write().await = TransactionState::Completed;
                    
                    if self.is_unreliable_transport() {
                        self.start_timer(TimerType::TimerG).await;
                    }
                    self.start_timer(TimerType::TimerH).await;
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Proceeding, TransactionEvent::SendResponse(response, addr)) => {
                let status = response.status_code().unwrap_or(0);
                
                self.transport.send_response(&response, addr).await?;
                
                if status >= 200 && status < 300 {
                    // 2xx response
                    *self.state.write().await = TransactionState::Terminated;
                } else if status >= 300 {
                    // Error response
                    *self.state.write().await = TransactionState::Completed;
                    
                    if self.is_unreliable_transport() {
                        self.start_timer(TimerType::TimerG).await;
                    }
                    self.start_timer(TimerType::TimerH).await;
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Proceeding, TransactionEvent::ReceivedRequest(_, _)) => {
                // Retransmission - resend response if we have one
                if let Some(ref response) = *self.response.read().await {
                    self.transport.send_response(response, self.remote_addr).await?;
                }
            }
            
            (TransactionState::Completed, TransactionEvent::TimerFired(TimerType::TimerG)) => {
                // Retransmit response
                if let Some(ref response) = *self.response.read().await {
                    self.transport.send_response(response, self.remote_addr).await?;
                    
                    // Restart Timer G with exponential backoff
                    let mut count = self.retransmit_count.write().await;
                    *count += 1;
                    let duration = std::cmp::min(
                        Duration::from_millis(500 * (1 << *count)),
                        Duration::from_secs(4)
                    );
                    self.start_timer_with_duration(TimerType::TimerG, duration).await;
                }
            }
            
            (TransactionState::Completed, TransactionEvent::ReceivedRequest(request, _)) => {
                // Check if this is an ACK
                if request.method() == Some(&SipMethod::Ack) {
                    self.cancel_timer(TimerType::TimerG).await;
                    self.cancel_timer(TimerType::TimerH).await;
                    
                    if self.is_unreliable_transport() {
                        *self.state.write().await = TransactionState::Confirmed;
                        self.start_timer(TimerType::TimerI).await;
                    } else {
                        *self.state.write().await = TransactionState::Terminated;
                    }
                } else {
                    // Retransmission - resend response
                    if let Some(ref response) = *self.response.read().await {
                        self.transport.send_response(response, self.remote_addr).await?;
                    }
                }
            }
            
            (TransactionState::Completed, TransactionEvent::TimerFired(TimerType::TimerH)) => {
                // ACK timeout
                self.cancel_timer(TimerType::TimerG).await;
                *self.state.write().await = TransactionState::Terminated;
            }
            
            (TransactionState::Confirmed, TransactionEvent::TimerFired(TimerType::TimerI)) => {
                *self.state.write().await = TransactionState::Terminated;
            }
            
            _ => {
                self.logger.debug(&format!("Unhandled event in state {:?}", current_state));
            }
        }
        
        Ok(())
    }

    async fn handle_server_non_invite_event(self: Arc<Self>, event: TransactionEvent) -> Result<()> {
        let current_state = *self.state.read().await;
        
        match (current_state, event) {
            (TransactionState::Trying, TransactionEvent::SendResponse(response, addr)) => {
                let status = response.status_code().unwrap_or(0);
                
                self.transport.send_response(&response, addr).await?;
                
                if status >= 100 && status < 200 {
                    // Provisional response
                    *self.state.write().await = TransactionState::Proceeding;
                } else {
                    // Final response
                    *self.state.write().await = TransactionState::Completed;
                    
                    if self.is_unreliable_transport() {
                        self.start_timer(TimerType::TimerJ).await;
                    } else {
                        *self.state.write().await = TransactionState::Terminated;
                    }
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Proceeding, TransactionEvent::SendResponse(response, addr)) => {
                let status = response.status_code().unwrap_or(0);
                
                self.transport.send_response(&response, addr).await?;
                
                if status >= 200 {
                    // Final response
                    *self.state.write().await = TransactionState::Completed;
                    
                    if self.is_unreliable_transport() {
                        self.start_timer(TimerType::TimerJ).await;
                    } else {
                        *self.state.write().await = TransactionState::Terminated;
                    }
                }
                
                *self.response.write().await = Some(response);
            }
            
            (TransactionState::Proceeding, TransactionEvent::ReceivedRequest(_, _)) |
            (TransactionState::Completed, TransactionEvent::ReceivedRequest(_, _)) => {
                // Retransmission - resend response
                if let Some(ref response) = *self.response.read().await {
                    self.transport.send_response(response, self.remote_addr).await?;
                }
            }
            
            (TransactionState::Completed, TransactionEvent::TimerFired(TimerType::TimerJ)) => {
                *self.state.write().await = TransactionState::Terminated;
            }
            
            _ => {
                self.logger.debug(&format!("Unhandled event in state {:?}", current_state));
            }
        }
        
        Ok(())
    }

    async fn send_ack_for_response(&self, response: &SipMessage) -> Result<()> {
        let mut ack = SipMessage::new_request(SipMethod::Ack, self.request.request_uri().unwrap().clone());
        
        // Copy headers from original INVITE
        if let Some(from) = self.request.get_from() {
            ack.headers.set(crate::HeaderName::new(crate::HeaderName::FROM), from.clone());
        }
        
        if let Some(to) = response.get_to() {
            ack.headers.set(crate::HeaderName::new(crate::HeaderName::TO), to.clone());
        }
        
        if let Some(call_id) = self.request.get_call_id() {
            ack.headers.set(crate::HeaderName::new(crate::HeaderName::CALL_ID), call_id.clone());
        }
        
        // CSeq with ACK method
        if let Some(cseq) = self.request.get_cseq() {
            let ack_cseq = CSeqHeader::new(cseq.sequence, SipMethod::Ack);
            ack.headers.set(crate::HeaderName::new(crate::HeaderName::CSEQ), ack_cseq.to_string());
        }
        
        // Via from original request
        if let Some(via) = self.request.get_via() {
            ack.add_via(via);
        }
        
        self.transport.send(&ack, self.remote_addr).await
    }

    async fn start_timer(&self, timer_type: TimerType) {
        self.start_timer_with_duration(timer_type, Duration::from_millis(timer_type.duration_ms())).await;
    }

    async fn start_timer_with_duration(&self, timer_type: TimerType, duration: Duration) {
        let (tx, rx) = oneshot::channel();
        
        {
            let mut timers = self.timers.write().await;
            if let Some(old_timer) = timers.insert(timer_type, tx) {
                let _ = old_timer.send(());
            }
        }
        
        let event_tx = self.event_tx.clone();
        let transaction_id = self.id.clone();
        
        tokio::spawn(async move {
            tokio::select! {
                _ = sleep(duration) => {
                    let _ = event_tx.send(TransactionEvent::TimerFired(timer_type)).await;
                }
                _ = rx => {
                    // Timer cancelled
                }
            }
        });
    }

    async fn cancel_timer(&self, timer_type: TimerType) {
        let mut timers = self.timers.write().await;
        if let Some(tx) = timers.remove(&timer_type) {
            let _ = tx.send(());
        }
    }

    fn is_unreliable_transport(&self) -> bool {
        self.transport.protocol() == "UDP"
    }

    pub async fn is_terminated(&self) -> bool {
        *self.state.read().await == TransactionState::Terminated
    }
}

// Transaction Manager
pub struct TransactionManager {
    transactions: Arc<RwLock<HashMap<TransactionId, Arc<Transaction>>>>,
    logger: Arc<dyn Logger>,
    event_handler: Arc<dyn TransactionEventHandler>,
}

// Transaction event handler trait
pub trait TransactionEventHandler: Send + Sync {
    fn handle_transaction_event<'a>(&'a self, transaction_id: TransactionId, event: TransactionEvent) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>>;
}

impl TransactionManager {
    pub fn new(
        logger: Arc<dyn Logger>,
        event_handler: Arc<dyn TransactionEventHandler>,
    ) -> Self {
        let manager = TransactionManager {
            transactions: Arc::new(RwLock::new(HashMap::new())),
            logger,
            event_handler,
        };
        
        // Start cleanup task
        let transactions = manager.transactions.clone();
        let logger = manager.logger.clone();
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(10)).await;
                
                let mut txns = transactions.write().await;
                let mut to_remove = Vec::new();
                
                for (id, txn) in txns.iter() {
                    if txn.is_terminated().await {
                        to_remove.push(id.clone());
                    }
                }
                
                for id in to_remove {
                    txns.remove(&id);
                    logger.debug(&format!("Removed terminated transaction: {}", id.0));
                }
            }
        });
        
        manager
    }

    pub async fn create_client_transaction(
        &self,
        request: SipMessage,
        transport: Arc<dyn Transport>,
        remote_addr: SocketAddr,
    ) -> Result<Arc<Transaction>> {
        let (event_tx, mut event_rx) = mpsc::channel(100);
        
        let transaction = Transaction::new_client(
            request,
            transport,
            remote_addr,
            event_tx,
            self.logger.clone(),
        )?;
        
        let transaction_id = transaction.id.clone();
        
        {
            let mut transactions = self.transactions.write().await;
            transactions.insert(transaction_id.clone(), transaction.clone());
        }
        
        // Start event handler for this transaction
        let txn = transaction.clone();
        let event_handler = self.event_handler.clone();
        let logger = self.logger.clone();
        
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let event_clone = event.clone();
                if let Err(e) = txn.clone().handle_event(event).await {
                    logger.error(&format!("Transaction {} error: {}", transaction_id.0, e));
                }
                event_handler.handle_transaction_event(transaction_id.clone(), event_clone).await;
            }
        });
        
        Ok(transaction)
    }

    pub async fn create_server_transaction(
        &self,
        request: SipMessage,
        transport: Arc<dyn Transport>,
        remote_addr: SocketAddr,
    ) -> Result<Arc<Transaction>> {
        let (event_tx, mut event_rx) = mpsc::channel(100);
        
        let transaction = Transaction::new_server(
            request,
            transport,
            remote_addr,
            event_tx,
            self.logger.clone(),
        )?;
        
        let transaction_id = transaction.id.clone();
        
        {
            let mut transactions = self.transactions.write().await;
            transactions.insert(transaction_id.clone(), transaction.clone());
        }
        
        // Start event handler for this transaction
        let txn = transaction.clone();
        let event_handler = self.event_handler.clone();
        let logger = self.logger.clone();
        
        tokio::spawn(async move {
            while let Some(event) = event_rx.recv().await {
                let event_clone = event.clone();
                if let Err(e) = txn.clone().handle_event(event).await {
                    logger.error(&format!("Transaction {} error: {}", transaction_id.0, e));
                }
                event_handler.handle_transaction_event(transaction_id.clone(), event_clone).await;
            }
        });
        
        Ok(transaction)
    }

    pub async fn find_transaction(&self, id: &TransactionId) -> Option<Arc<Transaction>> {
        let transactions = self.transactions.read().await;
        transactions.get(id).cloned()
    }

    pub async fn find_transaction_for_message(&self, message: &SipMessage) -> Option<Arc<Transaction>> {
        let method = message.method()?;
        let via = message.get_via()?;
        let id = TransactionId::from_message(method, &via.branch);
        
        self.find_transaction(&id).await
    }

    pub async fn terminate_transaction(&self, id: &TransactionId) -> Result<()> {
        if let Some(transaction) = self.find_transaction(id).await {
            transaction.event_tx.send(TransactionEvent::Terminate).await
                .map_err(|_| SipError::InvalidState("Failed to send terminate event".to_string()))?;
        }
        Ok(())
    }
}

// Dialog management
#[derive(Debug, Clone)]
pub struct Dialog {
    pub id: DialogId,
    pub local_uri: crate::SipUri,
    pub remote_uri: crate::SipUri,
    pub local_tag: String,
    pub remote_tag: String,
    pub call_id: String,
    pub local_cseq: u32,
    pub remote_cseq: u32,
    pub route_set: Vec<crate::SipUri>,
    pub secure: bool,
    pub state: DialogState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DialogState {
    Early,
    Confirmed,
    Terminated,
}

pub struct DialogManager {
    dialogs: Arc<RwLock<HashMap<DialogId, Arc<RwLock<Dialog>>>>>,
    logger: Arc<dyn Logger>,
}

impl DialogManager {
    pub fn new(logger: Arc<dyn Logger>) -> Self {
        DialogManager {
            dialogs: Arc::new(RwLock::new(HashMap::new())),
            logger,
        }
    }

    pub async fn create_dialog_from_request(
        &self,
        request: &SipMessage,
        local_tag: String,
    ) -> Result<Arc<RwLock<Dialog>>> {
        let from_uri = crate::ContactHeader::parse(request.get_from().ok_or_else(|| 
            SipError::InvalidHeader("Missing From header".to_string()))?)?.uri;
        
        let to_uri = crate::ContactHeader::parse(request.get_to().ok_or_else(|| 
            SipError::InvalidHeader("Missing To header".to_string()))?)?.uri;
        
        let call_id = request.get_call_id().ok_or_else(|| 
            SipError::InvalidHeader("Missing Call-ID header".to_string()))?.clone();
        
        let cseq = request.get_cseq().ok_or_else(|| 
            SipError::InvalidHeader("Missing CSeq header".to_string()))?;
        
        let dialog = Dialog {
            id: DialogId {
                call_id: call_id.clone(),
                local_tag: local_tag.clone(),
                remote_tag: String::new(), // Will be set when response received
            },
            local_uri: to_uri,
            remote_uri: from_uri,
            local_tag,
            remote_tag: String::new(),
            call_id,
            local_cseq: 0,
            remote_cseq: cseq.sequence,
            route_set: Vec::new(),
            secure: false,
            state: DialogState::Early,
        };
        
        let dialog = Arc::new(RwLock::new(dialog));
        
        // Don't add to dialogs yet - wait for response with remote tag
        
        Ok(dialog)
    }

    pub async fn confirm_dialog(
        &self,
        dialog: Arc<RwLock<Dialog>>,
        response: &SipMessage,
    ) -> Result<()> {
        let to_header = response.get_to().ok_or_else(|| 
            SipError::InvalidHeader("Missing To header".to_string()))?;
        
        // Extract remote tag from To header
        let remote_tag = if let Some(tag_start) = to_header.find(";tag=") {
            let tag_part = &to_header[tag_start + 5..];
            if let Some(end) = tag_part.find(';') {
                tag_part[..end].to_string()
            } else {
                tag_part.to_string()
            }
        } else {
            return Err(SipError::InvalidHeader("Missing tag in To header".to_string()));
        };
        
        {
            let mut d = dialog.write().await;
            d.remote_tag = remote_tag.clone();
            d.id.remote_tag = remote_tag;
            d.state = DialogState::Confirmed;
        }
        
        let dialog_id = dialog.read().await.id.clone();
        
        let mut dialogs = self.dialogs.write().await;
        dialogs.insert(dialog_id, dialog);
        
        Ok(())
    }

    pub async fn find_dialog(&self, id: &DialogId) -> Option<Arc<RwLock<Dialog>>> {
        let dialogs = self.dialogs.read().await;
        dialogs.get(id).cloned()
    }

    pub async fn terminate_dialog(&self, id: &DialogId) -> Result<()> {
        let mut dialogs = self.dialogs.write().await;
        if let Some(dialog) = dialogs.get(id) {
            dialog.write().await.state = DialogState::Terminated;
        }
        dialogs.remove(id);
        Ok(())
    }
}