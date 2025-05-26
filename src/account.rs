use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::net::SocketAddr;
use tokio::sync::RwLock;
use tokio::time::{sleep, Duration, interval};

use crate::{
    Result, SipError, AccountId, AccountConfig, AccountState, RegistrationState,
    SipMessage, SipMethod, SipUri, SipMessageBuilder, Session,
    ComponentRegistry, EventDispatcher, Logger, Event, RegistrationEvent,
    Transport, TransactionEvent, Transaction, CallId,
    generate_branch, generate_call_id, generate_tag, 
    ContactHeader, ViaHeader, CSeqHeader, HeaderName,
    auth::{AuthContext, parse_digest_challenge, add_authentication},
};

// Registration manager
pub struct RegistrationManager {
    state: RwLock<RegistrationState>,
    current_registration: RwLock<Option<Registration>>,
    retry_count: AtomicU32,
    auth_context: RwLock<Option<AuthContext>>,
    registration_expiry: RwLock<Option<tokio::time::Instant>>,
}

#[derive(Clone)]
struct Registration {
    call_id: String,
    cseq: u32,
    expires: u32,
    contact: String,
    from_tag: String,
    registrar_uri: SipUri,
}

// Account implementation
pub struct Account {
    pub id: AccountId,
    config: AccountConfig,
    state: RwLock<AccountState>,
    registration_manager: RegistrationManager,
    cseq_counter: AtomicU32,
    registry: ComponentRegistry,
    event_dispatcher: Arc<EventDispatcher>,
    logger: Arc<dyn Logger>,
    register_task: RwLock<Option<tokio::task::JoinHandle<()>>>,
}

impl Account {
    pub async fn new(
        id: AccountId,
        config: AccountConfig,
        registry: ComponentRegistry,
        event_dispatcher: Arc<EventDispatcher>,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let account = Arc::new(Account {
            id: id.clone(),
            config,
            state: RwLock::new(AccountState::Offline),
            registration_manager: RegistrationManager {
                state: RwLock::new(RegistrationState::None),
                current_registration: RwLock::new(None),
                retry_count: AtomicU32::new(0),
                auth_context: RwLock::new(None),
                registration_expiry: RwLock::new(None),
            },
            cseq_counter: AtomicU32::new(1),
            registry,
            event_dispatcher,
            logger,
            register_task: RwLock::new(None),
        });

        // Initialize auth context if password is provided
        if let Some(ref password) = account.config.password {
            let auth_ctx = AuthContext::new(
                account.config.username.clone(),
                password.clone(),
            );
            *account.registration_manager.auth_context.write().await = Some(auth_ctx);
        }

        if account.config.register_on_add {
            account.clone().start_registration().await?;
        }

        Ok(account)
    }

    pub async fn register(&self) -> Result<()> {
        self.clone_arc().start_registration().await
    }

    async fn start_registration(self: Arc<Self>) -> Result<()> {
        let current_state = *self.state.read().await;
        if current_state == AccountState::Registered || current_state == AccountState::Registering {
            return Ok(());
        }

        *self.state.write().await = AccountState::Registering;
        *self.registration_manager.state.write().await = RegistrationState::Sent;

        // Stop any existing registration task
        if let Some(task) = self.register_task.write().await.take() {
            task.abort();
        }

        // Start registration task
        let account = self.clone();
        let task = tokio::spawn(async move {
            account.registration_task().await;
        });

        *self.register_task.write().await = Some(task);

        Ok(())
    }

    async fn registration_task(self: Arc<Self>) {
        let mut retry_delay = Duration::from_secs(1);
        let max_retry_delay = Duration::from_secs(60);
        
        loop {
            match self.send_register(self.config.expire_seconds).await {
                Ok(_) => {
                    // Reset retry delay on success
                    retry_delay = Duration::from_secs(1);
                    
                    // Calculate next registration time (re-register before expiry)
                    let refresh_time = if self.config.expire_seconds > 60 {
                        self.config.expire_seconds - 30
                    } else {
                        self.config.expire_seconds / 2
                    };
                    
                    self.logger.info(&format!(
                        "Registration successful for {}, next refresh in {} seconds",
                        self.id.0, refresh_time
                    ));
                    
                    // Wait for refresh time or until stopped
                    tokio::select! {
                        _ = sleep(Duration::from_secs(refresh_time as u64)) => {
                            // Time to refresh registration
                            continue;
                        }
                        _ = self.wait_for_unregister() => {
                            // Account is being unregistered
                            break;
                        }
                    }
                }
                Err(e) => {
                    self.logger.error(&format!("Registration failed for {}: {}", self.id.0, e));
                    
                    // Update state
                    *self.state.write().await = AccountState::Error;
                    *self.registration_manager.state.write().await = RegistrationState::Failed;
                    
                    // Notify failure
                    self.event_dispatcher.dispatch(Event::Registration(
                        RegistrationEvent::RegistrationFailed {
                            account_id: self.id.clone(),
                            reason: e.to_string(),
                        }
                    )).await;
                    
                    // Wait before retry with exponential backoff
                    sleep(retry_delay).await;
                    retry_delay = std::cmp::min(retry_delay * 2, max_retry_delay);
                    
                    // Check if we should continue retrying
                    let state = *self.state.read().await;
                    if state == AccountState::Offline {
                        break;
                    }
                }
            }
        }
    }

    async fn wait_for_unregister(&self) {
        loop {
            sleep(Duration::from_secs(1)).await;
            let state = *self.state.read().await;
            if state == AccountState::Offline || state == AccountState::Unregistering {
                break;
            }
        }
    }

    async fn send_register(&self, mut expires: u32) -> Result<()> {
        loop {
            // Create REGISTER request
            let mut request = self.create_register_request(expires).await?;
            
            // Get transport and target
            let registrar_uri = if let Some(ref registrar) = self.config.registrar {
                SipUri::parse(registrar)?
            } else {
                SipUri::new(self.config.domain.clone())
            };

            let target_addrs = self.registry.dns_resolver.resolve_target(&registrar_uri).await?;
            if target_addrs.is_empty() {
                return Err(SipError::TransportError("No address found for registrar".to_string()));
            }

            let transport = self.registry.transport_manager
                .find_transport_for_target(target_addrs[0], "UDP").await
                .ok_or_else(|| SipError::TransportError("No suitable transport found".to_string()))?;

            // Send request and wait for response
            let response = self.send_request_with_auth(request, transport, target_addrs[0]).await?;
            
            // Check response
            let status = response.status_code().unwrap_or(0);
            
            match status {
                200..=299 => {
                    // Success - handle the same way as before
                    *self.state.write().await = AccountState::Registered;
                    *self.registration_manager.state.write().await = RegistrationState::Success;
                    
                    let expires_header = response.headers.get(HeaderName::EXPIRES)
                        .and_then(|e| e.parse::<u64>().ok())
                        .unwrap_or(expires as u64);
                    
                    *self.registration_manager.registration_expiry.write().await = 
                        Some(tokio::time::Instant::now() + Duration::from_secs(expires_header));
                    
                    self.event_dispatcher.dispatch(Event::Registration(
                        RegistrationEvent::Registered { account_id: self.id.clone() }
                    )).await;
                    
                    return Ok(());
                }
                423 => {
                    // Interval too brief - update expires and retry in the same loop
                    if let Some(min_expires) = response.headers.get(HeaderName::MIN_EXPIRES) {
                        if let Ok(min_exp) = min_expires.parse::<u32>() {
                            self.logger.info(&format!(
                                "Registrar requires minimum expires of {} seconds",
                                min_exp
                            ));
                            expires = min_exp;
                            continue;
                        }
                    }
                    return Err(SipError::RegistrationFailed("Interval too brief".to_string()));
                }
                _ => {
                    return Err(SipError::RegistrationFailed(
                        format!("Registration failed with status {}", status)
                    ));
                }
            }
        }
    }

    async fn send_request_with_auth(
        &self,
        mut request: SipMessage,
        transport: Arc<dyn Transport>,
        target: SocketAddr,
    ) -> Result<SipMessage> {
        let mut attempts = 0;
        let max_attempts = 2; // Initial request + one with auth
        
        loop {
            attempts += 1;
            
            // Create transaction
            let transaction = self.registry.transaction_manager
                .create_client_transaction(request.clone(), transport.clone(), target)
                .await?;

            // Send request
            transaction.event_tx.send(TransactionEvent::SendRequest(
                transaction.request.clone(),
                transaction.remote_addr
            )).await.map_err(|_| SipError::InvalidState("Failed to send request".to_string()))?;

            // Wait for response
            let response = self.wait_for_transaction_response(transaction).await?;
            let status = response.status_code().unwrap_or(0);
            
            match status {
                401 | 407 => {
                    // Authentication required
                    if attempts >= max_attempts {
                        return Err(SipError::AuthenticationFailed);
                    }
                    
                    // Get challenge header
                    let auth_header = if status == 401 {
                        HeaderName::WWW_AUTHENTICATE
                    } else {
                        HeaderName::PROXY_AUTHENTICATE
                    };
                    
                    let challenge_header = response.headers.get(auth_header)
                        .ok_or_else(|| SipError::InvalidHeader("Missing authentication challenge".to_string()))?;
                    
                    // Parse challenge and update auth context
                    let challenge = parse_digest_challenge(challenge_header)?;
                    
                    // Get auth context
                    let mut auth_ctx_opt = self.registration_manager.auth_context.write().await;
                    let auth_ctx = auth_ctx_opt.as_mut()
                        .ok_or_else(|| SipError::AuthenticationFailed)?;
                    
                    // Add authentication to request
                    add_authentication(&mut request, auth_ctx, &challenge)?;
                    
                    // Increment CSeq for new request
                    if let Some(cseq) = request.get_cseq() {
                        let new_cseq = CSeqHeader::new(cseq.sequence + 1, cseq.method);
                        request.headers.set(
                            HeaderName::new(HeaderName::CSEQ),
                            new_cseq.to_string(),
                        );
                    }
                    
                    // Try again with authentication
                    continue;
                }
                _ => {
                    // Any other response, return it
                    return Ok(response);
                }
            }
        }
    }

    async fn wait_for_transaction_response(&self, transaction: Arc<Transaction>) -> Result<SipMessage> {
        let timeout_duration = Duration::from_secs(32); // F timer for non-INVITE
        let start = tokio::time::Instant::now();
        
        loop {
            // Check if transaction has received a response
            if let Some(response) = transaction.response.read().await.clone() {
                return Ok(response);
            }
            
            // Check if transaction is terminated
            if transaction.is_terminated().await {
                return Err(SipError::TransactionTimeout);
            }
            
            // Check timeout
            if start.elapsed() > timeout_duration {
                return Err(SipError::TransactionTimeout);
            }
            
            // Wait a bit before checking again
            sleep(Duration::from_millis(50)).await;
        }
    }

    pub async fn unregister(&self) -> Result<()> {
        let current_state = *self.state.read().await;
        if current_state == AccountState::Offline {
            return Ok(());
        }

        *self.state.write().await = AccountState::Unregistering;

        // Stop refresh task
        if let Some(task) = self.register_task.write().await.take() {
            task.abort();
        }

        // Send REGISTER with Expires: 0
        match self.send_register(0).await {
            Ok(_) => {
                self.logger.info(&format!("Account {} unregistered successfully", self.id.0));
            }
            Err(e) => {
                self.logger.error(&format!("Failed to unregister account {}: {}", self.id.0, e));
            }
        }

        *self.state.write().await = AccountState::Offline;
        *self.registration_manager.state.write().await = RegistrationState::None;
        *self.registration_manager.current_registration.write().await = None;
        *self.registration_manager.registration_expiry.write().await = None;

        // Dispatch event
        self.event_dispatcher.dispatch(Event::Registration(
            RegistrationEvent::Unregistered { account_id: self.id.clone() }
        )).await;

        Ok(())
    }

    async fn create_register_request(&self, expires: u32) -> Result<SipMessage> {
        let registrar_uri = if let Some(ref registrar) = self.config.registrar {
            SipUri::parse(registrar)?
        } else {
            SipUri::new(self.config.domain.clone())
        };

        let from_uri = SipUri::parse(&format!("sip:{}@{}", 
            self.config.username, 
            self.config.domain
        ))?;

        let to_uri = from_uri.clone();
        
        // Get local IP for Contact header
        let transport = self.registry.transport_manager.get_transport("UDP", None).await
            .ok_or_else(|| SipError::TransportError("No UDP transport available".to_string()))?;
        
        let local_addr = transport.local_addr();
        let contact_uri = SipUri::parse(&format!("sip:{}@{}", 
            self.config.username,
            local_addr
        ))?;

        let mut builder = SipMessageBuilder::new()
            .request(SipMethod::Register, registrar_uri.clone());

        // Via header
        let via = ViaHeader::new(
            transport.protocol(),
            &local_addr.to_string(),
            &generate_branch(),
        );
        builder = builder.header(HeaderName::VIA, &via.to_string());

        // From header with tag
        let from_tag = if let Some(ref reg) = *self.registration_manager.current_registration.read().await {
            reg.from_tag.clone()
        } else {
            generate_tag()
        };
        
        builder = builder.header(
            HeaderName::FROM,
            &format!("{} <{}>;tag={}", 
                self.config.display_name, 
                from_uri, 
                from_tag
            ),
        );

        // To header (no tag for REGISTER)
        builder = builder.header(
            HeaderName::TO,
            &format!("{} <{}>", self.config.display_name, to_uri),
        );

        // Call-ID
        let call_id = if let Some(ref reg) = *self.registration_manager.current_registration.read().await {
            reg.call_id.clone()
        } else {
            generate_call_id(&self.config.domain)
        };
        builder = builder.header(HeaderName::CALL_ID, &call_id);

        // CSeq
        let cseq = self.cseq_counter.fetch_add(1, Ordering::SeqCst);
        builder = builder.header(HeaderName::CSEQ, &format!("{} REGISTER", cseq));

        // Contact
        let contact = if expires > 0 {
            format!("<{}>", contact_uri)
        } else {
            "*".to_string() // Wildcard for unregister
        };
        builder = builder.header(HeaderName::CONTACT, &contact);

        // Expires
        builder = builder.header(HeaderName::EXPIRES, &expires.to_string());

        // User-Agent
        builder = builder.header(HeaderName::USER_AGENT, "RustSIP/1.0");

        // Allow
        builder = builder.header(HeaderName::ALLOW, "INVITE, ACK, BYE, CANCEL, OPTIONS, MESSAGE, SUBSCRIBE, NOTIFY, INFO");

        let request = builder.build()?;

        // Store registration info
        *self.registration_manager.current_registration.write().await = Some(Registration {
            call_id,
            cseq,
            expires,
            contact: contact.clone(),
            from_tag,
            registrar_uri,
        });

        Ok(request)
    }

    fn clone_arc(&self) -> Arc<Self> {
        // This would need to be implemented properly with Arc
        panic!("clone_arc not implemented - use Arc<Account>");
    }

    pub async fn make_call(
        &self,
        uri: SipUri,
        sdp: Option<Session>,
    ) -> Result<Arc<crate::Call>> {
        let current_state = *self.state.read().await;
        if current_state != AccountState::Registered {
            return Err(SipError::InvalidState("Account not registered".to_string()));
        }

        // Create call
        let call_id = CallId(generate_call_id(&self.config.domain));
        let call = crate::Call::new_outgoing(
            call_id.clone(),
            self.id.clone(),
            uri.clone(),
            self.registry.clone(),
            self.event_dispatcher.clone(),
            self.logger.clone(),
        ).await?;

        // Create INVITE request
        let invite = self.create_invite_request(uri, &call_id, sdp).await?;
        
        // Start the call
        call.start_outgoing(invite).await?;

        Ok(call)
    }

    pub async fn handle_incoming_call(
        &self,
        request: SipMessage,
        from_uri: SipUri,
        source: SocketAddr,
        transport: Arc<dyn Transport>,
        transaction: Arc<Transaction>,
    ) -> Result<Arc<crate::Call>> {
        let call_id = request.get_call_id()
            .ok_or_else(|| SipError::InvalidHeader("Missing Call-ID".to_string()))?;
        
        let call_id = CallId(call_id.clone());
        
        let call = crate::Call::new_incoming(
            call_id.clone(),
            self.id.clone(),
            from_uri,
            request,
            source,
            transport,
            transaction,
            self.registry.clone(),
            self.event_dispatcher.clone(),
            self.logger.clone(),
        ).await?;

        Ok(call)
    }

    async fn create_invite_request(
        &self,
        uri: SipUri,
        call_id: &CallId,
        sdp: Option<Session>,
    ) -> Result<SipMessage> {
        let from_uri = SipUri::parse(&format!("sip:{}@{}", 
            self.config.username, 
            self.config.domain
        ))?;

        let mut builder = SipMessageBuilder::new()
            .request(SipMethod::Invite, uri.clone());

        // Via header
        let transport = self.registry.transport_manager.get_transport("UDP", None).await
            .ok_or_else(|| SipError::TransportError("No UDP transport available".to_string()))?;
        
        let via = ViaHeader::new(
            transport.protocol(),
            &transport.local_addr().to_string(),
            &generate_branch(),
        );
        builder = builder.header(HeaderName::VIA, &via.to_string());

        // From header with tag
        let from_tag = generate_tag();
        builder = builder.header(
            HeaderName::FROM,
            &format!("{} <{}>;tag={}", 
                self.config.display_name, 
                from_uri, 
                from_tag
            ),
        );

        // To header (no tag yet)
        builder = builder.header(HeaderName::TO, &format!("<{}>", uri));

        // Call-ID
        builder = builder.header(HeaderName::CALL_ID, &call_id.0);

        // CSeq
        let cseq = self.cseq_counter.fetch_add(1, Ordering::SeqCst);
        builder = builder.header(HeaderName::CSEQ, &format!("{} INVITE", cseq));

        // Contact
        let contact_uri = SipUri::parse(&format!("sip:{}@{}", 
            self.config.username,
            transport.local_addr()
        ))?;
        builder = builder.header(HeaderName::CONTACT, &format!("<{}>", contact_uri));

        // User-Agent
        builder = builder.header(HeaderName::USER_AGENT, "RustSIP/1.0");

        // Allow
        builder = builder.header(HeaderName::ALLOW, "INVITE, ACK, BYE, CANCEL, OPTIONS, UPDATE, INFO");

        // Add SDP if provided
        if let Some(session) = sdp {
            let sdp_content = session.to_sdp();
            builder = builder.body("application/sdp", sdp_content.into_bytes());
        }

        builder.build()
    }

    pub fn get_state(&self) -> AccountState {
        // This would need to be async in the real implementation
        AccountState::Offline
    }

    pub fn get_config(&self) -> &AccountConfig {
        &self.config
    }

    pub async fn is_registered(&self) -> bool {
        *self.state.read().await == AccountState::Registered
    }

    pub async fn get_registration_expiry(&self) -> Option<Duration> {
        if let Some(expiry) = *self.registration_manager.registration_expiry.read().await {
            let now = tokio::time::Instant::now();
            if expiry > now {
                Some(expiry - now)
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_account_creation() {
        let logger = Arc::new(crate::ConsoleLogger);
        let event_dispatcher = Arc::new(EventDispatcher::new());
        let transport_manager = Arc::new(crate::TransportManager::new(logger.clone()));
        let dialog_manager = Arc::new(crate::DialogManager::new(logger.clone()));
        let dns_resolver = Arc::new(crate::DnsResolver::new(logger.clone()));
        let transaction_manager = Arc::new(crate::TransactionManager::new(
            logger.clone(),
            Arc::new(TestTransactionHandler),
        ));

        let registry = ComponentRegistry {
            transport_manager,
            transaction_manager,
            dialog_manager,
            dns_resolver,
        };

        let config = AccountConfig {
            display_name: "Test User".to_string(),
            username: "test".to_string(),
            domain: "example.com".to_string(),
            password: Some("secret".to_string()),
            proxy: None,
            registrar: Some("sip:example.com".to_string()),
            expire_seconds: 3600,
            register_on_add: false,
        };

        let account = Account::new(
            AccountId("test@example.com".to_string()),
            config,
            registry,
            event_dispatcher,
            logger,
        ).await.unwrap();

        assert_eq!(account.id.0, "test@example.com");
        assert_eq!(account.config.username, "test");
    }

    struct TestTransactionHandler;

    impl crate::TransactionEventHandler for TestTransactionHandler {
        fn handle_transaction_event<'a>(&'a self, _id: crate::TransactionId, _event: TransactionEvent) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
            Box::pin(async move {
                // Test implementation
            })
        }
    }
}