use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::net::SocketAddr;
use tokio::sync::{RwLock, mpsc, oneshot};
use tokio::time::{sleep, Duration};

use crate::{
    Result, SipError, CallId, AccountId, CallState, MediaState,
    SipMessage, SipMethod, SipUri, SipMessageBuilder, Session, SdpParser,
    ComponentRegistry, EventDispatcher, Logger, Event, CallEvent,
    Transport, TransactionEvent, Transaction, Dialog, DialogState,
    generate_branch, generate_tag, ContactHeader, ViaHeader, CSeqHeader,
    HeaderName, MediaCapabilities, SdpNegotiator, SdpBuilder, RtpCodec,
};

// Call structure
pub struct Call {
    pub id: CallId,
    account_id: AccountId,
    dialog: RwLock<Option<Arc<RwLock<Dialog>>>>,
    local_uri: SipUri,
    remote_uri: SipUri,
    state: RwLock<CallState>,
    media_state: RwLock<MediaState>,
    direction: CallDirection,
    local_sdp: RwLock<Option<Session>>,
    remote_sdp: RwLock<Option<Session>>,
    media_manager: RwLock<Option<MediaManager>>,
    cseq_counter: AtomicU32,
    registry: ComponentRegistry,
    event_dispatcher: Arc<EventDispatcher>,
    logger: Arc<dyn Logger>,
    command_tx: mpsc::Sender<CallCommand>,
    command_rx: Arc<RwLock<mpsc::Receiver<CallCommand>>>,
    transaction: RwLock<Option<Arc<Transaction>>>,
    transport: RwLock<Option<Arc<dyn Transport>>>,
    remote_addr: RwLock<Option<SocketAddr>>,
}

#[derive(Debug, Clone, Copy)]
enum CallDirection {
    Outgoing,
    Incoming,
}

#[derive(Debug)]
enum CallCommand {
    Answer { sdp: Option<Session>, result_tx: oneshot::Sender<Result<()>> },
    Hangup { result_tx: oneshot::Sender<Result<()>> },
    Hold { result_tx: oneshot::Sender<Result<()>> },
    Resume { result_tx: oneshot::Sender<Result<()>> },
    SendDtmf { digit: char, result_tx: oneshot::Sender<Result<()>> },
    HandleResponse { response: SipMessage },
    HandleRequest { request: SipMessage, source: SocketAddr },
}

// Media manager placeholder
struct MediaManager {
    local_address: String,
    audio_port: Option<u16>,
    video_port: Option<u16>,
}

impl MediaManager {
    fn new(local_address: String) -> Self {
        MediaManager {
            local_address,
            audio_port: None,
            video_port: None,
        }
    }

    async fn start_media(&mut self, local_sdp: &Session, remote_sdp: &Session) -> Result<()> {
        // In real implementation, this would:
        // 1. Allocate media ports
        // 2. Start RTP/RTCP
        // 3. Configure codecs
        // 4. Start media flow
        
        self.audio_port = Some(10000); // Placeholder
        Ok(())
    }

    async fn stop_media(&mut self) -> Result<()> {
        // Stop media flow
        self.audio_port = None;
        self.video_port = None;
        Ok(())
    }
}

impl Call {
    pub async fn new_outgoing(
        id: CallId,
        account_id: AccountId,
        remote_uri: SipUri,
        registry: ComponentRegistry,
        event_dispatcher: Arc<EventDispatcher>,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let (command_tx, command_rx) = mpsc::channel(100);

        let local_uri = SipUri::parse(&format!("sip:{}@{}", 
            "user", // Would come from account
            "domain.com"
        ))?;

        let call = Arc::new(Call {
            id: id.clone(),
            account_id,
            dialog: RwLock::new(None),
            local_uri,
            remote_uri,
            state: RwLock::new(CallState::Null),
            media_state: RwLock::new(MediaState::None),
            direction: CallDirection::Outgoing,
            local_sdp: RwLock::new(None),
            remote_sdp: RwLock::new(None),
            media_manager: RwLock::new(None),
            cseq_counter: AtomicU32::new(1),
            registry,
            event_dispatcher,
            logger,
            command_tx,
            command_rx: Arc::new(RwLock::new(command_rx)),
            transaction: RwLock::new(None),
            transport: RwLock::new(None),
            remote_addr: RwLock::new(None),
        });

        // Start command handler
        let call_clone = call.clone();
        tokio::spawn(async move {
            call_clone.run_command_handler().await;
        });

        Ok(call)
    }

    pub async fn new_incoming(
        id: CallId,
        account_id: AccountId,
        remote_uri: SipUri,
        request: SipMessage,
        source: SocketAddr,
        transport: Arc<dyn Transport>,
        transaction: Arc<Transaction>,
        registry: ComponentRegistry,
        event_dispatcher: Arc<EventDispatcher>,
        logger: Arc<dyn Logger>,
    ) -> Result<Arc<Self>> {
        let (command_tx, command_rx) = mpsc::channel(100);

        let to_header = request.get_to()
            .ok_or_else(|| SipError::InvalidHeader("Missing To header".to_string()))?;
        let local_uri = ContactHeader::parse(to_header)?.uri;

        let call = Arc::new(Call {
            id: id.clone(),
            account_id,
            dialog: RwLock::new(None),
            local_uri,
            remote_uri,
            state: RwLock::new(CallState::Incoming),
            media_state: RwLock::new(MediaState::None),
            direction: CallDirection::Incoming,
            local_sdp: RwLock::new(None),
            remote_sdp: RwLock::new(None),
            media_manager: RwLock::new(None),
            cseq_counter: AtomicU32::new(1),
            registry,
            event_dispatcher: event_dispatcher.clone(),
            logger,
            command_tx,
            command_rx: Arc::new(RwLock::new(command_rx)),
            transaction: RwLock::new(Some(transaction)),
            transport: RwLock::new(Some(transport)),
            remote_addr: RwLock::new(Some(source)),
        });

        // Parse SDP from request
        if let Some(body) = &request.body {
            if body.content_type.contains("application/sdp") {
                match SdpParser::parse(&body.as_string()?) {
                    Ok(sdp) => {
                        *call.remote_sdp.write().await = Some(sdp);
                    }
                    Err(e) => {
                        call.logger.error(&format!("Failed to parse SDP: {}", e));
                    }
                }
            }
        }

        // Create dialog
        let local_tag = generate_tag();
        let dialog = call.registry.dialog_manager
            .create_dialog_from_request(&request, local_tag)
            .await?;
        
        *call.dialog.write().await = Some(dialog);

        // Send 180 Ringing
        call.send_provisional_response(180, "Ringing").await?;

        // Notify about incoming call
        event_dispatcher.dispatch(Event::Call(CallEvent::IncomingCall {
            call_id: id,
            from: call.remote_uri.clone(),
        })).await;

        // Start command handler
        let call_clone = call.clone();
        tokio::spawn(async move {
            call_clone.run_command_handler().await;
        });

        Ok(call)
    }

    pub async fn start_outgoing(&self, invite: SipMessage) -> Result<()> {
        *self.state.write().await = CallState::Calling;

        // Resolve target address
        let target_addrs = self.registry.dns_resolver
            .resolve_target(&self.remote_uri)
            .await?;
        
        if target_addrs.is_empty() {
            return Err(SipError::TransportError("No address found for target".to_string()));
        }

        let target = target_addrs[0];
        *self.remote_addr.write().await = Some(target);

        // Get transport
        let transport = self.registry.transport_manager
            .find_transport_for_target(target, "UDP")
            .await
            .ok_or_else(|| SipError::TransportError("No suitable transport found".to_string()))?;
        
        *self.transport.write().await = Some(transport.clone());

        // Create transaction
        let transaction = self.registry.transaction_manager
            .create_client_transaction(invite.clone(), transport, target)
            .await?;
        
        *self.transaction.write().await = Some(transaction.clone());

        // Send INVITE
        transaction.event_tx.send(TransactionEvent::SendRequest(
            invite,
            target
        )).await.map_err(|_| SipError::InvalidState("Failed to send INVITE".to_string()))?;

        // Notify state change
        self.event_dispatcher.dispatch(Event::Call(CallEvent::CallStateChanged {
            call_id: self.id.clone(),
            state: CallState::Calling,
        })).await;

        Ok(())
    }

    pub async fn answer(&self, sdp: Option<Session>) -> Result<()> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx.send(CallCommand::Answer { sdp, result_tx }).await
            .map_err(|_| SipError::InvalidState("Failed to send command".to_string()))?;
        result_rx.await.map_err(|_| SipError::InvalidState("Failed to get result".to_string()))?
    }

    pub async fn hangup(&self) -> Result<()> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx.send(CallCommand::Hangup { result_tx }).await
            .map_err(|_| SipError::InvalidState("Failed to send command".to_string()))?;
        result_rx.await.map_err(|_| SipError::InvalidState("Failed to get result".to_string()))?
    }

    pub async fn hold(&self) -> Result<()> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx.send(CallCommand::Hold { result_tx }).await
            .map_err(|_| SipError::InvalidState("Failed to send command".to_string()))?;
        result_rx.await.map_err(|_| SipError::InvalidState("Failed to get result".to_string()))?
    }

    pub async fn resume(&self) -> Result<()> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx.send(CallCommand::Resume { result_tx }).await
            .map_err(|_| SipError::InvalidState("Failed to send command".to_string()))?;
        result_rx.await.map_err(|_| SipError::InvalidState("Failed to get result".to_string()))?
    }

    pub async fn send_dtmf(&self, digit: char) -> Result<()> {
        let (result_tx, result_rx) = oneshot::channel();
        self.command_tx.send(CallCommand::SendDtmf { digit, result_tx }).await
            .map_err(|_| SipError::InvalidState("Failed to send command".to_string()))?;
        result_rx.await.map_err(|_| SipError::InvalidState("Failed to get result".to_string()))?
    }

    pub async fn get_state(&self) -> CallState {
        *self.state.read().await
    }

    pub async fn get_media_state(&self) -> MediaState {
        *self.media_state.read().await
    }

    async fn run_command_handler(&self) {
        let mut command_rx = self.command_rx.write().await;
        
        while let Some(command) = command_rx.recv().await {
            match command {
                CallCommand::Answer { sdp, result_tx } => {
                    let result = self.handle_answer(sdp).await;
                    let _ = result_tx.send(result);
                }
                CallCommand::Hangup { result_tx } => {
                    let result = self.handle_hangup().await;
                    let _ = result_tx.send(result);
                }
                CallCommand::Hold { result_tx } => {
                    let result = self.handle_hold().await;
                    let _ = result_tx.send(result);
                }
                CallCommand::Resume { result_tx } => {
                    let result = self.handle_resume().await;
                    let _ = result_tx.send(result);
                }
                CallCommand::SendDtmf { digit, result_tx } => {
                    let result = self.handle_send_dtmf(digit).await;
                    let _ = result_tx.send(result);
                }
                CallCommand::HandleResponse { response } => {
                    let _ = self.handle_response(response).await;
                }
                CallCommand::HandleRequest { request, source } => {
                    let _ = self.handle_request(request, source).await;
                }
            }
        }
    }

    async fn handle_answer(&self, sdp: Option<Session>) -> Result<()> {
        let state = *self.state.read().await;
        if state != CallState::Incoming {
            return Err(SipError::InvalidState("Can only answer incoming calls".to_string()));
        }

        // Create SDP answer if needed
        let local_sdp = if let Some(sdp) = sdp {
            sdp
        } else {
            // Create default SDP answer
            let capabilities = MediaCapabilities::new("192.168.1.100".to_string()); // Placeholder
            let remote_sdp = self.remote_sdp.read().await
                .as_ref()
                .ok_or_else(|| SipError::InvalidState("No remote SDP".to_string()))?
                .clone();
            
            SdpNegotiator::create_answer(&remote_sdp, &capabilities)?
        };

        *self.local_sdp.write().await = Some(local_sdp.clone());

        // Send 200 OK
        self.send_ok_response(Some(local_sdp)).await?;

        *self.state.write().await = CallState::Confirmed;
        
        // Start media
        self.start_media().await?;

        // Notify state change
        self.event_dispatcher.dispatch(Event::Call(CallEvent::CallStateChanged {
            call_id: self.id.clone(),
            state: CallState::Confirmed,
        })).await;

        Ok(())
    }

    async fn handle_hangup(&self) -> Result<()> {
        let state = *self.state.read().await;
        
        match state {
            CallState::Confirmed => {
                // Send BYE
                self.send_bye().await?;
                *self.state.write().await = CallState::Disconnecting;
            }
            CallState::Incoming | CallState::Calling | CallState::EarlyMedia => {
                // Send CANCEL or reject
                if state == CallState::Incoming {
                    self.send_error_response(486, "Busy Here").await?;
                } else {
                    self.send_cancel().await?;
                }
                *self.state.write().await = CallState::Disconnecting;
            }
            _ => {}
        }

        // Stop media
        self.stop_media().await?;

        // Update state
        *self.state.write().await = CallState::Disconnected;

        // Notify state change
        self.event_dispatcher.dispatch(Event::Call(CallEvent::CallStateChanged {
            call_id: self.id.clone(),
            state: CallState::Disconnected,
        })).await;

        Ok(())
    }

    async fn handle_hold(&self) -> Result<()> {
        let state = *self.state.read().await;
        if state != CallState::Confirmed {
            return Err(SipError::InvalidState("Call not established".to_string()));
        }

        // Send re-INVITE with inactive media
        self.send_reinvite(true).await?;

        *self.media_state.write().await = MediaState::LocalHold;

        // Notify media state change
        self.event_dispatcher.dispatch(Event::Call(CallEvent::MediaStateChanged {
            call_id: self.id.clone(),
            state: MediaState::LocalHold,
        })).await;

        Ok(())
    }

    async fn handle_resume(&self) -> Result<()> {
        let media_state = *self.media_state.read().await;
        if media_state != MediaState::LocalHold {
            return Err(SipError::InvalidState("Call not on hold".to_string()));
        }

        // Send re-INVITE with active media
        self.send_reinvite(false).await?;

        *self.media_state.write().await = MediaState::Active;

        // Notify media state change
        self.event_dispatcher.dispatch(Event::Call(CallEvent::MediaStateChanged {
            call_id: self.id.clone(),
            state: MediaState::Active,
        })).await;

        Ok(())
    }

    async fn handle_send_dtmf(&self, digit: char) -> Result<()> {
        let state = *self.state.read().await;
        if state != CallState::Confirmed {
            return Err(SipError::InvalidState("Call not established".to_string()));
        }

        // In real implementation, would send DTMF via RTP (RFC 2833) or SIP INFO
        self.logger.info(&format!("Sending DTMF digit: {}", digit));

        Ok(())
    }

    async fn handle_response(&self, response: SipMessage) -> Result<()> {
        let status = response.status_code().unwrap_or(0);
        let state = *self.state.read().await;

        match state {
            CallState::Calling => {
                match status {
                    180 => {
                        // Ringing
                        *self.state.write().await = CallState::EarlyMedia;
                        self.event_dispatcher.dispatch(Event::Call(CallEvent::CallStateChanged {
                            call_id: self.id.clone(),
                            state: CallState::EarlyMedia,
                        })).await;
                    }
                    183 => {
                        // Session Progress
                        *self.state.write().await = CallState::EarlyMedia;
                        
                        // Parse SDP if present
                        if let Some(body) = &response.body {
                            if body.content_type.contains("application/sdp") {
                                if let Ok(sdp) = SdpParser::parse(&body.as_string()?) {
                                    *self.remote_sdp.write().await = Some(sdp);
                                }
                            }
                        }
                    }
                    200 => {
                        // OK - Call established
                        *self.state.write().await = CallState::Confirmed;
                        
                        // Parse SDP
                        if let Some(body) = &response.body {
                            if body.content_type.contains("application/sdp") {
                                if let Ok(sdp) = SdpParser::parse(&body.as_string()?) {
                                    *self.remote_sdp.write().await = Some(sdp);
                                }
                            }
                        }
                        
                        // Confirm dialog
                        if let Some(dialog) = self.dialog.read().await.as_ref() {
                            self.registry.dialog_manager.confirm_dialog(dialog.clone(), &response).await?;
                        }
                        
                        // Send ACK
                        self.send_ack().await?;
                        
                        // Start media
                        self.start_media().await?;
                        
                        self.event_dispatcher.dispatch(Event::Call(CallEvent::CallStateChanged {
                            call_id: self.id.clone(),
                            state: CallState::Confirmed,
                        })).await;
                    }
                    _ if status >= 400 => {
                        // Error response
                        *self.state.write().await = CallState::Disconnected;
                        self.event_dispatcher.dispatch(Event::Call(CallEvent::CallFailed {
                            call_id: self.id.clone(),
                            reason: format!("Call failed with status {}", status),
                        })).await;
                    }
                    _ => {}
                }
            }
            _ => {
                self.logger.debug(&format!("Received response {} in state {:?}", status, state));
            }
        }

        Ok(())
    }

    async fn handle_request(&self, request: SipMessage, source: SocketAddr) -> Result<()> {
        match request.method() {
            Some(SipMethod::Bye) => {
                // Send 200 OK
                self.send_response_for_request(&request, 200, "OK", None).await?;
                
                // Stop media
                self.stop_media().await?;
                
                // Update state
                *self.state.write().await = CallState::Disconnected;
                
                self.event_dispatcher.dispatch(Event::Call(CallEvent::CallStateChanged {
                    call_id: self.id.clone(),
                    state: CallState::Disconnected,
                })).await;
            }
            Some(SipMethod::Cancel) => {
                // Send 200 OK for CANCEL
                self.send_response_for_request(&request, 200, "OK", None).await?;
                
                // Send 487 for original INVITE
                if let Some(transaction) = self.transaction.read().await.as_ref() {
                    let response = create_response(&transaction.request, 487, "Request Terminated")?;
                    transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
                        .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
                }
                
                *self.state.write().await = CallState::Disconnected;
            }
            _ => {
                self.logger.debug(&format!("Unhandled request method: {:?}", request.method()));
            }
        }

        Ok(())
    }

    async fn send_provisional_response(&self, status: u16, reason: &str) -> Result<()> {
        if let Some(transaction) = self.transaction.read().await.as_ref() {
            let response = create_response(&transaction.request, status, reason)?;
            
            if let Some(source) = *self.remote_addr.read().await {
                transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
                    .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
            }
        }
        Ok(())
    }

    async fn send_ok_response(&self, sdp: Option<Session>) -> Result<()> {
        if let Some(transaction) = self.transaction.read().await.as_ref() {
            let mut response = create_response(&transaction.request, 200, "OK")?;
            
            // Add Contact header
            let contact = ContactHeader::new(self.local_uri.clone());
            response.headers.set(
                HeaderName::new(HeaderName::CONTACT),
                contact.to_string(),
            );
            
            // Add SDP if provided
            if let Some(session) = sdp {
                response.set_body("application/sdp".to_string(), session.to_sdp().into_bytes());
            }
            
            if let Some(source) = *self.remote_addr.read().await {
                transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
                    .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
            }
        }
        Ok(())
    }

    async fn send_error_response(&self, status: u16, reason: &str) -> Result<()> {
        if let Some(transaction) = self.transaction.read().await.as_ref() {
            let response = create_response(&transaction.request, status, reason)?;
            
            if let Some(source) = *self.remote_addr.read().await {
                transaction.event_tx.send(TransactionEvent::SendResponse(response, source)).await
                    .map_err(|_| SipError::InvalidState("Failed to send response".to_string()))?;
            }
        }
        Ok(())
    }

    async fn send_response_for_request(
        &self, 
        request: &SipMessage, 
        status: u16, 
        reason: &str,
        body: Option<Vec<u8>>
    ) -> Result<()> {
        let response = create_response(request, status, reason)?;
        
        if let (Some(transport), Some(source)) = (
            self.transport.read().await.as_ref(),
            *self.remote_addr.read().await
        ) {
            transport.send_response(&response, source).await?;
        }
        
        Ok(())
    }

    async fn send_bye(&self) -> Result<()> {
        // Create BYE request
        let mut bye = SipMessage::new_request(SipMethod::Bye, self.remote_uri.clone());
        
        // Add headers from dialog
        if let Some(dialog) = self.dialog.read().await.as_ref() {
            let d = dialog.read().await;
            
            // Via
            if let Some(transport) = self.transport.read().await.as_ref() {
                let via = ViaHeader::new(
                    transport.protocol(),
                    &transport.local_addr().to_string(),
                    &generate_branch(),
                );
                bye.add_via(via);
            }
            
            // From/To
            bye.headers.set(
                HeaderName::new(HeaderName::FROM),
                format!("<{}>;tag={}", d.local_uri, d.local_tag),
            );
            bye.headers.set(
                HeaderName::new(HeaderName::TO),
                format!("<{}>;tag={}", d.remote_uri, d.remote_tag),
            );
            
            // Call-ID
            bye.headers.set(HeaderName::new(HeaderName::CALL_ID), d.call_id.clone());
            
            // CSeq
            let cseq = self.cseq_counter.fetch_add(1, Ordering::SeqCst);
            bye.headers.set(
                HeaderName::new(HeaderName::CSEQ),
                format!("{} BYE", cseq),
            );
        }
        
        // Send BYE
        if let (Some(transport), Some(target)) = (
            self.transport.read().await.as_ref(),
            *self.remote_addr.read().await
        ) {
            transport.send(&bye, target).await?;
        }
        
        Ok(())
    }

    async fn send_cancel(&self) -> Result<()> {
        // Create CANCEL request
        if let Some(transaction) = self.transaction.read().await.as_ref() {
            let mut cancel = SipMessage::new_request(SipMethod::Cancel, self.remote_uri.clone());
            
            // Copy headers from original INVITE
            if let Some(via) = transaction.request.get_via() {
                cancel.add_via(via);
            }
            
            if let Some(from) = transaction.request.get_from() {
                cancel.headers.set(HeaderName::new(HeaderName::FROM), from.clone());
            }
            
            if let Some(to) = transaction.request.get_to() {
                cancel.headers.set(HeaderName::new(HeaderName::TO), to.clone());
            }
            
            if let Some(call_id) = transaction.request.get_call_id() {
                cancel.headers.set(HeaderName::new(HeaderName::CALL_ID), call_id.clone());
            }
            
            // CSeq with CANCEL method
            if let Some(cseq) = transaction.request.get_cseq() {
                cancel.headers.set(
                    HeaderName::new(HeaderName::CSEQ),
                    format!("{} CANCEL", cseq.sequence),
                );
            }
            
            // Send CANCEL
            transaction.transport.send(&cancel, transaction.remote_addr).await?;
        }
        
        Ok(())
    }

    async fn send_ack(&self) -> Result<()> {
        // ACK is sent differently for 2xx vs non-2xx responses
        // For 2xx, it's a new transaction
        // For non-2xx, it's part of the INVITE transaction
        
        // This is simplified - real implementation would handle both cases
        if let Some(dialog) = self.dialog.read().await.as_ref() {
            let d = dialog.read().await;
            
            let mut ack = SipMessage::new_request(SipMethod::Ack, self.remote_uri.clone());
            
            // Via
            if let Some(transport) = self.transport.read().await.as_ref() {
                let via = ViaHeader::new(
                    transport.protocol(),
                    &transport.local_addr().to_string(),
                    &generate_branch(),
                );
                ack.add_via(via);
            }
            
            // From/To
            ack.headers.set(
                HeaderName::new(HeaderName::FROM),
                format!("<{}>;tag={}", d.local_uri, d.local_tag),
            );
            ack.headers.set(
                HeaderName::new(HeaderName::TO),
                format!("<{}>;tag={}", d.remote_uri, d.remote_tag),
            );
            
            // Call-ID
            ack.headers.set(HeaderName::new(HeaderName::CALL_ID), d.call_id.clone());
            
            // CSeq (same as INVITE)
            if let Some(transaction) = self.transaction.read().await.as_ref() {
                if let Some(cseq) = transaction.request.get_cseq() {
                    ack.headers.set(
                        HeaderName::new(HeaderName::CSEQ),
                        format!("{} ACK", cseq.sequence),
                    );
                }
            }
            
            // Send ACK
            if let (Some(transport), Some(target)) = (
                self.transport.read().await.as_ref(),
                *self.remote_addr.read().await
            ) {
                transport.send(&ack, target).await?;
            }
        }
        
        Ok(())
    }

    async fn send_reinvite(&self, hold: bool) -> Result<()> {
        // In real implementation, would send re-INVITE with updated SDP
        self.logger.info(&format!("Sending re-INVITE (hold={})", hold));
        Ok(())
    }

    async fn start_media(&self) -> Result<()> {
        let mut media_manager = MediaManager::new("192.168.1.100".to_string()); // Placeholder
        
        if let (Some(local_sdp), Some(remote_sdp)) = (
            self.local_sdp.read().await.as_ref(),
            self.remote_sdp.read().await.as_ref()
        ) {
            media_manager.start_media(local_sdp, remote_sdp).await?;
        }
        
        *self.media_manager.write().await = Some(media_manager);
        *self.media_state.write().await = MediaState::Active;
        
        self.event_dispatcher.dispatch(Event::Call(CallEvent::MediaStateChanged {
            call_id: self.id.clone(),
            state: MediaState::Active,
        })).await;
        
        Ok(())
    }

    async fn stop_media(&self) -> Result<()> {
        if let Some(mut media_manager) = self.media_manager.write().await.take() {
            media_manager.stop_media().await?;
        }
        
        *self.media_state.write().await = MediaState::None;
        
        self.event_dispatcher.dispatch(Event::Call(CallEvent::MediaStateChanged {
            call_id: self.id.clone(),
            state: MediaState::None,
        })).await;
        
        Ok(())
    }
}

// Helper function to create response from request
pub fn create_response(request: &SipMessage, status_code: u16, reason_phrase: &str) -> Result<SipMessage> {
    let mut response = SipMessage::new_response(status_code, reason_phrase);
    
    // Copy headers from request
    if let Some(via) = request.get_via() {
        response.add_via(via);
    }
    
    if let Some(from) = request.get_from() {
        response.headers.set(HeaderName::new(HeaderName::FROM), from.clone());
    }
    
    if let Some(to) = request.get_to() {
        // Add tag if not present (for dialog-creating responses)
        let to_value = to.clone();
        if status_code >= 200 && !to_value.contains("tag=") {
            let tag = generate_tag();
            response.headers.set(
                HeaderName::new(HeaderName::TO),
                format!("{};tag={}", to_value, tag),
            );
        } else {
            response.headers.set(HeaderName::new(HeaderName::TO), to_value);
        }
    }
    
    if let Some(call_id) = request.get_call_id() {
        response.headers.set(HeaderName::new(HeaderName::CALL_ID), call_id.clone());
    }
    
    if let Some(cseq) = request.get_cseq() {
        response.headers.set(HeaderName::new(HeaderName::CSEQ), cseq.to_string());
    }
    
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_call_creation() {
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

        let call_id = CallId("test-call-123".to_string());
        let account_id = AccountId("test@example.com".to_string());
        let remote_uri = SipUri::parse("sip:bob@example.com").unwrap();

        let call = Call::new_outgoing(
            call_id.clone(),
            account_id,
            remote_uri,
            registry,
            event_dispatcher,
            logger,
        ).await.unwrap();

        assert_eq!(call.id.0, "test-call-123");
        assert_eq!(call.get_state().await, CallState::Null);
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