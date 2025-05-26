// examples/simple_client.rs - Simple SIP client example


use std::sync::Arc;
use rs_sip::{AccountConfig, Call, CallEvent, ConsoleLogger, Endpoint, Event, EventHandler, MediaEvent, RegistrationEvent, RtpCodec, SdpBuilder, Session, SipUri, TransportEvent};
use tokio::io::{AsyncBufReadExt, BufReader};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("RustSIP Simple Client Example");
    println!("=============================\n");

    // Initialize the library
    rs_sip::init()?;
    

    // Create endpoint with custom configuration
    let endpoint = Endpoint::builder()
        .udp_port(5061)
        .user_agent("RustSIP Example/1.0")
        .max_calls(10)
        .logger(Arc::new(ConsoleLogger))
        .build()
        .await?;

    // Add event handler
    endpoint.add_event_handler(Box::new(ExampleEventHandler)).await;

    // Start the endpoint
    endpoint.start().await?;
    println!("Endpoint started successfully\n");

    // Create an account
    let account_config = AccountConfig {
        display_name: "Test".to_string(),
        username: "1000".to_string(),
        domain: "localhost".to_string(),
        password: Some("1000".to_string()),
        proxy: None,
        registrar: Some("sip:localhost".to_string()),
        expire_seconds: 3600,
        register_on_add: true,
    };

    let account = endpoint.create_account(account_config).await?;
    println!("Account created: {}", account.id.0);

    // Interactive command loop
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    loop {
        println!("\nCommands:");
        println!("  register    - Register the account");
        println!("  unregister  - Unregister the account");
        println!("  call <uri>  - Make a call (e.g., call sip:bob@example.com)");
        println!("  answer      - Answer incoming call");
        println!("  hangup      - Hang up current call");
        println!("  hold        - Put call on hold");
        println!("  resume      - Resume held call");
        println!("  dtmf <digit> - Send DTMF digit");
        println!("  status      - Show current status");
        println!("  quit        - Exit the application");
        println!();
        print!("> ");

        line.clear();
        reader.read_line(&mut line).await?;
        let parts: Vec<&str> = line.trim().split_whitespace().collect();

        if parts.is_empty() {
            continue;
        }

        match parts[0] {
            "register" => {
                match account.register().await {
                    Ok(_) => println!("Registration initiated"),
                    Err(e) => println!("Registration failed: {}", e),
                }
            }
            "unregister" => {
                match account.unregister().await {
                    Ok(_) => println!("Unregistration completed"),
                    Err(e) => println!("Unregistration failed: {}", e),
                }
            }
            "call" => {
                if parts.len() < 2 {
                    println!("Usage: call <uri>");
                    continue;
                }
                
                match SipUri::parse(parts[1]) {
                    Ok(uri) => {
                        // Create SDP offer
                        let sdp = create_sdp_offer();
                        
                        match endpoint.make_call(&account.id, uri, Some(sdp)).await {
                            Ok(call) => {
                                println!("Call initiated: {}", call.id.0);
                                // Store call reference for later use
                                CURRENT_CALL.lock().await.replace(call);
                            }
                            Err(e) => println!("Call failed: {}", e),
                        }
                    }
                    Err(e) => println!("Invalid URI: {}", e),
                }
            }
            "answer" => {
                if let Some(call) = get_current_call().await {
                    match call.answer(None).await {
                        Ok(_) => println!("Call answered"),
                        Err(e) => println!("Answer failed: {}", e),
                    }
                } else {
                    println!("No active call");
                }
            }
            "hangup" => {
                if let Some(call) = get_current_call().await {
                    match call.hangup().await {
                        Ok(_) => println!("Call terminated"),
                        Err(e) => println!("Hangup failed: {}", e),
                    }
                    CURRENT_CALL.lock().await.take();
                } else {
                    println!("No active call");
                }
            }
            "hold" => {
                if let Some(call) = get_current_call().await {
                    match call.hold().await {
                        Ok(_) => println!("Call on hold"),
                        Err(e) => println!("Hold failed: {}", e),
                    }
                } else {
                    println!("No active call");
                }
            }
            "resume" => {
                if let Some(call) = get_current_call().await {
                    match call.resume().await {
                        Ok(_) => println!("Call resumed"),
                        Err(e) => println!("Resume failed: {}", e),
                    }
                } else {
                    println!("No active call");
                }
            }
            "dtmf" => {
                if parts.len() < 2 {
                    println!("Usage: dtmf <digit>");
                    continue;
                }
                
                if let Some(digit) = parts[1].chars().next() {
                    if let Some(call) = get_current_call().await {
                        match call.send_dtmf(digit).await {
                            Ok(_) => println!("DTMF sent: {}", digit),
                            Err(e) => println!("DTMF failed: {}", e),
                        }
                    } else {
                        println!("No active call");
                    }
                } else {
                    println!("Invalid digit");
                }
            }
            "status" => {
                println!("Account status: {:?}", account.get_state());
                
                if let Some(call) = get_current_call().await {
                    println!("Call status: {:?}", call.get_state().await);
                    println!("Media status: {:?}", call.get_media_state().await);
                } else {
                    println!("No active call");
                }
            }
            "quit" | "exit" => {
                println!("Shutting down...");
                break;
            }
            _ => {
                println!("Unknown command: {}", parts[0]);
            }
        }
    }

    // Cleanup
    endpoint.stop().await?;
    println!("Goodbye!");

    Ok(())
}

// Event handler implementation
struct ExampleEventHandler;

impl EventHandler for ExampleEventHandler {
    fn on_event<'a>(&'a self, event: Event) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            match event {
                Event::Call(call_event) => handle_call_event(call_event).await,
                Event::Registration(reg_event) => handle_registration_event(reg_event).await,
                Event::Transport(transport_event) => handle_transport_event(transport_event).await,
                Event::Media(media_event) => handle_media_event(media_event).await,
            }
        })
    }
}

async fn handle_call_event(event: CallEvent) {
    match event {
        CallEvent::IncomingCall { call_id, from } => {
            println!("\n*** Incoming call from {} (ID: {}) ***", from, call_id.0);
            println!("Use 'answer' to accept or 'hangup' to reject");
        }
        CallEvent::CallStateChanged { call_id, state } => {
            println!("\n*** Call {} state changed to {:?} ***", call_id.0, state);
        }
        CallEvent::MediaStateChanged { call_id, state } => {
            println!("\n*** Call {} media state changed to {:?} ***", call_id.0, state);
        }
        CallEvent::CallFailed { call_id, reason } => {
            println!("\n*** Call {} failed: {} ***", call_id.0, reason);
        }
    }
}

async fn handle_registration_event(event: RegistrationEvent) {
    match event {
        RegistrationEvent::Registered { account_id } => {
            println!("\n*** Account {} registered successfully ***", account_id.0);
        }
        RegistrationEvent::Unregistered { account_id } => {
            println!("\n*** Account {} unregistered ***", account_id.0);
        }
        RegistrationEvent::RegistrationFailed { account_id, reason } => {
            println!("\n*** Account {} registration failed: {} ***", account_id.0, reason);
        }
    }
}

async fn handle_transport_event(event: TransportEvent) {
    match event {
        TransportEvent::Connected { transport_key } => {
            println!("\n*** Transport connected: {} on {} ***", 
                transport_key.protocol, transport_key.local_addr);
        }
        TransportEvent::Disconnected { transport_key } => {
            println!("\n*** Transport disconnected: {} on {} ***", 
                transport_key.protocol, transport_key.local_addr);
        }
        TransportEvent::Error { transport_key, error } => {
            println!("\n*** Transport error on {} {}: {} ***", 
                transport_key.protocol, transport_key.local_addr, error);
        }
    }
}

async fn handle_media_event(event: MediaEvent) {
    match event {
        MediaEvent::MediaStarted { call_id } => {
            println!("\n*** Media started for call {} ***", call_id.0);
        }
        MediaEvent::MediaStopped { call_id } => {
            println!("\n*** Media stopped for call {} ***", call_id.0);
        }
        MediaEvent::MediaError { call_id, error } => {
            println!("\n*** Media error for call {}: {} ***", call_id.0, error);
        }
    }
}

// Helper to store current call
use tokio::sync::Mutex;
use once_cell::sync::Lazy;

static CURRENT_CALL: Lazy<Mutex<Option<Arc<Call>>>> = Lazy::new(|| Mutex::new(None));

async fn get_current_call() -> Option<Arc<Call>> {
    CURRENT_CALL.lock().await.clone()
}

// Create a simple SDP offer
fn create_sdp_offer() -> Session {
    SdpBuilder::new()
        .origin("rustsip", "192.168.1.100")
        .connection("192.168.1.100")
        .add_audio_media(5004, vec![
            RtpCodec::pcmu(),
            RtpCodec::pcma(),
            RtpCodec::telephone_event(),
        ])
        .build()
}

// --- Cargo.toml for the example ---
/*
[package]
name = "rustsip"
version = "1.0.0"
edition = "2021"

[dependencies]
tokio = { version = "1", features = ["full"] }
once_cell = "1"
trait-variant = "0.1"

[[example]]
name = "simple_client"
path = "examples/simple_client.rs"

[lib]
name = "rustsip"
path = "src/lib.rs"
*/