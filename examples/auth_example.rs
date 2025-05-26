// examples/auth_registration.rs - Example showing full authentication and registration


use std::{collections::HashMap, sync::Arc};
use rs_sip::{auth::{create_authorization_header, generate_digest_response, AuthContext, AuthenticationManager, DigestChallenge}, AccountConfig, Endpoint, Event, EventHandler, Logger, RegistrationEvent, SipError, SipMessageBuilder, SipMethod, SipUri};
use tokio::time::{Duration, sleep};
use rs_sip::auth::parse_digest_challenge;
pub type Result<T> = std::result::Result<T, SipError>;
#[tokio::main]
async fn main() -> Result<()> {
    println!("RustSIP Authentication & Registration Example");
    println!("===========================================\n");

    // Initialize the library
    rs_sip::init()?;

    // Create endpoint with custom configuration
    let endpoint = Endpoint::builder()
        .user_agent("RustSIP-Auth/1.0")
        .udp_port(5061)
        .max_calls(10)
        .logger(Arc::new(DetailedLogger))
        .build()
        .await?;

    // Add event handler to monitor registration
    endpoint
        .add_event_handler(Box::new(RegistrationMonitor))
        .await;

    // Start the endpoint
    endpoint.start().await?;
    println!("✓ Endpoint started successfully\n");

    // Example 1: Register with a SIP server (e.g., Asterisk)
    register_with_asterisk(&endpoint).await?;

    // Example 2: Register with authentication required server
   // register_with_auth(&endpoint).await?;

    // Example 3: Handle registration expiry and refresh
   // test_registration_refresh(&endpoint).await?;

    // Keep running for a while to see registration refreshes
    println!("\nMonitoring registrations for 2 minutes...");
    sleep(Duration::from_secs(120)).await;

    // Cleanup
    endpoint.stop().await?;
    println!("\n✓ Endpoint stopped");

    Ok(())
}

// Example 1: Basic registration with Asterisk
async fn register_with_asterisk(endpoint: &Arc<Endpoint>) -> Result<()> {
    println!("Example 1: Registering with Asterisk server");
    println!("------------------------------------------");

    let account_config = AccountConfig {
        display_name: "Alice Smith".to_string(),
        username: "1000".to_string(),
        domain: "localhost".to_string(),
        password: Some("1000".to_string()),
        proxy: None,
        registrar: Some("sip:localhost".to_string()),
        expire_seconds: 3600,
        register_on_add: true, // Auto-register when account is added
    };

    let account = endpoint.create_account(account_config).await?;
    println!("✓ Account created: {}", account.id.0);

    // Wait for registration to complete
    sleep(Duration::from_secs(2)).await;

    // Check registration status
    if account.is_registered().await {
        println!("✓ Successfully registered!");

        if let Some(expiry) = account.get_registration_expiry().await {
            println!("  Registration expires in: {} seconds", expiry.as_secs());
        }
    } else {
        println!("✗ Registration failed or pending");
    }

    Ok(())
}

// Example 2: Registration with digest authentication
async fn register_with_auth(endpoint: &Arc<Endpoint>) -> Result<()> {
    println!("\nExample 2: Registration with authentication");
    println!("------------------------------------------");

    let account_config = AccountConfig {
        display_name: "Bob Jones".to_string(),
        username: "bob".to_string(),
        domain: "pbx.example.com".to_string(),
        password: Some("secret123".to_string()),
        proxy: None,
        registrar: Some("sip:pbx.example.com:5060".to_string()),
        expire_seconds: 1800,   // 30 minutes
        register_on_add: false, // Manual registration
    };

    let account = endpoint.create_account(account_config).await?;
    println!("✓ Account created: {}", account.id.0);

    // Manually trigger registration
    println!("→ Initiating registration...");
    account.register().await?;

    // Wait for authentication to complete
    sleep(Duration::from_secs(3)).await;

    // Check status
    if account.is_registered().await {
        println!("✓ Successfully authenticated and registered!");
    } else {
        println!("✗ Authentication/registration failed");
    }

    Ok(())
}

// Example 3: Test registration refresh
async fn test_registration_refresh(endpoint: &Arc<Endpoint>) -> Result<()> {
    println!("\nExample 3: Testing registration refresh");
    println!("--------------------------------------");

    let account_config = AccountConfig {
        display_name: "Charlie Test".to_string(),
        username: "charlie".to_string(),
        domain: "test.example.com".to_string(),
        password: Some("test456".to_string()),
        proxy: None,
        registrar: Some("sip:test.example.com".to_string()),
        expire_seconds: 120, // Short expiry for testing
        register_on_add: true,
    };

    let account = endpoint.create_account(account_config).await?;
    println!("✓ Account created with 120 second expiry: {}", account.id.0);

    // The account will automatically refresh before expiry (at ~90 seconds)
    println!("→ Registration will auto-refresh at ~90 seconds");

    Ok(())
}

// Detailed logger for debugging
struct DetailedLogger;

impl Logger for DetailedLogger {
    fn debug(&self, message: &str) {
        eprintln!(
            "[DEBUG] {}: {}",
            chrono::Local::now().format("%H:%M:%S%.3f"),
            message
        );
    }

    fn info(&self, message: &str) {
        eprintln!(
            "[INFO]  {}: {}",
            chrono::Local::now().format("%H:%M:%S"),
            message
        );
    }

    fn warn(&self, message: &str) {
        eprintln!(
            "[WARN]  {}: {}",
            chrono::Local::now().format("%H:%M:%S"),
            message
        );
    }

    fn error(&self, message: &str) {
        eprintln!(
            "[ERROR] {}: {}",
            chrono::Local::now().format("%H:%M:%S"),
            message
        );
    }
}

// Registration event monitor
struct RegistrationMonitor;

impl EventHandler for RegistrationMonitor {
    fn on_event<'a>(
        &'a self,
        event: Event,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            if let Event::Registration(reg_event) = event {
                let timestamp = chrono::Local::now().format("%H:%M:%S");
                match reg_event {
                    RegistrationEvent::Registered { account_id } => {
                        println!("\n[{}] ✓ REGISTERED: {}", timestamp, account_id.0);
                    }
                    RegistrationEvent::Unregistered { account_id } => {
                        println!("\n[{}] ✓ UNREGISTERED: {}", timestamp, account_id.0);
                    }
                    RegistrationEvent::RegistrationFailed { account_id, reason } => {
                        println!(
                            "\n[{}] ✗ REGISTRATION FAILED: {} - {}",
                            timestamp, account_id.0, reason
                        );
                    }
                }
            }
        })
    }
}

// Demonstration of manual authentication handling
async fn demonstrate_auth_parsing() -> Result<()> {
    println!("\nAuthentication Parsing Demo");
    println!("---------------------------");

    // Example WWW-Authenticate header from server
    let challenge_header =
        r#"Digest realm="asterisk", nonce="414e534f4e3a3132333435", algorithm=MD5, qop="auth""#;

    // Parse the challenge
    let challenge = parse_digest_challenge(challenge_header)?;
    println!("Parsed challenge:");
    println!("  Realm: {}", challenge.realm);
    println!("  Nonce: {}", challenge.nonce);
    println!("  Algorithm: {}", challenge.algorithm);
    println!("  QoP: {:?}", challenge.qop);

    // Create auth context
    let mut auth_ctx = AuthContext::new("alice".to_string(), "secret".to_string());
    auth_ctx.update_from_challenge(&challenge);

    // Generate response
    let creds = generate_digest_response(&auth_ctx, "REGISTER", "sip:asterisk.example.com", None);

    println!("\nGenerated credentials:");
    println!("  Username: {}", creds.username);
    println!("  Response: {}", creds.response);
    println!("  QoP: {:?}", creds.qop);
    println!("  NC: {:?}", creds.nc);
    println!("  CNonce: {:?}", creds.cnonce);

    // Create Authorization header
    let auth_header = create_authorization_header(&creds);
    println!("\nAuthorization header:");
    println!("  {}", auth_header);

    Ok(())
}

// Test authentication manager
async fn test_auth_manager() -> Result<()> {
    println!("\nAuthentication Manager Test");
    println!("--------------------------");

    let auth_manager = AuthenticationManager::new();

    // Add credentials for multiple realms
    auth_manager.add_credentials("asterisk", "alice".to_string(), "alice123".to_string());
    auth_manager.add_credentials("pbx", "bob".to_string(), "secret".to_string());

    // Simulate handling a 401 response
    let mut request = SipMessageBuilder::new()
        .request(SipMethod::Register, SipUri::parse("sip:example.com")?)
        .header("From", "<sip:alice@example.com>")
        .header("To", "<sip:alice@example.com>")
        .header("Call-ID", "test123")
        .header("CSeq", "1 REGISTER")
        .build()?;

    let challenge = r#"Digest realm="asterisk", nonce="123456", algorithm=MD5, qop="auth""#;

    // Handle the challenge
    auth_manager.handle_challenge(&mut request, challenge)?;

    // Check that Authorization header was added
    if request.headers.contains("authorization") {
        println!("✓ Authorization header added successfully");
        if let Some(auth) = request.headers.get("authorization") {
            println!("  {}", auth);
        }
    }

    Ok(())
}

// --- Additional test scenarios ---

// Test stale nonce handling
async fn test_stale_nonce() -> Result<()> {
    println!("\nStale Nonce Test");
    println!("----------------");

    let mut auth_ctx = AuthContext::new("test".to_string(), "password".to_string());

    // First challenge
    let challenge1 = DigestChallenge {
        realm: "test".to_string(),
        domain: None,
        nonce: "nonce1".to_string(),
        opaque: None,
        stale: false,
        algorithm: "MD5".to_string(),
        qop: Some(vec!["auth".to_string()]),
        auth_param: HashMap::new(),
    };

    auth_ctx.update_from_challenge(&challenge1);
    println!("Initial nonce: {}, nc: {}", auth_ctx.nonce, auth_ctx.nc);

    // Simulate some requests
    auth_ctx.increment_nc();
    auth_ctx.increment_nc();
    println!("After 2 requests, nc: {}", auth_ctx.nc);

    // Stale nonce challenge (same nonce but marked stale)
    let challenge2 = DigestChallenge {
        realm: "test".to_string(),
        domain: None,
        nonce: "nonce1".to_string(),
        opaque: None,
        stale: true,
        algorithm: "MD5".to_string(),
        qop: Some(vec!["auth".to_string()]),
        auth_param: HashMap::new(),
    };

    auth_ctx.update_from_challenge(&challenge2);
    println!("After stale challenge, nc should continue: {}", auth_ctx.nc);

    // New nonce challenge
    let challenge3 = DigestChallenge {
        realm: "test".to_string(),
        domain: None,
        nonce: "nonce2".to_string(),
        opaque: None,
        stale: false,
        algorithm: "MD5".to_string(),
        qop: Some(vec!["auth".to_string()]),
        auth_param: HashMap::new(),
    };

    auth_ctx.update_from_challenge(&challenge3);
    println!("After new nonce, nc should reset: {}", auth_ctx.nc);

    Ok(())
}

// Test auth-int qop
async fn test_auth_int() -> Result<()> {
    println!("\nAuth-Int QoP Test");
    println!("-----------------");

    let mut auth_ctx = AuthContext::new("alice".to_string(), "secret".to_string());
    auth_ctx.realm = "test".to_string();
    auth_ctx.nonce = "abc123".to_string();
    auth_ctx.qop = Some("auth-int".to_string());
    auth_ctx.cnonce = Some("xyz789".to_string());

    // Test with message body
    let body = b"v=0\r\no=- 0 0 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n";

    let creds = generate_digest_response(&auth_ctx, "INVITE", "sip:bob@example.com", Some(body));

    println!("Generated auth-int response:");
    println!("  QoP: {:?}", creds.qop);
    println!("  Response: {}", creds.response);

    Ok(())
}

// Test MD5-sess algorithm
async fn test_md5_sess() -> Result<()> {
    println!("\nMD5-sess Algorithm Test");
    println!("----------------------");

    let mut auth_ctx = AuthContext::new("alice".to_string(), "secret".to_string());
    auth_ctx.realm = "test".to_string();
    auth_ctx.nonce = "nonce123".to_string();
    auth_ctx.algorithm = "MD5-sess".to_string();
    auth_ctx.qop = Some("auth".to_string());
    auth_ctx.cnonce = Some("cnonce456".to_string());

    let creds = generate_digest_response(&auth_ctx, "REGISTER", "sip:example.com", None);

    println!("Generated MD5-sess response:");
    println!("  Algorithm: {}", creds.algorithm);
    println!("  Response: {}", creds.response);

    Ok(())
}
