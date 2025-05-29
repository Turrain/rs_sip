// Core error types
use std::error::Error;
use std::fmt;
use std::net::SocketAddr;
use std::collections::HashMap;
use std::sync::Arc;

use crate::SipMessage;

#[derive(Debug, Clone)]
pub enum SipError {
    ParseError(String),
    TransportError(String),
    InvalidUri(String),
    InvalidHeader(String),
    TransactionTimeout,
    DialogNotFound,
    AccountNotFound,
    MediaError(String),
    AuthenticationFailed,
    RegistrationFailed(String),
    CallFailed(String),
    InvalidState(String),
    IoError(String),
}

impl fmt::Display for SipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SipError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            SipError::TransportError(msg) => write!(f, "Transport error: {}", msg),
            SipError::InvalidUri(msg) => write!(f, "Invalid URI: {}", msg),
            SipError::InvalidHeader(msg) => write!(f, "Invalid header: {}", msg),
            SipError::TransactionTimeout => write!(f, "Transaction timeout"),
            SipError::DialogNotFound => write!(f, "Dialog not found"),
            SipError::AccountNotFound => write!(f, "Account not found"),
            SipError::MediaError(msg) => write!(f, "Media error: {}", msg),
            SipError::AuthenticationFailed => write!(f, "Authentication failed"),
            SipError::RegistrationFailed(msg) => write!(f, "Registration failed: {}", msg),
            SipError::CallFailed(msg) => write!(f, "Call failed: {}", msg),
            SipError::InvalidState(msg) => write!(f, "Invalid state: {}", msg),
            SipError::IoError(msg) => write!(f, "IO error: {}", msg),
        }
    }
}

impl Error for SipError {}

pub type Result<T> = std::result::Result<T, SipError>;

// SIP URI implementation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SipUri {
    pub scheme: String,
    pub user: Option<String>,
    pub password: Option<String>,
    pub host: String,
    pub port: Option<u16>,
    pub parameters: HashMap<String, Option<String>>,
    pub headers: HashMap<String, String>,
}

impl SipUri {
    pub fn new(host: String) -> Self {
        SipUri {
            scheme: "sip".to_string(),
            user: None,
            password: None,
            host,
            port: None,
            parameters: HashMap::new(),
            headers: HashMap::new(),
        }
    }

    pub fn parse(uri: &str) -> Result<Self> {
        let uri = uri.trim();
        
        // Basic parsing - full implementation would be more robust
        let scheme_end = uri.find(':').ok_or_else(|| SipError::InvalidUri("No scheme found".to_string()))?;
        let scheme = uri[..scheme_end].to_lowercase();
        
        if scheme != "sip" && scheme != "sips" {
            return Err(SipError::InvalidUri(format!("Invalid scheme: {}", scheme)));
        }

        let rest = &uri[scheme_end + 1..];
        let rest = rest.trim_start_matches("//");
        
        // Parse user info
        let (user_info, host_part) = if let Some(at_pos) = rest.find('@') {
            let user_part = &rest[..at_pos];
            let (user, password) = if let Some(colon_pos) = user_part.find(':') {
                (Some(user_part[..colon_pos].to_string()), Some(user_part[colon_pos + 1..].to_string()))
            } else {
                (Some(user_part.to_string()), None)
            };
            ((user, password), &rest[at_pos + 1..])
        } else {
            ((None, None), rest)
        };

        // Parse host and port
        let (host, port) = if host_part.starts_with('[') {
            // IPv6 address
            let end = host_part.find(']').ok_or_else(|| SipError::InvalidUri("Invalid IPv6 address".to_string()))?;
            let host = host_part[1..end].to_string();
            let port = if host_part.len() > end + 2 && &host_part[end + 1..end + 2] == ":" {
                host_part[end + 2..].parse().ok()
            } else {
                None
            };
            (host, port)
        } else {
            // IPv4 or hostname
            let parts: Vec<&str> = host_part.splitn(2, ':').collect();
            let host = parts[0].to_string();
            let port = if parts.len() > 1 {
                parts[1].parse().ok()
            } else {
                None
            };
            (host, port)
        };

        Ok(SipUri {
            scheme,
            user: user_info.0,
            password: user_info.1,
            host,
            port,
            parameters: HashMap::new(),
            headers: HashMap::new(),
        })
    }

    pub fn to_string(&self) -> String {
        let mut result = format!("{}:", self.scheme);
        
        if let Some(ref user) = self.user {
            result.push_str(user);
            if let Some(ref password) = self.password {
                result.push(':');
                result.push_str(password);
            }
            result.push('@');
        }
        
        if self.host.contains(':') {
            result.push('[');
            result.push_str(&self.host);
            result.push(']');
        } else {
            result.push_str(&self.host);
        }
        
        if let Some(port) = self.port {
            result.push(':');
            result.push_str(&port.to_string());
        }
        
        for (key, value) in &self.parameters {
            result.push(';');
            result.push_str(key);
            if let Some(val) = value {
                result.push('=');
                result.push_str(val);
            }
        }
        
        if !self.headers.is_empty() {
            result.push('?');
            let headers: Vec<String> = self.headers.iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect();
            result.push_str(&headers.join("&"));
        }
        
        result
    }
}

impl fmt::Display for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

// Common SIP types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SipMethod {
    Invite,
    Ack,
    Bye,
    Cancel,
    Options,
    Register,
    Prack,
    Subscribe,
    Notify,
    Publish,
    Info,
    Refer,
    Message,
    Update,
}

impl SipMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            SipMethod::Invite => "INVITE",
            SipMethod::Ack => "ACK",
            SipMethod::Bye => "BYE",
            SipMethod::Cancel => "CANCEL",
            SipMethod::Options => "OPTIONS",
            SipMethod::Register => "REGISTER",
            SipMethod::Prack => "PRACK",
            SipMethod::Subscribe => "SUBSCRIBE",
            SipMethod::Notify => "NOTIFY",
            SipMethod::Publish => "PUBLISH",
            SipMethod::Info => "INFO",
            SipMethod::Refer => "REFER",
            SipMethod::Message => "MESSAGE",
            SipMethod::Update => "UPDATE",
        }
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "INVITE" => Ok(SipMethod::Invite),
            "ACK" => Ok(SipMethod::Ack),
            "BYE" => Ok(SipMethod::Bye),
            "CANCEL" => Ok(SipMethod::Cancel),
            "OPTIONS" => Ok(SipMethod::Options),
            "REGISTER" => Ok(SipMethod::Register),
            "PRACK" => Ok(SipMethod::Prack),
            "SUBSCRIBE" => Ok(SipMethod::Subscribe),
            "NOTIFY" => Ok(SipMethod::Notify),
            "PUBLISH" => Ok(SipMethod::Publish),
            "INFO" => Ok(SipMethod::Info),
            "REFER" => Ok(SipMethod::Refer),
            "MESSAGE" => Ok(SipMethod::Message),
            "UPDATE" => Ok(SipMethod::Update),
            _ => Err(SipError::ParseError(format!("Unknown method: {}", s))),
        }
    }
}

// Header name type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HeaderName(pub String);

impl HeaderName {
    pub fn new(name: &str) -> Self {
        HeaderName(name.to_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// Common header names
impl HeaderName {
    pub const VIA: &'static str = "via";
    pub const FROM: &'static str = "from";
    pub const TO: &'static str = "to";
    pub const CALL_ID: &'static str = "call-id";
    pub const CSEQ: &'static str = "cseq";
    pub const CONTACT: &'static str = "contact";
    pub const MAX_FORWARDS: &'static str = "max-forwards";
    pub const CONTENT_TYPE: &'static str = "content-type";
    pub const CONTENT_LENGTH: &'static str = "content-length";
    pub const AUTHORIZATION: &'static str = "authorization";
    pub const WWW_AUTHENTICATE: &'static str = "www-authenticate";
    pub const PROXY_AUTHENTICATE: &'static str = "proxy-authenticate";
    pub const PROXY_AUTHORIZATION: &'static str = "proxy-authorization";
    pub const EXPIRES: &'static str = "expires";
    pub const ALLOW: &'static str = "allow";
    pub const SUPPORTED: &'static str = "supported";
    pub const REQUIRE: &'static str = "require";
    pub const PROXY_REQUIRE: &'static str = "proxy-require";
    pub const UNSUPPORTED: &'static str = "unsupported";
    pub const USER_AGENT: &'static str = "user-agent";
    pub const SERVER: &'static str = "server";
    pub const SUBJECT: &'static str = "subject";
    pub const REASON: &'static str = "reason";
    pub const WARNING: &'static str = "warning";
    pub const PRIORITY: &'static str = "priority";
    pub const ROUTE: &'static str = "route";
    pub const RECORD_ROUTE: &'static str = "record-route";
    pub const ACCEPT: &'static str = "accept";
    pub const ACCEPT_ENCODING: &'static str = "accept-encoding";
    pub const ACCEPT_LANGUAGE: &'static str = "accept-language";
    pub const ALERT_INFO: &'static str = "alert-info";
    pub const ALLOW_EVENTS: &'static str = "allow-events";
    pub const AUTHENTICATION_INFO: &'static str = "authentication-info";
    pub const ERROR_INFO: &'static str = "error-info";
    pub const EVENT: &'static str = "event";
    pub const IN_REPLY_TO: &'static str = "in-reply-to";
    pub const MIN_EXPIRES: &'static str = "min-expires";
    pub const MIME_VERSION: &'static str = "mime-version";
    pub const ORGANIZATION: &'static str = "organization";
    pub const RACK: &'static str = "rack";
    pub const REFER_TO: &'static str = "refer-to";
    pub const REFERRED_BY: &'static str = "referred-by";
    pub const REPLACES: &'static str = "replaces";
    pub const REPLY_TO: &'static str = "reply-to";
    pub const RETRY_AFTER: &'static str = "retry-after";
    pub const RSEQ: &'static str = "rseq";
    pub const SESSION_EXPIRES: &'static str = "session-expires";
    pub const SUBSCRIPTION_STATE: &'static str = "subscription-state";
    pub const TIMESTAMP: &'static str = "timestamp";
}

// Via header parameters
#[derive(Debug, Clone)]
pub struct ViaHeader {
    pub protocol: String,
    pub version: String,
    pub transport: String,
    pub host: String,
    pub port: Option<u16>,
    pub branch: String,
    pub rport: Option<u16>,
    pub received: Option<String>,
    pub maddr: Option<String>,
    pub ttl: Option<u8>,
}

impl ViaHeader {
    pub fn new(transport: &str, host: &str, branch: &str) -> Self {
        ViaHeader {
            protocol: "SIP".to_string(),
            version: "2.0".to_string(),
            transport: transport.to_uppercase(),
            host: host.to_string(),
            port: None,
            branch: branch.to_string(),
            rport: None,
            received: None,
            maddr: None,
            ttl: None,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() < 2 {
            return Err(SipError::InvalidHeader("Invalid Via header".to_string()));
        }

        let protocol_parts: Vec<&str> = parts[0].split('/').collect();
        if protocol_parts.len() != 3 {
            return Err(SipError::InvalidHeader("Invalid Via protocol".to_string()));
        }

        let mut via = ViaHeader {
            protocol: protocol_parts[0].to_string(),
            version: protocol_parts[1].to_string(),
            transport: protocol_parts[2].to_string(),
            host: String::new(),
            port: None,
            branch: String::new(),
            rport: None,
            received: None,
            maddr: None,
            ttl: None,
        };

        // Parse host:port
        let host_part = parts[1];
        let (host, port) = if let Some(colon_pos) = host_part.rfind(':') {
            let host = host_part[..colon_pos].to_string();
            let port = host_part[colon_pos + 1..].parse().ok();
            (host, port)
        } else {
            (host_part.to_string(), None)
        };

        via.host = host;
        via.port = port;

        // Parse parameters
        for part in &parts[2..] {
            if let Some(eq_pos) = part.find('=') {
                let key = &part[..eq_pos];
                let value = &part[eq_pos + 1..];
                match key {
                    "branch" => via.branch = value.to_string(),
                    "rport" => via.rport = value.parse().ok(),
                    "received" => via.received = Some(value.to_string()),
                    "maddr" => via.maddr = Some(value.to_string()),
                    "ttl" => via.ttl = value.parse().ok(),
                    _ => {}
                }
            } else if part == &"rport" {
                via.rport = Some(0); // rport without value
            }
        }

        Ok(via)
    }

    pub fn to_string(&self) -> String {
        let mut result = format!("{}/{}/{} {}",
            self.protocol, self.version, self.transport, self.host);
        
        if let Some(port) = self.port {
            result.push(':');
            result.push_str(&port.to_string());
        }

        if !self.branch.is_empty() {
            result.push_str(&format!(";branch={}", self.branch));
        }

        if let Some(rport) = self.rport {
            if rport == 0 {
                result.push_str(";rport");
            } else {
                result.push_str(&format!(";rport={}", rport));
            }
        }

        if let Some(ref received) = self.received {
            result.push_str(&format!(";received={}", received));
        }

        if let Some(ref maddr) = self.maddr {
            result.push_str(&format!(";maddr={}", maddr));
        }

        if let Some(ttl) = self.ttl {
            result.push_str(&format!(";ttl={}", ttl));
        }

        result
    }
}

// CSeq header
#[derive(Debug, Clone)]
pub struct CSeqHeader {
    pub sequence: u32,
    pub method: SipMethod,
}

impl CSeqHeader {
    pub fn new(sequence: u32, method: SipMethod) -> Self {
        CSeqHeader { sequence, method }
    }

    pub fn parse(value: &str) -> Result<Self> {
        let parts: Vec<&str> = value.split_whitespace().collect();
        if parts.len() != 2 {
            return Err(SipError::InvalidHeader("Invalid CSeq header".to_string()));
        }

        let sequence = parts[0].parse()
            .map_err(|_| SipError::InvalidHeader("Invalid CSeq number".to_string()))?;
        let method = SipMethod::from_str(parts[1])?;

        Ok(CSeqHeader { sequence, method })
    }

    pub fn to_string(&self) -> String {
        format!("{} {}", self.sequence, self.method.as_str())
    }
}

// Contact header
#[derive(Debug, Clone)]
pub struct ContactHeader {
    pub display_name: Option<String>,
    pub uri: SipUri,
    pub expires: Option<u32>,
    pub q: Option<f32>,
}

impl ContactHeader {
    pub fn new(uri: SipUri) -> Self {
        ContactHeader {
            display_name: None,
            uri,
            expires: None,
            q: None,
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        
        // Simple parsing - full implementation would handle quoted strings, etc.
        let (display_name, uri_part) = if value.starts_with('"') {
            let end_quote = value[1..].find('"').ok_or_else(|| 
                SipError::InvalidHeader("Unclosed quoted string".to_string()))?;
            let display = value[1..end_quote + 1].to_string();
            let rest = value[end_quote + 2..].trim();
            (Some(display), rest)
        } else if let Some(lt_pos) = value.find('<') {
            if lt_pos > 0 {
                let display = value[..lt_pos].trim().to_string();
                (Some(display), &value[lt_pos..])
            } else {
                (None, value)
            }
        } else {
            (None, value)
        };

        let uri_str = if uri_part.starts_with('<') && uri_part.ends_with('>') {
            &uri_part[1..uri_part.len() - 1]
        } else {
            uri_part
        };

        let uri = SipUri::parse(uri_str)?;

        Ok(ContactHeader {
            display_name,
            uri,
            expires: None,
            q: None,
        })
    }

    pub fn to_string(&self) -> String {
        let mut result = String::new();
        
        if let Some(ref name) = self.display_name {
            result.push('"');
            result.push_str(name);
            result.push_str("\" ");
        }
        
        result.push('<');
        result.push_str(&self.uri.to_string());
        result.push('>');
        
        if let Some(expires) = self.expires {
            result.push_str(&format!(";expires={}", expires));
        }
        
        if let Some(q) = self.q {
            result.push_str(&format!(";q={:.1}", q));
        }
        
        result
    }
}

// Generate a random branch parameter
pub fn generate_branch() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    // RFC 3261 requires z9hG4bK prefix + unique suffix
    format!("z9hG4bK{:x}{:x}", now.as_secs(), now.subsec_nanos())
}
// Generate a random Call-ID
pub fn generate_call_id(host: &str) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}{:x}@{}", now.as_secs(), now.subsec_nanos(), host)
}

// Generate a random tag
pub fn generate_tag() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:x}{:x}", now.as_secs(), now.subsec_nanos())
}

// Authentication types
#[derive(Debug, Clone)]
pub struct DigestCredentials {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: Option<String>,
    pub opaque: Option<String>,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub cnonce: Option<String>,
}

// Media types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    Audio,
    Video,
    Application,
    Text,
    Message,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaDirection {
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

// Transport key for identifying transports
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransportKey {
    pub protocol: String,
    pub local_addr: SocketAddr,
}

// Account ID type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountId(pub String);

// Call ID type  
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CallId(pub String);

// Dialog ID type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DialogId {
    pub call_id: String,
    pub local_tag: String,
    pub remote_tag: String,
}

// Transaction ID type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TransactionId(pub String);

impl TransactionId {
    pub fn from_message(method: &SipMethod, branch: &str) -> Self {
        // For RFC 3261 compliance, use branch as primary identifier
        if branch.starts_with("z9hG4bK") {
            TransactionId(format!("{}:{}", method.as_str(), branch))
        } else {
            // RFC 2543 compatibility - use method+branch
            TransactionId(format!("{}:{}", method.as_str(), branch))
        }
    }
    
    // New method for matching responses
    pub fn from_response(response: &SipMessage) -> Option<Self> {
        let via = response.get_via()?;
        let cseq = response.get_cseq()?;
        Some(TransactionId::from_message(&cseq.method, &via.branch))
    }
}

// Media port ID type
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MediaPortId(pub String);

// Session description
#[derive(Debug, Clone)]
pub struct Session {
    pub version: u32,
    pub origin: SessionOrigin,
    pub name: String,
    pub connection: Option<ConnectionData>,
    pub timing: Vec<TimingInfo>,
    pub media: Vec<MediaDescription>,
    pub attributes: HashMap<String, Option<String>>,
}

#[derive(Debug, Clone)]
pub struct SessionOrigin {
    pub username: String,
    pub session_id: String,
    pub session_version: String,
    pub network_type: String,
    pub address_type: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct ConnectionData {
    pub network_type: String,
    pub address_type: String,
    pub address: String,
}

#[derive(Debug, Clone)]
pub struct TimingInfo {
    pub start: u64,
    pub stop: u64,
}

#[derive(Debug, Clone)]
pub struct MediaDescription {
    pub media_type: MediaType,
    pub port: u16,
    pub port_count: Option<u16>,
    pub protocol: String,
    pub formats: Vec<String>,
    pub connection: Option<ConnectionData>,
    pub attributes: HashMap<String, Option<String>>,
    pub direction: MediaDirection,
}

// Logging abstraction
pub trait Logger: Send + Sync {
    fn debug(&self, message: &str);
    fn info(&self, message: &str);
    fn warn(&self, message: &str);
    fn error(&self, message: &str);
}

// Simple console logger
pub struct ConsoleLogger;

impl Logger for ConsoleLogger {
    fn debug(&self, message: &str) {
        eprintln!("[DEBUG] {}", message);
    }

    fn info(&self, message: &str) {
        eprintln!("[INFO] {}", message);
    }

    fn warn(&self, message: &str) {
        eprintln!("[WARN] {}", message);
    }

    fn error(&self, message: &str) {
        eprintln!("[ERROR] {}", message);
    }
}

// Configuration types
#[derive(Debug, Clone)]
pub struct EndpointConfig {
    pub user_agent: String,
    pub max_calls: usize,
    pub max_accounts: usize,
    pub nat_enabled: bool,
    pub stun_servers: Vec<String>,
    pub dns_servers: Vec<String>,
    pub media_config: MediaConfig,
    pub transport_config: TransportConfig,
}

impl Default for EndpointConfig {
    fn default() -> Self {
        EndpointConfig {
            user_agent: "RustSIP/1.0".to_string(),
            max_calls: 100,
            max_accounts: 10,
            nat_enabled: false,
            stun_servers: vec![],
            dns_servers: vec![],
            media_config: MediaConfig::default(),
            transport_config: TransportConfig::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MediaConfig {
    pub port_range: (u16, u16),
    pub enable_srtp: bool,
    pub codecs: Vec<String>,
    pub jitter_buffer_size: usize,
    pub echo_cancellation: bool,
}

impl Default for MediaConfig {
    fn default() -> Self {
        MediaConfig {
            port_range: (10000, 20000),
            enable_srtp: false,
            codecs: vec!["PCMU/8000".to_string(), "PCMA/8000".to_string()],
            jitter_buffer_size: 100,
            echo_cancellation: true,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TransportConfig {
    pub enable_tcp: bool,
    pub enable_tls: bool,
    pub udp_port: u16,
    pub tcp_port: u16,
    pub tls_port: u16,
}

impl Default for TransportConfig {
    fn default() -> Self {
        TransportConfig {
            enable_tcp: false,
            enable_tls: false,
            udp_port: 5060,
            tcp_port: 5060,
            tls_port: 5061,
        }
    }
}

#[derive(Debug, Clone)]
pub struct AccountConfig {
    pub display_name: String,
    pub username: String,
    pub domain: String,
    pub password: Option<String>,
    pub proxy: Option<String>,
    pub registrar: Option<String>,
    pub expire_seconds: u32,
    pub register_on_add: bool,
}

// Event types
#[derive(Debug, Clone)]
pub enum Event {
    Call(CallEvent),
    Registration(RegistrationEvent),
    Transport(TransportEvent),
    Media(MediaEvent),
}

#[derive(Debug, Clone)]
pub enum CallEvent {
    IncomingCall { call_id: CallId, from: SipUri },
    CallStateChanged { call_id: CallId, state: CallState },
    MediaStateChanged { call_id: CallId, state: MediaState },
    CallFailed { call_id: CallId, reason: String },
}

#[derive(Debug, Clone)]
pub enum RegistrationEvent {
    Registered { account_id: AccountId },
    Unregistered { account_id: AccountId },
    RegistrationFailed { account_id: AccountId, reason: String },
}

#[derive(Debug, Clone)]
pub enum TransportEvent {
    Connected { transport_key: TransportKey },
    Disconnected { transport_key: TransportKey },
    Error { transport_key: TransportKey, error: String },
}

#[derive(Debug, Clone)]
pub enum MediaEvent {
    MediaStarted { call_id: CallId },
    MediaStopped { call_id: CallId },
    MediaError { call_id: CallId, error: String },
}

// Call states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallState {
    Null,
    Calling,
    Incoming,
    EarlyMedia,
    Connecting,
    Confirmed,
    Disconnecting,
    Disconnected,
}

// Media states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MediaState {
    None,
    Active,
    LocalHold,
    RemoteHold,
    Error,
}

// Account states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccountState {
    Offline,
    Registering,
    Registered,
    Unregistering,
    Error,
}

// Registration states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistrationState {
    None,
    Sent,
    Success,
    Failed,
    Timeout,
}

// Timer types for state machines
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerType {
    T1,  // RTT estimate (500ms default)
    T2,  // Maximum retransmit interval for non-INVITE (4s)
    T4,  // Maximum duration for message to stay in network (5s)
    TimerA,  // INVITE request retransmit
    TimerB,  // INVITE transaction timeout
    TimerC,  // Proxy INVITE transaction timeout
    TimerD,  // Wait time for response retransmits
    TimerE,  // Non-INVITE request retransmit
    TimerF,  // Non-INVITE transaction timeout
    TimerG,  // INVITE response retransmit
    TimerH,  // Wait time for ACK receipt
    TimerI,  // Wait time for ACK retransmits
    TimerJ,  // Wait time for non-INVITE request retransmits
    TimerK,  // Wait time for response retransmits
}

impl TimerType {
    pub fn duration_ms(&self) -> u64 {
        match self {
            TimerType::T1 => 500,
            TimerType::T2 => 4000,
            TimerType::T4 => 5000,
            TimerType::TimerA => 500,  // T1
            TimerType::TimerB => 32000, // 64*T1
            TimerType::TimerC => 180000, // 3 minutes
            TimerType::TimerD => 32000,
            TimerType::TimerE => 500,  // T1
            TimerType::TimerF => 32000, // 64*T1
            TimerType::TimerG => 500,  // T1
            TimerType::TimerH => 32000, // 64*T1
            TimerType::TimerI => 5000,  // T4
            TimerType::TimerJ => 32000, // 64*T1 for non-INVITE
            TimerType::TimerK => 5000,  // T4
        }
    }
}

// Utility function to compute MD5 response for digest authentication
pub fn compute_digest_response(
    username: &str,
    realm: &str,
    password: &str,
    method: &str,
    uri: &str,
    nonce: &str,
) -> String {
    use std::fmt::Write;
    
    let ha1 = md5_string(&format!("{}:{}:{}", username, realm, password));
    let ha2 = md5_string(&format!("{}:{}", method, uri));
    let response = md5_string(&format!("{}:{}:{}", ha1, nonce, ha2));
    
    response
}

fn md5_string(input: &str) -> String {
    // Simple MD5 implementation - in production use a crypto library
    // This is a placeholder that returns a hash-like string
    let mut hash = 0u64;
    for byte in input.bytes() {
        hash = hash.wrapping_mul(31).wrapping_add(byte as u64);
    }
    format!("{:032x}", hash)
}