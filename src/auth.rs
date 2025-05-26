// auth.rs - Full digest authentication implementation

use crate::{CSeqHeader, HeaderName, Result, SipError, SipMessage, SipMethod};
use std::collections::HashMap;

// Digest authentication components
#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: String,
    pub domain: Option<String>,
    pub nonce: String,
    pub opaque: Option<String>,
    pub stale: bool,
    pub algorithm: String,
    pub qop: Option<Vec<String>>,
    pub auth_param: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct DigestCredentials {
    pub username: String,
    pub realm: String,
    pub nonce: String,
    pub uri: String,
    pub response: String,
    pub algorithm: String,
    pub cnonce: Option<String>,
    pub opaque: Option<String>,
    pub qop: Option<String>,
    pub nc: Option<String>,
    pub auth_param: HashMap<String, String>,
}

// Authentication context for maintaining state
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub username: String,
    pub password: String,
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: String,
    pub qop: Option<String>,
    pub nc: u32,
    pub cnonce: Option<String>,
    pub last_nonce: Option<String>,
}

impl AuthContext {
    pub fn new(username: String, password: String) -> Self {
        AuthContext {
            username,
            password,
            realm: String::new(),
            nonce: String::new(),
            opaque: None,
            algorithm: "MD5".to_string(),
            qop: None,
            nc: 1,
            cnonce: None,
            last_nonce: None,
        }
    }

    pub fn increment_nc(&mut self) {
        self.nc += 1;
    }

    pub fn update_from_challenge(&mut self, challenge: &DigestChallenge) {
        self.realm = challenge.realm.clone();

        // Check if this is a new nonce (not stale)
        if !challenge.stale && self.nonce != challenge.nonce {
            self.nc = 1;
            self.last_nonce = Some(self.nonce.clone());
        }

        self.nonce = challenge.nonce.clone();
        self.opaque = challenge.opaque.clone();
        self.algorithm = challenge.algorithm.clone();

        // Select qop if available
        if let Some(ref qop_options) = challenge.qop {
            // Prefer auth over auth-int
            if qop_options.contains(&"auth".to_string()) {
                self.qop = Some("auth".to_string());
                // Generate cnonce if using qop
                if self.cnonce.is_none() {
                    self.cnonce = Some(generate_cnonce());
                }
            } else if qop_options.contains(&"auth-int".to_string()) {
                self.qop = Some("auth-int".to_string());
                if self.cnonce.is_none() {
                    self.cnonce = Some(generate_cnonce());
                }
            }
        } else {
            self.qop = None;
            self.cnonce = None;
        }
    }
}

// Parse digest challenge from WWW-Authenticate or Proxy-Authenticate header
pub fn parse_digest_challenge(header_value: &str) -> Result<DigestChallenge> {
    // Check if it's a Digest challenge
    if !header_value.trim().starts_with("Digest ") {
        return Err(SipError::InvalidHeader(
            "Not a Digest challenge".to_string(),
        ));
    }

    let params_str = &header_value[7..]; // Skip "Digest "
    let params = parse_auth_params(params_str)?;

    let realm = params
        .get("realm")
        .ok_or_else(|| SipError::InvalidHeader("Missing realm in challenge".to_string()))?
        .clone();

    let nonce = params
        .get("nonce")
        .ok_or_else(|| SipError::InvalidHeader("Missing nonce in challenge".to_string()))?
        .clone();

    let algorithm = params
        .get("algorithm")
        .cloned()
        .unwrap_or_else(|| "MD5".to_string());

    let qop = params
        .get("qop")
        .map(|q| q.split(',').map(|s| s.trim().to_string()).collect());

    let stale = params
        .get("stale")
        .map(|s| s.to_lowercase() == "true")
        .unwrap_or(false);

    Ok(DigestChallenge {
        realm,
        domain: params.get("domain").cloned(),
        nonce,
        opaque: params.get("opaque").cloned(),
        stale,
        algorithm,
        qop,
        auth_param: params,
    })
}

// Parse authentication parameters (key="value" pairs)
fn parse_auth_params(params_str: &str) -> Result<HashMap<String, String>> {
    let mut params = HashMap::new();
    let mut current_key = String::new();
    let mut current_value = String::new();
    let mut in_quotes = false;
    let mut in_key = true;
    let mut escape_next = false;

    for ch in params_str.chars() {
        if escape_next {
            current_value.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if in_quotes => {
                escape_next = true;
            }
            '"' => {
                in_quotes = !in_quotes;
            }
            '=' if !in_quotes && in_key => {
                in_key = false;
            }
            ',' if !in_quotes => {
                // End of parameter
                if !current_key.is_empty() {
                    params.insert(
                        current_key.trim().to_string(),
                        current_value.trim().trim_matches('"').to_string(),
                    );
                }
                current_key.clear();
                current_value.clear();
                in_key = true;
            }
            _ => {
                if in_key {
                    current_key.push(ch);
                } else {
                    current_value.push(ch);
                }
            }
        }
    }

    // Don't forget the last parameter
    if !current_key.is_empty() {
        params.insert(
            current_key.trim().to_string(),
            current_value.trim().trim_matches('"').to_string(),
        );
    }

    Ok(params)
}

// Generate digest response
pub fn generate_digest_response(
    auth_ctx: &AuthContext,
    method: &str,
    uri: &str,
    body: Option<&[u8]>,
) -> DigestCredentials {
    let ha1 = calculate_ha1(
        &auth_ctx.username,
        &auth_ctx.realm,
        &auth_ctx.password,
        &auth_ctx.algorithm,
        &auth_ctx.nonce,
        auth_ctx.cnonce.as_deref(),
    );

    let ha2 = calculate_ha2(
        method,
        uri,
        &auth_ctx.algorithm,
        auth_ctx.qop.as_deref(),
        body,
    );

    let response = if let Some(ref qop) = auth_ctx.qop {
        // RFC 2617 - with qop
        let nc_str = format!("{:08x}", auth_ctx.nc);
        let data = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1,
            auth_ctx.nonce,
            nc_str,
            auth_ctx.cnonce.as_ref().unwrap(),
            qop,
            ha2
        );
        md5_hex(&data)
    } else {
        // RFC 2069 - without qop
        let data = format!("{}:{}:{}", ha1, auth_ctx.nonce, ha2);
        md5_hex(&data)
    };

    DigestCredentials {
        username: auth_ctx.username.clone(),
        realm: auth_ctx.realm.clone(),
        nonce: auth_ctx.nonce.clone(),
        uri: uri.to_string(),
        response,
        algorithm: auth_ctx.algorithm.clone(),
        cnonce: auth_ctx.cnonce.clone(),
        opaque: auth_ctx.opaque.clone(),
        qop: auth_ctx.qop.clone(),
        nc: auth_ctx
            .qop
            .as_ref()
            .map(|_| format!("{:08x}", auth_ctx.nc)),
        auth_param: HashMap::new(),
    }
}

// Calculate H(A1) according to RFC 2617
fn calculate_ha1(
    username: &str,
    realm: &str,
    password: &str,
    algorithm: &str,
    nonce: &str,
    cnonce: Option<&str>,
) -> String {
    let a1 = if algorithm.to_uppercase() == "MD5-SESS" {
        // MD5-sess: H(username:realm:password):nonce:cnonce
        let basic_a1 = format!("{}:{}:{}", username, realm, password);
        let basic_ha1 = md5_hex(&basic_a1);
        format!("{}:{}:{}", basic_ha1, nonce, cnonce.unwrap_or(""))
    } else {
        // MD5: username:realm:password
        format!("{}:{}:{}", username, realm, password)
    };

    md5_hex(&a1)
}

// Calculate H(A2) according to RFC 2617
fn calculate_ha2(
    method: &str,
    uri: &str,
    algorithm: &str,
    qop: Option<&str>,
    body: Option<&[u8]>,
) -> String {
    let a2 = if qop == Some("auth-int") {
        // auth-int includes body
        let body_hash = if let Some(body_data) = body {
            md5_hex(&String::from_utf8_lossy(body_data))
        } else {
            md5_hex("")
        };
        format!("{}:{}:{}", method, uri, body_hash)
    } else {
        // auth or no qop
        format!("{}:{}", method, uri)
    };

    md5_hex(&a2)
}

// MD5 hashing function
fn md5_hex(data: &str) -> String {
    use std::fmt::Write;

    // Using a proper MD5 implementation
    let digest = md5_hash(data.as_bytes());

    let mut hex = String::with_capacity(32);
    for byte in digest {
        write!(&mut hex, "{:02x}", byte).unwrap();
    }
    hex
}

// Proper MD5 implementation
fn md5_hash(data: &[u8]) -> [u8; 16] {
    // MD5 constants
    const S: [u32; 64] = [
        7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5,
        9, 14, 20, 5, 9, 14, 20, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10,
        15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
    ];

    const K: [u32; 64] = [
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613,
        0xfd469501, 0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
        0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d,
        0x02441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
        0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122,
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 0x289b7ec6, 0xeaa127fa,
        0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
        0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb,
        0xeb86d391,
    ];

    // Initialize MD5 state
    let mut a0: u32 = 0x67452301;
    let mut b0: u32 = 0xEFCDAB89;
    let mut c0: u32 = 0x98BADCFE;
    let mut d0: u32 = 0x10325476;

    // Pre-processing: adding a single 1 bit
    let mut msg = data.to_vec();
    msg.push(0x80);

    // Pre-processing: padding with zeros
    while (msg.len() % 64) != 56 {
        msg.push(0x00);
    }

    // Append original length in bits as 64-bit little-endian
    let bit_len = (data.len() as u64) * 8;
    msg.extend_from_slice(&bit_len.to_le_bytes());

    // Process the message in successive 512-bit chunks
    for chunk in msg.chunks(64) {
        let mut m = [0u32; 16];
        for i in 0..16 {
            m[i] = u32::from_le_bytes([
                chunk[i * 4],
                chunk[i * 4 + 1],
                chunk[i * 4 + 2],
                chunk[i * 4 + 3],
            ]);
        }

        // Initialize working variables
        let mut a = a0;
        let mut b = b0;
        let mut c = c0;
        let mut d = d0;

        // Main loop
        for i in 0..64 {
            let (f, g) = if i < 16 {
                ((b & c) | ((!b) & d), i)
            } else if i < 32 {
                ((d & b) | ((!d) & c), (5 * i + 1) % 16)
            } else if i < 48 {
                (b ^ c ^ d, (3 * i + 5) % 16)
            } else {
                (c ^ (b | (!d)), (7 * i) % 16)
            };

            let temp = d;
            d = c;
            c = b;
            b = b.wrapping_add(
                (a.wrapping_add(f).wrapping_add(K[i]).wrapping_add(m[g])).rotate_left(S[i]),
            );
            a = temp;
        }

        // Add this chunk's hash to result
        a0 = a0.wrapping_add(a);
        b0 = b0.wrapping_add(b);
        c0 = c0.wrapping_add(c);
        d0 = d0.wrapping_add(d);
    }

    // Produce the final hash value
    let mut result = [0u8; 16];
    result[0..4].copy_from_slice(&a0.to_le_bytes());
    result[4..8].copy_from_slice(&b0.to_le_bytes());
    result[8..12].copy_from_slice(&c0.to_le_bytes());
    result[12..16].copy_from_slice(&d0.to_le_bytes());

    result
}

// Generate client nonce
fn generate_cnonce() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
    format!("{:016x}", now.as_nanos())
}

// Create Authorization header value
pub fn create_authorization_header(creds: &DigestCredentials) -> String {
    let mut parts = vec![
        format!(r#"username="{}""#, creds.username),
        format!(r#"realm="{}""#, creds.realm),
        format!(r#"nonce="{}""#, creds.nonce),
        format!(r#"uri="{}""#, creds.uri),
        format!(r#"response="{}""#, creds.response),
    ];

    if creds.algorithm != "MD5" {
        parts.push(format!(r#"algorithm={}"#, creds.algorithm));
    }

    if let Some(ref cnonce) = creds.cnonce {
        parts.push(format!(r#"cnonce="{}""#, cnonce));
    }

    if let Some(ref opaque) = creds.opaque {
        parts.push(format!(r#"opaque="{}""#, opaque));
    }

    if let Some(ref qop) = creds.qop {
        parts.push(format!(r#"qop={}"#, qop));
    }

    if let Some(ref nc) = creds.nc {
        parts.push(format!(r#"nc={}"#, nc));
    }

    format!("Digest {}", parts.join(", "))
}

// Handle authentication for a request
pub fn add_authentication(
    request: &mut SipMessage,
    auth_ctx: &mut AuthContext,
    challenge: &DigestChallenge,
) -> Result<()> {
    // Update auth context with challenge
    auth_ctx.update_from_challenge(challenge);

    // Get method and URI
    let method = request
        .method()
        .ok_or_else(|| SipError::InvalidState("Request has no method".to_string()))?;

    let uri = request
        .request_uri()
        .ok_or_else(|| SipError::InvalidState("Request has no URI".to_string()))?;

    // Get body if present
    let body_data = request.body.as_ref().map(|b| b.content.as_slice());

    // Generate response
    let creds = generate_digest_response(auth_ctx, method.as_str(), &uri.to_string(), body_data);

    // Create authorization header
    let auth_header = create_authorization_header(&creds);

    // Determine which header to use
    let header_name = if request.headers.contains(HeaderName::PROXY_AUTHENTICATE) {
        HeaderName::PROXY_AUTHORIZATION
    } else {
        HeaderName::AUTHORIZATION
    };

    // Add authorization header
    request
        .headers
        .set(HeaderName::new(header_name), auth_header);

    // Increment nonce count for next request
    auth_ctx.increment_nc();

    Ok(())
}

// Authentication manager for handling multiple realms/domains
pub struct AuthenticationManager {
    contexts: std::sync::RwLock<HashMap<String, AuthContext>>,
    auth_sessions: std::sync::RwLock<HashMap<String, AuthSession>>,
}

// Authentication session tracking
#[derive(Debug, Clone)]
pub struct AuthSession {
    pub realm: String,
    pub last_nonce: String,
    pub last_response: String,
    pub successful_auths: u32,
    pub failed_attempts: u32,
    pub created_at: std::time::Instant,
    pub last_used: std::time::Instant,
}

impl AuthenticationManager {
    pub fn new() -> Self {
        AuthenticationManager {
            contexts: std::sync::RwLock::new(HashMap::new()),
            auth_sessions: std::sync::RwLock::new(HashMap::new()),
        }
    }

    pub fn add_credentials(&self, realm: &str, username: String, password: String) {
        let mut contexts = self.contexts.write().unwrap();
        contexts.insert(realm.to_string(), AuthContext::new(username, password));
    }

    pub fn get_context(&self, realm: &str) -> Option<AuthContext> {
        let contexts = self.contexts.read().unwrap();
        contexts.get(realm).cloned()
    }

    pub fn update_context(&self, realm: &str, context: AuthContext) {
        let mut contexts = self.contexts.write().unwrap();
        contexts.insert(realm.to_string(), context);
    }

    pub fn handle_challenge(&self, request: &mut SipMessage, challenge_header: &str) -> Result<()> {
        let challenge = parse_digest_challenge(challenge_header)?;

        // Get or create auth context for this realm
        let mut auth_ctx = self
            .get_context(&challenge.realm)
            .ok_or_else(|| SipError::AuthenticationFailed)?;

        // Add authentication to request
        add_authentication(request, &mut auth_ctx, &challenge)?;

        // Update stored context
        self.update_context(&challenge.realm, auth_ctx.clone());

        // Track authentication session
        self.update_session(&challenge.realm, &auth_ctx);

        Ok(())
    }

    pub fn handle_auth_info(&self, auth_info_header: &str) -> Result<()> {
        // Parse Authentication-Info header for mutual authentication
        let params = parse_auth_params(auth_info_header)?;

        if let Some(nextnonce) = params.get("nextnonce") {
            // Store next nonce for future requests
            if let Some(realm) = params.get("realm") {
                if let Some(mut ctx) = self.get_context(realm) {
                    ctx.nonce = nextnonce.clone();
                    self.update_context(realm, ctx);
                }
            }
        }

        // Verify response-auth if present (mutual authentication)
        if let Some(response_auth) = params.get("rspauth") {
            // In a full implementation, we would verify this against our expected value
            // This provides mutual authentication - the server proves it knows the password
        }

        Ok(())
    }

    fn update_session(&self, realm: &str, auth_ctx: &AuthContext) {
        let mut sessions = self.auth_sessions.write().unwrap();
        let now = std::time::Instant::now();

        let session = sessions
            .entry(realm.to_string())
            .or_insert_with(|| AuthSession {
                realm: realm.to_string(),
                last_nonce: String::new(),
                last_response: String::new(),
                successful_auths: 0,
                failed_attempts: 0,
                created_at: now,
                last_used: now,
            });

        session.last_nonce = auth_ctx.nonce.clone();
        session.last_used = now;
    }

    pub fn mark_auth_success(&self, realm: &str) {
        if let Ok(mut sessions) = self.auth_sessions.write() {
            if let Some(session) = sessions.get_mut(realm) {
                session.successful_auths += 1;
                session.failed_attempts = 0; // Reset failure count
                session.last_used = std::time::Instant::now();
            }
        }
    }

    pub fn mark_auth_failure(&self, realm: &str) {
        if let Ok(mut sessions) = self.auth_sessions.write() {
            if let Some(session) = sessions.get_mut(realm) {
                session.failed_attempts += 1;
                session.last_used = std::time::Instant::now();
            }
        }
    }

    pub fn should_retry_auth(&self, realm: &str) -> bool {
        if let Ok(sessions) = self.auth_sessions.read() {
            if let Some(session) = sessions.get(realm) {
                // Don't retry if we've failed too many times
                return session.failed_attempts < 3;
            }
        }
        true // Allow retry if no session exists
    }

    pub fn cleanup_expired_sessions(&self, max_age: std::time::Duration) {
        let now = std::time::Instant::now();
        if let Ok(mut sessions) = self.auth_sessions.write() {
            sessions.retain(|_, session| now.duration_since(session.last_used) < max_age);
        }
    }
}

// Enhanced authentication handling with proxy support
pub fn handle_auth_response(
    request: &SipMessage,
    response: &SipMessage,
    auth_manager: &AuthenticationManager,
) -> Result<Option<SipMessage>> {
    let status = response.status_code().unwrap_or(0);

    match status {
        401 => {
            // WWW-Authenticate challenge
            if let Some(challenge_header) = response.headers.get(HeaderName::WWW_AUTHENTICATE) {
                let mut new_request = request.clone();
                auth_manager.handle_challenge(&mut new_request, challenge_header)?;

                // Increment CSeq
                if let Some(cseq) = new_request.get_cseq() {
                    let new_cseq = CSeqHeader::new(cseq.sequence + 1, cseq.method);
                    new_request
                        .headers
                        .set(HeaderName::new(HeaderName::CSEQ), new_cseq.to_string());
                }

                Ok(Some(new_request))
            } else {
                Err(SipError::InvalidHeader(
                    "Missing WWW-Authenticate header".to_string(),
                ))
            }
        }
        407 => {
            // Proxy-Authenticate challenge
            if let Some(challenge_header) = response.headers.get(HeaderName::PROXY_AUTHENTICATE) {
                let mut new_request = request.clone();

                // Parse challenge and add proxy authorization
                let challenge = parse_digest_challenge(challenge_header)?;

                // Get auth context
                let mut auth_ctx = auth_manager
                    .get_context(&challenge.realm)
                    .ok_or_else(|| SipError::AuthenticationFailed)?;

                // Update from challenge
                auth_ctx.update_from_challenge(&challenge);

                // Generate credentials
                let method = request
                    .method()
                    .ok_or_else(|| SipError::InvalidState("Request has no method".to_string()))?;
                let uri = request
                    .request_uri()
                    .ok_or_else(|| SipError::InvalidState("Request has no URI".to_string()))?;

                let creds = generate_digest_response(
                    &auth_ctx,
                    method.as_str(),
                    &uri.to_string(),
                    request.body.as_ref().map(|b| b.content.as_slice()),
                );

                // Add Proxy-Authorization header
                new_request.headers.set(
                    HeaderName::new(HeaderName::PROXY_AUTHORIZATION),
                    create_authorization_header(&creds),
                );

                // Update stored context
                auth_manager.update_context(&challenge.realm, auth_ctx);

                // Increment CSeq
                if let Some(cseq) = new_request.get_cseq() {
                    let new_cseq = CSeqHeader::new(cseq.sequence + 1, cseq.method);
                    new_request
                        .headers
                        .set(HeaderName::new(HeaderName::CSEQ), new_cseq.to_string());
                }

                Ok(Some(new_request))
            } else {
                Err(SipError::InvalidHeader(
                    "Missing Proxy-Authenticate header".to_string(),
                ))
            }
        }
        200..=299 => {
            // Success - check for Authentication-Info
            if let Some(auth_info) = response.headers.get(HeaderName::AUTHENTICATION_INFO) {
                auth_manager.handle_auth_info(auth_info)?;
            }

            // Mark successful authentication
            if let Some(auth_header) = request.headers.get(HeaderName::AUTHORIZATION) {
                if let Ok(params) = parse_auth_params(auth_header) {
                    if let Some(realm) = params.get("realm") {
                        auth_manager.mark_auth_success(realm);
                    }
                }
            }

            Ok(None)
        }
        _ => Ok(None),
    }
}

// Calculate response-auth for Authentication-Info validation
pub fn calculate_response_auth(
    auth_ctx: &AuthContext,
    method: &str,
    uri: &str,
    body: Option<&[u8]>,
) -> String {
    // For response authentication, the method is empty
    let ha2 = calculate_ha2("", uri, &auth_ctx.algorithm, auth_ctx.qop.as_deref(), body);

    let ha1 = calculate_ha1(
        &auth_ctx.username,
        &auth_ctx.realm,
        &auth_ctx.password,
        &auth_ctx.algorithm,
        &auth_ctx.nonce,
        auth_ctx.cnonce.as_deref(),
    );

    if let Some(ref qop) = auth_ctx.qop {
        let nc_str = format!("{:08x}", auth_ctx.nc);
        let data = format!(
            "{}:{}:{}:{}:{}:{}",
            ha1,
            auth_ctx.nonce,
            nc_str,
            auth_ctx.cnonce.as_ref().unwrap(),
            qop,
            ha2
        );
        md5_hex(&data)
    } else {
        let data = format!("{}:{}:{}", ha1, auth_ctx.nonce, ha2);
        md5_hex(&data)
    }
}

// Utility to extract specific auth parameters
pub fn extract_auth_param(header: &str, param_name: &str) -> Option<String> {
    if let Ok(params) = parse_auth_params(header) {
        params.get(param_name).cloned()
    } else {
        None
    }
}

// Validate that a challenge is well-formed
pub fn validate_challenge(challenge: &DigestChallenge) -> Result<()> {
    if challenge.realm.is_empty() {
        return Err(SipError::InvalidHeader(
            "Empty realm in challenge".to_string(),
        ));
    }

    if challenge.nonce.is_empty() {
        return Err(SipError::InvalidHeader(
            "Empty nonce in challenge".to_string(),
        ));
    }

    // Check algorithm is supported
    match challenge.algorithm.to_uppercase().as_str() {
        "MD5" | "MD5-SESS" => Ok(()),
        _ => Err(SipError::InvalidHeader(format!(
            "Unsupported algorithm: {}",
            challenge.algorithm
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_digest_challenge() {
        let header =
            r#"Digest realm="asterisk", nonce="1234567890", algorithm=MD5, qop="auth,auth-int""#;
        let challenge = parse_digest_challenge(header).unwrap();

        assert_eq!(challenge.realm, "asterisk");
        assert_eq!(challenge.nonce, "1234567890");
        assert_eq!(challenge.algorithm, "MD5");
        assert_eq!(
            challenge.qop,
            Some(vec!["auth".to_string(), "auth-int".to_string()])
        );
    }

    #[test]
    fn test_digest_response_generation() {
        let mut auth_ctx = AuthContext::new("alice".to_string(), "secret".to_string());
        auth_ctx.realm = "asterisk".to_string();
        auth_ctx.nonce = "1234567890".to_string();
        auth_ctx.qop = Some("auth".to_string());
        auth_ctx.cnonce = Some("abcdef".to_string());
        auth_ctx.nc = 1;

        let creds = generate_digest_response(&auth_ctx, "REGISTER", "sip:example.com", None);

        assert_eq!(creds.username, "alice");
        assert_eq!(creds.realm, "asterisk");
        assert_eq!(creds.nonce, "1234567890");
        assert_eq!(creds.qop, Some("auth".to_string()));
        assert_eq!(creds.nc, Some("00000001".to_string()));
    }

    #[test]
    fn test_authorization_header_creation() {
        let creds = DigestCredentials {
            username: "alice".to_string(),
            realm: "asterisk".to_string(),
            nonce: "1234567890".to_string(),
            uri: "sip:example.com".to_string(),
            response: "abcdef0123456789".to_string(),
            algorithm: "MD5".to_string(),
            cnonce: Some("fedcba".to_string()),
            opaque: None,
            qop: Some("auth".to_string()),
            nc: Some("00000001".to_string()),
            auth_param: HashMap::new(),
        };

        let header = create_authorization_header(&creds);

        assert!(header.starts_with("Digest "));
        assert!(header.contains(r#"username="alice""#));
        assert!(header.contains(r#"realm="asterisk""#));
        assert!(header.contains(r#"qop=auth"#));
        assert!(header.contains(r#"nc=00000001"#));
    }
}
