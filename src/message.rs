use std::collections::HashMap;
use std::fmt;
use crate::{Result, SipError, SipMethod, SipUri, HeaderName, ViaHeader, CSeqHeader, ContactHeader};

// SIP Message structure
#[derive(Debug, Clone)]
pub struct SipMessage {
    pub start_line: StartLine,
    pub headers: HeaderMap,
    pub body: Option<MessageBody>,
}

// Start line variants
#[derive(Debug, Clone)]
pub enum StartLine {
    Request(RequestLine),
    Response(StatusLine),
}

// Request line
#[derive(Debug, Clone)]
pub struct RequestLine {
    pub method: SipMethod,
    pub uri: SipUri,
    pub version: String,
}

// Status line
#[derive(Debug, Clone)]
pub struct StatusLine {
    pub version: String,
    pub status_code: u16,
    pub reason_phrase: String,
}

// Header storage with efficient lookup
#[derive(Debug, Clone)]
pub struct HeaderMap {
    headers: HashMap<HeaderName, Vec<String>>,
    order: Vec<HeaderName>,
}

impl HeaderMap {
    pub fn new() -> Self {
        HeaderMap {
            headers: HashMap::new(),
            order: Vec::new(),
        }
    }

    pub fn add(&mut self, name: HeaderName, value: String) {
        let values = self.headers.entry(name.clone()).or_insert_with(Vec::new);
        values.push(value);
        if values.len() == 1 {
            self.order.push(name);
        }
    }

    pub fn set(&mut self, name: HeaderName, value: String) {
        self.headers.insert(name.clone(), vec![value]);
        if !self.order.contains(&name) {
            self.order.push(name);
        }
    }

    pub fn get(&self, name: &str) -> Option<&String> {
        let header_name = HeaderName::new(name);
        self.headers.get(&header_name).and_then(|v| v.first())
    }

    pub fn get_all(&self, name: &str) -> Option<&Vec<String>> {
        let header_name = HeaderName::new(name);
        self.headers.get(&header_name)
    }

    pub fn remove(&mut self, name: &str) -> Option<Vec<String>> {
        let header_name = HeaderName::new(name);
        self.order.retain(|n| n != &header_name);
        self.headers.remove(&header_name)
    }

    pub fn contains(&self, name: &str) -> bool {
        let header_name = HeaderName::new(name);
        self.headers.contains_key(&header_name)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&HeaderName, &Vec<String>)> {
        self.order.iter().filter_map(move |name| {
            self.headers.get(name).map(|values| (name, values))
        })
    }

    pub fn len(&self) -> usize {
        self.headers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.headers.is_empty()
    }
}

// Message body
#[derive(Debug, Clone)]
pub struct MessageBody {
    pub content_type: String,
    pub content: Vec<u8>,
}

impl MessageBody {
    pub fn new(content_type: String, content: Vec<u8>) -> Self {
        MessageBody {
            content_type,
            content,
        }
    }

    pub fn as_string(&self) -> Result<String> {
        String::from_utf8(self.content.clone())
            .map_err(|_| SipError::ParseError("Invalid UTF-8 in body".to_string()))
    }
}

// SIP Message implementation
impl SipMessage {
    pub fn new_request(method: SipMethod, uri: SipUri) -> Self {
        let mut headers = HeaderMap::new();
        headers.set(
            HeaderName::new(HeaderName::MAX_FORWARDS),
            "70".to_string(),
        );

        SipMessage {
            start_line: StartLine::Request(RequestLine {
                method,
                uri,
                version: "SIP/2.0".to_string(),
            }),
            headers,
            body: None,
        }
    }

    pub fn new_response(status_code: u16, reason_phrase: &str) -> Self {
        SipMessage {
            start_line: StartLine::Response(StatusLine {
                version: "SIP/2.0".to_string(),
                status_code,
                reason_phrase: reason_phrase.to_string(),
            }),
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn is_request(&self) -> bool {
        matches!(self.start_line, StartLine::Request(_))
    }

    pub fn is_response(&self) -> bool {
        matches!(self.start_line, StartLine::Response(_))
    }

    pub fn method(&self) -> Option<&SipMethod> {
        match &self.start_line {
            StartLine::Request(req) => Some(&req.method),
            _ => None,
        }
    }

    pub fn request_uri(&self) -> Option<&SipUri> {
        match &self.start_line {
            StartLine::Request(req) => Some(&req.uri),
            _ => None,
        }
    }

    pub fn status_code(&self) -> Option<u16> {
        match &self.start_line {
            StartLine::Response(resp) => Some(resp.status_code),
            _ => None,
        }
    }

    pub fn get_via(&self) -> Option<ViaHeader> {
        self.headers.get(HeaderName::VIA)
            .and_then(|v| ViaHeader::parse(v).ok())
    }

    pub fn get_from(&self) -> Option<&String> {
        self.headers.get(HeaderName::FROM)
    }

    pub fn get_to(&self) -> Option<&String> {
        self.headers.get(HeaderName::TO)
    }

    pub fn get_call_id(&self) -> Option<&String> {
        self.headers.get(HeaderName::CALL_ID)
    }

    pub fn get_cseq(&self) -> Option<CSeqHeader> {
        self.headers.get(HeaderName::CSEQ)
            .and_then(|v| CSeqHeader::parse(v).ok())
    }

    pub fn get_contact(&self) -> Option<ContactHeader> {
        self.headers.get(HeaderName::CONTACT)
            .and_then(|v| ContactHeader::parse(v).ok())
    }

    pub fn add_via(&mut self, via: ViaHeader) {
        self.headers.add(HeaderName::new(HeaderName::VIA), via.to_string());
    }

    pub fn remove_via(&mut self) -> Option<ViaHeader> {
        self.headers.get_all(HeaderName::VIA)
            .and_then(|vias| vias.first())
            .and_then(|v| ViaHeader::parse(v).ok())
            .map(|via| {
                if let Some(mut vias) = self.headers.remove(HeaderName::VIA) {
                    vias.remove(0);
                    if !vias.is_empty() {
                        for v in vias {
                            self.headers.add(HeaderName::new(HeaderName::VIA), v);
                        }
                    }
                }
                via
            })
    }

    pub fn set_body(&mut self, content_type: String, content: Vec<u8>) {
        let len = content.len();
        self.body = Some(MessageBody::new(content_type.clone(), content));
        self.headers.set(
            HeaderName::new(HeaderName::CONTENT_TYPE),
            content_type,
        );
        self.headers.set(
            HeaderName::new(HeaderName::CONTENT_LENGTH),
            len.to_string(),
        );
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        
        // Start line
        match &self.start_line {
            StartLine::Request(req) => {
                result.extend_from_slice(req.method.as_str().as_bytes());
                result.push(b' ');
                result.extend_from_slice(req.uri.to_string().as_bytes());
                result.push(b' ');
                result.extend_from_slice(req.version.as_bytes());
            }
            StartLine::Response(resp) => {
                result.extend_from_slice(resp.version.as_bytes());
                result.push(b' ');
                result.extend_from_slice(resp.status_code.to_string().as_bytes());
                result.push(b' ');
                result.extend_from_slice(resp.reason_phrase.as_bytes());
            }
        }
        result.extend_from_slice(b"\r\n");

        // Headers
        for (name, values) in self.headers.iter() {
            for value in values {
                result.extend_from_slice(format_header_name(name.as_str()).as_bytes());
                result.extend_from_slice(b": ");
                result.extend_from_slice(value.as_bytes());
                result.extend_from_slice(b"\r\n");
            }
        }
        
        // Empty line
        result.extend_from_slice(b"\r\n");

        // Body
        if let Some(ref body) = self.body {
            result.extend_from_slice(&body.content);
        }

        result
    }
}

// Format header name with proper capitalization
fn format_header_name(name: &str) -> String {
    // Common compact forms
    match name {
        "via" => "Via",
        "from" => "From",
        "to" => "To",
        "call-id" => "Call-ID",
        "cseq" => "CSeq",
        "contact" => "Contact",
        "content-type" => "Content-Type",
        "content-length" => "Content-Length",
        "max-forwards" => "Max-Forwards",
        "user-agent" => "User-Agent",
        "www-authenticate" => "WWW-Authenticate",
        "proxy-authenticate" => "Proxy-Authenticate",
        "proxy-authorization" => "Proxy-Authorization",
        "record-route" => "Record-Route",
        "allow-events" => "Allow-Events",
        "authentication-info" => "Authentication-Info",
        "error-info" => "Error-Info",
        "in-reply-to" => "In-Reply-To",
        "min-expires" => "Min-Expires",
        "mime-version" => "MIME-Version",
        "refer-to" => "Refer-To",
        "referred-by" => "Referred-By",
        "reply-to" => "Reply-To",
        "retry-after" => "Retry-After",
        "session-expires" => "Session-Expires",
        "subscription-state" => "Subscription-State",
        _ => name
    }.to_string()
}

// SIP Message Parser
pub struct SipParser;

impl SipParser {
    pub fn parse(data: &[u8]) -> Result<(SipMessage, usize)> {
        let mut parser = MessageParser::new(data);
        parser.parse()
    }
}

struct MessageParser<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> MessageParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        MessageParser { data, pos: 0 }
    }

    fn parse(&mut self) -> Result<(SipMessage, usize)> {
        // Parse start line
        let start_line = self.parse_start_line()?;
        
        // Parse headers
        let mut headers = HeaderMap::new();
        let body_start = self.parse_headers(&mut headers)?;
        
        // Get Content-Length
        let content_length = headers.get(HeaderName::CONTENT_LENGTH)
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);

        // Parse body if present
        let body = if content_length > 0 && body_start + content_length <= self.data.len() {
            let content_type = headers.get(HeaderName::CONTENT_TYPE)
                .cloned()
                .unwrap_or_else(|| "application/octet-stream".to_string());
            
            let content = self.data[body_start..body_start + content_length].to_vec();
            Some(MessageBody::new(content_type, content))
        } else {
            None
        };

        let total_size = if content_length > 0 {
            body_start + content_length
        } else {
            body_start
        };

        Ok((SipMessage {
            start_line,
            headers,
            body,
        }, total_size))
    }

    fn parse_start_line(&mut self) -> Result<StartLine> {
        let line = self.read_line()?;
        let parts: Vec<&str> = line.splitn(3, ' ').collect();
        
        if parts.len() < 3 {
            return Err(SipError::ParseError("Invalid start line".to_string()));
        }

        if parts[0].starts_with("SIP/") {
            // Response
            let status_code = parts[1].parse()
                .map_err(|_| SipError::ParseError("Invalid status code".to_string()))?;
            
            Ok(StartLine::Response(StatusLine {
                version: parts[0].to_string(),
                status_code,
                reason_phrase: parts[2].to_string(),
            }))
        } else {
            // Request
            let method = SipMethod::from_str(parts[0])?;
            let uri = SipUri::parse(parts[1])?;
            
            Ok(StartLine::Request(RequestLine {
                method,
                uri,
                version: parts[2].to_string(),
            }))
        }
    }

    fn parse_headers(&mut self, headers: &mut HeaderMap) -> Result<usize> {
        loop {
            let line = self.read_line()?;
            if line.is_empty() {
                // Empty line indicates end of headers
                return Ok(self.pos);
            }

            // Handle header folding (continuation lines)
            let mut full_line = line.to_string();
            while self.peek_char() == Some(' ') || self.peek_char() == Some('\t') {
                let continuation = self.read_line()?;
                full_line.push(' ');
                full_line.push_str(continuation.trim());
            }

            // Parse header
            if let Some(colon_pos) = full_line.find(':') {
                let name = full_line[..colon_pos].trim();
                let value = full_line[colon_pos + 1..].trim();
                
                headers.add(HeaderName::new(name), value.to_string());
            } else {
                return Err(SipError::ParseError(format!("Invalid header: {}", full_line)));
            }
        }
    }

    fn read_line(&mut self) -> Result<&'a str> {
        let start = self.pos;
        
        while self.pos < self.data.len() {
            if self.pos + 1 < self.data.len() && 
               self.data[self.pos] == b'\r' && 
               self.data[self.pos + 1] == b'\n' {
                let line = std::str::from_utf8(&self.data[start..self.pos])
                    .map_err(|_| SipError::ParseError("Invalid UTF-8 in header".to_string()))?;
                self.pos += 2;
                return Ok(line);
            }
            self.pos += 1;
        }
        
        Err(SipError::ParseError("Unexpected end of data".to_string()))
    }

    fn peek_char(&self) -> Option<char> {
        if self.pos < self.data.len() {
            Some(self.data[self.pos] as char)
        } else {
            None
        }
    }
}

// SIP Message Builder
pub struct SipMessageBuilder {
    method: Option<SipMethod>,
    uri: Option<SipUri>,
    status_code: Option<u16>,
    reason_phrase: Option<String>,
    headers: HeaderMap,
    body: Option<MessageBody>,
}

impl SipMessageBuilder {
    pub fn new() -> Self {
        SipMessageBuilder {
            method: None,
            uri: None,
            status_code: None,
            reason_phrase: None,
            headers: HeaderMap::new(),
            body: None,
        }
    }

    pub fn request(mut self, method: SipMethod, uri: SipUri) -> Self {
        self.method = Some(method);
        self.uri = Some(uri);
        self
    }

    pub fn response(mut self, status_code: u16, reason_phrase: &str) -> Self {
        self.status_code = Some(status_code);
        self.reason_phrase = Some(reason_phrase.to_string());
        self
    }

    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.set(HeaderName::new(name), value.to_string());
        self
    }

    pub fn add_header(mut self, name: &str, value: &str) -> Self {
        self.headers.add(HeaderName::new(name), value.to_string());
        self
    }

    pub fn body(mut self, content_type: &str, content: Vec<u8>) -> Self {
        self.body = Some(MessageBody::new(content_type.to_string(), content));
        self
    }

    pub fn build(mut self) -> Result<SipMessage> {
        let start_line = if let (Some(method), Some(uri)) = (self.method, self.uri) {
            StartLine::Request(RequestLine {
                method,
                uri,
                version: "SIP/2.0".to_string(),
            })
        } else if let (Some(status_code), Some(reason_phrase)) = (self.status_code, self.reason_phrase) {
            StartLine::Response(StatusLine {
                version: "SIP/2.0".to_string(),
                status_code,
                reason_phrase,
            })
        } else {
            return Err(SipError::InvalidState("Must specify either request or response".to_string()));
        };

        // Set Content-Length if body present
        if let Some(ref body) = self.body {
            self.headers.set(
                HeaderName::new(HeaderName::CONTENT_TYPE),
                body.content_type.clone(),
            );
            self.headers.set(
                HeaderName::new(HeaderName::CONTENT_LENGTH),
                body.content.len().to_string(),
            );
        } else if !self.headers.contains(HeaderName::CONTENT_LENGTH) {
            self.headers.set(
                HeaderName::new(HeaderName::CONTENT_LENGTH),
                "0".to_string(),
            );
        }

        // Set Max-Forwards for requests if not present
        if matches!(start_line, StartLine::Request(_)) && !self.headers.contains(HeaderName::MAX_FORWARDS) {
            self.headers.set(
                HeaderName::new(HeaderName::MAX_FORWARDS),
                "70".to_string(),
            );
        }

        Ok(SipMessage {
            start_line,
            headers: self.headers,
            body: self.body,
        })
    }
}

// Response reason phrases
pub fn reason_phrase(code: u16) -> &'static str {
    match code {
        // 1xx
        100 => "Trying",
        180 => "Ringing",
        181 => "Call Is Being Forwarded",
        182 => "Queued",
        183 => "Session Progress",

        // 2xx
        200 => "OK",
        202 => "Accepted",

        // 3xx
        300 => "Multiple Choices",
        301 => "Moved Permanently",
        302 => "Moved Temporarily",
        305 => "Use Proxy",
        380 => "Alternative Service",

        // 4xx
        400 => "Bad Request",
        401 => "Unauthorized",
        402 => "Payment Required",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        406 => "Not Acceptable",
        407 => "Proxy Authentication Required",
        408 => "Request Timeout",
        410 => "Gone",
        413 => "Request Entity Too Large",
        414 => "Request-URI Too Large",
        415 => "Unsupported Media Type",
        416 => "Unsupported URI Scheme",
        420 => "Bad Extension",
        421 => "Extension Required",
        423 => "Interval Too Brief",
        480 => "Temporarily Unavailable",
        481 => "Call/Transaction Does Not Exist",
        482 => "Loop Detected",
        483 => "Too Many Hops",
        484 => "Address Incomplete",
        485 => "Ambiguous",
        486 => "Busy Here",
        487 => "Request Terminated",
        488 => "Not Acceptable Here",
        491 => "Request Pending",
        493 => "Undecipherable",

        // 5xx
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Server Time-out",
        505 => "SIP Version Not Supported",
        513 => "Message Too Large",

        // 6xx
        600 => "Busy Everywhere",
        603 => "Decline",
        604 => "Does Not Exist Anywhere",
        606 => "Not Acceptable",

        _ => "Unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_parsing() {
        let request = b"INVITE sip:bob@example.com SIP/2.0\r\n\
                       Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds\r\n\
                       From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                       To: Bob <sip:bob@example.com>\r\n\
                       Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                       CSeq: 314159 INVITE\r\n\
                       Max-Forwards: 70\r\n\
                       Contact: <sip:alice@192.168.1.100>\r\n\
                       Content-Type: application/sdp\r\n\
                       Content-Length: 4\r\n\
                       \r\n\
                       test";

        let (msg, size) = SipParser::parse(request).unwrap();
        assert!(msg.is_request());
        assert_eq!(msg.method().unwrap(), &SipMethod::Invite);
        assert_eq!(msg.get_call_id().unwrap(), "a84b4c76e66710@pc33.example.com");
        assert_eq!(msg.body.unwrap().content, b"test");
        assert_eq!(size, request.len());
    }

    #[test]
    fn test_response_parsing() {
        let response = b"SIP/2.0 200 OK\r\n\
                        Via: SIP/2.0/UDP 192.168.1.100:5060;branch=z9hG4bK776asdhds\r\n\
                        From: Alice <sip:alice@example.com>;tag=1928301774\r\n\
                        To: Bob <sip:bob@example.com>;tag=a6c85cf\r\n\
                        Call-ID: a84b4c76e66710@pc33.example.com\r\n\
                        CSeq: 314159 INVITE\r\n\
                        Contact: <sip:bob@192.168.1.200>\r\n\
                        Content-Length: 0\r\n\
                        \r\n";

        let (msg, size) = SipParser::parse(response).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.status_code().unwrap(), 200);
        assert_eq!(size, response.len());
    }

    #[test]
    fn test_message_builder() {
        let uri = SipUri::parse("sip:bob@example.com").unwrap();
        let msg = SipMessageBuilder::new()
            .request(SipMethod::Invite, uri)
            .header("From", "Alice <sip:alice@example.com>")
            .header("To", "Bob <sip:bob@example.com>")
            .header("Call-ID", "test123@example.com")
            .header("CSeq", "1 INVITE")
            .build()
            .unwrap();

        assert!(msg.is_request());
        assert_eq!(msg.method().unwrap(), &SipMethod::Invite);
        assert_eq!(msg.get_call_id().unwrap(), "test123@example.com");
    }
}