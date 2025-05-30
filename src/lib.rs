// lib.rs - Main library module for RustSIP

// Since all the code is in single files for this implementation,
// we'll include the modules inline rather than as separate files

#[path = "account.rs"]
mod account;
#[path = "auth.rs"]
pub mod auth;
#[path = "call.rs"]
mod call;
#[path = "core.rs"]
mod core;
#[path = "endpoint.rs"]
mod endpoint;
#[path = "media.rs"]
mod media;
#[path = "message.rs"]
mod message;
#[path = "sdp.rs"]
mod sdp;
#[path = "transaction.rs"]
mod transaction;
#[path = "transport.rs"]
mod transport;

pub mod event_system;

// Re-export core types
pub use crate::account::*;
pub use crate::call::*;
pub use crate::core::*;
pub use crate::endpoint::*;
pub use crate::media::*;
pub use crate::message::*;
pub use crate::sdp::*;
pub use crate::transaction::*;
pub use crate::transport::*;

// Prelude for convenient imports
pub mod prelude {
    pub use crate::{
        Account,
        AccountConfig,
        // IDs
        AccountId,
        AccountState,
        Call,

        CallEvent,
        CallId,

        // States
        CallState,
        ConsoleLogger,
        // Main API
        Endpoint,
        EndpointBuilder,
        // Configuration
        EndpointConfig,
        // Events
        Event,
        EventHandler,
        // Logging
        Logger,
        MediaCapabilities,

        MediaConfig,
        MediaEvent,

        MediaState,
        RegistrationEvent,
        RegistrationState,

        // Core types
        Result,
        RtpCodec,
        SdpBuilder,
        SdpParser,
        // SDP
        Session,
        SipError,
        SipMethod,

        SipUri,
        TransportConfig,

        TransportEvent,
    };
}

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 0;
pub const VERSION_PATCH: u32 = 0;

// Library initialization (if needed)
pub fn init() -> Result<()> {
    // Any global initialization
    Ok(())
}

// Convenience function to create endpoint with default settings
pub async fn create_endpoint() -> Result<std::sync::Arc<Endpoint>> {
    Endpoint::builder().build().await
}

// Test the library is working
#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    async fn get_available_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    }

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[tokio::test]
    async fn test_create_endpoint() {
        let port = get_available_port().await;
        let endpoint = Endpoint::builder().udp_port(port).build().await.unwrap();
        assert!(endpoint.start().await.is_ok());
        assert!(endpoint.stop().await.is_ok());
    }
}
