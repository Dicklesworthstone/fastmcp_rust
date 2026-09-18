//! AUTH-03 public API tests: real TLS metadata GETs, registration and token
//! POSTs, with an in-process browser-callback simulator. No external IdP/browser
//! is exercised. All registration writes are confined to the local TLS fixture.

use std::collections::BTreeMap;
use std::future::{Future, poll_fn};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::Poll;
use std::time::Duration;

use asupersync::Cx;
use asupersync::channel::oneshot;
use asupersync::io::{AsyncReadExt, AsyncWriteExt};
use asupersync::net::{TcpListener, TcpStream};
use asupersync::runtime::{RuntimeBuilder, reactor::create_reactor};
use asupersync::tls::{Certificate, CertificateChain, PrivateKey, TlsAcceptor, TlsAcceptorBuilder, TlsStream};
use fastmcp_client::http_auth::BoundBearerCredential;
use fastmcp_client::http_auth::discovery::{
    OAuthDiscoveryError, OAuthDiscoveryPlan, TrustedOAuthIssuer,
    ResourceMetadataCause, ResourceMetadataFailureClass, ResourceMetadataLocation,
    MAX_OAUTH_METADATA_BYTES,
};
use fastmcp_client::http_auth::discovery::registration::{
    NativeClientRegistration, OAuthRegistrationError, NATIVE_REGISTRATION_REDIRECT_URIS,
};
use fastmcp_client::http_auth::managed::OAuthSessionPolicy;
use fastmcp_client::http_auth::oauth::OAuthError;
use fastmcp_core::CanonicalHttpUrl;
use serde_json::{Value, json};

// Public TEST ONLY fixture material. These keys must never be deployment keys.
const ROOT: &[u8] = b"-----BEGIN CERTIFICATE-----\nMIIBgzCCASmgAwIBAgICA+kwCgYIKoZIzj0EAwIwJzElMCMGA1UEAwwcRmFzdE1D\nUCBPQXV0aCBURVNUIE9OTFkgUm9vdDAeFw0yMDAxMDEwMDAwMDBaFw00OTEyMzEw\nMDAwMDBaMCcxJTAjBgNVBAMMHEZhc3RNQ1AgT0F1dGggVEVTVCBPTkxZIFJvb3Qw\nWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS5t2O8JZ0hNjgI38E9Ov6i6mKoDRGo\nApMsykFkvgb6Zm9/5gCZ90eIKw7aWgK6b8d765\n-----END CERTIFICATE-----\n";
