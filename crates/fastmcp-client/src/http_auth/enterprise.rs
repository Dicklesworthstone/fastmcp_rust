//! Local enterprise-managed authorization policy admission for native clients.
//!
//! The IdP and resource authorization server have independently admitted
//! metadata, preregistrations, confidential-client methods and signing-key
//! purposes. Scope grants are literal bounded sets: narrowing must agree with
//! the signed assertion and explicit token-response grant.
//!
//! These operations validate trusted configuration and already-obtained
//! documents. They do not activate the extension, acquire assertions, dispatch
//! exchanges, obtain credentials, or supply deployment/replay attestations.

pub mod policy;
