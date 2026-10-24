//! Connection-local custody of catalog continuation tokens.
//!
//! A raw server cursor has no client-side credential provenance. In particular,
//! comparing the CURRENT connection's generation to a freshly acquired snapshot
//! does not establish which generation originally issued a caller's cursor.
//! Keep the raw value private and publish a fresh local handle instead.

use fastmcp_core::draw_security_identifier;
use fastmcp_protocol::{CoreResult, FinalCoreResult};

use super::ManagedHttpClientError;

// At most four raw cursors (one per catalog) are retained by a connection.
const MAX_CURSOR_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub(super) enum CatalogKind {
    Tools,
    Resources,
    Templates,
    Prompts,
}

impl CatalogKind {
    fn index(self) -> usize {
        match self {
            Self::Tools => 0,
            Self::Resources => 1,
            Self::Templates => 2,
            Self::Prompts => 3,
        }
    }
}

// No Debug or Clone: neither diagnostics nor a second connection can obtain
// this connection's raw cursor custody by deriving either trait.
struct Binding {
    handle: String,
    wire: String,
}

#[derive(Default)]
pub(super) struct CursorLedger([Option<Binding>; 4]);

impl CursorLedger {
    pub(super) fn admits(&self, kind: CatalogKind, handle: &str) -> bool {
        self.0[kind.index()]
            .as_ref()
            .is_some_and(|binding| binding.handle == handle)
    }

    pub(super) fn take(
        &mut self,
        kind: CatalogKind,
        handle: Option<&str>,
    ) -> Result<Option<String>, ManagedHttpClientError> {
        if let Some(handle) = handle {
            if !self.admits(kind, handle) {
                return Err(ManagedHttpClientError::InvalidCatalogCursor);
            }
            Ok(self.0[kind.index()].take().map(|binding| binding.wire))
        } else {
            // A fresh traversal supersedes only this kind's previous page.
            self.0[kind.index()] = None;
            Ok(None)
        }
    }

    pub(super) fn publish(
        &mut self,
        kind: CatalogKind,
        value: &mut CoreResult,
    ) -> Result<(), ManagedHttpClientError> {
        let cursor = match (kind, value) {
            (CatalogKind::Tools, CoreResult::Final(FinalCoreResult::ToolsList { result, .. })) => {
                &mut result.payload.next_cursor
            }
            (
                CatalogKind::Resources,
                CoreResult::Final(FinalCoreResult::ResourcesList { result, .. }),
            ) => &mut result.payload.next_cursor,
            (
                CatalogKind::Templates,
                CoreResult::Final(FinalCoreResult::ResourceTemplatesList { result, .. }),
            ) => &mut result.payload.next_cursor,
            (
                CatalogKind::Prompts,
                CoreResult::Final(FinalCoreResult::PromptsList { result, .. }),
            ) => &mut result.payload.next_cursor,
            _ => return Err(ManagedHttpClientError::Request { code: None }),
        };
        self.publish_cursor(kind, cursor, || {
            draw_security_identifier()
                .map(|id| *id.as_bytes())
                .map_err(|_| ())
        })
    }

    fn publish_cursor(
        &mut self,
        kind: CatalogKind,
        cursor: &mut Option<String>,
        draw: impl FnOnce() -> Result<[u8; 32], ()>,
    ) -> Result<(), ManagedHttpClientError> {
        let Some(wire) = cursor.as_ref() else {
            self.0[kind.index()] = None;
            return Ok(());
        };
        if wire.len() > MAX_CURSOR_BYTES {
            return Err(ManagedHttpClientError::CatalogCursorUnavailable);
        }
        let nonce = draw().map_err(|()| ManagedHttpClientError::CatalogCursorUnavailable)?;
        let mut handle = String::with_capacity(76);
        handle.push_str("mcp-cursor-");
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for byte in nonce {
            handle.push(char::from(HEX[usize::from(byte >> 4)]));
            handle.push(char::from(HEX[usize::from(byte & 15)]));
        }
        let binding = Binding {
            handle: handle.clone(),
            wire: wire.clone(),
        };
        self.0[kind.index()] = Some(binding);
        *cursor = Some(handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn publish(ledger: &mut CursorLedger, kind: CatalogKind, wire: &str, nonce: u8) -> String {
        let mut cursor = Some(wire.to_owned());
        ledger
            .publish_cursor(kind, &mut cursor, || Ok([nonce; 32]))
            .unwrap();
        cursor.unwrap()
    }

    #[test]
    fn exact_wire_bytes_round_trip_once_but_never_become_local_authority() {
        for wire in ["", "server-secret-cursor", "utf8-雪%2f"] {
            let mut ledger = CursorLedger::default();
            let handle = publish(&mut ledger, CatalogKind::Tools, wire, 1);
            assert_ne!(handle, wire);
            assert!(!ledger.admits(CatalogKind::Tools, wire));
            assert_eq!(
                ledger.take(CatalogKind::Tools, Some(&handle)).unwrap(),
                Some(wire.to_owned())
            );
            assert!(matches!(
                ledger.take(CatalogKind::Tools, Some(&handle)),
                Err(ManagedHttpClientError::InvalidCatalogCursor)
            ));
        }
    }

    #[test]
    fn handle_is_bound_to_its_catalog_and_a_fresh_connection_cannot_adopt_it() {
        let kinds = [
            CatalogKind::Tools,
            CatalogKind::Resources,
            CatalogKind::Templates,
            CatalogKind::Prompts,
        ];
        let mut ledger = CursorLedger::default();
        let handles: Vec<_> = kinds
            .iter()
            .enumerate()
            .map(|(index, kind)| publish(&mut ledger, *kind, "same-peer-text", index as u8))
            .collect();
        for (index, handle) in handles.iter().enumerate() {
            for (other, kind) in kinds.iter().enumerate() {
                assert_eq!(ledger.admits(*kind, handle), index == other);
                assert!(!CursorLedger::default().admits(*kind, handle));
            }
        }
    }

    #[test]
    fn peer_reusing_a_cursor_does_not_revive_a_previous_handle() {
        let mut ledger = CursorLedger::default();
        let old = publish(&mut ledger, CatalogKind::Tools, "same", 1);
        let current = publish(&mut ledger, CatalogKind::Tools, "same", 2);
        assert!(!ledger.admits(CatalogKind::Tools, &old));
        assert!(ledger.admits(CatalogKind::Tools, &current));
        let mut replacement = CursorLedger::default();
        let renewed = publish(&mut replacement, CatalogKind::Tools, "same", 3);
        assert!(!replacement.admits(CatalogKind::Tools, &old));
        assert!(!replacement.admits(CatalogKind::Tools, &current));
        assert!(replacement.admits(CatalogKind::Tools, &renewed));
    }

    #[test]
    fn fresh_and_terminal_pages_retire_only_their_own_catalog() {
        let mut ledger = CursorLedger::default();
        let tools = publish(&mut ledger, CatalogKind::Tools, "t", 1);
        let prompts = publish(&mut ledger, CatalogKind::Prompts, "p", 2);
        ledger.take(CatalogKind::Tools, None).unwrap();
        assert!(!ledger.admits(CatalogKind::Tools, &tools));
        assert!(ledger.admits(CatalogKind::Prompts, &prompts));
        ledger
            .publish_cursor(CatalogKind::Prompts, &mut None, || {
                panic!("terminal page needs no entropy")
            })
            .unwrap();
        assert!(!ledger.admits(CatalogKind::Prompts, &prompts));
    }

    #[test]
    fn size_and_entropy_failures_cannot_publish_or_replace_a_binding() {
        let mut ledger = CursorLedger::default();
        let old = publish(
            &mut ledger,
            CatalogKind::Tools,
            &"x".repeat(MAX_CURSOR_BYTES),
            1,
        );
        let mut oversized = Some("x".repeat(MAX_CURSOR_BYTES + 1));
        assert!(matches!(
            ledger.publish_cursor(CatalogKind::Tools, &mut oversized, || panic!(
                "check size before entropy"
            )),
            Err(ManagedHttpClientError::CatalogCursorUnavailable)
        ));
        let mut cursor = Some("private-cursor".to_owned());
        let error = ledger
            .publish_cursor(CatalogKind::Tools, &mut cursor, || Err(()))
            .unwrap_err();
        assert!(ledger.admits(CatalogKind::Tools, &old));
        assert_eq!(cursor.as_deref(), Some("private-cursor"));
        assert!(!format!("{error:?} {error}").contains("private-cursor"));
    }
}
