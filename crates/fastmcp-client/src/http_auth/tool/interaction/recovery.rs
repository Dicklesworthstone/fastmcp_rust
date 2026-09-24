//! Explicit continuation-reply recovery without leaving a tool's schema contract.
//!
//! The core recovery owner alone decides whether an interrupted attempt can be
//! retried under an independently configured server journal. This layer never
//! infers replay permission from a schema, annotation, error, or missing reply.
//! It retains the original tool contract and its invalidation wake throughout
//! preparation, sending, recovery, result admission, and hand-back.

use std::fmt;
use std::sync::Arc;

use asupersync::Cx;
use fastmcp_core::McpRequestCancellation;
use fastmcp_protocol::{FinalInputResponses, RequestId};

use super::{ManagedInteractionEvent, ManagedToolInteraction};
use super::super::{ManagedToolError, ToolContract, await_validity, check_tool_call};
use crate::http_auth::rpc::interaction::recovery::{
    ContinuationRecoveryError, ContinuationReplayContract, RecoverableManagedContinuation,
};

/// Keeps correctable recovery refusals distinct from contract failures. Neither
/// branch retains answers, continuation state, a schema, or remote output.
#[derive(Debug)]
pub enum ManagedToolRecoveryError {
    Tool(ManagedToolError),
    Recovery(ContinuationRecoveryError),
}

impl fmt::Display for ManagedToolRecoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Tool(error) => fmt::Display::fmt(error, f),
            Self::Recovery(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for ManagedToolRecoveryError {}

impl From<ManagedToolError> for ManagedToolRecoveryError {
    fn from(error: ManagedToolError) -> Self { Self::Tool(error) }
}

impl From<ContinuationRecoveryError> for ManagedToolRecoveryError {
    fn from(error: ContinuationRecoveryError) -> Self { Self::Recovery(error) }
}

impl ManagedToolInteraction {
    /// Transfers this operation's current challenge to explicit reply recovery.
    /// The independently configured contract must name this exact endpoint and
    /// its real server-side continuation journal. Misconfiguration can repeat
    /// remote effects; this API cannot prove the server's deployment contract.
    ///
    /// Consumes the interaction even on local refusal, matching the core owner.
    /// Ordinary `resume` remains the choice for correcting invalid answers.
    /// Partial, complete, and state-only answers use the existing core rules;
    /// no new arguments, schema, login, state, or resolver can be substituted.
    pub fn prepare_recoverable_continuation(
        mut self,
        cx: &Cx,
        responses: Option<FinalInputResponses>,
        replay: ContinuationReplayContract,
    ) -> Result<RecoverableManagedToolContinuation, ManagedToolRecoveryError> {
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        let operation = self.operation.take().ok_or(ManagedToolError::Closed)?;
        let operation = operation.prepare_recoverable_continuation(cx, responses, replay)?;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        Ok(RecoverableManagedToolContinuation {
            operation, contract: self.contract, cancellation: self.cancellation,
            publication: Publication::Pending,
        })
    }
}

/// Exclusive, schema-checked custody of one continuation and its recovered reply.
///
/// Each explicit send/recover delegates one attempt to the existing core owner,
/// retaining its original deadline, byte reservations, IDs and answer counters.
/// Dropping a polled send/read closes that attempt's socket but retains core
/// recovery eligibility; it does not rerun a host resolver or schedule a retry.
/// Dropping this owner discards its retained answers and recovery permission.
///
/// Tool/catalog invalidation wakes pending I/O and refuses later publication.
/// A schema-invalid terminal reply closes recovery irreversibly: it is neither
/// recoverable transport loss nor a way to obtain an unchecked core interaction.
/// Already-committed effects are not undone. No durable restart or exactly-once
/// guarantee is added; the configured server journal remains authoritative.
#[must_use = "send once, validate the reply, and explicitly decide any recovery"]
pub struct RecoverableManagedToolContinuation {
    operation: RecoverableManagedContinuation,
    contract: Arc<ToolContract>,
    cancellation: McpRequestCancellation,
    publication: Publication,
}

impl fmt::Debug for RecoverableManagedToolContinuation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecoverableManagedToolContinuation")
            .field("attempts", &self.attempts())
            .field("publication", &self.publication)
            .field("invalidated", &self.contract.is_invalidated())
            .finish_non_exhaustive()
    }
}

impl RecoverableManagedToolContinuation {
    /// Includes the first continuation send and every explicit recovery attempt.
    pub fn attempts(&self) -> usize { self.operation.attempts() }

    /// An observation, not authority to retry. `recover` rechecks all guards.
    pub fn is_recovery_pending(&self) -> bool {
        self.publication == Publication::Pending
            && !self.contract.is_invalidated()
            && !self.cancellation.is_cancel_requested()
            && self.operation.is_recovery_pending()
    }

    pub fn close(&mut self) {
        self.operation.close();
        self.publication = Publication::Closed;
    }

    /// Sends the prepared continuation once, without implicitly replaying it.
    pub async fn send(&mut self, cx: &Cx, request_id: RequestId) -> Result<(), ManagedToolRecoveryError> {
        Box::pin(self.attempt(cx, request_id, false)).await
    }

    /// Explicitly recovers an interrupted reply using a fresh correlation ID.
    /// The underlying core owner enforces journal, phase and attempt limits.
    pub async fn recover(&mut self, cx: &Cx, request_id: RequestId) -> Result<(), ManagedToolRecoveryError> {
        Box::pin(self.attempt(cx, request_id, true)).await
    }

    async fn attempt(&mut self, cx: &Cx, request_id: RequestId, recovery: bool)
        -> Result<(), ManagedToolRecoveryError>
    {
        self.check(cx)?;
        let outcome = Box::pin(await_validity(cx, &self.cancellation, &self.contract, async {
            if recovery { self.operation.recover(cx, request_id).await }
            else { self.operation.send(cx, request_id).await }
        })).await;
        // Borrow, do not take, the core owner across the await: abandoning a
        // polled attempt must preserve its explicitly configured recovery state.
        match outcome {
            Err(error) => { self.close(); Err(error.into()) }
            Ok(outcome) => {
                self.check(cx)?;
                outcome.map_err(ManagedToolRecoveryError::from)
            }
        }
    }

    /// Publishes exactly one schema-checked terminal or successor challenge.
    /// A tool execution error is preserved as a tool result, not retried. The
    /// original lossless result is returned, never the validation parse copy.
    pub async fn next_event(&mut self, cx: &Cx) -> Result<ManagedInteractionEvent, ManagedToolRecoveryError> {
        self.check(cx)?;
        if self.publication != Publication::Pending {
            return Err(ContinuationRecoveryError::WrongPhase.into());
        }
        let outcome = await_validity(cx, &self.cancellation, &self.contract, self.operation.next_event(cx)).await;
        let event = match outcome {
            Err(error) => { self.close(); return Err(error.into()); }
            Ok(Err(error)) => { self.check(cx)?; return Err(error.into()); }
            Ok(Ok(event)) => event,
        };
        self.check(cx)?;
        if let Err(error) = self.publication.admit(&self.contract, &event) {
            self.close();
            return Err(error);
        }
        self.check(cx)?;
        Ok(event)
    }

    /// Returns only the same schema-bound interaction, after a validated reply.
    /// A successor keeps its new challenge and the original contract. A terminal
    /// result is already delivered, so the returned interaction is finished.
    /// Calling this before reading/validation cannot expose the core owner.
    pub fn into_interaction(mut self, cx: &Cx) -> Result<ManagedToolInteraction, ManagedToolRecoveryError> {
        self.check(cx)?;
        if !self.publication.can_return() {
            return Err(ContinuationRecoveryError::WrongPhase.into());
        }
        let operation = self.operation.into_interaction()?;
        check_tool_call(cx, &self.cancellation, &self.contract)?;
        Ok(ManagedToolInteraction {
            operation: Some(operation), contract: self.contract,
            cancellation: self.cancellation, finished: self.publication == Publication::Complete,
        })
    }

    fn check(&mut self, cx: &Cx) -> Result<(), ManagedToolRecoveryError> {
        if let Err(error) = check_tool_call(cx, &self.cancellation, &self.contract) {
            self.close();
            return Err(error.into());
        }
        if self.publication == Publication::Closed {
            return Err(ManagedToolError::Closed.into());
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Publication { Pending, Successor, Complete, Closed }

impl Publication {
    fn can_return(self) -> bool { matches!(self, Self::Successor | Self::Complete) }

    fn admit(&mut self, contract: &ToolContract, event: &ManagedInteractionEvent)
        -> Result<(), ManagedToolRecoveryError>
    {
        if *self != Self::Pending { return Err(ContinuationRecoveryError::WrongPhase.into()); }
        // Fail closed before validation. Even though core already consumed its
        // reply, validation failure must never unlock unchecked hand-back.
        *self = Self::Closed;
        contract.check()?;
        let next = match event {
            ManagedInteractionEvent::Complete(result) => {
                contract.validate_result(result)?;
                Self::Complete
            }
            ManagedInteractionEvent::InputRequired(_) => Self::Successor,
            ManagedInteractionEvent::Notification(_) => return Err(ContinuationRecoveryError::JsonReplyRequired.into()),
        };
        contract.check()?;
        *self = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fastmcp_protocol::{ClientCapabilities, CoreRequest, FinalRequestMeta, FinalTool, ServerNotification};
    use fastmcp_protocol::protocol_policy::ProtocolEra;
    use serde_json::json;
    use std::sync::atomic::{AtomicBool, Ordering};

    fn contract() -> ToolContract {
        ToolContract::admit(FinalTool {
            name: "checkout".to_owned(), title: None, description: None, icons: None,
            input_schema: json!({"type":"object"}),
            output_schema: Some(json!({"type":"object", "properties":{"quantity":{"type":"integer"}},
                "required":["quantity"], "additionalProperties":false})),
            annotations: None, meta: None,
        }).unwrap()
    }

    fn event(raw: &str) -> ManagedInteractionEvent {
        let params = json!({"name":"checkout","_meta":FinalRequestMeta::new(ClientCapabilities::default())});
        let request = CoreRequest::decode(ProtocolEra::Modern2026, "tools/call", Some(&params)).unwrap();
        let result = request.decode_result(raw).unwrap();
        if let Some(input) = crate::http_auth::rpc::interaction::input_required(&result) {
            ManagedInteractionEvent::InputRequired(Box::new(input.clone()))
        } else { ManagedInteractionEvent::Complete(Box::new(result)) }
    }

    fn success() -> ManagedInteractionEvent {
        event(r#"{"resultType":"complete","content":[],"structuredContent":{"quantity":7},"x-exact":1.20e+4}"#)
    }

    #[test]
    fn recovered_success_keeps_the_lossless_result_and_unlocks_only_finished_handback() {
        let event = success();
        let ManagedInteractionEvent::Complete(result) = &event else { unreachable!() };
        let before = result.encode().unwrap();
        let mut publication = Publication::Pending;
        publication.admit(&contract(), &event).unwrap();
        assert_eq!(publication, Publication::Complete);
        assert!(publication.can_return());
        assert_eq!(result.encode().unwrap(), before);
        assert!(before.contains("1.20e+4"));
    }

    #[test]
    fn missing_or_invalid_output_closes_recovery_and_cannot_be_replaced_with_success() {
        for raw in [
            r#"{"resultType":"complete","content":[]}"#,
            r#"{"resultType":"complete","content":[],"structuredContent":{"quantity":"private-output-canary"}}"#,
        ] {
            let mut publication = Publication::Pending;
            let error = publication.admit(&contract(), &event(raw)).err().unwrap();
            assert!(matches!(error, ManagedToolRecoveryError::Tool(
                ManagedToolError::MissingStructuredOutput | ManagedToolError::InvalidStructuredOutput)));
            assert!(!format!("{error:?} {error}").contains("private-output-canary"));
            assert_eq!(publication, Publication::Closed);
            assert!(!publication.can_return());
            assert!(matches!(publication.admit(&contract(), &success()),
                Err(ManagedToolRecoveryError::Recovery(ContinuationRecoveryError::WrongPhase))));
        }
    }

    #[test]
    fn execution_errors_remain_terminal_tool_results_not_schema_failures_or_retries() {
        let event = event(r#"{"resultType":"complete","content":[],"isError":true}"#);
        let mut publication = Publication::Pending;
        publication.admit(&contract(), &event).unwrap();
        assert_eq!(publication, Publication::Complete);
    }

    #[test]
    fn successor_retains_opaque_state_without_demanding_final_output() {
        let event = event(r#"{"resultType":"input_required","requestState":"  successor\u0000  "}"#);
        let mut publication = Publication::Pending;
        publication.admit(&contract(), &event).unwrap();
        assert_eq!(publication, Publication::Successor);
        assert!(publication.can_return());
        let ManagedInteractionEvent::InputRequired(input) = &event else { unreachable!() };
        assert_eq!(input.request_state(), Some("  successor\0  "));
    }

    #[test]
    fn individual_and_catalog_invalidation_fence_both_terminal_and_successor_replies() {
        for catalog in [false, true] {
            for event in [success(), event(r#"{"resultType":"input_required","requestState":"state"}"#)] {
                let mut contract = contract();
                if catalog {
                    contract.catalog_invalidated = Some(Arc::new(AtomicBool::new(true)));
                } else { contract.invalidate(); }
                let mut publication = Publication::Pending;
                assert!(matches!(publication.admit(&contract, &event),
                    Err(ManagedToolRecoveryError::Tool(ManagedToolError::Invalidated))));
                assert_eq!(publication, Publication::Closed);
                assert!(!publication.can_return());
            }
        }
    }

    #[test]
    fn duplicate_publication_is_refused_without_reopening_a_delivered_reply() {
        let mut publication = Publication::Pending;
        publication.admit(&contract(), &success()).unwrap();
        assert!(matches!(publication.admit(&contract(), &success()),
            Err(ManagedToolRecoveryError::Recovery(ContinuationRecoveryError::WrongPhase))));
        assert_eq!(publication, Publication::Complete);
    }

    #[test]
    fn notifications_and_unread_results_do_not_unlock_handback() {
        let mut publication = Publication::Pending;
        assert!(!publication.can_return());
        let notification = ManagedInteractionEvent::Notification(Box::new(ServerNotification::ToolsListChanged(None)));
        assert!(matches!(publication.admit(&contract(), &notification),
            Err(ManagedToolRecoveryError::Recovery(ContinuationRecoveryError::JsonReplyRequired))));
        assert!(!publication.can_return());
        assert_eq!(publication, Publication::Closed);
    }

    #[test]
    fn invalid_recovered_output_does_not_invalidate_the_shared_contract_or_siblings() {
        let contract = contract();
        let mut failed = Publication::Pending;
        assert!(failed.admit(&contract, &event(r#"{"resultType":"complete","content":[]}"#)).is_err());
        assert!(!contract.invalidated.load(Ordering::Acquire));
        assert!(contract.check().is_ok());
        let mut sibling = Publication::Pending;
        sibling.admit(&contract, &success()).unwrap();
        assert_eq!(sibling, Publication::Complete);
        assert_eq!(failed, Publication::Closed);
    }
}
