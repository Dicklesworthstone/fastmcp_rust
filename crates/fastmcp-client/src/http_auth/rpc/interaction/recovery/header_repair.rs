//! Transfer one actual, unread header-repair retry into the normal MRTR owner.
//! There is no response decoder, send, catalog lookup, or replacement budget here.

use std::sync::Arc;

use asupersync::Cx;
use fastmcp_protocol::RequestId;

use super::super::{
    ManagedCoreCall, ManagedCoreError, ManagedInteraction, ManagedInteractionError,
    ManagedInteractionLimits, ManagedOAuthSession, Step, admit_fresh_id, check_call,
    validate_initial,
};
use crate::http_executor::parameter_headers::ReviewedToolHeaders;

impl ManagedInteraction {
    /// Crate-only handoff from the single-use repair capsule. The retry body
    /// has not been read, so its decoder remains the sole publication authority.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_repaired_call(
        cx: &Cx,
        session: ManagedOAuthSession,
        mut call: ManagedCoreCall,
        reviewed: Arc<ReviewedToolHeaders>,
        ids: Vec<RequestId>,
        continuations: usize,
        responses: usize,
    ) -> Result<Self, ManagedInteractionError> {
        let limits = ManagedInteractionLimits::new(call.decoder.limits, continuations, responses)?;
        validate_initial(&call.decoder.request)?;
        admit_history(&ids, call.request_id())?;
        if call.finished || call.body.is_none() || call.decoder.notifications != 0
            || call.decoder.last_progress.is_some()
            || call.decoder.request.method() != "tools/call"
            || reviewed.resource() != session.resource()
        {
            return Err(ManagedCoreError::InvalidResponse.into());
        }
        call.deadline = cx.budget().deadline.map_or(call.deadline, |parent| parent.min(call.deadline));
        check_call(cx, &call.cancellation, call.deadline)?;
        // Reject the impossible internal handoff rather than resetting usage.
        // The repair stage already reserved a complete final frame's capacity.
        if call.decoder.bytes >= limits.core.total_bytes {
            return Err(ManagedCoreError::ResponseByteLimit.into());
        }
        Ok(Self {
            session, original: call.decoder.request.clone(), header_review: Some(reviewed),
            cancellation: call.cancellation.clone(), deadline: call.deadline, limits,
            used_ids: ids, continuations: 0, input_responses: 0,
            response_bytes: call.decoder.bytes, notifications: call.decoder.notifications,
            generation: call.credential_generation(), step: Some(Step::Reading(Box::new(call))),
        })
    }
}

fn admit_history(ids: &[RequestId], current: &RequestId) -> Result<(), ManagedInteractionError> {
    // At least the rejected call, one catalog page and the successful retry.
    // Upper bounds and encoded-byte accounting belong to repair's IdLedger.
    if ids.len() < 3 || !ids.last().is_some_and(|id| id.correlates_with(current)) {
        return Err(ManagedCoreError::InvalidResponse.into());
    }
    for (index, id) in ids.iter().enumerate() { admit_fresh_id(&ids[..index], id)?; }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handoff_preserves_every_reserved_request_id() {
        let ids = vec![RequestId::Number(7), RequestId::String("page-one".to_owned()),
            RequestId::String("page-two".to_owned()), RequestId::Number(8)];
        admit_history(&ids, &RequestId::Number(8)).unwrap();
        for id in &ids {
            assert!(matches!(admit_fresh_id(&ids, id), Err(ManagedInteractionError::RepeatedRequestId)));
        }
        admit_fresh_id(&ids, &RequestId::Number(9)).unwrap();
    }

    #[test]
    fn handoff_rejects_missing_mismatched_or_duplicate_history() {
        for ids in [vec![], vec![RequestId::Number(1), RequestId::Number(3)],
            vec![RequestId::Number(1), RequestId::Number(2), RequestId::Number(4)]] {
            assert!(matches!(admit_history(&ids, &RequestId::Number(3)),
                Err(ManagedInteractionError::Core(ManagedCoreError::InvalidResponse))));
        }
        assert!(matches!(admit_history(&[RequestId::Number(1), RequestId::Number(1), RequestId::Number(3)],
            &RequestId::Number(3)), Err(ManagedInteractionError::RepeatedRequestId)));
    }

    #[test]
    fn continuation_limits_do_not_replace_original_core_bounds() {
        let core = super::super::super::super::ManagedCoreLimits::new(
            1024, 2048, 8192, 3, std::time::Duration::from_secs(7),
        ).unwrap();
        let limits = ManagedInteractionLimits::new(core, 2, 4).unwrap();
        assert_eq!(limits.core.request_bytes, 1024);
        assert_eq!(limits.core.frame_bytes, 2048);
        assert_eq!(limits.core.total_bytes, 8192);
        assert_eq!(limits.core.notifications, 3);
        assert_eq!(limits.core.timeout, std::time::Duration::from_secs(7));
        assert!(ManagedInteractionLimits::new(core, 65, 4).is_err());
        assert!(ManagedInteractionLimits::new(core, 2, 1025).is_err());
        assert!(ManagedInteractionLimits::new(core, 0, 0).is_ok());
    }
}
