use super::*;
use super::super::IdLedger;
use std::time::Duration;
use crate::http_auth::rpc::ManagedCoreLimits;
use crate::http_auth::rpc::interaction::admit_fresh_id;

#[test]
fn interaction_configuration_cannot_reset_repair_transport_budgets() {
    let core = ManagedCoreLimits::new(1024, 2048, 8192, 7, Duration::from_secs(9)).unwrap();
    let repair = ToolHeaderRepairLimits::new(core, 1024, 3, 5).unwrap();
    let limits = ToolHeaderInteractionLimits::new(repair, 2, 4).unwrap();
    let retained = limits.repair.core;
    assert_eq!(retained.request_bytes, core.request_bytes);
    assert_eq!(retained.frame_bytes, core.frame_bytes);
    assert_eq!(retained.total_bytes, core.total_bytes);
    assert_eq!(retained.notifications, core.notifications);
    assert_eq!(retained.timeout, core.timeout);
    assert_eq!(limits.repair.catalog_bytes, 1024);
    assert_eq!(limits.repair.catalog_pages, 3);
    assert_eq!(limits.repair.catalog_tools, 5);
    assert_eq!(limits.maximum_continuations, 2);
    assert_eq!(limits.maximum_input_responses, 4);
}

#[test]
fn zero_rounds_are_explicit_but_hard_interaction_limits_remain_binding() {
    let repair = ToolHeaderRepairLimits::default();
    assert!(ToolHeaderInteractionLimits::new(repair, 0, 0).is_ok());
    assert!(ToolHeaderInteractionLimits::new(repair, 64, 1024).is_ok());
    for (rounds, answers) in [(65, 1), (1, 1025)] {
        assert!(matches!(ToolHeaderInteractionLimits::new(repair, rounds, answers),
            Err(ManagedInteractionError::InvalidLimits)));
    }
}

#[test]
fn handoff_keeps_every_attempted_id_including_catalog_and_rejection() {
    let expected = [RequestId::Number(10), RequestId::String("catalog-page".to_owned()),
        RequestId::Number(12), RequestId::Number(13)];
    let mut ledger = IdLedger::default();
    for id in &expected { ledger.reserve(id).unwrap(); }
    let transferred = ledger.ids;
    assert_eq!(transferred, expected);
    for id in &expected {
        assert!(matches!(admit_fresh_id(&transferred, id), Err(ManagedInteractionError::RepeatedRequestId)));
    }
    // String and numeric IDs retain the protocol's distinct correlation domains.
    assert!(admit_fresh_id(&transferred, &RequestId::String("10".to_owned())).is_ok());
    assert!(admit_fresh_id(&transferred, &RequestId::Number(14)).is_ok());
}
