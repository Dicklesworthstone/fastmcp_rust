use super::*;

fn working(interval_ms: Option<u64>) -> Task {
    let mut value = json!({
        "taskId":"task-one","status":"working",
        "createdAt":"2026-09-16T00:00:00Z","lastUpdatedAt":"2026-09-16T00:00:00Z",
        "ttlMs":null
    });
    if let Some(interval) = interval_ms {
        value["pollIntervalMs"] = json!(interval);
    }
    serde_json::from_value(value).unwrap()
}

#[test]
fn fallback_policy_is_explicit_finite_and_honors_peer_hint() {
    let base = DpopTaskWatchPolicy::new(6).unwrap();
    for (polls, interval) in [
        (0, Duration::from_millis(1)),
        (1025, Duration::from_millis(1)),
        (1, Duration::ZERO),
        (1, Duration::from_secs(61)),
    ] {
        assert!(base.with_polling_fallback(polls, interval).is_err());
    }
    let policy = base.with_polling_fallback(2, Duration::from_millis(100)).unwrap();
    let mut state = WatchState::new("fallback", policy, limits(4)).unwrap();
    let now = asupersync::Time::from_nanos(1_000);
    state.note_snapshot(now, &working(Some(300))).unwrap();
    assert_eq!(
        state.begin_fallback_poll().unwrap(),
        Some(now.saturating_add_nanos(300_000_000))
    );
    let later = now.saturating_add_nanos(400_000_000);
    state.note_snapshot(later, &working(Some(1))).unwrap();
    assert_eq!(
        state.begin_fallback_poll().unwrap(),
        Some(later.saturating_add_nanos(100_000_000))
    );
    assert!(matches!(
        state.begin_fallback_poll(),
        Err(DpopTaskWatchError::FallbackLimit)
    ));
}

#[test]
fn fallback_disabled_and_snapshot_budget_remain_fail_closed() {
    let mut state = WatchState::new(
        "watch", DpopTaskWatchPolicy::new(4).unwrap(), limits(2),
    ).unwrap();
    state.note_snapshot(asupersync::Time::from_nanos(0), &working(None)).unwrap();
    assert_eq!(state.begin_fallback_poll().unwrap(), None);

    let policy = DpopTaskWatchPolicy::new(1).unwrap()
        .with_polling_fallback(1, Duration::from_millis(1)).unwrap();
    let mut state = WatchState::new("watch", policy, limits(2)).unwrap();
    state.snapshot_request(&task()).unwrap();
    state.note_snapshot(asupersync::Time::from_nanos(0), &working(None)).unwrap();
    assert!(matches!(
        state.begin_fallback_poll(),
        Err(DpopTaskWatchError::SnapshotLimit)
    ));
    assert_eq!(state.fallback_polls, 0);
}
