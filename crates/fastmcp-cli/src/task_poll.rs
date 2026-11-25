//! Read-only observation when the operator selects polling instead of a listener.

use std::time::{Duration, Instant};

use asupersync::Cx;
use chrono::{DateTime, Utc};
use fastmcp_core::{McpError, McpResult};
use fastmcp_protocol::tasks_extension::Task;

use super::{TaskCommandBudget, TaskOutput, reconcile_task_snapshot, wait_for_task_poll_delay};

const DEFAULT_INTERVAL: Duration = Duration::from_secs(1);
const MAX_READS: usize = 4096;

fn instant_nanos<T: chrono::TimeZone>(instant: &DateTime<T>) -> i128 {
    i128::from(instant.timestamp()) * 1_000_000_000 + i128::from(instant.timestamp_subsec_nanos())
}

fn created(task: &Task) -> McpResult<i128> {
    DateTime::parse_from_rfc3339(task.base().created_at.as_str())
        .map(|date| instant_nanos(&date))
        .map_err(|_| McpError::invalid_request("invalid Task creation instant"))
}

fn interval(task: &Task) -> McpResult<Duration> {
    task.base().poll_interval_ms.as_ref().map_or(Ok(DEFAULT_INTERVAL), |value| {
        value.try_as_millis().map(Duration::from_millis)
            .map_err(|_| McpError::invalid_request("invalid Task polling interval"))
    })
}

struct PollClock {
    command: TaskCommandBudget,
    last_tick: Instant,
    last_wall: i128,
}

impl PollClock {
    fn new(command: TaskCommandBudget) -> Self {
        Self {
            command,
            last_tick: Instant::now(),
            last_wall: instant_nanos(&Utc::now()),
        }
    }

    // Keep the original command deadline. A backward civil-clock adjustment
    // must never extend the Task's lifetime; a forward adjustment can shorten it.
    fn remaining(&mut self, cx: &Cx, task: &Task) -> McpResult<Duration> {
        cx.checkpoint().map_err(|_| McpError::request_cancelled())?;
        let remaining = self.command.remaining()?;
        let tick = Instant::now();
        self.last_wall = instant_nanos(&Utc::now())
            .max(self.last_wall + tick.duration_since(self.last_tick).as_nanos() as i128);
        self.last_tick = tick;
        let Some(ttl) = &task.base().ttl_ms else {
            return Ok(remaining);
        };
        let millis = ttl.try_as_millis().map_err(|_| McpError::invalid_request("invalid Task TTL"))?;
        let expires = created(task)? + i128::from(millis) * 1_000_000;
        if expires <= self.last_wall {
            return Err(McpError::invalid_request("Task retention expired during observation"));
        }
        // Meet a possibly huge millisecond TTL with the finite command budget
        // before narrowing to the local nanosecond clock.
        Ok(u64::try_from(expires - self.last_wall)
            .map_or(remaining, |ns| remaining.min(Duration::from_nanos(ns))))
    }

    fn accept(&mut self, cx: &Cx, previous: &Task, next: &Task) -> McpResult<()> {
        self.remaining(cx, previous)?;
        if previous.base().task_id != next.base().task_id || created(previous)? != created(next)? {
            return Err(McpError::invalid_request("task watch returned a different task identity"));
        }
        self.remaining(cx, next)?;
        Ok(())
    }
}

/// Keep one clock across the initial output and every later read. Entering
/// with a terminal snapshot still checks its identity and finite retention.
fn start(
    cx: &Cx,
    output: &TaskOutput,
    budget: TaskCommandBudget,
    expected: &fastmcp_protocol::FinalTaskId,
    task: &Task,
) -> McpResult<Option<PollClock>> {
    let mut clock = PollClock::new(budget);
    if &task.base().task_id != expected {
        return Err(McpError::invalid_request("task watch returned a different task identity"));
    }
    clock.remaining(cx, task)?;
    output.write_event(cx, "snapshot", task)?;
    if super::is_terminal_task_status(task.base().status) {
        output.write_event(cx, "watch-ended", &serde_json::json!({"reason":"task-terminal","updates":0}))?;
        return Ok(None);
    }
    Ok(Some(clock))
}

fn exhausted() -> McpError {
    McpError::internal_error("task watch exhausted its 4096 polls; task completion is unknown")
}

/// Each transport supplies exactly one authoritative get on its current client.
pub(super) async fn watch(
    cx: &Cx,
    output: &TaskOutput,
    budget: TaskCommandBudget,
    expected: &fastmcp_protocol::FinalTaskId,
    mut latest: Task,
    max_events: u64,
    mut read: impl AsyncFnMut(Duration) -> McpResult<Task>,
) -> McpResult<()> {
    let Some(mut clock) = start(cx, output, budget, expected, &latest)? else {
        return Ok(());
    };
    let mut updates = 0;
    for _ in 0..MAX_READS {
        let delay = interval(&latest)?.min(clock.remaining(cx, &latest)?);
        wait_for_task_poll_delay(cx, budget, delay).await?;
        let remaining = clock.remaining(cx, &latest)?;
        let result = asupersync::time::timeout(cx.now(), remaining, Box::pin(read(remaining))).await;
        clock.remaining(cx, &latest)?;
        let next = result.map_err(|_| McpError::internal_error("task watch read exceeded its observation deadline"))??;
        clock.accept(cx, &latest, &next)?;
        if reconcile_task_snapshot(cx, output, &latest, &next, &mut updates, max_events)? {
            return Ok(());
        }
        latest = next;
    }
    Err(exhausted())
}

#[cfg(not(unix))]
pub(super) fn watch_sync(
    cx: &Cx,
    output: &TaskOutput,
    budget: TaskCommandBudget,
    expected: &fastmcp_protocol::FinalTaskId,
    mut latest: Task,
    max_events: u64,
    mut read: impl FnMut(Duration) -> McpResult<Task>,
) -> McpResult<()> {
    let Some(mut clock) = start(cx, output, budget, expected, &latest)? else {
        return Ok(());
    };
    let mut updates = 0;
    for _ in 0..MAX_READS {
        let delay = interval(&latest)?.min(clock.remaining(cx, &latest)?);
        super::wait_for_task_poll_delay_sync(cx, budget, delay)?;
        let next = read(clock.remaining(cx, &latest)?)?;
        clock.accept(cx, &latest, &next)?;
        if reconcile_task_snapshot(cx, output, &latest, &next, &mut updates, max_events)? {
            return Ok(());
        }
        latest = next;
    }
    Err(exhausted())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_watch_refreshes_authoritative_retention_only_while_old_ttl_is_live() {
        crate::build_cli_runtime().unwrap().block_on(async {
            let initial: Task = serde_json::from_value(serde_json::json!({
                "taskId":"clock", "status":"working", "createdAt":"2090-01-01T00:00:00.123456789Z",
                "lastUpdatedAt":"2090-01-01T00:00:00.123456789Z", "ttlMs": 1000
            })).unwrap();
            let cx = Cx::current().unwrap();
            let start = created(&initial).unwrap();
            for replacement in [serde_json::Value::Null, serde_json::json!(3000)] {
                let mut wire = serde_json::to_value(&initial).unwrap();
                wire["createdAt"] = serde_json::json!("2090-01-01T02:00:00.123456789+02:00");
                wire["ttlMs"] = replacement;
                let next: Task = serde_json::from_value(wire).unwrap();
                let mut clock = PollClock::new(TaskCommandBudget {
                    deadline: Instant::now() + Duration::from_secs(10),
                });
                clock.last_wall = start + 500_000_000;
                clock.accept(&cx, &initial, &next).unwrap();
                clock.last_wall = start + 1_500_000_000;
                assert!(clock.remaining(&cx, &next).is_ok());
                assert!(clock.accept(&cx, &initial, &next).is_err());
            }
        });
    }
}
