//! Timing utilities for test measurements.
//!
//! Provides stopwatch functionality for measuring operation durations
//! in tests and benchmarks.

use std::time::{Duration, Instant};

/// Measures the duration of a closure execution.
///
/// # Example
///
/// ```ignore
/// use fastmcp::testing::prelude::*;
///
/// let (result, duration) = measure_duration(|| {
///     // Some operation
///     42
/// });
///
/// assert_eq!(result, 42);
/// println!("Operation took {:?}", duration);
/// ```
pub fn measure_duration<T, F: FnOnce() -> T>(f: F) -> (T, Duration) {
    let start = Instant::now();
    let result = f();
    let duration = start.elapsed();
    (result, duration)
}

/// A stopwatch for measuring elapsed time with lap support.
///
/// # Example
///
/// ```ignore
/// use fastmcp::testing::prelude::*;
///
/// let mut stopwatch = Stopwatch::new();
///
/// // Do first operation
/// stopwatch.lap("operation_1");
///
/// // Do second operation
/// stopwatch.lap("operation_2");
///
/// println!("Total time: {:?}", stopwatch.elapsed());
/// for (name, duration) in stopwatch.laps() {
///     println!("{}: {:?}", name, duration);
/// }
/// ```
#[derive(Debug, Clone)]
pub struct Stopwatch {
    /// Start time.
    start: Instant,
    /// Last lap time.
    last_lap: Instant,
    /// Recorded laps with names.
    laps: Vec<(String, Duration)>,
}

impl Default for Stopwatch {
    fn default() -> Self {
        Self::new()
    }
}

impl Stopwatch {
    /// Creates a new stopwatch and starts it immediately.
    #[must_use]
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start: now,
            last_lap: now,
            laps: Vec::new(),
        }
    }

    /// Creates a stopped stopwatch that starts when `start()` is called.
    #[must_use]
    pub fn stopped() -> Self {
        // Use a sentinel value; will be overwritten by start()
        let now = Instant::now();
        Self {
            start: now,
            last_lap: now,
            laps: Vec::new(),
        }
    }

    /// Restarts the stopwatch, clearing all laps.
    pub fn restart(&mut self) {
        let now = Instant::now();
        self.start = now;
        self.last_lap = now;
        self.laps.clear();
    }

    /// Records a lap with the given name.
    ///
    /// The duration is measured from the last lap (or start if no laps).
    pub fn lap(&mut self, name: impl Into<String>) {
        let now = Instant::now();
        let duration = now - self.last_lap;
        self.laps.push((name.into(), duration));
        self.last_lap = now;
    }

    /// Returns the total elapsed time since the stopwatch started.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }

    /// Returns the time since the last lap (or start if no laps).
    #[must_use]
    pub fn since_last_lap(&self) -> Duration {
        self.last_lap.elapsed()
    }

    /// Returns all recorded laps.
    #[must_use]
    pub fn laps(&self) -> &[(String, Duration)] {
        &self.laps
    }

    /// Returns the number of recorded laps.
    #[must_use]
    pub fn lap_count(&self) -> usize {
        self.laps.len()
    }

    /// Returns the lap with the given name, if it exists.
    #[must_use]
    pub fn get_lap(&self, name: &str) -> Option<Duration> {
        self.laps
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| *d)
    }

    /// Returns the sum of all lap durations.
    #[must_use]
    pub fn total_lap_time(&self) -> Duration {
        self.laps.iter().map(|(_, d)| *d).sum()
    }

    /// Returns timing statistics.
    #[must_use]
    pub fn stats(&self) -> TimingStats {
        if self.laps.is_empty() {
            return TimingStats {
                count: 0,
                total: Duration::ZERO,
                min: None,
                max: None,
                mean: None,
            };
        }

        let durations: Vec<_> = self.laps.iter().map(|(_, d)| *d).collect();
        let total: Duration = durations.iter().sum();
        let min = durations.iter().min().copied();
        let max = durations.iter().max().copied();
        let mean = Some(total / durations.len() as u32);

        TimingStats {
            count: durations.len(),
            total,
            min,
            max,
            mean,
        }
    }

    /// Formats the stopwatch results as a human-readable report.
    #[must_use]
    pub fn report(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("Total elapsed: {:?}", self.elapsed()));
        lines.push(format!("Laps: {}", self.lap_count()));

        if !self.laps.is_empty() {
            lines.push(String::new());
            for (name, duration) in &self.laps {
                lines.push(format!("  {name}: {duration:?}"));
            }

            let stats = self.stats();
            lines.push(String::new());
            lines.push("Statistics:".to_string());
            if let Some(min) = stats.min {
                lines.push(format!("  Min: {min:?}"));
            }
            if let Some(max) = stats.max {
                lines.push(format!("  Max: {max:?}"));
            }
            if let Some(mean) = stats.mean {
                lines.push(format!("  Mean: {mean:?}"));
            }
        }

        lines.join("\n")
    }
}

/// Timing statistics for a set of measurements.
#[derive(Debug, Clone)]
pub struct TimingStats {
    /// Number of measurements.
    pub count: usize,
    /// Total duration.
    pub total: Duration,
    /// Minimum duration.
    pub min: Option<Duration>,
    /// Maximum duration.
    pub max: Option<Duration>,
    /// Mean duration.
    pub mean: Option<Duration>,
}

impl TimingStats {
    /// Returns whether there are any measurements.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
}

/// A simple timer that fires after a duration.
///
/// Useful for timeout testing.
#[derive(Debug, Clone)]
pub struct Timer {
    /// Start time.
    start: Instant,
    /// Target duration.
    duration: Duration,
}

impl Timer {
    /// Creates a new timer with the given duration.
    #[must_use]
    pub fn new(duration: Duration) -> Self {
        Self {
            start: Instant::now(),
            duration,
        }
    }

    /// Creates a timer from seconds.
    #[must_use]
    pub fn from_secs(secs: u64) -> Self {
        Self::new(Duration::from_secs(secs))
    }

    /// Creates a timer from milliseconds.
    #[must_use]
    pub fn from_millis(ms: u64) -> Self {
        Self::new(Duration::from_millis(ms))
    }

    /// Returns whether the timer has expired.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.start.elapsed() >= self.duration
    }

    /// Returns the remaining time, or zero if expired.
    #[must_use]
    pub fn remaining(&self) -> Duration {
        let elapsed = self.start.elapsed();
        if elapsed >= self.duration {
            Duration::ZERO
        } else {
            self.duration - elapsed
        }
    }

    /// Resets the timer.
    pub fn reset(&mut self) {
        self.start = Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_measure_duration() {
        let (result, duration) = measure_duration(|| {
            sleep(Duration::from_millis(10));
            42
        });

        assert_eq!(result, 42);
        assert!(duration >= Duration::from_millis(10));
    }

    #[test]
    fn test_stopwatch_basic() {
        let mut sw = Stopwatch::new();
        sleep(Duration::from_millis(10));
        sw.lap("first");
        sleep(Duration::from_millis(10));
        sw.lap("second");

        assert_eq!(sw.lap_count(), 2);
        assert!(sw.elapsed() >= Duration::from_millis(20));
    }

    #[test]
    fn test_stopwatch_get_lap() {
        let mut sw = Stopwatch::new();
        sleep(Duration::from_millis(5));
        sw.lap("test_lap");

        let lap = sw.get_lap("test_lap");
        assert!(lap.is_some());
        assert!(lap.unwrap() >= Duration::from_millis(5));

        assert!(sw.get_lap("nonexistent").is_none());
    }

    #[test]
    fn test_stopwatch_stats() {
        let mut sw = Stopwatch::new();
        sw.lap("a");
        sw.lap("b");
        sw.lap("c");

        let stats = sw.stats();
        assert_eq!(stats.count, 3);
        assert!(stats.min.is_some());
        assert!(stats.max.is_some());
        assert!(stats.mean.is_some());
    }

    #[test]
    fn test_stopwatch_empty_stats() {
        let sw = Stopwatch::new();
        let stats = sw.stats();
        assert_eq!(stats.count, 0);
        assert!(stats.is_empty());
    }

    #[test]
    fn test_stopwatch_restart() {
        let mut sw = Stopwatch::new();
        sw.lap("first");
        sw.restart();

        assert_eq!(sw.lap_count(), 0);
    }

    #[test]
    fn test_timer_basic() {
        let timer = Timer::from_millis(50);
        assert!(!timer.is_expired());
        assert!(timer.remaining() > Duration::ZERO);

        sleep(Duration::from_millis(60));
        assert!(timer.is_expired());
        assert_eq!(timer.remaining(), Duration::ZERO);
    }

    #[test]
    fn test_timer_reset() {
        let mut timer = Timer::from_millis(100);
        sleep(Duration::from_millis(50));
        timer.reset();

        // After reset, remaining should be close to full duration
        assert!(timer.remaining() > Duration::from_millis(80));
    }

    #[test]
    fn test_stopwatch_report() {
        let mut sw = Stopwatch::new();
        sw.lap("setup");
        sw.lap("execute");
        sw.lap("teardown");

        let report = sw.report();
        assert!(report.contains("Total elapsed"));
        assert!(report.contains("Laps: 3"));
        assert!(report.contains("setup"));
        assert!(report.contains("execute"));
        assert!(report.contains("teardown"));
    }
}
