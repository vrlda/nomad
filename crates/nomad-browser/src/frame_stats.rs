//! Frame-time profiling for the native redraw path.
//!
//! Enabled with `NOMAD_FRAME_STATS=1`. Collects one duration per
//! `RedrawRequested` pass and periodically prints a summary to stderr: the
//! achieved frame rate, the mean and worst frame times in the reporting
//! window, and the number of missed frames measured against the display
//! refresh interval. A final summary is printed when the browser exits.
//!
//! This measures the chrome-side redraw pass only. Servo-internal compositor
//! work and event coalescing are not visible at this layer.

use std::time::{Duration, Instant};

/// How often the rolling summary is printed while the browser runs.
const REPORT_INTERVAL: Duration = Duration::from_secs(5);
/// A frame is "missed" when it takes more than 1.5x the refresh interval.
const MISSED_FRAME_FACTOR: f64 = 1.5;
/// Assumed refresh rate when the monitor does not report one.
const DEFAULT_REFRESH_HZ: f64 = 60.0;

pub(crate) struct FrameProfiler {
    expected_frame_interval: Duration,
    window: Vec<f64>,
    missed_frames: u64,
    total_frames: u64,
    report_started: Instant,
}

impl FrameProfiler {
    /// Returns `None` unless `NOMAD_FRAME_STATS=1`. The expected frame
    /// interval comes from the window's current monitor refresh rate.
    pub(crate) fn from_env(refresh_rate_milli_hz: Option<u32>) -> Option<Self> {
        if std::env::var("NOMAD_FRAME_STATS").ok().as_deref() != Some("1") {
            return None;
        }
        let refresh_hz = match refresh_rate_milli_hz {
            Some(milli_hz) if milli_hz > 0 => f64::from(milli_hz) / 1000.0,
            _ => DEFAULT_REFRESH_HZ,
        };
        eprintln!("Nomad frame statistics enabled: expected refresh {refresh_hz:.3} Hz");
        Some(Self {
            expected_frame_interval: Duration::from_secs_f64(1.0 / refresh_hz),
            window: Vec::new(),
            missed_frames: 0,
            total_frames: 0,
            report_started: Instant::now(),
        })
    }

    /// Records one completed redraw pass and prints the rolling summary when
    /// the report interval has elapsed.
    pub(crate) fn record_frame(&mut self, duration: Duration, now: Instant) {
        let frame_ms = duration.as_secs_f64() * 1000.0;
        self.window.push(frame_ms);
        self.total_frames += 1;
        if frame_ms > MISSED_FRAME_FACTOR * self.expected_frame_interval.as_secs_f64() * 1000.0 {
            self.missed_frames += 1;
        }
        let elapsed = now - self.report_started;
        if elapsed >= REPORT_INTERVAL {
            self.report(now, elapsed);
            self.window.clear();
            self.missed_frames = 0;
            self.total_frames = 0;
            self.report_started = now;
        }
    }

    /// Prints the final summary over the whole remaining window.
    pub(crate) fn finish(&mut self, now: Instant) {
        let elapsed = now - self.report_started;
        if elapsed.is_zero() {
            return;
        }
        self.report(now, elapsed);
        self.window.clear();
        self.missed_frames = 0;
        self.total_frames = 0;
        self.report_started = now;
    }

    fn report(&self, now: Instant, elapsed: Duration) {
        if self.window.is_empty() {
            return;
        }
        let mut samples = self.window.clone();
        samples.sort_by(f64::total_cmp);
        #[allow(clippy::cast_precision_loss)] // Window holds at most a few seconds of frames.
        let mean = samples.iter().sum::<f64>() / samples.len() as f64;
        let p95 = samples[(samples.len() * 95 / 100).min(samples.len() - 1)];
        let worst = samples[samples.len() - 1];
        let seconds = elapsed.as_secs_f64();
        #[allow(clippy::cast_precision_loss)] // Frame counts are far below f64 precision limits.
        let fps = self.total_frames as f64 / seconds;
        eprintln!(
            "Nomad frame stats [{}s]: {:.1} fps, mean {:.2} ms, p95 {:.2} ms, max {:.2} ms, {} missed of {} frames (interval {:.2} ms), at {:?}",
            seconds.round(),
            fps,
            mean,
            p95,
            worst,
            self.missed_frames,
            self.total_frames,
            self.expected_frame_interval.as_secs_f64() * 1000.0,
            now,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::FrameProfiler;
    use std::time::Duration;

    fn profiler() -> FrameProfiler {
        FrameProfiler {
            expected_frame_interval: Duration::from_millis(1),
            window: Vec::new(),
            missed_frames: 0,
            total_frames: 0,
            report_started: std::time::Instant::now(),
        }
    }

    #[test]
    fn frames_over_one_and_a_half_intervals_count_as_missed() {
        let mut profiler = profiler();
        let start = std::time::Instant::now();
        profiler.record_frame(Duration::from_millis(1), start);
        profiler.record_frame(Duration::from_millis(2), start);
        profiler.record_frame(Duration::from_millis(5), start);
        assert_eq!(profiler.total_frames, 3);
        assert_eq!(profiler.missed_frames, 2);
    }
}
