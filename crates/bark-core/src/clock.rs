//! Monotonic timing and latency accounting.
//!
//! Every latency number BARK reports comes from here. Two rules govern this
//! module:
//!
//! 1. **One clock.** All stage timestamps come from `QueryPerformanceCounter`,
//!    which is monotonic, cheap (a few nanoseconds, usually no syscall) and has
//!    sub-microsecond resolution. Mixing clocks produces stage timings that do
//!    not add up, which makes the whole instrumentation useless.
//! 2. **Microseconds, as `u64`.** Milliseconds are too coarse to see a 300 µs
//!    encoder regression. Floating point invites drift in accumulated sums.
//!
//! Timestamps are relative to an arbitrary epoch fixed at process start, so they
//! are only comparable within one machine. [`ClockOffset`] handles converting a
//! peer's timestamps into the local timeline.

use std::sync::atomic::{AtomicU64, Ordering};

/// Ticks per second reported by the platform timer, cached on first use.
static QPC_FREQ: AtomicU64 = AtomicU64::new(0);
/// The counter value at process start, so returned values begin near zero.
static QPC_EPOCH: AtomicU64 = AtomicU64::new(0);

#[cfg(windows)]
#[inline]
fn raw_counter() -> u64 {
    use windows::Win32::System::Performance::QueryPerformanceCounter;
    let mut v: i64 = 0;
    // Documented to always succeed on Windows XP and later.
    unsafe { let _ = QueryPerformanceCounter(&mut v); }
    v as u64
}

#[cfg(not(windows))]
#[inline]
fn raw_counter() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}

#[cfg(windows)]
fn raw_frequency() -> u64 {
    use windows::Win32::System::Performance::QueryPerformanceFrequency;
    let mut v: i64 = 0;
    unsafe { let _ = QueryPerformanceFrequency(&mut v); }
    if v <= 0 { 10_000_000 } else { v as u64 }
}

#[cfg(not(windows))]
fn raw_frequency() -> u64 {
    1_000_000_000
}

#[inline]
fn ensure_init() -> (u64, u64) {
    let mut f = QPC_FREQ.load(Ordering::Relaxed);
    if f == 0 {
        f = raw_frequency();
        QPC_FREQ.store(f, Ordering::Relaxed);
        QPC_EPOCH.store(raw_counter(), Ordering::Relaxed);
    }
    (f, QPC_EPOCH.load(Ordering::Relaxed))
}

/// Call once at process start so the first `now_us()` in a hot path does not pay
/// for initialisation. Optional; everything works without it.
pub fn init() {
    let _ = ensure_init();
}

/// Microseconds since this process started. Monotonic.
#[inline]
pub fn now_us() -> u64 {
    let (freq, epoch) = ensure_init();
    let now = raw_counter();
    let delta = now.wrapping_sub(epoch);
    // Split the multiply so a long-running process cannot overflow: at 10 MHz,
    // `delta * 1_000_000` overflows u64 after about 21 hours.
    let secs = delta / freq;
    let rem = delta % freq;
    secs * 1_000_000 + (rem * 1_000_000) / freq
}

/// Nanoseconds since process start, for measuring things too fast for
/// microsecond resolution (a single memcpy, a lock acquisition).
#[inline]
pub fn now_ns() -> u64 {
    let (freq, epoch) = ensure_init();
    let delta = raw_counter().wrapping_sub(epoch);
    let secs = delta / freq;
    let rem = delta % freq;
    secs * 1_000_000_000 + (rem * 1_000_000_000) / freq
}

/// Wall-clock microseconds since the Unix epoch. For log lines and "last seen"
/// columns only, never for latency arithmetic: it can jump backwards when the
/// machine syncs its time.
pub fn unix_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

/// Converts between a peer's monotonic timeline and the local one.
///
/// Both ends start their clock at process start, so their timestamps are
/// unrelated. Every round trip gives an estimate of the offset between them.
/// The minimum observed round trip is the least contaminated by queueing, so
/// the offset derived from it is the most accurate one available; that is the
/// standard approach used by NTP and by RTP sender reports, and it is what lets
/// BARK report a genuine *one-way* network transit time rather than halving an
/// RTT and hoping the path is symmetric.
#[derive(Debug, Clone, Copy)]
pub struct ClockOffset {
    /// local_us - peer_us, for the sample with the smallest round trip seen.
    offset_us: i64,
    /// The round trip that produced the current offset.
    best_rtt_us: u64,
    samples: u32,
}

impl Default for ClockOffset {
    fn default() -> Self {
        Self::new()
    }
}

impl ClockOffset {
    pub fn new() -> Self {
        ClockOffset { offset_us: 0, best_rtt_us: u64::MAX, samples: 0 }
    }

    /// Feeds one round trip.
    ///
    /// * `sent_local` — local time the probe was sent
    /// * `peer_time`  — peer's clock when it handled the probe
    /// * `recv_local` — local time the reply came back
    pub fn observe(&mut self, sent_local: u64, peer_time: u64, recv_local: u64) {
        let rtt = recv_local.saturating_sub(sent_local);
        self.samples = self.samples.saturating_add(1);

        // Assume the peer handled the probe at the midpoint of the round trip.
        // That assumption is wrong on an asymmetric path, but the error is
        // bounded by the asymmetry and shrinks as we see less-delayed samples.
        let midpoint = sent_local as i64 + (rtt as i64) / 2;
        let offset = midpoint - peer_time as i64;

        // Only trust a sample that beats the best round trip seen so far. Allow
        // slow upward drift so the estimate can recover if the path genuinely
        // changes (for instance a relayed session upgrading to direct).
        if rtt <= self.best_rtt_us {
            self.best_rtt_us = rtt;
            self.offset_us = offset;
        } else if self.best_rtt_us != u64::MAX {
            self.best_rtt_us = self.best_rtt_us.saturating_add(self.best_rtt_us / 256 + 1);
        }
    }

    /// Translates a peer timestamp into the local timeline.
    #[inline]
    pub fn to_local(&self, peer_us: u64) -> u64 {
        (peer_us as i64 + self.offset_us).max(0) as u64
    }

    /// True once enough round trips have been seen for the estimate to be worth
    /// showing. Below this the panel reports transit time as unavailable rather
    /// than showing a number that is mostly noise.
    pub fn is_calibrated(&self) -> bool {
        self.samples >= 8 && self.best_rtt_us != u64::MAX
    }

    pub fn best_rtt_us(&self) -> Option<u64> {
        (self.best_rtt_us != u64::MAX).then_some(self.best_rtt_us)
    }
}

/// A rolling window of latency samples.
///
/// Latency is reported as median and 95th percentile rather than as a mean.
/// A mean hides exactly the thing that makes a session feel bad: the occasional
/// 80 ms frame among 59 good ones. The window is small and sorted on demand,
/// which costs nothing at the once-per-second rate the panel refreshes at.
#[derive(Debug, Clone)]
pub struct LatencyWindow {
    samples: Vec<u32>,
    next: usize,
    capacity: usize,
    /// Exponentially weighted mean, updated per sample, for the smooth number
    /// shown in the status bar where a jittery readout would be distracting.
    ewma_us: f32,
    count: u64,
}

impl LatencyWindow {
    pub fn new(capacity: usize) -> Self {
        LatencyWindow {
            samples: Vec::with_capacity(capacity),
            next: 0,
            capacity: capacity.max(1),
            ewma_us: 0.0,
            count: 0,
        }
    }

    pub fn push_us(&mut self, us: u64) {
        let v = us.min(u32::MAX as u64) as u32;
        if self.samples.len() < self.capacity {
            self.samples.push(v);
        } else {
            self.samples[self.next] = v;
            self.next = (self.next + 1) % self.capacity;
        }
        self.count += 1;
        // Converge quickly for the first samples, then settle to a 1/16 weight.
        let alpha = if self.count < 16 { 1.0 / self.count as f32 } else { 1.0 / 16.0 };
        self.ewma_us += alpha * (v as f32 - self.ewma_us);
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn total_samples(&self) -> u64 {
        self.count
    }

    pub fn ewma_us(&self) -> u32 {
        self.ewma_us as u32
    }

    /// Percentile in 0..=100, computed over the current window.
    pub fn percentile_us(&self, pct: u8) -> u32 {
        if self.samples.is_empty() {
            return 0;
        }
        let mut sorted = self.samples.clone();
        sorted.sort_unstable();
        let pct = pct.min(100) as usize;
        // Nearest-rank: the smallest value at or above the requested rank.
        let rank = (pct * sorted.len()).div_ceil(100);
        let idx = rank.saturating_sub(1).min(sorted.len() - 1);
        sorted[idx]
    }

    pub fn median_us(&self) -> u32 {
        self.percentile_us(50)
    }

    pub fn p95_us(&self) -> u32 {
        self.percentile_us(95)
    }

    pub fn max_us(&self) -> u32 {
        self.samples.iter().copied().max().unwrap_or(0)
    }

    pub fn min_us(&self) -> u32 {
        self.samples.iter().copied().min().unwrap_or(0)
    }

    /// Mean absolute deviation between consecutive samples: the interarrival
    /// jitter figure the info panel shows.
    pub fn jitter_us(&self) -> u32 {
        if self.samples.len() < 2 {
            return 0;
        }
        let mut total = 0u64;
        for w in self.samples.windows(2) {
            total += (w[1] as i64 - w[0] as i64).unsigned_abs();
        }
        (total / (self.samples.len() as u64 - 1)) as u32
    }

    pub fn clear(&mut self) {
        self.samples.clear();
        self.next = 0;
        self.ewma_us = 0.0;
        self.count = 0;
    }
}

/// A waitable timer with sub-millisecond accuracy, used by the frame pacer.
///
/// `std::thread::sleep` rounds up to the system timer resolution, historically
/// 15.6 ms and still 1 ms at best. Sleeping 1 ms when 4 ms was asked for, or
/// 15 ms when 4 ms was asked for, wrecks frame pacing. A high-resolution
/// waitable timer sleeps accurately without raising the timer resolution
/// globally, which would cost battery life across the whole machine.
#[cfg(windows)]
pub struct PreciseTimer {
    handle: windows::Win32::Foundation::HANDLE,
}

#[cfg(windows)]
impl PreciseTimer {
    pub fn new() -> crate::Result<Self> {
        use windows::Win32::System::Threading::{
            CreateWaitableTimerExW, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS,
        };
        let handle = unsafe {
            CreateWaitableTimerExW(
                None,
                None,
                CREATE_WAITABLE_TIMER_HIGH_RESOLUTION,
                TIMER_ALL_ACCESS.0,
            )
        }?;
        Ok(PreciseTimer { handle })
    }

    /// Sleeps for approximately `us` microseconds. Returns immediately for zero.
    pub fn sleep_us(&self, us: u64) {
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::{SetWaitableTimer, WaitForSingleObject, INFINITE};
        if us == 0 {
            return;
        }
        // Negative due time means "relative", in 100 ns units.
        let due: i64 = -((us as i64) * 10);
        unsafe {
            if SetWaitableTimer(self.handle, &due, 0, None, None, false).is_err() {
                // Fall back to a coarse sleep rather than spinning a core.
                std::thread::sleep(std::time::Duration::from_micros(us));
                return;
            }
            let r = WaitForSingleObject(self.handle, INFINITE);
            debug_assert_eq!(r, WAIT_OBJECT_0);
        }
    }

    /// Sleeps until `target_us` on the local monotonic clock.
    ///
    /// The last fraction of a millisecond is spent yielding rather than
    /// sleeping, because even a high-resolution timer can overshoot by a few
    /// hundred microseconds under load, and overshooting is what shows up as a
    /// dropped frame.
    pub fn sleep_until_us(&self, target_us: u64) {
        const SPIN_THRESHOLD_US: u64 = 400;
        loop {
            let now = now_us();
            if now >= target_us {
                return;
            }
            let remaining = target_us - now;
            if remaining > SPIN_THRESHOLD_US {
                self.sleep_us(remaining - SPIN_THRESHOLD_US);
            } else {
                std::hint::spin_loop();
                std::thread::yield_now();
            }
        }
    }
}

#[cfg(windows)]
impl Drop for PreciseTimer {
    fn drop(&mut self) {
        use windows::Win32::Foundation::CloseHandle;
        unsafe { let _ = CloseHandle(self.handle); }
    }
}

// The handle is only used from the thread that owns the timer, but the struct
// itself may be moved between threads before use (for example, constructed on
// the setup path and handed to the pacer thread).
#[cfg(windows)]
unsafe impl Send for PreciseTimer {}

/// Records the moment each pipeline stage happened for one frame.
///
/// Values are microseconds on the clock of whichever machine stamped them; the
/// capture-side fields are stamped by the remote, the rest by the controller.
/// [`ClockOffset`] is applied before any cross-machine subtraction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FrameStamps {
    pub frame_id: u64,
    pub capture_begin: u64,
    pub capture_end: u64,
    pub encode_begin: u64,
    pub encode_end: u64,
    pub send: u64,
    pub receive: u64,
    pub decode_begin: u64,
    pub decode_end: u64,
    pub present: u64,
    /// The controller timestamp of the most recent input event the remote had
    /// processed when this frame was captured. Zero if no input was pending.
    /// This is what makes true input-to-photon measurement possible.
    pub input_echo: u64,
}

/// Per-stage durations in microseconds, derived from [`FrameStamps`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StageLatencies {
    pub capture_us: u32,
    pub encode_us: u32,
    pub transit_us: u32,
    pub decode_us: u32,
    pub render_us: u32,
    pub total_us: u32,
    /// Time from the input event leaving the controller to the first frame that
    /// reflects it being on screen. `None` when the frame carried no echo.
    pub input_to_photon_us: Option<u32>,
}

impl FrameStamps {
    /// Computes stage durations, converting the remote's timestamps into the
    /// local timeline first.
    pub fn latencies(&self, offset: &ClockOffset) -> StageLatencies {
        let capture_begin = offset.to_local(self.capture_begin);
        let capture_end = offset.to_local(self.capture_end);
        let encode_begin = offset.to_local(self.encode_begin);
        let encode_end = offset.to_local(self.encode_end);
        let send = offset.to_local(self.send);

        let sub = |a: u64, b: u64| -> u32 { a.saturating_sub(b).min(u32::MAX as u64) as u32 };

        StageLatencies {
            capture_us: sub(capture_end, capture_begin),
            encode_us: sub(encode_end, encode_begin),
            transit_us: sub(self.receive, send),
            decode_us: sub(self.decode_end, self.decode_begin),
            render_us: sub(self.present, self.decode_end),
            total_us: sub(self.present, capture_begin),
            input_to_photon_us: (self.input_echo != 0).then(|| sub(self.present, self.input_echo)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monotonic_clock_moves_forward() {
        let a = now_us();
        let mut b = now_us();
        for _ in 0..1000 {
            b = now_us();
        }
        assert!(b >= a, "{b} < {a}");
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let mut w = LatencyWindow::new(100);
        for i in 1..=100u64 {
            w.push_us(i * 1000);
        }
        assert_eq!(w.median_us(), 50_000);
        assert_eq!(w.p95_us(), 95_000);
        assert_eq!(w.max_us(), 100_000);
        assert_eq!(w.min_us(), 1_000);
        assert_eq!(w.percentile_us(100), 100_000);
    }

    #[test]
    fn window_wraps_and_keeps_only_recent_samples() {
        let mut w = LatencyWindow::new(4);
        for v in [100u64, 200, 300, 400, 500, 600] {
            w.push_us(v);
        }
        assert_eq!(w.len(), 4);
        assert_eq!(w.min_us(), 300, "the two oldest samples should be gone");
        assert_eq!(w.max_us(), 600);
        assert_eq!(w.total_samples(), 6);
    }

    #[test]
    fn empty_window_reports_zero_rather_than_panicking() {
        let w = LatencyWindow::new(8);
        assert!(w.is_empty());
        assert_eq!(w.median_us(), 0);
        assert_eq!(w.p95_us(), 0);
        assert_eq!(w.jitter_us(), 0);
    }

    #[test]
    fn jitter_is_mean_consecutive_difference() {
        let mut w = LatencyWindow::new(8);
        for v in [1000u64, 1100, 1000, 1100] {
            w.push_us(v);
        }
        assert_eq!(w.jitter_us(), 100);
    }

    #[test]
    fn clock_offset_recovers_a_known_skew() {
        // Peer clock runs 5_000_000 µs behind ours; path takes 10 ms each way.
        let skew = 5_000_000i64;
        let mut off = ClockOffset::new();
        for i in 0..20u64 {
            let sent = 1_000_000 + i * 1000;
            let peer = (sent as i64 + 10_000 - skew) as u64;
            let recv = sent + 20_000;
            off.observe(sent, peer, recv);
        }
        assert!(off.is_calibrated());
        let peer_now = 500_000u64;
        let local = off.to_local(peer_now);
        let expected = (peer_now as i64 + skew) as u64;
        let err = (local as i64 - expected as i64).abs();
        assert!(err < 1_000, "offset error {err} µs is too large");
    }

    #[test]
    fn latencies_add_up_and_subtract_safely() {
        let s = FrameStamps {
            frame_id: 1,
            capture_begin: 1_000,
            capture_end: 1_500,
            encode_begin: 1_500,
            encode_end: 3_200,
            send: 3_300,
            receive: 9_000,
            decode_begin: 9_100,
            decode_end: 10_400,
            present: 11_000,
            input_echo: 500,
        };
        let l = s.latencies(&ClockOffset::new());
        assert_eq!(l.capture_us, 500);
        assert_eq!(l.encode_us, 1_700);
        assert_eq!(l.transit_us, 5_700);
        assert_eq!(l.decode_us, 1_300);
        assert_eq!(l.render_us, 600);
        assert_eq!(l.total_us, 10_000);
        assert_eq!(l.input_to_photon_us, Some(10_500));
    }

    #[test]
    fn out_of_order_stamps_do_not_underflow() {
        // A frame whose stamps are nonsense (clock adjusted, bug upstream) must
        // report zero rather than a four-billion-microsecond latency.
        let s = FrameStamps { present: 0, capture_begin: 9_999, ..Default::default() };
        let l = s.latencies(&ClockOffset::new());
        assert_eq!(l.total_us, 0);
        assert_eq!(l.input_to_photon_us, None);
    }
}
