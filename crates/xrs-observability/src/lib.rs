#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TrafficCounterPolicy {
    pub uplink: bool,
    pub downlink: bool,
}

impl TrafficCounterPolicy {
    #[must_use]
    pub const fn enabled() -> Self {
        Self {
            uplink: true,
            downlink: true,
        }
    }

    #[must_use]
    pub const fn disabled() -> Self {
        Self {
            uplink: false,
            downlink: false,
        }
    }
}

impl Default for TrafficCounterPolicy {
    fn default() -> Self {
        Self::enabled()
    }
}

#[derive(Debug)]
pub struct TrafficCounters {
    uplink: AtomicU64,
    downlink: AtomicU64,
    uplink_enabled: AtomicBool,
    downlink_enabled: AtomicBool,
}

impl Default for TrafficCounters {
    fn default() -> Self {
        Self::enabled()
    }
}

impl TrafficCounters {
    #[must_use]
    pub fn enabled() -> Self {
        Self::with_policy(TrafficCounterPolicy::enabled())
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self::with_policy(TrafficCounterPolicy::disabled())
    }

    #[must_use]
    pub fn with_policy(policy: TrafficCounterPolicy) -> Self {
        Self {
            uplink: AtomicU64::new(0),
            downlink: AtomicU64::new(0),
            uplink_enabled: AtomicBool::new(policy.uplink),
            downlink_enabled: AtomicBool::new(policy.downlink),
        }
    }

    pub fn add_uplink(&self, bytes: u64) {
        if self.uplink_enabled.load(Ordering::Relaxed) {
            self.uplink.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    pub fn add_downlink(&self, bytes: u64) {
        if self.downlink_enabled.load(Ordering::Relaxed) {
            self.downlink.fetch_add(bytes, Ordering::Relaxed);
        }
    }

    #[must_use]
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            uplink: self.uplink.load(Ordering::Relaxed),
            downlink: self.downlink.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficSnapshot {
    pub uplink: u64,
    pub downlink: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accumulates_traffic_counters() {
        let counters = TrafficCounters::default();
        counters.add_uplink(7);
        counters.add_downlink(9);

        assert_eq!(
            counters.snapshot(),
            TrafficSnapshot {
                uplink: 7,
                downlink: 9
            }
        );
    }

    #[test]
    fn ignores_disabled_counter_directions() {
        let counters = TrafficCounters::disabled();
        counters.add_uplink(7);
        counters.add_downlink(9);

        assert_eq!(counters.snapshot(), TrafficSnapshot::default());
    }
}
