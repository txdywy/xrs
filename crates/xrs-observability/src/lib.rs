#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Default)]
pub struct TrafficCounters {
    uplink: AtomicU64,
    downlink: AtomicU64,
}

impl TrafficCounters {
    pub fn add_uplink(&self, bytes: u64) {
        self.uplink.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_downlink(&self, bytes: u64) {
        self.downlink.fetch_add(bytes, Ordering::Relaxed);
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
}
