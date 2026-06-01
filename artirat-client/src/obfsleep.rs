use std::time::Duration;
use rand::Rng;

/// Obfuscated sleep — splits a single sleep into randomised micro-sleeps
/// to evade sandboxes that monitor sleep calls for acceleration detection.
pub fn obfuscated_sleep(total_ms: u64) {
    let mut rng = rand::thread_rng();
    let mut remaining = total_ms;
    while remaining > 0 {
        let chunk = if remaining > 50 {
            rng.gen_range(10..=std::cmp::min(remaining, 100))
        } else {
            remaining
        };
        std::thread::sleep(Duration::from_millis(chunk));
        remaining -= chunk;

        let junk_loops = rng.gen_range(0..5);
        for _ in 0..junk_loops {
            let _ = rng.gen_range(0..u64::MAX).wrapping_mul(0xDEADBEEF);
        }
    }
}

/// Tokio-compatible async obfuscated sleep
pub async fn obfuscated_sleep_async(total_ms: u64) {
    let mut remaining = total_ms;
    while remaining > 0 {
        let chunk = {
            let mut rng = rand::thread_rng();
            if remaining > 50 {
                rng.gen_range(10..=std::cmp::min(remaining, 100))
            } else {
                remaining
            }
        };
        tokio::time::sleep(Duration::from_millis(chunk)).await;
        remaining -= chunk;
    }
}
