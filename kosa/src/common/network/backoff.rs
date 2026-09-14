use std::time::Duration;

const INITIAL_MS: u64 = 1_000;
const CAP_MS: u64 = 60_000;

pub(crate) fn capped_delay_ms(attempt: u32) -> u64 {
    INITIAL_MS
        .saturating_mul(1u64 << attempt.min(16))
        .min(CAP_MS)
}

pub(crate) fn reconnect_delay(attempt: u32) -> Duration {
    let cap = capped_delay_ms(attempt);
    Duration::from_millis(rand::random_range(0..=cap))
}

#[cfg(test)]
mod tests {
    use super::capped_delay_ms;

    #[test]
    fn delay_starts_at_one_second() {
        assert_eq!(capped_delay_ms(0), 1_000);
    }

    #[test]
    fn delay_doubles_until_cap() {
        assert_eq!(capped_delay_ms(1), 2_000);
        assert_eq!(capped_delay_ms(2), 4_000);
        assert_eq!(capped_delay_ms(5), 32_000);
        assert_eq!(capped_delay_ms(6), 60_000);
        assert_eq!(capped_delay_ms(10), 60_000);
        assert_eq!(capped_delay_ms(32), 60_000);
    }
}
