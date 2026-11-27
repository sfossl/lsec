use super::algorithm::{generate_code, TotpAlgorithm};
use super::error::TotpError;
use crate::config::SecurityConfig;
use crate::crypto::constant_time_eq;

pub fn verify_code_at(
    secret: &[u8],
    candidate_code: &str,
    timestamp: u64,
    config: &SecurityConfig,
    algorithm: TotpAlgorithm,
) -> Result<bool, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if config.totp_step_seconds == 0 {
        return Err(TotpError::InvalidStepSeconds);
    }

    let drift = i64::from(config.totp_drift_steps);
    let step_secs = config.totp_step_seconds;
    let candidate_bytes = candidate_code.trim().as_bytes();

    let mut is_valid = false;

    for offset in -drift..=drift {
        let Some(step_delta) = u64::from(offset.unsigned_abs()).checked_mul(step_secs) else {
            continue;
        };
        let check_time = if offset < 0 {
            timestamp.checked_sub(step_delta)
        } else {
            timestamp.checked_add(step_delta)
        };
        let Some(check_time) = check_time else {
            continue;
        };

        let expected = generate_code(
            secret,
            check_time,
            config.totp_step_seconds,
            config.totp_digits,
            algorithm,
        )?;
        if constant_time_eq(candidate_bytes, expected.as_bytes()) {
            is_valid = true;
        }
    }

    Ok(is_valid)
}

pub fn verify_code_current(
    secret: &[u8],
    candidate_code: &str,
    config: &SecurityConfig,
    algorithm: TotpAlgorithm,
) -> Result<bool, TotpError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TotpError::SystemTimeBeforeEpoch)?
        .as_secs();

    verify_code_at(secret, candidate_code, now, config, algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SECRET: &[u8] = b"12345678901234567890";

    #[test]
    fn test_verify_exact_step() {
        let config = SecurityConfig::default();
        let time = 1234567890u64;
        let valid_code = generate_code(
            RFC_SECRET,
            time,
            config.totp_step_seconds,
            config.totp_digits,
            TotpAlgorithm::Sha1,
        )
        .expect("gen");

        assert!(
            verify_code_at(RFC_SECRET, &valid_code, time, &config, TotpAlgorithm::Sha1)
                .expect("verify ok")
        );
    }

    #[test]
    fn test_verify_within_drift_window() {
        let config = SecurityConfig::builder().totp_drift_steps(1).build();
        let time = 1234567890u64;
        let past_time = time - 30;
        let past_code = generate_code(
            RFC_SECRET,
            past_time,
            config.totp_step_seconds,
            config.totp_digits,
            TotpAlgorithm::Sha1,
        )
        .expect("gen");

        assert!(
            verify_code_at(RFC_SECRET, &past_code, time, &config, TotpAlgorithm::Sha1)
                .expect("verify ok")
        );
    }

    #[test]
    fn test_verify_outside_drift_window_fails() {
        let config = SecurityConfig::builder().totp_drift_steps(1).build();
        let time = 1234567890u64;
        let far_past_time = time - 60;
        let far_past_code = generate_code(
            RFC_SECRET,
            far_past_time,
            config.totp_step_seconds,
            config.totp_digits,
            TotpAlgorithm::Sha1,
        )
        .expect("gen");

        assert!(!verify_code_at(
            RFC_SECRET,
            &far_past_code,
            time,
            &config,
            TotpAlgorithm::Sha1
        )
        .expect("verify ok"));
    }

    #[test]
    fn test_verify_invalid_code_fails() {
        let config = SecurityConfig::default();
        let time = 1234567890u64;

        assert!(
            !verify_code_at(RFC_SECRET, "000000", time, &config, TotpAlgorithm::Sha1)
                .expect("verify ok")
        );
    }

    #[test]
    fn test_verify_u64_max_timestamp_and_large_step() {
        let step = i64::MAX as u64;
        let config = SecurityConfig::builder()
            .totp_step_seconds(step)
            .totp_drift_steps(2)
            .build();
        let code = generate_code(
            RFC_SECRET,
            u64::MAX,
            step,
            config.totp_digits,
            TotpAlgorithm::Sha1,
        )
        .expect("gen ok");

        assert!(
            verify_code_at(RFC_SECRET, &code, u64::MAX, &config, TotpAlgorithm::Sha1)
                .expect("verify ok")
        );
    }

    #[test]
    fn test_verify_invalid_digits_propagates_error() {
        let config = SecurityConfig::builder().totp_digits(5).build();
        let res = verify_code_at(
            RFC_SECRET,
            "12345",
            1234567890,
            &config,
            TotpAlgorithm::Sha1,
        );
        assert!(matches!(res, Err(TotpError::InvalidDigits(5))));
    }
}
