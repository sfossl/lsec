use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroize;

use super::error::TotpError;
use crate::config::{MAX_TOTP_DIGITS, MIN_TOTP_DIGITS, SecurityConfig};

type HmacSha1 = Hmac<Sha1>;
type HmacSha256 = Hmac<Sha256>;
type HmacSha512 = Hmac<Sha512>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TotpAlgorithm {
    #[default]
    Sha1,
    Sha256,
    Sha512,
}

fn modulo_for_digits(digits: u32) -> Result<u32, TotpError> {
    if !(MIN_TOTP_DIGITS..=MAX_TOTP_DIGITS).contains(&digits) {
        return Err(TotpError::InvalidDigits(digits));
    }

    match digits {
        6 => Ok(1_000_000),
        7 => Ok(10_000_000),
        8 => Ok(100_000_000),
        _ => Err(TotpError::InvalidDigits(digits)),
    }
}

fn compute_hmac(algorithm: TotpAlgorithm, secret: &[u8], counter: u64) -> Result<Vec<u8>, TotpError> {
    let counter_bytes = counter.to_be_bytes();

    let digest = match algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac = HmacSha1::new_from_slice(secret).map_err(|_| TotpError::InvalidKeyLength)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha256 => {
            let mut mac = HmacSha256::new_from_slice(secret).map_err(|_| TotpError::InvalidKeyLength)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        TotpAlgorithm::Sha512 => {
            let mut mac = HmacSha512::new_from_slice(secret).map_err(|_| TotpError::InvalidKeyLength)?;
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    };

    Ok(digest)
}

pub fn generate_code(
    secret: &[u8],
    timestamp: u64,
    step_seconds: u64,
    digits: u32,
    algorithm: TotpAlgorithm,
) -> Result<String, TotpError> {
    if secret.is_empty() {
        return Err(TotpError::EmptySecret);
    }
    if step_seconds == 0 {
        return Err(TotpError::InvalidStepSeconds);
    }

    let modulo = modulo_for_digits(digits)?;
    let counter = timestamp / step_seconds;

    let mut hash = compute_hmac(algorithm, secret, counter)?;
    let offset = (hash[hash.len() - 1] & 0x0f) as usize;

    let binary_code = ((u32::from(hash[offset] & 0x7f)) << 24)
        | ((u32::from(hash[offset + 1])) << 16)
        | ((u32::from(hash[offset + 2])) << 8)
        | (u32::from(hash[offset + 3]));

    hash.zeroize();

    let code = binary_code % modulo;
    Ok(format!("{:0width$}", code, width = digits as usize))
}

pub fn generate_at(
    secret: &[u8],
    timestamp: u64,
    config: &SecurityConfig,
    algorithm: TotpAlgorithm,
) -> Result<String, TotpError> {
    generate_code(
        secret,
        timestamp,
        config.totp_step_seconds,
        config.totp_digits,
        algorithm,
    )
}

pub fn generate_current(
    secret: &[u8],
    config: &SecurityConfig,
    algorithm: TotpAlgorithm,
) -> Result<String, TotpError> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| TotpError::SystemTimeBeforeEpoch)?
        .as_secs();

    generate_at(secret, now, config, algorithm)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC_SEED_SHA1: &[u8] = b"12345678901234567890";
    const RFC_SEED_SHA256: &[u8] = b"12345678901234567890123456789012";
    const RFC_SEED_SHA512: &[u8] = b"1234567890123456789012345678901234567890123456789012345678901234";

    #[test]
    fn test_rfc6238_sha1_8digits() {
        let vectors = [
            (59u64, "94287082"),
            (1111111109u64, "07081804"),
            (1111111111u64, "14050471"),
            (1234567890u64, "89005924"),
            (2000000000u64, "69279037"),
        ];

        for (time, expected) in vectors {
            let code = generate_code(RFC_SEED_SHA1, time, 30, 8, TotpAlgorithm::Sha1).expect("gen ok");
            assert_eq!(code, expected, "sha1 failed at t={}", time);
        }
    }

    #[test]
    fn test_rfc6238_sha256_8digits() {
        let vectors = [
            (59u64, "46119246"),
            (1111111109u64, "68084774"),
            (1111111111u64, "67062674"),
            (1234567890u64, "91819424"),
            (2000000000u64, "90698825"),
        ];

        for (time, expected) in vectors {
            let code = generate_code(RFC_SEED_SHA256, time, 30, 8, TotpAlgorithm::Sha256).expect("gen ok");
            assert_eq!(code, expected, "sha256 failed at t={}", time);
        }
    }

    #[test]
    fn test_rfc6238_sha512_8digits() {
        let vectors = [
            (59u64, "90693936"),
            (1111111109u64, "25091201"),
            (1111111111u64, "99943326"),
            (1234567890u64, "93441116"),
            (2000000000u64, "38618901"),
        ];

        for (time, expected) in vectors {
            let code = generate_code(RFC_SEED_SHA512, time, 30, 8, TotpAlgorithm::Sha512).expect("gen ok");
            assert_eq!(code, expected, "sha512 failed at t={}", time);
        }
    }

    #[test]
    fn test_standard_6digits_padding() {
        let code = generate_code(RFC_SEED_SHA1, 59, 30, 6, TotpAlgorithm::Sha1).expect("ok");
        assert_eq!(code.len(), 6);
        assert_eq!(code, "287082");
    }

    #[test]
    fn test_empty_secret_fails() {
        let res = generate_code(b"", 1000, 30, 6, TotpAlgorithm::Sha1);
        assert!(matches!(res, Err(TotpError::EmptySecret)));
    }

    #[test]
    fn test_zero_step_fails() {
        let res = generate_code(RFC_SEED_SHA1, 1000, 0, 6, TotpAlgorithm::Sha1);
        assert!(matches!(res, Err(TotpError::InvalidStepSeconds)));
    }

    #[test]
    fn test_invalid_digits_fails() {
        let res_too_low = generate_code(RFC_SEED_SHA1, 1000, 30, 5, TotpAlgorithm::Sha1);
        assert!(matches!(res_too_low, Err(TotpError::InvalidDigits(5))));

        let res_too_high = generate_code(RFC_SEED_SHA1, 1000, 30, 9, TotpAlgorithm::Sha1);
        assert!(matches!(res_too_high, Err(TotpError::InvalidDigits(9))));
    }
}
