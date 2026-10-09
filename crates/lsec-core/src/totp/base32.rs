use zeroize::Zeroize;

use super::error::TotpError;
use crate::memguard::ProtectedBuffer;

fn decode_char(c: u8) -> Result<u8, TotpError> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a'),
        b'2'..=b'7' => Ok(c - b'2' + 26),
        _ => Err(TotpError::InvalidBase32),
    }
}

pub fn decode_secret(encoded: &str) -> Result<ProtectedBuffer, TotpError> {
    let mut clean = Vec::with_capacity(encoded.len());
    for &b in encoded.as_bytes() {
        if b == b' ' || b == b'-' || b == b'=' {
            continue;
        }
        clean.push(b);
    }

    if clean.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    let estimated_capacity = (clean.len() * 5) / 8;
    let mut raw_bytes = Vec::with_capacity(estimated_capacity);

    let mut buffer = 0u32;
    let mut bits_left = 0u32;

    for &c in &clean {
        let val = decode_char(c)?;
        buffer = (buffer << 5) | u32::from(val);
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            raw_bytes.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }

    clean.zeroize();

    if bits_left > 0 && buffer != 0 {
        raw_bytes.zeroize();
        return Err(TotpError::InvalidBase32);
    }

    buffer.zeroize();

    let protected = ProtectedBuffer::new(&raw_bytes)?;
    raw_bytes.zeroize();

    Ok(protected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_standard_vector() {
        // "Hello!" in ascii is 48 65 6c 6c 6f 21 -> base32 "JBSWY3DPEE======"
        let protected = decode_secret("JBSWY3DPEE======").expect("decode ok");
        assert_eq!(&protected[..], b"Hello!");
    }

    #[test]
    fn test_decode_with_spaces_and_hyphens() {
        let protected = decode_secret("jbsw-y3dp ee==").expect("decode ok");
        assert_eq!(&protected[..], b"Hello!");
    }

    #[test]
    fn test_decode_empty_fails() {
        assert!(matches!(decode_secret(""), Err(TotpError::EmptySecret)));
        assert!(matches!(decode_secret("   --- ==="), Err(TotpError::EmptySecret)));
    }

    #[test]
    fn test_decode_invalid_chars_fails() {
        // '0', '1', '8', '9' are not in standard base32
        assert!(matches!(decode_secret("JBSWY3DPE8"), Err(TotpError::InvalidBase32)));
        assert!(matches!(decode_secret("JBSWY3DPE0"), Err(TotpError::InvalidBase32)));
    }

    #[test]
    fn test_decode_nonzero_residual_bits_fails() {
        // 'JBSWY3DPEE======' has valid zero padding; changing 'E' to 'F' introduces non-zero residual bits
        assert!(matches!(decode_secret("JBSWY3DPEF======"), Err(TotpError::InvalidBase32)));
    }
}

