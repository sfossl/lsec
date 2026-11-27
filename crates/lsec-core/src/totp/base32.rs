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
    let mut raw_bytes = zeroize::Zeroizing::new(Vec::with_capacity((encoded.len() * 5) / 8));

    let mut buffer = 0u32;
    let mut bits_left = 0u32;

    for &b in encoded.as_bytes() {
        if b == b' ' || b == b'-' || b == b'=' {
            continue;
        }
        let val = match decode_char(b) {
            Ok(v) => v,
            Err(e) => {
                buffer.zeroize();
                return Err(e);
            }
        };
        buffer = (buffer << 5) | u32::from(val);
        bits_left += 5;

        if bits_left >= 8 {
            bits_left -= 8;
            raw_bytes.push((buffer >> bits_left) as u8);
            buffer &= (1 << bits_left) - 1;
        }
    }

    if bits_left > 0 && buffer != 0 {
        buffer.zeroize();
        return Err(TotpError::InvalidBase32);
    }

    buffer.zeroize();

    if raw_bytes.is_empty() {
        return Err(TotpError::EmptySecret);
    }

    Ok(ProtectedBuffer::new(&raw_bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_standard_vector() {
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
        assert!(matches!(
            decode_secret("   --- ==="),
            Err(TotpError::EmptySecret)
        ));
        assert!(matches!(decode_secret("A"), Err(TotpError::EmptySecret)));
        assert!(matches!(
            decode_secret("A======="),
            Err(TotpError::EmptySecret)
        ));
    }

    #[test]
    fn test_decode_invalid_chars_fails() {
        assert!(matches!(
            decode_secret("JBSWY3DPE8"),
            Err(TotpError::InvalidBase32)
        ));
        assert!(matches!(
            decode_secret("JBSWY3DPE0"),
            Err(TotpError::InvalidBase32)
        ));
    }

    #[test]
    fn test_decode_nonzero_residual_bits_fails() {
        assert!(matches!(
            decode_secret("JBSWY3DPEF======"),
            Err(TotpError::InvalidBase32)
        ));
    }
}
