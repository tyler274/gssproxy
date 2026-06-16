//! SunRPC record-marking framing as used on the gssproxy Unix socket.
//!
//! gssproxy uses a single-fragment record marking scheme (see `gp_socket.c`
//! and `gpm_common.c`): every message is preceded by a 4-byte big-endian
//! length word whose top bit (`FRAGMENT_BIT`) marks the last fragment. Only a
//! single fragment is ever used, so the body length is the low 31 bits.

use crate::rpc::{FRAGMENT_BIT, MAX_RPC_SIZE};

/// Error returned while parsing a record header/body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameError {
    /// The fragment header did not have the last-fragment bit set (multiple
    /// fragments are not supported, matching the C daemon).
    MultiFragment,
    /// The advertised body length exceeds `MAX_RPC_SIZE`.
    TooLarge(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::MultiFragment => write!(f, "multi-fragment records are not supported"),
            FrameError::TooLarge(n) => write!(f, "record body too large: {n} bytes"),
        }
    }
}

impl std::error::Error for FrameError {}

/// Encode the 4-byte record-marking header for a body of `len` bytes.
pub fn encode_header(len: usize) -> [u8; 4] {
    let marked = (len as u32) | FRAGMENT_BIT;
    marked.to_be_bytes()
}

/// Prepend a record header to `body`, returning the full frame to write.
pub fn frame(body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&encode_header(body.len()));
    out.extend_from_slice(body);
    out
}

/// Parse a record-marking header word, validating the last-fragment bit and
/// the size cap. Returns the body length in bytes.
pub fn parse_header(word: u32) -> Result<usize, FrameError> {
    if word & FRAGMENT_BIT == 0 {
        return Err(FrameError::MultiFragment);
    }
    let len = (word & !FRAGMENT_BIT) as usize;
    if len > MAX_RPC_SIZE {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        let h = encode_header(5);
        let word = u32::from_be_bytes(h);
        assert_eq!(parse_header(word).unwrap(), 5);
    }

    #[test]
    fn rejects_missing_fragment_bit() {
        assert_eq!(parse_header(5), Err(FrameError::MultiFragment));
    }

    #[test]
    fn rejects_oversized() {
        let word = ((MAX_RPC_SIZE as u32) + 1) | FRAGMENT_BIT;
        assert!(matches!(parse_header(word), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn frame_prepends_header() {
        let f = frame(b"hi");
        assert_eq!(&f[4..], b"hi");
        assert_eq!(
            parse_header(u32::from_be_bytes([f[0], f[1], f[2], f[3]])).unwrap(),
            2
        );
    }
}
