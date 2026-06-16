//! Minimal XDR (RFC 4506) codec matching the behaviour of the SunRPC `xdr_*`
//! routines that the C gssproxy uses via rpcgen.
//!
//! The encoder/decoder are deliberately explicit so the byte layout can be
//! validated against the C implementation:
//!   - integers are big-endian, encoded in 4-byte units;
//!   - `uint64` is two 4-byte units, high word first (see `gp_xdr_uint64_t`);
//!   - `bool`/`enum` occupy 4 bytes;
//!   - variable opaque/string data is a 4-byte length followed by the bytes,
//!     zero-padded up to the next 4-byte boundary;
//!   - arrays are a 4-byte count followed by the elements;
//!   - an optional ("pointer") value is a 4-byte bool followed by the value
//!     when present.

use std::fmt;

/// Error returned while decoding an XDR stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XdrError {
    /// Not enough bytes left in the buffer to decode the requested item.
    Eof,
    /// A boolean/enum or discriminant held a value outside the allowed range.
    InvalidValue(&'static str),
    /// A length field exceeded the configured maximum.
    TooLong,
}

impl fmt::Display for XdrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            XdrError::Eof => write!(f, "unexpected end of XDR stream"),
            XdrError::InvalidValue(what) => write!(f, "invalid XDR value: {what}"),
            XdrError::TooLong => write!(f, "XDR length exceeds maximum"),
        }
    }
}

impl std::error::Error for XdrError {}

/// Result type for decoding.
pub type XdrResult<T> = Result<T, XdrError>;

/// Append-only XDR encoder backed by a growable byte buffer.
#[derive(Default)]
pub struct XdrEncoder {
    buf: Vec<u8>,
}

impl XdrEncoder {
    pub fn new() -> Self {
        Self { buf: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self {
            buf: Vec::with_capacity(cap),
        }
    }

    /// Current encoded length in bytes (matches `xdr_getpos`).
    pub fn position(&self) -> usize {
        self.buf.len()
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn put_u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    pub fn put_i32(&mut self, v: i32) {
        self.put_u32(v as u32);
    }

    /// Matches `gp_xdr_uint64_t`: high 32 bits first, then low 32 bits.
    pub fn put_u64(&mut self, v: u64) {
        self.put_u32((v >> 32) as u32);
        self.put_u32(v as u32);
    }

    /// XDR bool is a 4-byte integer that is 1 (TRUE) or 0 (FALSE).
    pub fn put_bool(&mut self, v: bool) {
        self.put_u32(if v { 1 } else { 0 });
    }

    /// XDR enum is encoded like a signed 4-byte integer.
    pub fn put_enum(&mut self, v: i32) {
        self.put_i32(v);
    }

    /// Variable-length opaque/string: length prefix, data, zero pad to 4 bytes.
    pub fn put_opaque(&mut self, data: &[u8]) {
        self.put_u32(data.len() as u32);
        self.buf.extend_from_slice(data);
        let pad = (4 - (data.len() % 4)) % 4;
        for _ in 0..pad {
            self.buf.push(0);
        }
    }
}

/// Borrowing XDR decoder over a byte slice.
pub struct XdrDecoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> XdrDecoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> XdrResult<&'a [u8]> {
        if self.remaining() < n {
            return Err(XdrError::Eof);
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn get_u32(&mut self) -> XdrResult<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn get_i32(&mut self) -> XdrResult<i32> {
        Ok(self.get_u32()? as i32)
    }

    pub fn get_u64(&mut self) -> XdrResult<u64> {
        let h = self.get_u32()? as u64;
        let l = self.get_u32()? as u64;
        Ok((h << 32) | l)
    }

    pub fn get_bool(&mut self) -> XdrResult<bool> {
        match self.get_u32()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(XdrError::InvalidValue("bool")),
        }
    }

    pub fn get_enum(&mut self) -> XdrResult<i32> {
        self.get_i32()
    }

    /// Reads a variable-length opaque/string and consumes the 4-byte padding.
    pub fn get_opaque(&mut self) -> XdrResult<Vec<u8>> {
        let len = self.get_u32()? as usize;
        let data = self.take(len)?.to_vec();
        let pad = (4 - (len % 4)) % 4;
        self.take(pad)?;
        Ok(data)
    }
}

/// Trait for types that can be (de)serialized as XDR exactly like their C
/// rpcgen counterparts.
pub trait Xdr: Sized {
    fn encode(&self, e: &mut XdrEncoder);
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self>;
}

impl Xdr for u32 {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_u32(*self);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        d.get_u32()
    }
}

impl Xdr for u64 {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_u64(*self);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        d.get_u64()
    }
}

impl Xdr for bool {
    fn encode(&self, e: &mut XdrEncoder) {
        e.put_bool(*self);
    }
    fn decode(d: &mut XdrDecoder) -> XdrResult<Self> {
        d.get_bool()
    }
}

/// XDR `array`: a 4-byte count followed by each element in order.
pub fn encode_array<T: Xdr>(e: &mut XdrEncoder, items: &[T]) {
    e.put_u32(items.len() as u32);
    for item in items {
        item.encode(e);
    }
}

pub fn decode_array<T: Xdr>(d: &mut XdrDecoder) -> XdrResult<Vec<T>> {
    let count = d.get_u32()? as usize;
    // Guard against absurd allocations from a corrupt length.
    if count > d.remaining() + 1 {
        return Err(XdrError::TooLong);
    }
    let mut out = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        out.push(T::decode(d)?);
    }
    Ok(out)
}

/// XDR optional ("pointer"): a 4-byte bool, then the value when present.
pub fn encode_optional<T: Xdr>(e: &mut XdrEncoder, value: &Option<T>) {
    match value {
        Some(v) => {
            e.put_bool(true);
            v.encode(e);
        }
        None => e.put_bool(false),
    }
}

pub fn decode_optional<T: Xdr>(d: &mut XdrDecoder) -> XdrResult<Option<T>> {
    if d.get_bool()? {
        Ok(Some(T::decode(d)?))
    } else {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn u32_roundtrip_and_layout() {
        let mut e = XdrEncoder::new();
        e.put_u32(0x01020304);
        assert_eq!(e.as_bytes(), &[0x01, 0x02, 0x03, 0x04]);
        let mut d = XdrDecoder::new(e.as_bytes());
        assert_eq!(d.get_u32().unwrap(), 0x01020304);
    }

    #[test]
    fn u64_high_word_first() {
        let mut e = XdrEncoder::new();
        e.put_u64(0x0102030405060708);
        assert_eq!(
            e.as_bytes(),
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        );
        let mut d = XdrDecoder::new(e.as_bytes());
        assert_eq!(d.get_u64().unwrap(), 0x0102030405060708);
    }

    #[test]
    fn opaque_is_length_prefixed_and_padded() {
        let mut e = XdrEncoder::new();
        e.put_opaque(b"abc");
        // length 3, 'a','b','c', one pad byte -> 8 bytes total
        assert_eq!(e.as_bytes(), &[0, 0, 0, 3, b'a', b'b', b'c', 0]);
        let mut d = XdrDecoder::new(e.as_bytes());
        assert_eq!(d.get_opaque().unwrap(), b"abc");
        assert_eq!(d.remaining(), 0);
    }

    #[test]
    fn empty_opaque_has_no_padding() {
        let mut e = XdrEncoder::new();
        e.put_opaque(b"");
        assert_eq!(e.as_bytes(), &[0, 0, 0, 0]);
    }

    #[test]
    fn bool_values() {
        let mut e = XdrEncoder::new();
        e.put_bool(true);
        e.put_bool(false);
        assert_eq!(e.as_bytes(), &[0, 0, 0, 1, 0, 0, 0, 0]);
    }
}
