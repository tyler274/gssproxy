//! Kani bounded-model-checking harnesses for the gssx wire codec.
//!
//! These complement `tests/proptest_proto.rs`: where proptest *samples* random
//! inputs, Kani *proves* the same safety and round-trip properties for every
//! input within the stated bounds (no panic, no arithmetic overflow, no
//! out-of-bounds access, no over-allocation, exact consumption).
//!
//! The whole module is gated on `#[cfg(kani)]`, so it is compiled only under
//! `cargo kani` and never affects normal builds. See
//! `rust/docs/formal-verification.md` for the rationale and how to run it.

use crate::frame::{encode_header, parse_header, FrameError};
use crate::gssx::Opaque;
use crate::rpc::{FRAGMENT_BIT, MAX_RPC_SIZE};
use crate::xdr::{Xdr, XdrDecoder, XdrEncoder};

/// `u32` encodes to exactly 4 bytes and decodes back to the same value.
#[kani::proof]
#[kani::unwind(8)]
fn u32_round_trips() {
    let v: u32 = kani::any();
    let mut e = XdrEncoder::new();
    v.encode(&mut e);
    let bytes = e.into_bytes();
    assert!(bytes.len() == 4);
    let mut d = XdrDecoder::new(&bytes);
    assert!(u32::decode(&mut d).unwrap() == v);
    assert!(d.remaining() == 0);
}

/// `u64` is two big-endian 4-byte words (high first) and round-trips.
#[kani::proof]
#[kani::unwind(12)]
fn u64_round_trips() {
    let v: u64 = kani::any();
    let mut e = XdrEncoder::new();
    v.encode(&mut e);
    let bytes = e.into_bytes();
    assert!(bytes.len() == 8);
    let mut d = XdrDecoder::new(&bytes);
    assert!(u64::decode(&mut d).unwrap() == v);
    assert!(d.remaining() == 0);
}

/// `bool` round-trips and only ever encodes the canonical 0/1 words.
#[kani::proof]
#[kani::unwind(8)]
fn bool_round_trips() {
    let v: bool = kani::any();
    let mut e = XdrEncoder::new();
    v.encode(&mut e);
    let bytes = e.into_bytes();
    let mut d = XdrDecoder::new(&bytes);
    assert!(bool::decode(&mut d).unwrap() == v);
    assert!(d.remaining() == 0);
}

/// Encoding an `Opaque` of bounded length and decoding it returns the same
/// bytes and leaves the decoder fully consumed (length prefix + padding).
#[kani::proof]
#[kani::unwind(12)]
fn opaque_round_trips() {
    // Bound the payload so CBMC stays tractable; 5 bytes exercises both the
    // length prefix and a non-trivial zero pad (5 -> 3 pad bytes).
    let data: [u8; 5] = kani::any();
    let value = Opaque::new(data.to_vec());
    let mut e = XdrEncoder::new();
    value.encode(&mut e);
    let bytes = e.into_bytes();
    let mut d = XdrDecoder::new(&bytes);
    let decoded = Opaque::decode(&mut d).unwrap();
    assert!(decoded.as_slice() == &data[..]);
    assert!(d.remaining() == 0);
}

/// Decoding an `Opaque` from arbitrary bounded bytes never panics and never
/// over-allocates: the declared length is validated against the bytes actually
/// present before any copy, so a hostile length yields `Eof`, not a crash.
#[kani::proof]
#[kani::unwind(16)]
fn opaque_decode_is_panic_free() {
    let bytes: [u8; 12] = kani::any();
    let mut d = XdrDecoder::new(&bytes);
    match Opaque::decode(&mut d) {
        Ok(o) => {
            // A decoded value can never claim more bytes than were available.
            assert!(o.as_slice().len() <= bytes.len());
            assert!(d.position() <= bytes.len());
        }
        Err(_) => {}
    }
}

/// `parse_header` honours the fragment-bit / size-cap contract for *every*
/// 32-bit record-marking word.
#[kani::proof]
fn frame_parse_header_matches_spec() {
    let word: u32 = kani::any();
    match parse_header(word) {
        Ok(len) => {
            assert!(word & FRAGMENT_BIT != 0);
            assert!(len <= MAX_RPC_SIZE);
            assert!(len as u32 == word & !FRAGMENT_BIT);
        }
        Err(FrameError::MultiFragment) => {
            assert!(word & FRAGMENT_BIT == 0);
        }
        Err(FrameError::TooLarge(n)) => {
            assert!(word & FRAGMENT_BIT != 0);
            assert!(n > MAX_RPC_SIZE);
        }
    }
}

/// Every in-range body length encodes to a header word that parses back to the
/// same length.
#[kani::proof]
fn frame_header_round_trips() {
    let len: usize = kani::any();
    kani::assume(len <= MAX_RPC_SIZE);
    let word = u32::from_be_bytes(encode_header(len));
    assert!(parse_header(word).unwrap() == len);
}
