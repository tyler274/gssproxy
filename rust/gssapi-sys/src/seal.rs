//! Credential-handle sealing, ported from `gp_encrypt_buffer` /
//! `gp_decrypt_buffer` / `gp_init_creds_handle` in `src/gp_export.c`.
//!
//! gssproxy hands the client an opaque, encrypted blob ("cred_handle_reference")
//! instead of a live credential, so the daemon can stay stateless. The blob is
//! the `gss_export_cred` token sealed with a per-service key (the first usable
//! key from the service keytab, or an ephemeral random AES256 key) using
//! `krb5_c_encrypt` with the `APP_DATA_ENCRYPT` key usage.
//!
//! We only need the blob to be self-consistent within a daemon's lifetime (the
//! client round-trips it back to the same daemon), so the contents need not be
//! byte-identical to the C daemon. We keep the same algorithm anyway, including
//! the explicit padding dance that works around `krb5_c_decrypt` padding for
//! some enctypes.
//!
//! The handle stores only the raw key bytes + enctype; each seal/unseal spins up
//! a short-lived `krb5_context` so the type is `Send`/`Sync` and safe to share
//! across the daemon's blocking worker threads (a `krb5_context` must not be used
//! concurrently from multiple threads).

use std::ffi::CString;
use std::os::raw::{c_char, c_uint};
use std::ptr;

use crate::krb5::*;

/// Minimum padding length (matches `ENC_MIN_PAD_LEN` in `src/gp_common.h`).
const ENC_MIN_PAD_LEN: u8 = 8;

/// A krb5 error wrapped with the operation that produced it.
#[derive(Debug, Clone)]
pub struct SealError {
    pub code: krb5_error_code,
    pub what: &'static str,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} failed (krb5 error {})", self.what, self.code)
    }
}

impl std::error::Error for SealError {}

type Result<T> = std::result::Result<T, SealError>;

fn check(code: krb5_error_code, what: &'static str) -> Result<()> {
    if code == 0 {
        Ok(())
    } else {
        Err(SealError { code, what })
    }
}

/// A per-service sealing key.
#[derive(Debug, Clone)]
pub struct CredHandle {
    enctype: krb5_enctype,
    key: Vec<u8>,
}

// The handle holds only plain bytes; no krb5 state is retained.
unsafe impl Send for CredHandle {}
unsafe impl Sync for CredHandle {}

impl CredHandle {
    /// Derive the sealing key for a service. Tries the given keytab (falling
    /// back to the default keytab), and if no usable key is found, generates an
    /// ephemeral random AES256 key - exactly the fallback order in
    /// `gp_init_creds_handle`.
    pub fn new(keytab: Option<&str>) -> Result<CredHandle> {
        unsafe {
            let mut context: krb5_context = ptr::null_mut();
            check(krb5_init_context(&mut context), "krb5_init_context")?;

            let derived = derive_from_keytab(context, keytab).or_else(|| derive_ephemeral(context));

            krb5_free_context(context);

            match derived {
                Some((enctype, key)) => Ok(CredHandle { enctype, key }),
                None => Err(SealError {
                    code: 0,
                    what: "key derivation",
                }),
            }
        }
    }

    /// Build a keyblock view over our stored key bytes for use in a crypto call.
    fn keyblock(&self) -> krb5_keyblock {
        let mut kb: krb5_keyblock = unsafe { std::mem::zeroed() };
        kb.enctype = self.enctype;
        kb.length = self.key.len() as c_uint;
        kb.contents = self.key.as_ptr() as *mut _;
        kb
    }

    /// Encrypt `plain`, returning the ciphertext blob.
    pub fn seal(&self, plain: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut context: krb5_context = ptr::null_mut();
            check(krb5_init_context(&mut context), "krb5_init_context")?;
            let res = self.seal_inner(context, plain);
            krb5_free_context(context);
            res
        }
    }

    unsafe fn seal_inner(&self, context: krb5_context, plain: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let kb = self.keyblock();
            let len = plain.len();

            let mut cipherlen: usize = 0;
            check(
                krb5_c_encrypt_length(context, self.enctype, len, &mut cipherlen),
                "krb5_c_encrypt_length",
            )?;
            let mut padcheck: usize = 0;
            check(
                krb5_c_encrypt_length(context, self.enctype, len + 1, &mut padcheck),
                "krb5_c_encrypt_length",
            )?;

            // Determine how much explicit padding is needed (see the long comment in
            // gp_export.c): if adding one byte doesn't grow the ciphertext, the
            // enctype pads internally and we must add our own deterministic padding.
            let mut pad: u8 = 0;
            if padcheck == cipherlen {
                pad = ENC_MIN_PAD_LEN;
                check(
                    krb5_c_encrypt_length(
                        context,
                        self.enctype,
                        len + pad as usize,
                        &mut cipherlen,
                    ),
                    "krb5_c_encrypt_length",
                )?;
                for i in 0..15usize {
                    check(
                        krb5_c_encrypt_length(
                            context,
                            self.enctype,
                            len + pad as usize + i + 1,
                            &mut padcheck,
                        ),
                        "krb5_c_encrypt_length",
                    )?;
                    if padcheck > cipherlen {
                        pad += i as u8;
                        break;
                    }
                }
            }

            let data_in: Vec<u8> = if pad != 0 {
                let mut v = Vec::with_capacity(len + pad as usize);
                v.extend_from_slice(plain);
                v.extend(std::iter::repeat_n(pad, pad as usize));
                v
            } else {
                plain.to_vec()
            };

            let input = krb5_data {
                magic: 0,
                length: data_in.len() as c_uint,
                data: data_in.as_ptr() as *mut c_char,
            };

            let mut ct = vec![0u8; cipherlen];
            let mut output: krb5_enc_data = std::mem::zeroed();
            output.ciphertext.length = cipherlen as c_uint;
            output.ciphertext.data = ct.as_mut_ptr() as *mut c_char;

            check(
                krb5_c_encrypt(
                    context,
                    &kb,
                    KRB5_KEYUSAGE_APP_DATA_ENCRYPT as krb5_keyusage,
                    ptr::null(),
                    &input,
                    &mut output,
                ),
                "krb5_c_encrypt",
            )?;

            ct.truncate(output.ciphertext.length as usize);
            Ok(ct)
        }
    }

    /// Decrypt a blob produced by [`CredHandle::seal`].
    pub fn unseal(&self, cipher: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let mut context: krb5_context = ptr::null_mut();
            check(krb5_init_context(&mut context), "krb5_init_context")?;
            let res = self.unseal_inner(context, cipher);
            krb5_free_context(context);
            res
        }
    }

    unsafe fn unseal_inner(&self, context: krb5_context, cipher: &[u8]) -> Result<Vec<u8>> {
        unsafe {
            let kb = self.keyblock();

            let mut enc: krb5_enc_data = std::mem::zeroed();
            enc.enctype = self.enctype;
            enc.ciphertext.length = cipher.len() as c_uint;
            enc.ciphertext.data = cipher.as_ptr() as *mut c_char;

            // The plaintext is no longer than the ciphertext; krb5_c_decrypt trims
            // output.length to the real value.
            let mut out = vec![0u8; cipher.len()];
            let mut data_out = krb5_data {
                magic: 0,
                length: out.len() as c_uint,
                data: out.as_mut_ptr() as *mut c_char,
            };

            check(
                krb5_c_decrypt(
                    context,
                    &kb,
                    KRB5_KEYUSAGE_APP_DATA_ENCRYPT as krb5_keyusage,
                    ptr::null(),
                    &enc,
                    &mut data_out,
                ),
                "krb5_c_decrypt",
            )?;

            let mut length = data_out.length as usize;
            // Strip our explicit padding (mirrors gp_decrypt_buffer): the last byte
            // is the pad length; it is valid only if every padding byte equals it.
            if length >= 1 {
                let i = length - 1;
                let pad = out[i];
                if pad >= ENC_MIN_PAD_LEN && (pad as usize) < i {
                    let all_match = (0..pad as usize).all(|j| out[i - j] == pad);
                    if all_match {
                        length -= pad as usize;
                    }
                }
            }
            out.truncate(length);
            Ok(out)
        }
    }
}

/// Find the first keytab key whose enctype is permitted, returning its bytes.
unsafe fn derive_from_keytab(
    context: krb5_context,
    keytab: Option<&str>,
) -> Option<(krb5_enctype, Vec<u8>)> {
    unsafe {
        let mut ktid: krb5_keytab = ptr::null_mut();

        let mut resolved = false;
        if let Some(kt) = keytab
            && let Ok(c) = CString::new(kt)
            && krb5_kt_resolve(context, c.as_ptr(), &mut ktid) == 0
        {
            resolved = true;
        }
        if !resolved && krb5_kt_default(context, &mut ktid) != 0 {
            return None;
        }

        if krb5_kt_have_content(context, ktid) != 0 {
            krb5_kt_close(context, ktid);
            return None;
        }

        let mut permitted: *mut krb5_enctype = ptr::null_mut();
        if krb5_get_permitted_enctypes(context, &mut permitted) != 0 {
            krb5_kt_close(context, ktid);
            return None;
        }

        let mut found: Option<(krb5_enctype, Vec<u8>)> = None;
        let mut cursor: krb5_kt_cursor = ptr::null_mut();
        if krb5_kt_start_seq_get(context, ktid, &mut cursor) == 0 {
            loop {
                let mut entry: krb5_keytab_entry = std::mem::zeroed();
                if krb5_kt_next_entry(context, ktid, &mut entry, &mut cursor) != 0 {
                    break;
                }
                if found.is_none() {
                    let mut p = permitted;
                    while *p != 0 {
                        if *p == entry.key.enctype {
                            let bytes = std::slice::from_raw_parts(
                                entry.key.contents,
                                entry.key.length as usize,
                            )
                            .to_vec();
                            found = Some((entry.key.enctype, bytes));
                            break;
                        }
                        p = p.add(1);
                    }
                }
                krb5_free_keytab_entry_contents(context, &mut entry);
                if found.is_some() {
                    break;
                }
            }
            krb5_kt_end_seq_get(context, ktid, &mut cursor);
        }

        krb5_free_enctypes(context, permitted);
        krb5_kt_close(context, ktid);
        found
    }
}

/// Generate an ephemeral random AES256 key (the keytab fallback).
unsafe fn derive_ephemeral(context: krb5_context) -> Option<(krb5_enctype, Vec<u8>)> {
    unsafe {
        let enctype = ENCTYPE_AES256_CTS_HMAC_SHA1_96 as krb5_enctype;
        let mut key: *mut krb5_keyblock = ptr::null_mut();
        if krb5_init_keyblock(context, enctype, 0, &mut key) != 0 {
            return None;
        }
        if krb5_c_make_random_key(context, enctype, key) != 0 {
            krb5_free_keyblock(context, key);
            return None;
        }
        let kb = &*key;
        let bytes = std::slice::from_raw_parts(kb.contents, kb.length as usize).to_vec();
        let et = kb.enctype;
        krb5_free_keyblock(context, key);
        Some((et, bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_unseal_round_trip() {
        // No keytab in the build sandbox, so this exercises the ephemeral-key
        // fallback path plus the full encrypt/pad/decrypt/depad round trip.
        let handle = CredHandle::new(None).expect("derive sealing key");

        for len in [0usize, 1, 7, 8, 15, 16, 17, 31, 100, 1000] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 7 + 3) as u8).collect();
            let sealed = handle.seal(&plain).expect("seal");
            let opened = handle.unseal(&sealed).expect("unseal");
            assert_eq!(opened, plain, "round trip mismatch at len {len}");
        }
    }

    #[test]
    fn distinct_handles_do_not_share_keys() {
        let a = CredHandle::new(None).expect("a");
        let b = CredHandle::new(None).expect("b");
        let sealed = a.seal(b"secret payload").expect("seal");
        // b has a different random key, so decryption must not yield the
        // plaintext (it either errors or produces garbage).
        if let Ok(p) = b.unseal(&sealed) {
            assert_ne!(p, b"secret payload");
        }
    }
}
