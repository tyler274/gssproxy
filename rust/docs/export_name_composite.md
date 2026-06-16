# `gssi_export_name_composite` - status, background, and round-trip gap

This note documents the **composite name export** GSSAPI operation, why the
gssproxy interposer entry point (`gssi_export_name_composite`) is currently
*not* exported, and what would have to change - on both the **interposer** and
the **daemon (server)** side - to support it under a configuration that needs
attribute-carrying exported names (e.g. PAC / authorization-data round trips).

It lives next to [`names.rs`](./names.rs), which implements the `gssi_*` name
operations and is where `gssi_export_name_composite` would be added if/when the
round trip is fixed.

## TL;DR

- `gss_export_name_composite()` (RFC 6680) exports a name **including its
  attributes** (and the authenticated/complete flags), unlike `gss_export_name()`
  which exports only the bare mechanism name (MN).
- The C interposer deliberately disables `gssi_export_name_composite` with
  `#if 0` (`src/mechglue/gpp_import_and_canon_name.c`), commented *"disabled until
  better understood"*. The v0.2.2 changelog reads *"Disable
  gss_export_name_composite() for now."* The matching test in
  `tests/interposetest.c` is also `#if 0` *"disabled until
  gss_export_name_composite server-side is fixed."*
- The Rust port faithfully mirrors this: there is **no** `gssi_export_name_composite`
  in `names.rs`, keeping byte-for-byte symbol parity with the C `proxymech.so`.
- The reason it is unfinished is a **round-trip asymmetry in the daemon**: the
  daemon *exports* the composite blob but never *re-imports* it and never
  transfers `name_attributes`. Enabling the interposer entry alone would expose
  a one-way feature whose result cannot be faithfully imported back through
  gssproxy.

## What `gss_export_name_composite` is (RFC 6680)

RFC 6680 ("GSS-API Naming Extensions", §7.8) defines:

```c
OM_uint32 gss_export_name_composite(
    OM_uint32        *minor_status,
    gss_const_name_t  name,
    gss_buffer_t      exp_composite_name);
```

Key properties from the spec:

- It outputs a token that can be re-imported with `gss_import_name()` using the
  name type **`GSS_C_NT_COMPOSITE_EXPORT`**, OID **`1.3.6.1.5.6.6`**
  (`{iso(1) org(3) dod(6) internet(1) security(5) nametypes(6)
  gss-composite-export(6)}`). In this tree it is `NT_COMPOSITE_EXPORT_OID`
  (`rust/gssapi-sys/src/consts.rs`).
- Unlike `gss_export_name()`, the composite token **preserves any name attribute
  information**, including the *authenticated* and *complete* flags associated
  with the input name. Plain `gss_export_name()` "may well not" preserve them.
- The token format is intentionally unspecified (it is meant for
  inter-process communication only) **except** that every token MUST begin with
  the two-octet token ID `04 02` (network byte order). For comparison,
  `gss_export_name()` (RFC 2743) tokens start with `04 01`.
- Output buffer is freed by the caller with `gss_release_buffer()`.

The canonical use case is moving an authenticated name - together with its
mechanism attributes (e.g. a Kerberos PAC, group memberships, SID/UID mappings,
`urn:` naming-extension attributes) - from one process to another and then
re-importing it without losing the attributes or the "this was authenticated"
property.

## How other implementations expose it

### MIT krb5

- Declared in `src/lib/gssapi/generic/gssapi_ext.h` and exported from
  `libgssapi_krb5` (`src/lib/gssapi/libgssapi_krb5.exports`).
- The krb5 mechanism wires `krb5_gss_export_name_composite` into its dispatch
  table (`krb5_mechanism` in `src/lib/gssapi/krb5/gssapi_krb5.c`).
- The **mechglue** is the dispatch layer. For an **interposer** module (which is
  what gssproxy's `proxymech.so` is), the mechglue copies the *real* mechanism's
  dispatch table and overrides only the slots for which the interposer exports a
  `gssi_<op>` symbol. Therefore:
  - If `gssi_export_name_composite` is **not exported**, `gss_export_name_composite()`
    routes straight to the underlying real krb5 mechanism (no proxying) - which is
    exactly today's behavior. The local krb5 library answers from the local
    name; gssproxy is bypassed for this single call.
  - MIT's own plugin docs note that a module may simply refrain from exporting an
    extension and "the mechglue will fail gracefully" (returns
    `GSS_S_UNAVAILABLE`) if neither interposer nor real mech implements it.
- MIT also documents the interposer re-entry rule: to call back into the original
  mechanism for token-bearing functions, the interposer must wrap the mech token
  in the mechglue's concatenated-OID format. For name import specifically, the
  exported-name token is `04 01` + 2-byte OID len + mech OID (DER, with `06`
  tag) + 4-byte token len + token, with `input_name_type = GSS_C_NT_EXPORT_NAME`.
  The composite variant is analogous but begins `04 02` and is imported with
  `GSS_C_NT_COMPOSITE_EXPORT`.

### Heimdal

- `lib/gssapi/gssapi/gssapi.h` declares `gss_export_name_composite` under the
  "Naming extensions" section and reserves the static
  `__gss_c_nt_composite_export_oid_desc` (`{1.3.6.1.5.6.6}`), exposed as
  `GSS_C_NT_COMPOSITE_EXPORT`, matching the RFC.

## How gssproxy carries it on the wire

The gssx protocol already has a slot for the composite blob: `gssx_name` has both
`exported_name` and `exported_composite_name` fields.

- C: `struct gssx_name` (xdr) / Rust: `GssxName` in
  `rust/gssproxy-proto/src/gssx.rs` (`exported_composite_name: GssxBuffer`).
- The client-direction RPC stub already exists and simply returns the cached
  blob from the `gssx_name`:
  - C: `gpm_export_name_composite` (`src/client/gpm_import_and_canon_name.c`) -
    returns `GSS_S_NAME_NOT_MN` if `exported_composite_name` is empty, otherwise
    copies it out.
  - The disabled interposer wrapper (`gpp_import_and_canon_name.c`, `#if 0`) would
    dispatch to either `gss_export_name_composite` (local name) or
    `gpm_export_name_composite` (remote name).

So the **export** half is plumbed end-to-end. The gap is the **import / attribute
transfer** half.

## The round-trip gap (this is the "server fix")

A faithful composite-name feature must round-trip: export on side A → transport →
import on side B → attributes still present and usable. Today the daemon does the
first half but not the second. Concretely:

1. **Export side - attributes never serialized.** `gp_conv_name_to_gssx`
   (`src/gp_conv.c`) calls `gss_export_name_composite()` and stores the blob in
   `out.exported_composite_name`, but the `out->name_attributes` population is a
   bare comment / no-op (`/* out->name_attributes */`). Only the opaque composite
   blob travels; the structured attribute set does not.

   The Rust port mirrors this exactly: `name_to_gssx` in
   `rust/gssproxy-server/src/conv.rs` fills `exported_composite_name` via
   `Name::export_composite()` but does not populate `name_attributes`.

2. **Import side - composite blob ignored.** `gp_conv_gssx_to_name`
   (`src/gp_conv.c`) reconstructs a live name from `display_name` (re-import +
   canonicalize) or else from `exported_name` (imported as
   `GSS_C_NT_EXPORT_NAME`). It **never** looks at `exported_composite_name` and
   never imports it as `GSS_C_NT_COMPOSITE_EXPORT`, so the attribute-carrying form
   is dropped on the way back in.

   Rust mirror: `gssx_to_name` in `rust/gssproxy-server/src/conv.rs` does the same
   (display_name → `Name::import`, else `Name::import_exported`).

3. **Import RPC handler - explicit TODOs.** `gp_rpc_import_and_canon_name.c`
   carries the smoking gun:

   ```c
   /* TODO: check also icna->input_name.exported_composite_name */
   /* TODO: icna->name_attributes */
   ```

   i.e. the daemon's import-and-canonicalize entry never honors a
   composite-exported input name or incoming attributes.

Net effect: even though `gssi_export_name_composite` *could* return a blob, a
client that then re-imported that blob (`GSS_C_NT_COMPOSITE_EXPORT`) through
gssproxy would get a name stripped of its attributes and of the authenticated/
complete flags - defeating the entire purpose of the call. That is why the
interposer entry was disabled rather than shipped half-working.

## What a fix would require

To support composite names "under a different configuration", changes are needed
on **both** sides; doing only the interposer side reintroduces the original
half-working trap.

Daemon (server) - the actual blocker:

1. **Serialize attributes on export.** In `gp_conv_name_to_gssx` /
   `name_to_gssx`, enumerate `gss_inquire_name` + `gss_get_name_attribute` and
   fill `gssx_name.name_attributes` (mirrored in
   `rust/gssproxy-server/src/conv.rs`).
2. **Honor the composite blob on import.** In `gp_conv_gssx_to_name` /
   `gssx_to_name`, when `exported_composite_name` is present, import it with
   `GSS_C_NT_COMPOSITE_EXPORT` (preferring it over, or in addition to,
   `exported_name`).
3. **Re-apply attributes on import.** In `gp_rpc_import_and_canon_name.c`
   (and the Rust `handlers::import_and_canon_name`), resolve the two TODOs:
   consume `input_name.exported_composite_name` and re-apply
   `input_name.name_attributes` via `gss_set_name_attribute` on the reconstructed
   name.
4. **Validate symmetry.** Confirm MIT krb5's `gss_import_name` with
   `GSS_C_NT_COMPOSITE_EXPORT` accepts the blob produced by the server's
   `gss_export_name_composite` for the deployed krb5 version (historically this
   asymmetry is exactly why upstream disabled the feature).

Interposer (this crate) - straightforward once the daemon round-trips:

5. Add `gssi_export_name_composite` to [`names.rs`](./names.rs), dispatching like
   the other name ops: local name → real `gss_export_name_composite`; remote name
   → `gpm::export_name_composite` (a thin wrapper over the cached
   `exported_composite_name`, matching `gpm_export_name`). Tolerate
   `GSS_S_NAME_NOT_MN` / `GSS_S_UNAVAILABLE` like `export_composite()` already
   does in `rust/gssapi-sys/src/wrap.rs`.
6. Re-enable the interposer composite test (the `#if 0` block in
   `tests/interposetest.c`) and add it to the Nix integration matrix.

## Decision / current stance

Until the daemon round trip (steps 1–4) is implemented and validated against the
target krb5, the interposer entry stays **unexported** in both the C and Rust
builds. This is the correct, parity-preserving choice: omitting `gssi_export_name_composite`
makes the mechglue route `gss_export_name_composite()` to the local krb5
mechanism, which is well-defined behavior, rather than shipping a proxied path
whose results cannot be imported back faithfully.

## References

- RFC 6680, GSS-API Naming Extensions, §7.8 `GSS_Export_name_composite()` and §8
  (IANA: `gss-composite-export` = `1.3.6.1.5.6.6`).
  <https://www.rfc-editor.org/rfc/rfc6680>
- MIT krb5 GSSAPI mechanism/interposer interface:
  <https://web.mit.edu/Kerberos/krb5-latest/doc/plugindev/gssapi.html>
- MIT krb5 dispatch table (`krb5_gss_export_name_composite`):
  `src/lib/gssapi/krb5/gssapi_krb5.c`; signature in
  `src/lib/gssapi/generic/gssapi_ext.h`.
- Heimdal declaration + OID: `lib/gssapi/gssapi/gssapi.h`
  (`__gss_c_nt_composite_export_oid_desc`).
- In-tree: `src/gp_conv.c` (`gp_conv_name_to_gssx`, `gp_conv_gssx_to_name`),
  `src/gp_rpc_import_and_canon_name.c` (TODOs),
  `src/mechglue/gpp_import_and_canon_name.c` (`#if 0` wrapper),
  `src/client/gpm_import_and_canon_name.c` (`gpm_export_name_composite`),
  `rust/gssproxy-server/src/conv.rs`, `rust/gssapi-sys/src/wrap.rs`
  (`export_composite`), `rust/gssapi-sys/src/consts.rs` (`NT_COMPOSITE_EXPORT_OID`).
