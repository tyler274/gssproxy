/* Copyright (C) 2026 the GSS-PROXY contributors, see COPYING for license */

/*
 * Thin benchmark shim over the C rpcgen XDR codec.
 *
 * Each message has a setup function (builds a representative gp_rpc_msg + arg
 * into file-static storage) and hot encode/decode functions that only exercise
 * the serialization path, so Criterion times the codec rather than struct
 * construction. All functions are single-threaded and reuse static buffers.
 */

#ifndef GSSPROXY_BENCH_SHIM_H
#define GSSPROXY_BENCH_SHIM_H

#include <stddef.h>

/* indicate_mechs: minimal CALL (empty call_ctx). */
void cbench_setup_indicate_mechs(void);
size_t cbench_encode_indicate_mechs(unsigned char *buf, size_t cap);
int cbench_decode_indicate_mechs(const unsigned char *buf, size_t len);

/*
 * init_sec_context: CALL with the krb5 mech OID and an input_token of
 * payload_len bytes (exercises the opaque/length-prefix/padding hot path and
 * the optional-pointer envelope fields).
 */
void cbench_setup_init_sec_context(size_t payload_len);
size_t cbench_encode_init_sec_context(unsigned char *buf, size_t cap);
int cbench_decode_init_sec_context(const unsigned char *buf, size_t len);

#endif /* GSSPROXY_BENCH_SHIM_H */
