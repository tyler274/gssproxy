/* Copyright (C) 2026 the GSS-PROXY contributors, see COPYING for license */

#include "bench_shim.h"

#include <stdlib.h>
#include <string.h>

#include "rpcgen/gp_xdr.h"
#include "rpcgen/gp_rpc.h"
#include "rpcgen/gss_proxy.h"

/* krb5 mech OID DER bytes: 1.2.840.113554.1.2.2 (matches oids.rs KRB5). */
static char krb5_oid[] = {
    0x2a, (char)0x86, 0x48, (char)0x86, (char)0xf7, 0x12, 0x01, 0x02, 0x02,
};

/* Build the SunRPC CALL envelope shared by every benchmarked request. */
static void fill_call_header(gp_rpc_msg *msg, unsigned int proc)
{
    memset(msg, 0, sizeof(*msg));
    msg->xid = 1;
    msg->header.type = GP_RPC_CALL;

    gp_rpc_call_header *chdr = &msg->header.gp_rpc_msg_union_u.chdr;
    chdr->rpcvers = 2;
    chdr->prog = GSSPROXY;
    chdr->vers = GSSPROXYVERS;
    chdr->proc = proc;
    chdr->cred.flavor = GP_RPC_AUTH_NONE;
    chdr->cred.body.body_len = 0;
    chdr->cred.body.body_val = NULL;
    chdr->verf.flavor = GP_RPC_AUTH_NONE;
    chdr->verf.body.body_len = 0;
    chdr->verf.body.body_val = NULL;
}

/* ---------------------------------------------------------------- indicate_mechs */

static gp_rpc_msg im_msg;
static gssx_arg_indicate_mechs im_arg;

void cbench_setup_indicate_mechs(void)
{
    fill_call_header(&im_msg, GSSX_INDICATE_MECHS);
    memset(&im_arg, 0, sizeof(im_arg));
}

size_t cbench_encode_indicate_mechs(unsigned char *buf, size_t cap)
{
    XDR xdrs;
    size_t pos = 0;
    xdrmem_create(&xdrs, (caddr_t)buf, (u_int)cap, XDR_ENCODE);
    if (xdr_gp_rpc_msg(&xdrs, &im_msg) &&
        xdr_gssx_arg_indicate_mechs(&xdrs, &im_arg)) {
        pos = xdr_getpos(&xdrs);
    }
    xdr_destroy(&xdrs);
    return pos;
}

int cbench_decode_indicate_mechs(const unsigned char *buf, size_t len)
{
    XDR xdrs;
    gp_rpc_msg msg;
    gssx_arg_indicate_mechs arg;
    int ok;

    memset(&msg, 0, sizeof(msg));
    memset(&arg, 0, sizeof(arg));
    xdrmem_create(&xdrs, (caddr_t)buf, (u_int)len, XDR_DECODE);
    ok = xdr_gp_rpc_msg(&xdrs, &msg) && xdr_gssx_arg_indicate_mechs(&xdrs, &arg);
    xdr_destroy(&xdrs);

    /* Release whatever the decoder allocated. */
    xdr_free((xdrproc_t)xdr_gssx_arg_indicate_mechs, (char *)&arg);
    xdr_free((xdrproc_t)xdr_gp_rpc_msg, (char *)&msg);
    return ok;
}

/* ------------------------------------------------------------- init_sec_context */

static gp_rpc_msg isc_msg;
static gssx_arg_init_sec_context isc_arg;
static gssx_buffer isc_token;

void cbench_setup_init_sec_context(size_t payload_len)
{
    fill_call_header(&isc_msg, GSSX_INIT_SEC_CONTEXT);

    memset(&isc_arg, 0, sizeof(isc_arg));
    isc_arg.mech_type.octet_string_len = (u_int)sizeof(krb5_oid);
    isc_arg.mech_type.octet_string_val = krb5_oid;

    free(isc_token.octet_string_val);
    isc_token.octet_string_len = (u_int)payload_len;
    isc_token.octet_string_val = NULL;
    if (payload_len > 0) {
        isc_token.octet_string_val = calloc(1, payload_len);
    }
    /* input_token is an optional (pointer) field in the XDR. */
    isc_arg.input_token = &isc_token;
}

size_t cbench_encode_init_sec_context(unsigned char *buf, size_t cap)
{
    XDR xdrs;
    size_t pos = 0;
    xdrmem_create(&xdrs, (caddr_t)buf, (u_int)cap, XDR_ENCODE);
    if (xdr_gp_rpc_msg(&xdrs, &isc_msg) &&
        xdr_gssx_arg_init_sec_context(&xdrs, &isc_arg)) {
        pos = xdr_getpos(&xdrs);
    }
    xdr_destroy(&xdrs);
    return pos;
}

int cbench_decode_init_sec_context(const unsigned char *buf, size_t len)
{
    XDR xdrs;
    gp_rpc_msg msg;
    gssx_arg_init_sec_context arg;
    int ok;

    memset(&msg, 0, sizeof(msg));
    memset(&arg, 0, sizeof(arg));
    xdrmem_create(&xdrs, (caddr_t)buf, (u_int)len, XDR_DECODE);
    ok = xdr_gp_rpc_msg(&xdrs, &msg) &&
         xdr_gssx_arg_init_sec_context(&xdrs, &arg);
    xdr_destroy(&xdrs);

    xdr_free((xdrproc_t)xdr_gssx_arg_init_sec_context, (char *)&arg);
    xdr_free((xdrproc_t)xdr_gp_rpc_msg, (char *)&msg);
    return ok;
}
