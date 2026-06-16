//! RPC envelope handling and per-procedure routing.
//!
//! Decodes the SunRPC call envelope, validates program/version/procedure
//! (emitting the standard RPC accept-status replies on mismatch), decodes the
//! procedure argument, runs the handler, and encodes the reply body (envelope +
//! result) ready to be record-marked by the caller.

use gssproxy_proto::proc::*;
use gssproxy_proto::rpc::{GSSPROXY, GSSPROXYVERS, Message, MismatchInfo, OpaqueAuth, ReplyBody};
use gssproxy_proto::xdr::{Xdr, XdrDecoder, XdrEncoder, XdrResult};

use crate::call::CallContext;
use crate::handlers;

// RPC accept_stat values (rpc.h).
const PROG_UNAVAIL: i32 = 1;
const PROC_UNAVAIL: i32 = 3;
const GARBAGE_ARGS: i32 = 4;

/// Process one decoded request body, returning the reply body to frame, or
/// `None` if the message isn't a well-formed call we should answer.
pub fn handle_request(ctx: &CallContext, body: &[u8]) -> Option<Vec<u8>> {
    let mut d = XdrDecoder::new(body);
    let msg = Message::decode(&mut d).ok()?;
    if !msg.is_call {
        tracing::debug!("dropping non-call RPC message");
        return None;
    }
    let call = msg.call.as_ref()?;
    let xid = msg.xid;

    if call.prog != GSSPROXY {
        tracing::warn!(xid, prog = call.prog, "unknown RPC program");
        return Some(reply_accept_other(xid, PROG_UNAVAIL));
    }
    if call.vers != GSSPROXYVERS {
        tracing::warn!(xid, vers = call.vers, "RPC program version mismatch");
        return Some(reply_prog_mismatch(xid));
    }
    let proc = match GssxProc::from_u32(call.proc_num) {
        Some(p) => p,
        None => {
            tracing::warn!(xid, proc = call.proc_num, "unknown gssproxy procedure");
            return Some(reply_accept_other(xid, PROC_UNAVAIL));
        }
    };

    // One span per request: every handler log line is attributed to the peer,
    // the procedure, and the xid without each handler re-logging that context.
    let span = tracing::debug_span!(
        "rpc",
        ?proc,
        xid,
        uid = ctx.uid,
        pid = ctx.pid,
        service = ctx
            .service
            .as_ref()
            .map(|s| s.name.as_str())
            .unwrap_or("<none>")
    );
    let _enter = span.enter();
    tracing::debug!(req_len = body.len(), "handling request");

    match encode_proc_reply(ctx, proc, xid, &mut d) {
        Ok(bytes) => {
            tracing::debug!(res_len = bytes.len(), "request handled");
            Some(bytes)
        }
        // Argument failed to decode: RPC GARBAGE_ARGS.
        Err(e) => {
            tracing::warn!(error = %e, "failed to decode procedure arguments (GARBAGE_ARGS)");
            Some(reply_accept_other(xid, GARBAGE_ARGS))
        }
    }
}

macro_rules! run {
    ($ctx:expr_2021, $d:expr_2021, $xid:expr_2021, $arg:ty, $handler:path) => {{
        let arg = <$arg as Xdr>::decode($d)?;
        Ok(gssproxy_proto::encode_reply($xid, &$handler($ctx, arg)))
    }};
}

fn encode_proc_reply(
    ctx: &CallContext,
    proc: GssxProc,
    xid: u32,
    d: &mut XdrDecoder,
) -> XdrResult<Vec<u8>> {
    match proc {
        GssxProc::IndicateMechs => run!(ctx, d, xid, ArgIndicateMechs, handlers::indicate_mechs),
        GssxProc::GetCallContext => {
            run!(ctx, d, xid, ArgGetCallContext, handlers::get_call_context)
        }
        GssxProc::ImportAndCanonName => {
            run!(
                ctx,
                d,
                xid,
                ArgImportAndCanonName,
                handlers::import_and_canon_name
            )
        }
        GssxProc::ExportCred => run!(ctx, d, xid, ArgExportCred, handlers::export_cred),
        GssxProc::ImportCred => run!(ctx, d, xid, ArgImportCred, handlers::import_cred),
        GssxProc::AcquireCred => run!(ctx, d, xid, ArgAcquireCred, handlers::acquire_cred),
        GssxProc::StoreCred => run!(ctx, d, xid, ArgStoreCred, handlers::store_cred),
        GssxProc::InitSecContext => {
            run!(ctx, d, xid, ArgInitSecContext, handlers::init_sec_context)
        }
        GssxProc::AcceptSecContext => {
            run!(
                ctx,
                d,
                xid,
                ArgAcceptSecContext,
                handlers::accept_sec_context
            )
        }
        GssxProc::ReleaseHandle => run!(ctx, d, xid, ArgReleaseHandle, handlers::release_handle),
        GssxProc::GetMic => run!(ctx, d, xid, ArgGetMic, handlers::get_mic),
        GssxProc::VerifyMic => run!(ctx, d, xid, ArgVerifyMic, handlers::verify_mic),
        GssxProc::Wrap => run!(ctx, d, xid, ArgWrap, handlers::wrap_msg),
        GssxProc::Unwrap => run!(ctx, d, xid, ArgUnwrap, handlers::unwrap_msg),
        GssxProc::WrapSizeLimit => run!(ctx, d, xid, ArgWrapSizeLimit, handlers::wrap_size_limit),
    }
}

fn reply_accept_other(xid: u32, status: i32) -> Vec<u8> {
    encode_reply_body(
        xid,
        ReplyBody::AcceptedOther {
            verf: OpaqueAuth::none(),
            status,
        },
    )
}

fn reply_prog_mismatch(xid: u32) -> Vec<u8> {
    encode_reply_body(
        xid,
        ReplyBody::ProgMismatch {
            verf: OpaqueAuth::none(),
            info: MismatchInfo {
                low: GSSPROXYVERS,
                high: GSSPROXYVERS,
            },
        },
    )
}

fn encode_reply_body(xid: u32, reply: ReplyBody) -> Vec<u8> {
    let msg = Message {
        xid,
        is_call: false,
        call: None,
        reply: Some(reply),
    };
    let mut e = XdrEncoder::new();
    msg.encode(&mut e);
    e.into_bytes()
}
