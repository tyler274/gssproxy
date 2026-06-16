//! End-to-end smoke test of the daemon's socket path: bind the listener, then
//! drive a real `GSSX_INDICATE_MECHS` request over the Unix socket and decode
//! the framed reply. This exercises the whole pipeline (listener -> SunRPC
//! framing -> envelope validation -> dispatch -> handler -> live GSSAPI ->
//! encode), which is the part the upstream test suite cannot reach until more
//! procedures are ported.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use gssproxy_proto::frame::{encode_header, parse_header};
use gssproxy_proto::proc::{GssxProc, ArgIndicateMechs, ResIndicateMechs};
use gssproxy_proto::rpc::ReplyBody;
use gssproxy_proto::{encode_request, Message, XdrDecoder, Xdr};

/// DER encoding of the krb5 mechanism OID 1.2.840.113554.1.2.2.
const KRB5_MECH_OID: &[u8] = &[
    0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02,
];

fn unique_socket_path() -> PathBuf {
    let mut p = std::env::temp_dir();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    p.push(format!("gssproxy-rs-test-{}-{}.sock", std::process::id(), nanos));
    p
}

fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).expect("read record header");
    let len = parse_header(u32::from_be_bytes(header)).expect("valid record header");
    let mut body = vec![0u8; len];
    stream.read_exact(&mut body).expect("read record body");
    body
}

#[test]
fn indicate_mechs_round_trips_over_socket() {
    let socket = unique_socket_path();
    let socket_for_server = socket.clone();

    // Run the listener on its own current-thread runtime. The thread is detached
    // and torn down when the test process exits.
    std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let _ = rt.block_on(gssproxy_server::server::run(&socket_for_server));
    });

    // Wait for the socket to accept connections.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut stream = loop {
        match UnixStream::connect(&socket) {
            Ok(s) => break s,
            Err(_) if Instant::now() < deadline => {
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(e) => panic!("daemon never came up: {e}"),
        }
    };

    let xid = 0x1234_5678;
    let body = encode_request(
        xid,
        GssxProc::IndicateMechs as u32,
        &ArgIndicateMechs::default(),
    );
    let mut request = encode_header(body.len()).to_vec();
    request.extend_from_slice(&body);
    stream.write_all(&request).expect("write request");
    stream.flush().expect("flush request");

    let reply = read_frame(&mut stream);
    let mut d = XdrDecoder::new(&reply);
    let msg = Message::decode(&mut d).expect("decode reply envelope");
    assert_eq!(msg.xid, xid, "reply xid must echo the request xid");
    assert!(!msg.is_call, "reply must be a REPLY, not a CALL");
    assert!(
        matches!(msg.reply, Some(ReplyBody::AcceptedSuccess { .. })),
        "reply must be MSG_ACCEPTED + SUCCESS, got {:?}",
        msg.reply
    );

    let res = ResIndicateMechs::decode(&mut d).expect("decode indicate_mechs result");
    assert_eq!(d.remaining(), 0, "no trailing bytes after the result");

    // The build sandbox always has MIT krb5 compiled in, so indicate_mechs must
    // succeed and advertise the krb5 mechanism.
    assert_eq!(
        res.status.major_status, 0,
        "indicate_mechs failed: major=0x{:x}",
        res.status.major_status
    );
    assert!(
        res.mechs.iter().any(|m| m.mech.0 == KRB5_MECH_OID),
        "krb5 mechanism OID missing from indicate_mechs result"
    );
}
