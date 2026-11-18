//! Cleartext handshake messages and the client side of the handshake.
//!
//! Flow (every message is one frame, postcard-encoded `Hs`):
//!
//! ```text
//! C -> S  Hello        version, client name, auth mode, client nonce
//! S -> C  ServerHello  version, server id, server nonce, Proceed | Reject
//!   auth none: both sides switch to plaintext transport here.
//! C -> S  CpaceA       Ya
//! S -> C  CpaceB       Yb, Tb      (Tb proves the server holds the same derived key)
//! C -> S  Confirm      Ta          (zfsd checks Ta before netd receives any key)
//! C -> S  Noise        Noise_NNpsk0 message 1 (psk = KDF(ISK)), prologue = both hellos
//! S -> C  Noise | Fail message 2, or the reason the server gave up
//! ```
//!
//! CPace inputs: PRS = the client's derived key; CI = lv_cat("strata", client, server id);
//! sid = client nonce || server nonce; ADa = "client", ADb = "server".

use std::io::{Read, Write};
use std::net::TcpStream;

use serde::{Deserialize, Serialize};

use crate::cpace::{self, Element, Tag};
use crate::frame::{read_frame, write_frame};
use crate::kdf::{DerivedKey, ServerId};
use crate::msg::{AuthMode, PROTOCOL_VERSION};
use crate::session::Session;
use crate::{Error, Result};

pub const NOISE_PARAMS: &str = "Noise_NNpsk0_25519_AESGCM_SHA256";
pub const AD_CLIENT: &[u8] = b"client";
pub const AD_SERVER: &[u8] = b"server";
pub const PSK_LABEL: &[u8] = b"noise-psk0";

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ClientHello {
    pub version: u16,
    pub client: String,
    pub auth: AuthMode,
    pub nonce: [u8; 16],
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    UnsupportedVersion,
    UnknownClient,
    AuthModeMismatch,
    AddressNotAllowed,
    BackingOff,
    AuthFailed,
    Internal,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloResult {
    Proceed,
    Reject { reason: RejectReason, retry_after_ms: u32 },
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ServerHello {
    pub version: u16,
    pub server_id: ServerId,
    pub nonce: [u8; 16],
    pub result: HelloResult,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum Hs {
    Hello(ClientHello),
    ServerHello(ServerHello),
    CpaceA {
        ya: Element,
    },
    CpaceB {
        yb: Element,
        #[serde(with = "serde_bytes")]
        tb: Tag,
    },
    Confirm {
        #[serde(with = "serde_bytes")]
        ta: Tag,
    },
    Noise(#[serde(with = "serde_bytes")] Vec<u8>),
    Fail(RejectReason),
}

pub fn send_hs(w: &mut impl Write, hs: &Hs) -> Result<Vec<u8>> {
    let bytes = postcard::to_allocvec(hs).expect("postcard");
    write_frame(w, &bytes)?;
    Ok(bytes)
}

pub fn recv_hs(r: &mut impl Read) -> Result<(Hs, Vec<u8>)> {
    let mut buf = Vec::new();
    read_frame(r, &mut buf)?;
    let hs = postcard::from_bytes(&buf).map_err(|e| Error::Protocol(format!("bad handshake message: {e}")))?;
    Ok((hs, buf))
}

pub fn channel_id(client: &str, server_id: &ServerId) -> Vec<u8> {
    cpace::lv_cat(&[b"strata", client.as_bytes(), server_id])
}

pub fn session_id(client_nonce: &[u8; 16], server_nonce: &[u8; 16]) -> Vec<u8> {
    let mut sid = client_nonce.to_vec();
    sid.extend_from_slice(server_nonce);
    sid
}

pub fn prologue(client_hello: &[u8], server_hello: &[u8]) -> Vec<u8> {
    cpace::lv_cat(&[b"strata-prologue", client_hello, server_hello])
}

pub fn noise_builder<'a>(prologue: &'a [u8], psk: &'a [u8; 32]) -> snow::Builder<'a> {
    let resolver = snow::resolvers::FallbackResolver::new(
        Box::new(snow::resolvers::RingResolver),
        Box::new(snow::resolvers::DefaultResolver),
    );
    snow::Builder::with_resolver(NOISE_PARAMS.parse().expect("noise params"), Box::new(resolver))
        .prologue(prologue)
        .expect("prologue")
        .psk(0, psk)
        .expect("psk")
}

pub enum ClientSecret {
    Password(Vec<u8>),
    Key(DerivedKey),
}

pub struct ClientAuth {
    pub client: String,
    pub mode: AuthMode,
    pub secret: Option<ClientSecret>,
}

pub fn random16() -> [u8; 16] {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).expect("getrandom");
    b
}

/// Runs the client side of the handshake on a connected stream and returns the session.
/// `compress_threads` sizes the session's compression pool.
pub fn client_handshake(stream: TcpStream, auth: &ClientAuth, compress_threads: usize) -> Result<Session> {
    stream.set_nodelay(true).ok();
    let mut s = &stream;
    let nonce_c = random16();
    let hello = ClientHello {
        version: PROTOCOL_VERSION,
        client: auth.client.clone(),
        auth: auth.mode,
        nonce: nonce_c,
    };
    let hello_bytes = send_hs(&mut s, &Hs::Hello(hello))?;
    let (reply, reply_bytes) = recv_hs(&mut s)?;
    let Hs::ServerHello(sh) = reply else {
        return Err(Error::Protocol("expected ServerHello".into()));
    };
    if let HelloResult::Reject { reason, retry_after_ms } = sh.result {
        return Err(Error::Rejected { reason, retry_after_ms });
    }
    if sh.version != PROTOCOL_VERSION {
        return Err(Error::Protocol(format!("server chose unsupported version {}", sh.version)));
    }
    let prologue = prologue(&hello_bytes, &reply_bytes);
    match auth.mode {
        AuthMode::None => Ok(Session::plain(stream, compress_threads)?),
        AuthMode::Psk => {
            let prs = match auth.secret.as_ref() {
                Some(ClientSecret::Key(k)) => *k,
                Some(ClientSecret::Password(p)) => crate::kdf::derive_key(p, &sh.server_id, &auth.client),
                None => return Err(Error::Protocol("psk auth needs a password or key".into())),
            };
            let ci = channel_id(&auth.client, &sh.server_id);
            let sid = session_id(&nonce_c, &sh.nonce);
            let (init, ya) = cpace::Initiator::start(&prs, &ci, &sid, AD_CLIENT);
            send_hs(&mut s, &Hs::CpaceA { ya })?;
            let (yb, tb) = match recv_hs(&mut s)?.0 {
                Hs::CpaceB { yb, tb } => (yb, tb),
                Hs::Fail(reason) => return Err(Error::Rejected { reason, retry_after_ms: 0 }),
                _ => return Err(Error::Protocol("expected CpaceB".into())),
            };
            let keys = init.finish(&yb, AD_SERVER).map_err(|_| Error::AuthFailed)?;
            keys.verify(&yb, AD_SERVER, &tb).map_err(|_| Error::AuthFailed)?;
            send_hs(&mut s, &Hs::Confirm { ta: keys.tag(&ya, AD_CLIENT) })?;
            let psk = keys.derive(PSK_LABEL);
            let mut noise = noise_builder(&prologue, &psk).build_initiator()?;
            let mut buf = vec![0u8; 1024];
            let n = noise.write_message(&[], &mut buf)?;
            send_hs(&mut s, &Hs::Noise(buf[..n].to_vec()))?;
            let msg2 = match recv_hs(&mut s)?.0 {
                Hs::Noise(m) => m,
                Hs::Fail(reason) => return Err(Error::Rejected { reason, retry_after_ms: 0 }),
                _ => return Err(Error::Protocol("expected Noise message 2".into())),
            };
            noise.read_message(&msg2, &mut buf)?;
            let transport = noise.into_stateless_transport_mode()?;
            Ok(Session::noise(stream, transport, compress_threads)?)
        }
    }
}
