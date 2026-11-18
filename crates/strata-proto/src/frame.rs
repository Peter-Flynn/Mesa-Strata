use std::io::{self, Read, Write};

/// Noise's maximum message length; frames use the same limit in plaintext mode.
pub const MAX_FRAME: usize = 65535;
pub const AEAD_TAG: usize = 16;
pub const MAX_PLAINTEXT: usize = MAX_FRAME - AEAD_TAG;

pub fn write_frame(w: &mut impl Write, payload: &[u8]) -> io::Result<()> {
    assert!(payload.len() <= MAX_FRAME, "frame too large");
    let mut buf = Vec::with_capacity(payload.len() + 2);
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    w.write_all(&buf)
}

pub fn read_frame(r: &mut impl Read, buf: &mut Vec<u8>) -> io::Result<()> {
    let mut len = [0u8; 2];
    r.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    buf.resize(len, 0);
    r.read_exact(buf)
}
