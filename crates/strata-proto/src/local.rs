//! Local IPC between the privilege-split halves (netd ↔ zfsd, the client's ZFS half ↔
//! network half): `SOCK_SEQPACKET` Unix sockets carrying fixed-size messages, with file
//! descriptors passed alongside as `SCM_RIGHTS`.
//!
//! Every message is exactly `LOCAL_MSG` bytes: `tag u16 LE` followed by fixed-width fields.
//! Strings are `len u16 LE || max bytes`, zero-padded, and every unused byte must be zero,
//! so a decoder accepts exactly one byte string per message value.

use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
    SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags, SocketType,
};

pub const LOCAL_MSG: usize = 2048;
pub const MAX_FDS: usize = 2;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed local message: {0}")]
pub struct Malformed(pub &'static str);

pub struct Enc {
    buf: Box<[u8; LOCAL_MSG]>,
    pos: usize,
    err: Option<&'static str>,
}

impl Enc {
    pub fn new(tag: u16) -> Enc {
        let mut e = Enc { buf: Box::new([0; LOCAL_MSG]), pos: 0, err: None };
        e.u16(tag);
        e
    }

    fn put(&mut self, b: &[u8]) -> &mut Self {
        if self.pos + b.len() > LOCAL_MSG {
            self.err.get_or_insert("message overflow");
            return self;
        }
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.put(&[v])
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.put(&v.to_le_bytes())
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.put(&v.to_le_bytes())
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.put(&v.to_le_bytes())
    }
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.put(&v.to_le_bytes())
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.u8(v as u8)
    }
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.put(b)
    }

    pub fn str(&mut self, s: &str, max: usize) -> &mut Self {
        if s.len() > max || s.contains('\0') {
            self.err.get_or_insert("string too long or contains NUL");
            return self;
        }
        self.u16(s.len() as u16);
        self.put(s.as_bytes());
        let pad = max - s.len();
        if self.pos + pad > LOCAL_MSG {
            self.err.get_or_insert("message overflow");
        } else {
            self.pos += pad;
        }
        self
    }

    pub fn opt_str(&mut self, s: Option<&str>, max: usize) -> &mut Self {
        self.bool(s.is_some());
        self.str(s.unwrap_or(""), max)
    }

    pub fn finish(&mut self) -> Result<Box<[u8; LOCAL_MSG]>, Malformed> {
        if let Some(e) = self.err {
            return Err(Malformed(e));
        }
        Ok(std::mem::replace(&mut self.buf, Box::new([0; LOCAL_MSG])))
    }
}

pub struct Dec<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Dec<'a> {
    pub fn new(buf: &'a [u8; LOCAL_MSG]) -> Dec<'a> {
        Dec { buf: &buf[..], pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], Malformed> {
        if self.pos + n > self.buf.len() {
            return Err(Malformed("truncated"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, Malformed> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16, Malformed> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    pub fn u32(&mut self) -> Result<u32, Malformed> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    pub fn u64(&mut self) -> Result<u64, Malformed> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn i64(&mut self) -> Result<i64, Malformed> {
        Ok(i64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
    pub fn bool(&mut self) -> Result<bool, Malformed> {
        match self.u8()? {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(Malformed("bad bool")),
        }
    }
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N], Malformed> {
        Ok(self.take(N)?.try_into().unwrap())
    }

    pub fn str(&mut self, max: usize) -> Result<String, Malformed> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(Malformed("string length over field size"));
        }
        let field = self.take(max)?;
        if field[len..].iter().any(|&b| b != 0) {
            return Err(Malformed("nonzero string padding"));
        }
        let s = std::str::from_utf8(&field[..len]).map_err(|_| Malformed("string not UTF-8"))?;
        if s.contains('\0') {
            return Err(Malformed("NUL in string"));
        }
        Ok(s.to_string())
    }

    pub fn opt_str(&mut self, max: usize) -> Result<Option<String>, Malformed> {
        let present = self.bool()?;
        let s = self.str(max)?;
        match (present, s.is_empty()) {
            (true, _) => Ok(Some(s)),
            (false, true) => Ok(None),
            (false, false) => Err(Malformed("absent string with content")),
        }
    }

    pub fn finish(&self) -> Result<(), Malformed> {
        if self.buf[self.pos..].iter().any(|&b| b != 0) {
            return Err(Malformed("trailing bytes"));
        }
        Ok(())
    }
}

/// A connected `SOCK_SEQPACKET` socket.
pub struct LocalSock {
    fd: OwnedFd,
}

pub struct Received {
    pub msg: Box<[u8; LOCAL_MSG]>,
    pub fds: Vec<OwnedFd>,
}

impl LocalSock {
    pub fn from_fd(fd: OwnedFd) -> LocalSock {
        LocalSock { fd }
    }

    pub fn connect(path: &Path) -> io::Result<LocalSock> {
        let fd = rustix::net::socket_with(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None)?;
        rustix::net::connect(&fd, &SocketAddrUnix::new(path)?)?;
        Ok(LocalSock { fd })
    }

    pub fn pair() -> io::Result<(LocalSock, LocalSock)> {
        let (a, b) = rustix::net::socketpair(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None)?;
        Ok((LocalSock { fd: a }, LocalSock { fd: b }))
    }

    pub fn send(&self, msg: &[u8; LOCAL_MSG], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        assert!(fds.len() <= MAX_FDS);
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() {
            control.push(SendAncillaryMessage::ScmRights(fds));
        }
        let n = rustix::net::sendmsg(&self.fd, &[IoSlice::new(&msg[..])], &mut control, SendFlags::NOSIGNAL)?;
        if n != LOCAL_MSG {
            return Err(io::Error::other("short seqpacket send"));
        }
        Ok(())
    }

    /// Receives one message; `Ok(None)` when the peer has closed the socket.
    pub fn recv(&self) -> io::Result<Option<Received>> {
        let mut msg = Box::new([0u8; LOCAL_MSG]);
        let mut extra = [0u8; 1];
        let mut space = [MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let r = rustix::net::recvmsg(
            &self.fd,
            &mut [IoSliceMut::new(&mut msg[..]), IoSliceMut::new(&mut extra)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )?;
        let mut fds = Vec::new();
        for m in control.drain() {
            if let RecvAncillaryMessage::ScmRights(it) = m {
                fds.extend(it);
            }
        }
        if r.bytes == 0 && fds.is_empty() {
            return Ok(None);
        }
        if r.flags.intersects(ReturnFlags::TRUNC | ReturnFlags::CTRUNC) || r.bytes != LOCAL_MSG {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "local message has the wrong size"));
        }
        if fds.len() > MAX_FDS {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "too many descriptors"));
        }
        Ok(Some(Received { msg, fds }))
    }

    pub fn peer_uid(&self) -> io::Result<u32> {
        Ok(rustix::net::sockopt::socket_peercred(&self.fd)?.uid.as_raw())
    }
}

impl AsFd for LocalSock {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

/// A listening `SOCK_SEQPACKET` socket, either bound here or inherited from systemd.
pub struct LocalListener {
    fd: OwnedFd,
}

impl LocalListener {
    pub fn from_fd(fd: OwnedFd) -> LocalListener {
        LocalListener { fd }
    }

    pub fn bind(path: &Path) -> io::Result<LocalListener> {
        let _ = std::fs::remove_file(path);
        let fd = rustix::net::socket_with(AddressFamily::UNIX, SocketType::SEQPACKET, SocketFlags::CLOEXEC, None)?;
        rustix::net::bind(&fd, &SocketAddrUnix::new(path)?)?;
        rustix::net::listen(&fd, 64)?;
        Ok(LocalListener { fd })
    }

    pub fn accept(&self) -> io::Result<LocalSock> {
        Ok(LocalSock { fd: rustix::net::accept_with(&self.fd, SocketFlags::CLOEXEC)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn codec_roundtrip_and_strictness() {
        let msg = Enc::new(7).u64(42).str("tank/strata", 64).opt_str(None, 16).bool(true).finish().unwrap();
        let mut d = Dec::new(&msg);
        assert_eq!(d.u16().unwrap(), 7);
        assert_eq!(d.u64().unwrap(), 42);
        assert_eq!(d.str(64).unwrap(), "tank/strata");
        assert_eq!(d.opt_str(16).unwrap(), None);
        assert!(d.bool().unwrap());
        d.finish().unwrap();

        let mut bad = msg.clone();
        bad[LOCAL_MSG - 1] = 1;
        let mut d = Dec::new(&bad);
        d.u16().unwrap();
        d.u64().unwrap();
        d.str(64).unwrap();
        d.opt_str(16).unwrap();
        d.bool().unwrap();
        assert!(d.finish().is_err());

        assert!(Enc::new(1).str(&"x".repeat(65), 64).finish().is_err());
    }

    #[test]
    fn passes_fds() {
        let (a, b) = LocalSock::pair().unwrap();
        let (r, w) = rustix::pipe::pipe().unwrap();
        let msg = Enc::new(1).finish().unwrap();
        a.send(&msg, &[w.as_fd()]).unwrap();
        drop(w);
        let got = b.recv().unwrap().unwrap();
        assert_eq!(got.fds.len(), 1);
        let mut wf = std::fs::File::from(got.fds.into_iter().next().unwrap());
        wf.write_all(b"hi").unwrap();
        drop(wf);
        let mut s = String::new();
        std::fs::File::from(r).read_to_string(&mut s).unwrap();
        assert_eq!(s, "hi");
        drop(a);
        assert!(b.recv().unwrap().is_none());
    }
}
