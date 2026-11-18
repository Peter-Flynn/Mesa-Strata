use std::collections::HashMap;
use std::net::IpAddr;
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

use rustix::net::{AddressFamily, SocketType, sockopt};

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
pub enum Key {
    Client(String),
    Addr(IpAddr),
}

const FIRST_DELAY: Duration = Duration::from_secs(1);
const MAX_DELAY: Duration = Duration::from_secs(15 * 60);
const MAX_ENTRIES: usize = 65_536;

#[derive(Default)]
pub struct Backoff {
    entries: HashMap<Key, (u32, Instant)>,
}

impl Backoff {
    pub fn wait(&self, key: &Key, now: Instant) -> Option<Duration> {
        let (_, until) = self.entries.get(key)?;
        (*until > now).then(|| *until - now)
    }

    pub fn fail(&mut self, key: Key, now: Instant) {
        if self.entries.len() >= MAX_ENTRIES {
            self.entries.retain(|_, (_, until)| *until > now);
        }
        let e = self.entries.entry(key).or_insert((0, now));
        e.0 = e.0.saturating_add(1);
        let delay = FIRST_DELAY.saturating_mul(1u32 << (e.0 - 1).min(20)).min(MAX_DELAY);
        e.1 = now + delay;
    }

    pub fn succeed(&mut self, key: &Key) {
        self.entries.remove(key);
    }
}

/// Learns the client's address from the accepted TCP socket netd forwards before it
/// reads any client byte. The socket must be a connected TCP stream on the configured
/// listening port: an outbound connection a compromised process opens itself can't bind
/// that port while the listener holds it, so it can't pose as an allowed address.
pub fn peer_of(fd: &OwnedFd, listen_port: u16) -> Result<IpAddr, String> {
    let dom = sockopt::socket_domain(fd).map_err(|e| format!("socket_domain: {e}"))?;
    if dom != AddressFamily::INET && dom != AddressFamily::INET6 {
        return Err("not an IP socket".into());
    }
    if sockopt::socket_type(fd).map_err(|e| e.to_string())? != SocketType::STREAM {
        return Err("not a stream socket".into());
    }
    if sockopt::socket_acceptconn(fd).map_err(|e| e.to_string())? {
        return Err("listening socket".into());
    }
    let local = rustix::net::getsockname(fd).map_err(|e| e.to_string())?;
    let local = std::net::SocketAddr::try_from(local).map_err(|_| "unreadable local address".to_string())?;
    if local.port() != listen_port {
        return Err(format!("socket is on port {}, not {listen_port}", local.port()));
    }
    let peer = rustix::net::getpeername(fd).map_err(|e| e.to_string())?.ok_or("not connected")?;
    let peer = std::net::SocketAddr::try_from(peer).map_err(|_| "unreadable peer address".to_string())?;
    Ok(peer.ip())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_grows_and_resets() {
        let mut b = Backoff::default();
        let k = Key::Client("nas".into());
        let t0 = Instant::now();
        assert!(b.wait(&k, t0).is_none());
        b.fail(k.clone(), t0);
        assert_eq!(b.wait(&k, t0), Some(Duration::from_secs(1)));
        b.fail(k.clone(), t0);
        b.fail(k.clone(), t0);
        assert_eq!(b.wait(&k, t0), Some(Duration::from_secs(4)));
        for _ in 0..40 {
            b.fail(k.clone(), t0);
        }
        assert_eq!(b.wait(&k, t0), Some(MAX_DELAY));
        b.succeed(&k);
        assert!(b.wait(&k, t0).is_none());
    }

    #[test]
    fn peer_check() {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        let _c = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let (s, _) = l.accept().unwrap();
        let fd = OwnedFd::from(s);
        assert_eq!(peer_of(&fd, port).unwrap(), "127.0.0.1".parse::<IpAddr>().unwrap());
        assert!(peer_of(&fd, port + 1).is_err());
        assert!(peer_of(&OwnedFd::from(l), port).is_err());
    }
}
