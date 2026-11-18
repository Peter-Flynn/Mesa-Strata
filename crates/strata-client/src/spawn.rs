use std::os::fd::OwnedFd;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use strata_proto::local::LocalSock;

use crate::net::NetClient;

/// UID/GID of `nobody`/`nogroup` (65534 on NixOS and most distributions).
const NOBODY: u32 = 65534;

fn nobody() -> (u32, u32) {
    let passwd = std::fs::read_to_string("/etc/passwd").unwrap_or_default();
    passwd
        .lines()
        .find_map(|l| {
            let f: Vec<&str> = l.split(':').collect();
            (f.len() > 3 && f[0] == "nobody").then(|| Some((f[2].parse().ok()?, f[3].parse().ok()?)))?
        })
        .unwrap_or((NOBODY, NOBODY))
}

/// Starts the network half as a child process talking over its stdin. Run as root, the
/// child drops to `nobody` with no supplementary groups before it executes.
pub fn spawn_net_child(exe: &Path, args: &[&str]) -> anyhow::Result<(NetClient, Child)> {
    let (ours, theirs) = LocalSock::pair()?;
    let mut cmd = Command::new(exe);
    cmd.args(args).stdin(Stdio::from(OwnedFd::from(theirs))).stdout(Stdio::null());
    if rustix::process::geteuid().is_root() {
        let (uid, gid) = nobody();
        cmd.uid(uid).gid(gid);
    }
    let child = cmd.spawn()?;
    Ok((NetClient::new(ours), child))
}

/// In the child: takes the socket from stdin and forbids regaining privileges.
pub fn net_child_socket() -> anyhow::Result<LocalSock> {
    rustix::thread::set_no_new_privs(true)?;
    let fd = rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3)?;
    Ok(LocalSock::from_fd(fd))
}
