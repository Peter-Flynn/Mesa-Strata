use std::os::fd::{FromRawFd, OwnedFd};

const SD_LISTEN_FDS_START: i32 = 3;

/// Takes the sockets systemd passed under the socket-activation protocol (`LISTEN_PID`,
/// `LISTEN_FDS`, descriptors from 3 upward) and clears those variables so children don't
/// inherit them.
pub fn listen_fds() -> Vec<OwnedFd> {
    let pid_ok = std::env::var("LISTEN_PID")
        .ok()
        .and_then(|p| p.parse::<u32>().ok())
        .is_some_and(|p| p == std::process::id());
    let n = std::env::var("LISTEN_FDS").ok().and_then(|n| n.parse::<i32>().ok()).unwrap_or(0);
    // SAFETY: remove_var is unsound only while another thread reads the environment; this
    // runs at the top of main, before any thread is spawned.
    unsafe {
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_FDNAMES");
    }
    if !pid_ok {
        return Vec::new();
    }
    (0..n.max(0))
        .map(|i| {
            // SAFETY: under the socket-activation protocol systemd hands this process
            // ownership of descriptors 3..3+LISTEN_FDS, and nothing else in the process
            // has wrapped them yet because this is the only place that reads LISTEN_FDS.
            unsafe { OwnedFd::from_raw_fd(SD_LISTEN_FDS_START + i) }
        })
        .collect()
}
