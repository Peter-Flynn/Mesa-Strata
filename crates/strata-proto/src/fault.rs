//! Fault-injection points for the crash tests in `strata-e2e`.
//!
//! With the `fault-injection` feature, `point(name)` appends `name` to the file named by
//! `STRATA_FAULT_TRACE` (if set) and sends SIGKILL to the whole process when `STRATA_FAULT`
//! equals `name`, which leaves on-disk state exactly as a crash or power cut would.
//! Without the feature it compiles to nothing.

#[cfg(feature = "fault-injection")]
pub fn point(name: &'static str) {
    use std::io::Write;
    use std::sync::OnceLock;
    static CONFIG: OnceLock<(Option<String>, Option<String>)> = OnceLock::new();
    let (target, trace) =
        CONFIG.get_or_init(|| (std::env::var("STRATA_FAULT").ok(), std::env::var("STRATA_FAULT_TRACE").ok()));
    if let Some(path) = trace
        && let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path)
    {
        let _ = writeln!(f, "{name}");
    }
    if target.as_deref() == Some(name) {
        let _ = rustix::process::kill_process(rustix::process::getpid(), rustix::process::Signal::KILL);
        loop {
            std::thread::park();
        }
    }
}

#[cfg(not(feature = "fault-injection"))]
#[inline(always)]
pub fn point(_name: &'static str) {}
