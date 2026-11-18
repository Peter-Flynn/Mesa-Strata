pub mod fake;
mod lzc;
pub mod real;

use std::collections::BTreeMap;
use std::os::fd::OwnedFd;
use std::thread::JoinHandle;

pub use fake::Fake;
pub use real::Real;

#[derive(Debug, thiserror::Error)]
pub enum ZfsError {
    #[error("{0}: does not exist")]
    NotFound(String),
    #[error("{0}: already exists")]
    Exists(String),
    #[error("{0}: busy")]
    Busy(String),
    #[error("{0}")]
    Failed(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("this build has no libzfs_core support")]
    Unsupported,
}

pub type Result<T> = std::result::Result<T, ZfsError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum DsType {
    Filesystem,
    Volume,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snap {
    /// The part after `@`.
    pub name: String,
    pub guid: u64,
    pub createtxg: u64,
    pub creation: i64,
    pub used: u64,
    pub userrefs: u64,
    pub has_clones: bool,
    pub props: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bookmark {
    /// The part after `#`.
    pub name: String,
    pub guid: u64,
    pub createtxg: u64,
}

/// `zfs send` flags: `-L`, `-e`, `-c`, `-w`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SendFlags {
    pub large_block: bool,
    pub embed: bool,
    pub compress: bool,
    pub raw: bool,
}

impl SendFlags {
    pub fn standard(raw: bool) -> SendFlags {
        SendFlags { large_block: true, embed: true, compress: true, raw }
    }
}

#[derive(Clone, Debug, Default)]
pub struct RecvOpts {
    /// `-s`
    pub resumable: bool,
    /// `-u`
    pub no_mount: bool,
    /// `-o prop=value`
    pub props: Vec<(String, String)>,
    /// `-o origin=snapshot`
    pub origin: Option<String>,
}

pub enum Job {
    Thread(JoinHandle<Result<()>>),
    Child { child: std::process::Child, what: String, stderr: Option<JoinHandle<String>> },
}

impl Job {
    pub fn wait(self) -> Result<()> {
        match self {
            Job::Thread(h) => h.join().unwrap_or_else(|_| Err(ZfsError::Failed("zfs worker thread panicked".into()))),
            Job::Child { mut child, what, stderr } => {
                let status = child.wait()?;
                let err = stderr.and_then(|h| h.join().ok()).unwrap_or_default();
                if status.success() {
                    Ok(())
                } else {
                    Err(ZfsError::Failed(format!("{what}: {status}: {}", err.trim())))
                }
            }
        }
    }

    /// Stops a child process; a thread job stops on its own once its pipe is closed.
    pub fn kill(&mut self) {
        if let Job::Child { child, .. } = self {
            let _ = child.kill();
        }
    }
}

pub struct Receiving {
    /// Write end of the stream pipe.
    pub stdin: OwnedFd,
    pub job: Job,
}

pub trait Zfs: Send + Sync {
    fn exists(&self, ds: &str) -> Result<bool>;
    fn dataset_type(&self, ds: &str) -> Result<DsType>;
    fn children(&self, ds: &str) -> Result<Vec<String>>;
    /// Snapshots of `ds` (not of its children), oldest first, with the listed user
    /// properties filled in where set.
    fn snapshots(&self, ds: &str, user_props: &[&str]) -> Result<Vec<Snap>>;
    fn bookmarks(&self, ds: &str) -> Result<Vec<Bookmark>>;
    /// A property's value; `None` when unset (`-`).
    fn get_prop(&self, ds: &str, prop: &str) -> Result<Option<String>>;
    fn set_props(&self, target: &str, props: &[(&str, &str)]) -> Result<()>;
    fn create(&self, ds: &str, props: &[(&str, &str)]) -> Result<()>;
    /// Creates the snapshots atomically, with user properties set at creation.
    fn snapshot(&self, snaps: &[String], props: &[(&str, &str)]) -> Result<()>;
    fn hold(&self, snap: &str, tag: &str) -> Result<()>;
    fn release(&self, snap: &str, tag: &str) -> Result<()>;
    fn holds(&self, snap: &str) -> Result<Vec<String>>;
    /// Destroys what it can and returns the snapshots it could not destroy.
    fn destroy_snapshots(&self, snaps: &[String]) -> Result<Vec<(String, ZfsError)>>;
    fn bookmark(&self, snap: &str, bookmark: &str) -> Result<()>;
    fn destroy_bookmarks(&self, bookmarks: &[String]) -> Result<()>;
    /// Writes a send stream of `snap` (incremental from `from`, a snapshot or bookmark) to
    /// `out`, resuming at `(object, offset)` when given.
    fn send(&self, snap: &str, from: Option<&str>, flags: SendFlags, resume: Option<(u64, u64)>, out: OwnedFd)
    -> Result<Job>;
    fn receive(&self, target: &str, opts: &RecvOpts) -> Result<Receiving>;
    /// `zfs receive -A`: discards a partially received stream.
    fn receive_abort(&self, ds: &str) -> Result<()>;
    fn rename(&self, from: &str, to: &str) -> Result<()>;
    /// `zfs mount`; needs root on Linux.
    fn mount(&self, ds: &str) -> Result<()>;
    /// `zfs promote`: the clone takes over its origin's snapshots up to the origin.
    fn promote(&self, ds: &str) -> Result<()>;
    /// `zfs inherit`, which also removes a user property.
    fn inherit(&self, ds: &str, prop: &str) -> Result<()>;
    /// Destroys a dataset that has no snapshots and no children.
    fn destroy(&self, ds: &str) -> Result<()>;
    /// `zfs unmount`; fails with `Busy` while files are open.
    fn unmount(&self, ds: &str) -> Result<()>;
    /// Properties set locally on `ds` (`zfs get -s local`), user properties included.
    fn local_props(&self, ds: &str) -> Result<Vec<(String, String)>>;
    fn destroy_recursive(&self, ds: &str) -> Result<()>;
    fn allow(&self, user: &str, perms: &str, ds: &str) -> Result<()>;
}

pub fn split_snapshot(full: &str) -> Option<(&str, &str)> {
    full.split_once('@')
}
