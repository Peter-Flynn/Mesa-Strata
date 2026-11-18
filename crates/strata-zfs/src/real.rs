//! Real pools: libzfs_core for snapshot, hold, release, send, destroy and bookmark; the
//! `zfs` command (`-Hp` where it prints) for receive and everything else.

use std::collections::BTreeMap;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use crate::{Bookmark, DsType, Job, Receiving, RecvOpts, Result, SendFlags, Snap, Zfs, ZfsError, lzc};

pub struct Real {
    zfs: PathBuf,
}

impl Default for Real {
    fn default() -> Self {
        Real::new("zfs")
    }
}

impl Real {
    pub fn new(zfs: impl Into<PathBuf>) -> Real {
        Real { zfs: zfs.into() }
    }

    fn run(&self, args: &[&str]) -> Result<String> {
        let out = Command::new(&self.zfs).args(args).stdin(Stdio::null()).output()?;
        if out.status.success() {
            return Ok(String::from_utf8_lossy(&out.stdout).into_owned());
        }
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        let what = format!("zfs {}: {err}", args.join(" "));
        if err.contains("does not exist") {
            Err(ZfsError::NotFound(what))
        } else if err.contains("already exists") {
            Err(ZfsError::Exists(what))
        } else if err.contains("busy") {
            Err(ZfsError::Busy(what))
        } else {
            Err(ZfsError::Failed(what))
        }
    }
}

fn opt(v: &str) -> Option<String> {
    if v == "-" || v.is_empty() { None } else { Some(v.to_string()) }
}

fn num(field: &str, v: &str) -> Result<u64> {
    v.parse().map_err(|_| ZfsError::Failed(format!("zfs printed a non-numeric {field}: {v:?}")))
}

impl Zfs for Real {
    fn exists(&self, ds: &str) -> Result<bool> {
        match self.run(&["list", "-H", "-o", "name", ds]) {
            Ok(_) => Ok(true),
            Err(ZfsError::NotFound(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn dataset_type(&self, ds: &str) -> Result<DsType> {
        match self.run(&["get", "-Hp", "-o", "value", "type", ds])?.trim() {
            "filesystem" => Ok(DsType::Filesystem),
            "volume" => Ok(DsType::Volume),
            t => Err(ZfsError::Failed(format!("{ds} is a {t}, not a filesystem or volume"))),
        }
    }

    fn children(&self, ds: &str) -> Result<Vec<String>> {
        let out = self.run(&["list", "-Hp", "-d", "1", "-t", "filesystem,volume", "-o", "name", ds])?;
        Ok(out.lines().filter(|l| *l != ds).map(str::to_string).collect())
    }

    fn snapshots(&self, ds: &str, user_props: &[&str]) -> Result<Vec<Snap>> {
        let mut cols = vec!["name", "guid", "createtxg", "creation", "used", "userrefs", "clones"];
        cols.extend_from_slice(user_props);
        let cols = cols.join(",");
        let out = self.run(&["list", "-Hp", "-t", "snapshot", "-d", "1", "-s", "createtxg", "-o", &cols, ds])?;
        let mut snaps = Vec::new();
        for line in out.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 7 + user_props.len() {
                return Err(ZfsError::Failed(format!("unexpected zfs list output: {line:?}")));
            }
            let Some((parent, name)) = f[0].split_once('@') else { continue };
            if parent != ds {
                continue;
            }
            let mut props = BTreeMap::new();
            for (i, p) in user_props.iter().enumerate() {
                if let Some(v) = opt(f[7 + i]) {
                    props.insert(p.to_string(), v);
                }
            }
            snaps.push(Snap {
                name: name.to_string(),
                guid: num("guid", f[1])?,
                createtxg: num("createtxg", f[2])?,
                creation: num("creation", f[3])? as i64,
                used: num("used", f[4])?,
                userrefs: num("userrefs", f[5])?,
                has_clones: opt(f[6]).is_some(),
                props,
            });
        }
        Ok(snaps)
    }

    fn bookmarks(&self, ds: &str) -> Result<Vec<Bookmark>> {
        let out = self.run(&["list", "-Hp", "-t", "bookmark", "-d", "1", "-s", "createtxg", "-o", "name,guid,createtxg", ds])?;
        let mut v = Vec::new();
        for line in out.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() != 3 {
                return Err(ZfsError::Failed(format!("unexpected zfs list output: {line:?}")));
            }
            let Some((parent, name)) = f[0].split_once('#') else { continue };
            if parent == ds {
                v.push(Bookmark { name: name.to_string(), guid: num("guid", f[1])?, createtxg: num("createtxg", f[2])? });
            }
        }
        Ok(v)
    }

    fn get_prop(&self, ds: &str, prop: &str) -> Result<Option<String>> {
        Ok(opt(self.run(&["get", "-Hp", "-o", "value", prop, ds])?.trim_end_matches('\n')))
    }

    fn set_props(&self, target: &str, props: &[(&str, &str)]) -> Result<()> {
        let kv: Vec<String> = props.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut args = vec!["set"];
        args.extend(kv.iter().map(String::as_str));
        args.push(target);
        self.run(&args).map(drop)
    }

    fn create(&self, ds: &str, props: &[(&str, &str)]) -> Result<()> {
        let kv: Vec<String> = props.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut args = vec!["create"];
        for p in &kv {
            args.extend(["-o", p.as_str()]);
        }
        args.push(ds);
        self.run(&args).map(drop)
    }

    fn snapshot(&self, snaps: &[String], props: &[(&str, &str)]) -> Result<()> {
        lzc::snapshot(snaps, props)
    }

    fn hold(&self, snap: &str, tag: &str) -> Result<()> {
        lzc::hold(snap, tag)
    }

    fn release(&self, snap: &str, tag: &str) -> Result<()> {
        lzc::release(snap, tag)
    }

    fn holds(&self, snap: &str) -> Result<Vec<String>> {
        let out = self.run(&["holds", "-H", snap])?;
        Ok(out.lines().filter_map(|l| l.split('\t').nth(1)).map(str::to_string).collect())
    }

    fn destroy_snapshots(&self, snaps: &[String]) -> Result<Vec<(String, ZfsError)>> {
        if snaps.is_empty() {
            return Ok(Vec::new());
        }
        lzc::destroy_snaps(snaps)
    }

    fn bookmark(&self, snap: &str, bookmark: &str) -> Result<()> {
        lzc::bookmark(snap, bookmark)
    }

    fn destroy_bookmarks(&self, bookmarks: &[String]) -> Result<()> {
        if bookmarks.is_empty() {
            return Ok(());
        }
        lzc::destroy_bookmarks(bookmarks)
    }

    fn send(&self, snap: &str, from: Option<&str>, flags: SendFlags, resume: Option<(u64, u64)>, out: OwnedFd) -> Result<Job> {
        let snap = snap.to_string();
        let from = from.map(str::to_string);
        Ok(Job::Thread(std::thread::spawn(move || {
            let r = lzc::send(&snap, from.as_deref(), flags, resume, &out);
            drop(out);
            r
        })))
    }

    fn receive(&self, target: &str, opts: &RecvOpts) -> Result<Receiving> {
        let (r, w) = rustix::pipe::pipe_with(rustix::pipe::PipeFlags::CLOEXEC).map_err(std::io::Error::from)?;
        let mut cmd = Command::new(&self.zfs);
        cmd.arg("receive");
        if opts.resumable {
            cmd.arg("-s");
        }
        if opts.no_mount {
            cmd.arg("-u");
        }
        for (k, v) in &opts.props {
            cmd.arg("-o").arg(format!("{k}={v}"));
        }
        if let Some(o) = &opts.origin {
            cmd.arg("-o").arg(format!("origin={o}"));
        }
        cmd.arg(target).stdin(Stdio::from(r)).stdout(Stdio::null()).stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let mut err = child.stderr.take().unwrap();
        let stderr = std::thread::spawn(move || {
            let mut s = String::new();
            let _ = err.read_to_string(&mut s);
            s
        });
        Ok(Receiving {
            stdin: w,
            job: Job::Child { child, what: format!("zfs receive {target}"), stderr: Some(stderr) },
        })
    }

    fn receive_abort(&self, ds: &str) -> Result<()> {
        self.run(&["receive", "-A", ds]).map(drop)
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.run(&["rename", from, to]).map(drop)
    }

    fn mount(&self, ds: &str) -> Result<()> {
        self.run(&["mount", ds]).map(drop)
    }

    fn destroy_recursive(&self, ds: &str) -> Result<()> {
        self.run(&["destroy", "-r", ds]).map(drop)
    }

    fn allow(&self, user: &str, perms: &str, ds: &str) -> Result<()> {
        self.run(&["allow", "-u", user, perms, ds]).map(drop)
    }
}
