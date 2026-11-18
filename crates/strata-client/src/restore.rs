//! `strata restore`, `strata sources`, `strata snapshots`: run as the invoking user
//! (normally root), with all network traffic in an unprivileged network-half child.

use std::fmt::Write as _;
use std::io::BufRead;

use anyhow::{Context, bail};
use strata_proto::msg::SnapshotInfo;
use strata_proto::names::{utc_compact, utc_readable};
use strata_zfs::{RecvOpts, Zfs};

use crate::config::SourceConfig;
use crate::ipc::{CReq, CResp};
use crate::net::NetClient;

pub fn list_snapshots(net: &NetClient, source: &str) -> anyhow::Result<Vec<SnapshotInfo>> {
    Ok(net
        .list(&CReq::ListSnapshots { source: source.into() })?
        .into_iter()
        .filter_map(|r| match r {
            CResp::Snapshot(s) => Some(s),
            _ => None,
        })
        .collect())
}

pub fn sources_table(net: &NetClient) -> anyhow::Result<String> {
    let mut out = String::new();
    let _ = writeln!(out, "{:<16} {:<8} {:>5}  NEWEST", "SOURCE", "KIND", "SNAPS");
    for r in net.list(&CReq::ListSources)? {
        if let CResp::Source { name, kind, snapshots, newest } = r {
            let newest = newest.map(|n| format!("{} ({})", n.name, utc_readable(n.unix_time))).unwrap_or_else(|| "-".into());
            let _ = writeln!(out, "{name:<16} {:<8} {snapshots:>5}  {newest}", format!("{kind:?}"));
        }
    }
    Ok(out)
}

pub fn snapshots_table(snaps: &[SnapshotInfo]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{:<34} {:>6} {:<22} {:>14}", "SNAPSHOT", "GEN", "TIME", "USED");
    for s in snaps {
        let _ = writeln!(out, "{:<34} {:>6} {:<22} {:>14}", s.name, s.generation, utc_readable(s.unix_time), s.used_bytes);
    }
    out
}

pub struct RestoreOpts {
    pub source: String,
    pub snapshot: Option<String>,
    pub target: Option<String>,
    pub replace: bool,
    pub yes: bool,
    pub full: bool,
}

fn confirm(prompt: &str, expected: &str) -> anyhow::Result<()> {
    eprint!("{prompt} Type {expected:?} to confirm: ");
    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    if line.trim() != expected {
        bail!("not confirmed");
    }
    Ok(())
}

/// Receives the chosen snapshot into a new dataset (incrementally, as a clone of a local
/// snapshot the server also has, when one exists); with `replace`, swaps it into the
/// original's place and keeps the original under a `-strata-old-<UTC>` name.
pub fn restore(zfs: &dyn Zfs, net: &NetClient, src: &SourceConfig, o: &RestoreOpts) -> anyhow::Result<String> {
    let ds = src.dataset.as_str();
    let snaps = list_snapshots(net, &o.source)?;
    let want = o.snapshot.as_deref().unwrap_or("latest");
    let s = if want == "latest" {
        snaps.last().context("the server has no snapshots of this source")?
    } else {
        snaps.iter().find(|s| s.name == want).with_context(|| format!("no snapshot {want} of {}", o.source))?
    };
    let target = o.target.clone().unwrap_or_else(|| format!("{ds}-restore-g{}", s.generation));
    if zfs.exists(&target)? {
        bail!("{target} already exists; pick another --target");
    }
    let mut origin = None;
    let mut from = None;
    if !o.full && zfs.exists(ds)? {
        let local = zfs.snapshots(ds, &[])?;
        let older = snaps.iter().take_while(|x| x.name != s.name);
        if let Some((srv, loc)) =
            older.filter_map(|x| local.iter().find(|l| l.guid == x.guid).map(|l| (x, l))).last()
        {
            log::info!("restoring incrementally from {}@{} (= server {})", ds, loc.name, srv.name);
            origin = Some(format!("{ds}@{}", loc.name));
            from = Some(srv);
        }
    }
    let rx = zfs.receive(&target, &RecvOpts { resumable: false, no_mount: false, props: Vec::new(), origin })?;
    net.send(
        &CReq::Restore {
            source: o.source.clone(),
            snapshot: s.name.clone(),
            from: from.map(|f| f.name.clone()),
            fromguid: from.map_or(0, |f| f.guid),
            toguid: s.guid,
        },
        Some(&rx.stdin),
    )?;
    // The receive sees EOF only when every copy of the pipe's write end is closed, and the
    // network half now holds its own.
    drop(rx.stdin);
    let reply = net.recv()?;
    let recv = rx.job.wait();
    match reply {
        CResp::Restored => {}
        CResp::Error { code, message } => bail!("restore failed: {code:?}: {message}"),
        other => bail!("unexpected reply {other:?}"),
    }
    recv.context("zfs receive")?;
    eprintln!("restored {}@{} into {target}", o.source, s.name);
    if o.replace {
        if !zfs.exists(ds)? {
            zfs.rename(&target, ds)?;
            return Ok(ds.to_string());
        }
        let old = format!("{ds}-strata-old-{}", utc_compact(now()));
        if !o.yes {
            confirm(&format!("Replace {ds} with the restored copy? {ds} itself is kept as {old}."), ds)?;
        }
        zfs.rename(ds, &old)?;
        zfs.rename(&target, ds)?;
        eprintln!("{ds} now holds {}@{}; the previous contents are in {old}", o.source, s.name);
        return Ok(ds.to_string());
    }
    Ok(target)
}

fn now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}
