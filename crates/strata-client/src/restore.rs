//! `strata restore`, `strata sources`, `strata snapshots`: run as the invoking user
//! (normally root), with all network traffic in an unprivileged network-half child.

use std::fmt::Write as _;
use std::io::BufRead;

use anyhow::{Context, bail};
use strata_proto::msg::{ErrorCode, SnapshotInfo};
use strata_proto::names::{unix_now, utc_compact, utc_readable};
use strata_zfs::{DsType, RecvOpts, Zfs};

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
            let newest =
                newest.map(|n| format!("{} ({})", n.name, utc_readable(n.unix_time))).unwrap_or_else(|| "-".into());
            let _ = writeln!(out, "{name:<16} {:<8} {snapshots:>5}  {newest}", format!("{kind:?}"));
        }
    }
    Ok(out)
}

pub fn snapshots_table(snaps: &[SnapshotInfo]) -> String {
    let mut out = String::new();
    let _ = writeln!(out, "{:<34} {:>6} {:<22} {:>14}", "SNAPSHOT", "GEN", "TIME", "USED");
    for s in snaps {
        let _ =
            writeln!(out, "{:<34} {:>6} {:<22} {:>14}", s.name, s.generation, utc_readable(s.unix_time), s.used_bytes);
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
    if o.replace && zfs.exists(ds)? {
        let kids = zfs.children(ds)?;
        if !kids.is_empty() {
            bail!(
                "{ds} has child datasets ({}); --replace would move them along with it. Restore into a separate --target instead",
                kids.join(", ")
            );
        }
    }
    let mut base = None;
    if !o.full && zfs.exists(ds)? {
        let local = zfs.snapshots(ds, &[])?;
        let older = snaps.iter().take_while(|x| x.name != s.name);
        base = older
            .filter_map(|x| local.iter().find(|l| l.guid == x.guid).map(|l| (x, format!("{ds}@{}", l.name))))
            .last();
    }
    let mut result = receive(zfs, net, &o.source, src, &target, s, base)?;
    if let Err(Refused::NotAncestor) = result {
        log::info!("the shared snapshot is not an ancestor of {}; restoring the full snapshot", s.name);
        result = receive(zfs, net, &o.source, src, &target, s, None)?;
    }
    match result {
        Ok(()) => {}
        Err(Refused::NotAncestor) => bail!("restore failed: the server refused the incremental base"),
        Err(Refused::Other(e)) => bail!("restore failed: {e}"),
    }
    eprintln!("restored {}@{} into {target}", o.source, s.name);
    if src.raw {
        eprintln!("{target} is encrypted: run `zfs load-key {target}` and `zfs mount {target}`");
    }
    if o.replace {
        replace(zfs, ds, &target, o.yes)?;
        eprintln!("{ds} now holds {}@{}", o.source, s.name);
        rebase(zfs, net, &o.source, src, s)?;
        return Ok(ds.to_string());
    }
    Ok(target)
}

enum Refused {
    NotAncestor,
    Other(String),
}

/// One receive of `s` into `target`, incrementally as a clone of `base`'s local copy when
/// given. The outer error is a local failure; the inner one is the server's or the
/// stream's refusal.
fn receive(
    zfs: &dyn Zfs,
    net: &NetClient,
    source: &str,
    src: &SourceConfig,
    target: &str,
    s: &SnapshotInfo,
    base: Option<(&SnapshotInfo, String)>,
) -> anyhow::Result<Result<(), Refused>> {
    if let Some((srv, loc)) = &base {
        log::info!("restoring incrementally from {loc} (= server {})", srv.name);
    }
    // A raw stream arrives encrypted with its key unloaded, so it can't be mounted yet.
    let opts =
        RecvOpts { resumable: false, no_mount: src.raw, props: Vec::new(), origin: base.as_ref().map(|b| b.1.clone()) };
    let rx = zfs.receive(target, &opts)?;
    net.send(
        &CReq::Restore {
            source: source.to_string(),
            snapshot: s.name.clone(),
            from: base.as_ref().map(|b| b.0.name.clone()),
            fromguid: base.as_ref().map_or(0, |b| b.0.guid),
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
        CResp::Error { code: ErrorCode::Conflict, .. } if base.is_some() => return Ok(Err(Refused::NotAncestor)),
        CResp::Error { code, message } => return Ok(Err(Refused::Other(format!("{code:?}: {message}")))),
        other => bail!("unexpected reply {other:?}"),
    }
    recv.context("zfs receive")?;
    Ok(Ok(()))
}

/// After `--replace`, the source's data is snapshot `s`. The server records the rebase
/// first and the cursor bookmark comes second: if the client stops in between, `s` is
/// still a local snapshot with the GUID the server reports, and the next backup bookmarks
/// it itself. The local copy of `s` goes last, because the client keeps no snapshots.
fn rebase(zfs: &dyn Zfs, net: &NetClient, source: &str, src: &SourceConfig, s: &SnapshotInfo) -> anyhow::Result<()> {
    match net.call(&CReq::Rebase { source: source.to_string(), snapshot: s.name.clone() })? {
        CResp::Ok => {}
        CResp::Error { code, message } => bail!(
            "{} was replaced, but the server didn't record the rebase ({code:?}: {message}); the next backup of {source} \
             fails until a restore with --replace succeeds",
            src.dataset
        ),
        other => bail!("unexpected reply to Rebase: {other:?}"),
    }
    strata_proto::fault::point("client.rebase.recorded");
    let ds = src.dataset.as_str();
    let local = zfs.snapshots(ds, &[])?.into_iter().find(|l| l.guid == s.guid).context("restored snapshot vanished")?;
    let full = format!("{ds}@{}", local.name);
    zfs.bookmark(&full, &format!("{ds}#{}", crate::backup::cursor_name(source, s.guid)))?;
    strata_proto::fault::point("client.rebase.bookmarked");
    for (n, e) in zfs.destroy_snapshots(std::slice::from_ref(&full))? {
        log::warn!("could not destroy {n}: {e}");
    }
    Ok(())
}

/// Properties that can't be set after creation, or that the restored stream already
/// fixed (`volsize`): carrying them over would fail or undo the restore.
const NOT_CARRIED: &[&str] = &[
    "encryption",
    "keyformat",
    "pbkdf2iters",
    "pbkdf2salt",
    "casesensitivity",
    "normalization",
    "utf8only",
    "volblocksize",
    "volsize",
];

/// Swaps the restored `target` into `ds`'s place. Order: read `ds`'s local properties,
/// unmount `ds` (a busy dataset stops everything here, before any change), set it
/// `canmount=noauto` so it never mounts over the restored copy at boot, rename it aside,
/// rename `target` into place, then carry the local properties over (received streams
/// carry none, so without this a local `mountpoint` would be lost). A failed rename puts
/// the original back.
fn replace(zfs: &dyn Zfs, ds: &str, target: &str, yes: bool) -> anyhow::Result<()> {
    if !zfs.exists(ds)? {
        zfs.rename(target, ds)?;
        return Ok(());
    }
    let stamp = utc_compact(unix_now());
    let mut old = format!("{ds}-strata-old-{stamp}");
    let mut n = 1;
    while zfs.exists(&old)? {
        n += 1;
        old = format!("{ds}-strata-old-{stamp}-{n}");
    }
    if !yes {
        confirm(&format!("Replace {ds} with the restored copy? {ds} itself is kept as {old}."), ds)?;
    }
    let props = zfs.local_props(ds)?;
    let is_fs = zfs.dataset_type(ds)? == DsType::Filesystem;
    if is_fs {
        zfs.unmount(ds).map_err(|e| {
            anyhow::anyhow!("{ds} can't be unmounted ({e}); nothing was changed. The restored copy is at {target}")
        })?;
    }
    let undo = |renamed: bool| {
        if renamed {
            let _ = zfs.rename(&old, ds);
        }
        if is_fs {
            let canmount = props.iter().find(|(k, _)| k == "canmount").map_or("on", |(_, v)| v.as_str());
            let _ = zfs.set_props(ds, &[("canmount", canmount)]);
            let _ = zfs.mount(ds);
        }
    };
    if is_fs && let Err(e) = zfs.set_props(ds, &[("canmount", "noauto")]) {
        undo(false);
        bail!("setting canmount=noauto on {ds}: {e}; nothing was changed");
    }
    if let Err(e) = zfs.rename(ds, &old) {
        undo(false);
        bail!("renaming {ds} to {old}: {e}; nothing was changed");
    }
    if let Err(e) = zfs.rename(target, ds) {
        undo(true);
        bail!("renaming {target} to {ds}: {e}; {ds} was put back");
    }
    let mut failed = Vec::new();
    for (k, v) in props.iter().filter(|(k, _)| !NOT_CARRIED.contains(&k.as_str())) {
        if let Err(e) = zfs.set_props(ds, &[(k, v)]) {
            failed.push(format!("{k}={v} ({e})"));
        }
    }
    eprintln!(
        "the previous contents of {ds} are in {old} (canmount=noauto); delete it with `zfs destroy -r {old}` once you no longer need it"
    );
    if !failed.is_empty() {
        bail!("{ds} was replaced, but these properties could not be carried over: {}", failed.join(", "));
    }
    Ok(())
}
