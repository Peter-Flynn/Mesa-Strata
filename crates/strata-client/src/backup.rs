//! The ZFS half of a dataset or zvol backup.
//!
//! The incremental base is a cursor bookmark `<dataset>#strata_<source>_G_<guid hex>`;
//! the client keeps no snapshot between runs. A run:
//! 1. asks the server for its newest snapshot's GUID (`Ready`) and finds the local cursor
//!    with that GUID; if only a local snapshot has it (the previous run crashed after the
//!    server committed), it bookmarks that snapshot first;
//! 2. destroys other cursors of this source and its own leftover snapshots;
//! 3. resumes the server's partial receive when the snapshot it was receiving still exists
//!    here, or asks the server to discard it;
//! 4. takes `@strata_<source>_<UTC>` (or picks the newest `snapshotPattern` match, held
//!    while it is sent), sends it incrementally from the cursor, and once the server has
//!    committed it, creates the new cursor, then destroys the old one, then destroys (or
//!    releases) the snapshot.

use std::time::Duration;

use anyhow::{Context, bail};
use strata_proto::fault;
use strata_proto::msg::{ResumePoint, SourceKind};
use strata_proto::names::{parse_server_snapshot_name, utc_compact};
use strata_zfs::{Bookmark, DsType, SendFlags, Snap, Zfs};

use crate::config::{SourceConfig, glob};
use crate::ipc::{CReq, CResp};
use crate::net::NetClient;

const MAX_BUSY_RETRIES: u32 = 40;

pub fn cursor_name(source: &str, guid: u64) -> String {
    format!("strata_{source}_G_{guid:016x}")
}

fn parse_cursor(source: &str, name: &str) -> Option<u64> {
    let (prefix, guid) = name.rsplit_once("_G_")?;
    if prefix != format!("strata_{source}") || guid.len() != 16 {
        return None;
    }
    u64::from_str_radix(guid, 16).ok()
}

pub fn own_snapshot_name(source: &str, unix: i64) -> String {
    format!("strata_{source}_{}", utc_compact(unix))
}

fn is_own_snapshot(source: &str, name: &str) -> bool {
    match name.rsplit_once('_') {
        Some((prefix, stamp)) => {
            prefix == format!("strata_{source}")
                && stamp.len() == 16
                && stamp.ends_with('Z')
                && stamp.as_bytes()[8] == b'T'
        }
        None => false,
    }
}

fn hold_tag(source: &str) -> String {
    format!("strata-send-{source}")
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Outcome {
    pub committed: Vec<String>,
}

struct Ready {
    head: Option<(String, u64)>,
    resume: Option<ResumePoint>,
}

fn expect_ready(r: CResp) -> anyhow::Result<Option<Ready>> {
    match r {
        CResp::Ready { head, resume, .. } => Ok(Some(Ready { head, resume })),
        CResp::Busy { .. } => Ok(None),
        CResp::Error { code, message } => bail!("server: {code:?}: {message}"),
        other => bail!("unexpected reply {other:?}"),
    }
}

fn begin(net: &NetClient, source: &str, kind: SourceKind, retry_scale: f64) -> anyhow::Result<Ready> {
    for attempt in 0..=MAX_BUSY_RETRIES {
        let r = net.call(&CReq::Backup { source: source.into(), kind })?;
        let retry = match &r {
            CResp::Busy { retry_after_ms } => *retry_after_ms,
            _ => 0,
        };
        if let Some(ready) = expect_ready(r)? {
            return Ok(ready);
        }
        let jitter = strata_proto::hs::random16()[0] as f64 / 255.0 * 0.5;
        let wait = Duration::from_secs_f64(retry as f64 / 1000.0 * (1.0 + jitter) * retry_scale);
        log::info!("server busy; retrying in {:.0?} (attempt {})", wait, attempt + 1);
        std::thread::sleep(wait);
    }
    bail!("server stayed busy")
}

struct Ctx<'a> {
    zfs: &'a dyn Zfs,
    net: &'a NetClient,
    source: &'a str,
    src: &'a SourceConfig,
    ds: &'a str,
    flags: SendFlags,
    interval_secs: Option<u64>,
}

impl Ctx<'_> {
    fn cursors(&self) -> anyhow::Result<Vec<Bookmark>> {
        Ok(self.zfs.bookmarks(self.ds)?.into_iter().filter(|b| parse_cursor(self.source, &b.name).is_some()).collect())
    }

    fn snaps(&self) -> anyhow::Result<Vec<Snap>> {
        let mut v = self.zfs.snapshots(self.ds, &[])?;
        v.sort_by_key(|s| s.createtxg);
        Ok(v)
    }

    fn eligible(&self, s: &Snap) -> bool {
        if self.src.create_snapshots {
            is_own_snapshot(self.source, &s.name)
        } else {
            self.src.snapshot_pattern.as_deref().is_some_and(|p| glob(p, &s.name))
        }
    }

    /// Finds the local cursor for the server's newest snapshot, creating it from a local
    /// snapshot with that GUID if the previous run stopped before doing so.
    fn base(&self, head: &Option<(String, u64)>) -> anyhow::Result<Option<Bookmark>> {
        let Some((hname, hguid)) = head else { return Ok(None) };
        if let Some(b) = self.cursors()?.into_iter().find(|b| b.guid == *hguid) {
            return Ok(Some(b));
        }
        if let Some(s) = self.snaps()?.into_iter().find(|s| s.guid == *hguid) {
            let bm = cursor_name(self.source, s.guid);
            log::info!("{}: the server already has {}@{}; recording it as the cursor", self.source, self.ds, s.name);
            self.zfs.bookmark(&format!("{}@{}", self.ds, s.name), &format!("{}#{bm}", self.ds))?;
            return Ok(self.cursors()?.into_iter().find(|b| b.guid == *hguid));
        }
        bail!(
            "{}: the server's newest snapshot {hname} (guid {hguid:016x}) has no cursor bookmark or snapshot on {}; \
             the cursor was lost, so the next backup can't be incremental. Back up under a new source name, or \
             have the server forget this one (strata-server forget)",
            self.source,
            self.ds
        )
    }

    /// Destroys this source's other cursors and its own snapshots except `keep_guid`'s.
    fn tidy(&self, base: Option<&Bookmark>, keep_guid: Option<u64>) -> anyhow::Result<()> {
        let stale: Vec<String> = self
            .cursors()?
            .into_iter()
            .filter(|b| Some(b.guid) != base.map(|x| x.guid))
            .map(|b| format!("{}#{}", self.ds, b.name))
            .collect();
        if !stale.is_empty() {
            self.zfs.destroy_bookmarks(&stale)?;
        }
        let tag = hold_tag(self.source);
        let mut doomed = Vec::new();
        for s in self.snaps()? {
            let full = format!("{}@{}", self.ds, s.name);
            if Some(s.guid) == keep_guid {
                continue;
            }
            // A server-named snapshot here is what a restore received; once its cursor
            // exists, it is as disposable as the client's own snapshots.
            let restored = parse_server_snapshot_name(&s.name).is_some() && Some(s.guid) == base.map(|b| b.guid);
            if restored || (self.src.create_snapshots && is_own_snapshot(self.source, &s.name)) {
                doomed.push(full);
            } else if s.userrefs > 0 && self.zfs.holds(&full)?.contains(&tag) {
                self.zfs.release(&full, &tag)?;
            }
        }
        for (n, e) in self.zfs.destroy_snapshots(&doomed)? {
            log::warn!("could not destroy {n}: {e}");
        }
        Ok(())
    }

    fn stream(&self, snap: &Snap, base: Option<&Bookmark>, resume: Option<(u64, u64)>) -> anyhow::Result<String> {
        let full = format!("{}@{}", self.ds, snap.name);
        let from = base.map(|b| format!("{}#{}", self.ds, b.name));
        let (r, w) = strata_zfs::pipe()?;
        self.net.send(&CReq::Stream, Some(&r))?;
        drop(r);
        let job = self.zfs.send(&full, from.as_deref(), self.flags, resume, w)?;
        let res = job.wait();
        if let Err(e) = &res {
            log::error!("zfs send {full}: {e}");
        }
        fault::point("client.stream.done");
        self.net.send(&CReq::StreamDone { ok: res.is_ok(), interval_secs: self.interval_secs }, None)?;
        match self.net.recv()? {
            CResp::Committed { snapshot } => Ok(snapshot),
            CResp::Error { code, message } => bail!("backup of {full} failed: {code:?}: {message}"),
            other => bail!("unexpected reply {other:?}"),
        }
    }

    /// After the server committed `snap`: new cursor first, then the old cursor goes,
    /// then the snapshot is destroyed (own) or released (pattern mode).
    fn advance(&self, snap: &Snap, old: Option<&Bookmark>) -> anyhow::Result<Bookmark> {
        let full = format!("{}@{}", self.ds, snap.name);
        let bm = cursor_name(self.source, snap.guid);
        self.zfs.bookmark(&full, &format!("{}#{bm}", self.ds))?;
        fault::point("client.cursor.created");
        if let Some(o) = old
            && o.guid != snap.guid
        {
            self.zfs.destroy_bookmarks(&[format!("{}#{}", self.ds, o.name)])?;
        }
        fault::point("client.cursor.advanced");
        if self.src.create_snapshots {
            for (n, e) in self.zfs.destroy_snapshots(std::slice::from_ref(&full))? {
                log::warn!("could not destroy {n}: {e}");
            }
        } else {
            let _ = self.zfs.release(&full, &hold_tag(self.source));
        }
        self.cursors()?.into_iter().find(|b| b.guid == snap.guid).context("new cursor vanished")
    }
}

pub fn backup(
    zfs: &dyn Zfs,
    net: &NetClient,
    source: &str,
    src: &SourceConfig,
    interval_secs: Option<u64>,
    busy_retry_scale: f64,
) -> anyhow::Result<Outcome> {
    let ds = src.dataset.as_str();
    let kind = match zfs.dataset_type(ds).with_context(|| format!("source {source}: dataset {ds}"))? {
        DsType::Filesystem => SourceKind::Dataset,
        DsType::Volume => SourceKind::Zvol,
    };
    let cx = Ctx { zfs, net, source, src, ds, flags: SendFlags::standard(src.raw), interval_secs };
    let mut out = Outcome::default();
    let mut ready = begin(net, source, kind, busy_retry_scale)?;
    for _round in 0..3 {
        let base = cx.base(&ready.head)?;
        let keep = ready.resume.map(|r| r.toguid);
        cx.tidy(base.as_ref(), keep)?;
        if let Some(r) = ready.resume {
            let snap = cx.snaps()?.into_iter().find(|s| s.guid == r.toguid && cx.eligible(s));
            let base_guid = base.as_ref().map_or(0, |b| b.guid);
            // The resume fields come from the server and are untrusted: only a snapshot
            // and base this client holds are resumed, always with the client's own flags;
            // anything else makes the server discard its partial receive.
            match snap {
                Some(snap) if r.fromguid == base_guid && r.raw == src.raw => {
                    log::info!("{source}: resuming {}@{} at object {} offset {}", ds, snap.name, r.object, r.offset);
                    if !src.create_snapshots {
                        let _ = zfs.hold(&format!("{ds}@{}", snap.name), &hold_tag(source));
                    }
                    let committed = cx.stream(&snap, base.as_ref(), Some((r.object, r.offset)))?;
                    fault::point("client.committed");
                    cx.advance(&snap, base.as_ref())?;
                    out.committed.push(committed);
                    ready = begin(net, source, kind, busy_retry_scale)?;
                }
                _ => {
                    log::info!("{source}: the server's partial receive can't be resumed from here; discarding it");
                    ready =
                        expect_ready(net.call(&CReq::DiscardResume)?)?.context("server busy after DiscardResume")?;
                }
            }
            continue;
        }
        let target = if src.create_snapshots {
            let name = own_snapshot_name(source, strata_proto::names::unix_now());
            zfs.snapshot(&[format!("{ds}@{name}")], &[])?;
            fault::point("client.snapshot.taken");
            cx.snaps()?.into_iter().find(|s| s.name == name).context("new snapshot vanished")?
        } else {
            let base_txg = base.as_ref().map_or(0, |b| b.createtxg);
            let head_guid = ready.head.as_ref().map(|h| h.1);
            let Some(t) = cx
                .snaps()?
                .into_iter()
                .rfind(|s| cx.eligible(s) && s.createtxg > base_txg && Some(s.guid) != head_guid)
            else {
                log::info!("{source}: no new snapshot matches {:?}; nothing to do", src.snapshot_pattern);
                net.call(&CReq::Abort)?;
                return Ok(out);
            };
            zfs.hold(&format!("{ds}@{}", t.name), &hold_tag(source))?;
            t
        };
        let committed = cx.stream(&target, base.as_ref(), None)?;
        fault::point("client.committed");
        cx.advance(&target, base.as_ref())?;
        log::info!("{source}: committed {committed}");
        out.committed.push(committed);
        return Ok(out);
    }
    bail!("{source}: gave up after repeated resume rounds")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use strata_proto::local::LocalSock;
    use strata_zfs::Fake;

    /// A network half that offers `resume` once and records what the ZFS half asks for.
    fn fake_net(resume: ResumePoint) -> (NetClient, std::thread::JoinHandle<Vec<String>>) {
        let (a, b) = LocalSock::pair().unwrap();
        let t = std::thread::spawn(move || {
            let mut log = Vec::new();
            let reply = |r: CResp| b.send(&r.encode().unwrap(), &[]).unwrap();
            while let Some(m) = b.recv().unwrap() {
                let req = CReq::decode(&m.msg).unwrap();
                log.push(format!("{req:?}"));
                match req {
                    CReq::Backup { .. } => reply(CResp::Ready { server_gen: 0, head: None, resume: Some(resume) }),
                    CReq::DiscardResume => reply(CResp::Ready { server_gen: 0, head: None, resume: None }),
                    CReq::Stream => {
                        let mut f = std::fs::File::from(m.fds.into_iter().next().unwrap());
                        let mut v = Vec::new();
                        f.read_to_end(&mut v).unwrap();
                        log.push(format!("streamed {} bytes", v.len()));
                    }
                    CReq::StreamDone { .. } => {
                        reply(CResp::Committed { snapshot: "strata-20260101T000000Z-g1".into() })
                    }
                    _ => reply(CResp::Ok),
                }
            }
            log
        });
        (NetClient::new(a), t)
    }

    fn setup() -> (tempfile::TempDir, Fake, SourceConfig) {
        let t = tempfile::tempdir().unwrap();
        let z = Fake::open(t.path()).unwrap();
        z.create_pool("rpool").unwrap();
        z.create("rpool/home", &[]).unwrap();
        z.write_object("rpool/home", 1, b"data").unwrap();
        let src = SourceConfig {
            dataset: "rpool/home".into(),
            interval: None,
            create_snapshots: true,
            snapshot_pattern: None,
            raw: false,
        };
        (t, z, src)
    }

    #[test]
    fn untrusted_resume_points_start_the_send_over() {
        // Each case names a leftover own snapshot by GUID but gets another field wrong:
        // an unknown snapshot, a base the client never had, or the other raw mode.
        let cases: [fn(u64) -> ResumePoint; 3] = [
            |_| ResumePoint { fromguid: 0, toguid: 0xbad, object: 1, offset: 0, raw: false },
            |mine| ResumePoint { fromguid: 0x1234, toguid: mine, object: 1, offset: 0, raw: false },
            |mine| ResumePoint { fromguid: 0, toguid: mine, object: 1, offset: 0, raw: true },
        ];
        for case in cases {
            let (_t, z, src) = setup();
            z.snapshot(&[format!("rpool/home@{}", own_snapshot_name("home", 1))], &[]).unwrap();
            let r = case(z.snapshots("rpool/home", &[]).unwrap()[0].guid);
            let (net, t) = fake_net(r);
            let out = backup(&z, &net, "home", &src, None, 0.0).unwrap();
            drop(net);
            let log = t.join().unwrap();
            assert_eq!(out.committed.len(), 1);
            assert!(log.iter().any(|l| l == "DiscardResume"), "{r:?} was not discarded: {log:?}");
        }
    }

    #[test]
    fn names_are_unambiguous() {
        assert_eq!(parse_cursor("home", &cursor_name("home", 0xabc)), Some(0xabc));
        assert_eq!(parse_cursor("home", &cursor_name("home_G_1", 5)), None);
        assert_eq!(parse_cursor("home_G_1", &cursor_name("home_G_1", 5)), Some(5));
        let n = own_snapshot_name("home", 0);
        assert!(is_own_snapshot("home", &n));
        assert!(!is_own_snapshot("hom", &n));
        assert!(!is_own_snapshot("home", &own_snapshot_name("home_x", 0)));
        assert!(is_own_snapshot("home_x", &own_snapshot_name("home_x", 0)));
    }
}
