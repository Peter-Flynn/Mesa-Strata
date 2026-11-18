//! A source on the server is a set of datasets under `<pool>/strata/<client>/ds`: the
//! original `<source>` and a sibling `<source>.g<N>` for every dataset rebase, N being the
//! first generation received into it. Generations count up across the whole set; the head
//! is the snapshot with the highest generation, wherever it lives.
//!
//! Dataset rebase, after a client restored snapshot S and replaced its data with it:
//! 1. `Rebase` holds S (`strata-rebase`) and records `<S guid>:<generation at the time>`
//!    in the user property `strata:rebase:<source>` on `<client>/ds` (a member can be
//!    destroyed later, so no member holds it). While it is set, `Ready` reports S as the
//!    head, so the client's cursor check passes.
//! 2. The next backup's stream is received as a clone of S into a new sibling.
//! 3. Once the set's generation exceeds the recorded one, the receive has landed:
//!    `finalize_rebase` promotes the head's dataset until it is no longer a clone (moving
//!    S and everything before it into the new sibling), releases S and clears the property.
//!    Every step is idempotent, and `Begin` runs it too, so a crash anywhere converges.
//! 4. The old dataset keeps only the abandoned branch (the snapshots after S). Retention
//!    prunes those like any others, and a member left with no snapshots is destroyed.

use strata_proto::fault;
use strata_proto::msg::{ResumePoint, SnapshotInfo, SourceKind};
use strata_proto::names::{parse_server_snapshot_name, valid_name};
use strata_zfs::{DsType, Snap, Zfs, ZfsError};
use strata_zstream::token::ResumeToken;

use crate::config::Retention;
use crate::retention::{Candidate, plan};

pub const BASE_HOLD: &str = "strata-base";
pub const REBASE_HOLD: &str = "strata-rebase";
pub const USER_PROPS: [&str; 4] = ["strata:gen", "strata:time", "strata:source", "strata:interval"];

pub fn kind_matches(kind: SourceKind, t: DsType) -> bool {
    matches!((kind, t), (SourceKind::Dataset, DsType::Filesystem) | (SourceKind::Zvol, DsType::Volume))
}

pub fn kind_of(t: DsType) -> SourceKind {
    match t {
        DsType::Filesystem => SourceKind::Dataset,
        DsType::Volume => SourceKind::Zvol,
    }
}

/// The source a member dataset's last name component belongs to: `<source>` or
/// `<source>.g<N>`.
pub fn member_source(leaf: &str) -> Option<&str> {
    let source = match leaf.split_once('.') {
        Some((s, g)) => {
            let n = g.strip_prefix('g')?;
            if n.is_empty() || !n.bytes().all(|c| c.is_ascii_digit()) {
                return None;
            }
            s
        }
        None => leaf,
    };
    valid_name(source).then_some(source)
}

pub fn sibling(client_ds: &str, source: &str, generation: u64) -> String {
    format!("{client_ds}/{source}.g{generation}")
}

pub fn snapshot_info(s: &Snap) -> SnapshotInfo {
    SnapshotInfo {
        name: s.name.clone(),
        guid: s.guid,
        generation: parse_server_snapshot_name(&s.name).unwrap_or(0),
        unix_time: s.creation,
        used_bytes: s.used,
    }
}

pub struct SourceSet {
    pub client_ds: String,
    pub source: String,
    pub members: Vec<String>,
    /// (member dataset, snapshot), Strata-named snapshots only, oldest generation first.
    pub snaps: Vec<(String, Snap)>,
}

impl SourceSet {
    pub fn load(zfs: &dyn Zfs, client_ds: &str, source: &str) -> Result<SourceSet, ZfsError> {
        let mut members = Vec::new();
        if zfs.exists(client_ds)? {
            for child in zfs.children(client_ds)? {
                let leaf = child.rsplit('/').next().unwrap_or_default();
                if member_source(leaf) == Some(source) {
                    members.push(child);
                }
            }
        }
        let mut snaps = Vec::new();
        for m in &members {
            for s in zfs.snapshots(m, &USER_PROPS)? {
                if parse_server_snapshot_name(&s.name).is_some() {
                    snaps.push((m.clone(), s));
                }
            }
        }
        snaps.sort_by_key(|(_, s)| (parse_server_snapshot_name(&s.name), s.createtxg));
        Ok(SourceSet { client_ds: client_ds.to_string(), source: source.to_string(), members, snaps })
    }

    pub fn head(&self) -> Option<&(String, Snap)> {
        self.snaps.last()
    }

    pub fn generation(&self) -> u64 {
        self.head().and_then(|(_, s)| parse_server_snapshot_name(&s.name)).unwrap_or(0)
    }

    pub fn find(&self, name: &str) -> Option<&(String, Snap)> {
        self.snaps.iter().find(|(_, s)| s.name == name)
    }

    pub fn find_guid(&self, guid: u64) -> Option<&(String, Snap)> {
        self.snaps.iter().find(|(_, s)| s.guid == guid)
    }

    pub fn kind(&self, zfs: &dyn Zfs) -> Result<Option<DsType>, ZfsError> {
        match self.members.first() {
            Some(m) => Ok(Some(zfs.dataset_type(m)?)),
            None => Ok(None),
        }
    }

    /// The member holding a partially received stream, with its resume point.
    pub fn resume(&self, zfs: &dyn Zfs) -> anyhow::Result<Option<(String, ResumePoint)>> {
        for m in &self.members {
            if let Some(t) = zfs.get_prop(m, "receive_resume_token")? {
                let t = ResumeToken::decode(&t).map_err(|e| anyhow::anyhow!("{m}: unreadable resume token: {e}"))?;
                let r = ResumePoint {
                    fromguid: t.fromguid,
                    toguid: t.toguid,
                    object: t.object,
                    offset: t.offset,
                    raw: t.rawok,
                };
                return Ok(Some((m.clone(), r)));
            }
        }
        Ok(None)
    }
}

pub fn full(ds: &str, snap: &str) -> String {
    format!("{ds}@{snap}")
}

fn marker_prop(source: &str) -> String {
    format!("strata:rebase:{source}")
}

/// The pending rebase: S's GUID and the set's generation when `Rebase` arrived.
pub fn read_marker(zfs: &dyn Zfs, client_ds: &str, source: &str) -> Result<Option<(u64, u64)>, ZfsError> {
    let Some(v) = zfs.get_prop(client_ds, &marker_prop(source))? else { return Ok(None) };
    Ok(v.split_once(':').and_then(|(g, n)| Some((g.parse().ok()?, n.parse().ok()?))))
}

fn release_if_held(zfs: &dyn Zfs, snap: &str, tag: &str) -> Result<(), ZfsError> {
    if zfs.holds(snap)?.iter().any(|h| h == tag) {
        zfs.release(snap, tag)?;
    }
    Ok(())
}

/// Records a rebase onto `name`; a rebase onto the head only cancels a pending one.
pub fn set_rebase(zfs: &dyn Zfs, set: &SourceSet, name: &str) -> anyhow::Result<()> {
    let (ds, s) = set.find(name).ok_or_else(|| anyhow::anyhow!("no snapshot {name} of {}", set.source))?;
    let prop = marker_prop(&set.source);
    if let Some((old, _)) = read_marker(zfs, &set.client_ds, &set.source)?
        && let Some((ods, os)) = set.find_guid(old)
    {
        release_if_held(zfs, &full(ods, &os.name), REBASE_HOLD)?;
    }
    if set.head().is_some_and(|(_, h)| h.guid == s.guid) {
        zfs.inherit(&set.client_ds, &prop)?;
        return Ok(());
    }
    let snap = full(ds, &s.name);
    if !zfs.holds(&snap)?.iter().any(|h| h == REBASE_HOLD) {
        zfs.hold(&snap, REBASE_HOLD)?;
    }
    zfs.set_props(&set.client_ds, &[(prop.as_str(), format!("{}:{}", s.guid, set.generation()).as_str())])?;
    Ok(())
}

/// Completes a rebase whose clone receive has landed (see the module header). Returns the
/// pending rebase base, if one is still waiting for its receive.
pub fn finalize_rebase(zfs: &dyn Zfs, client_ds: &str, source: &str) -> anyhow::Result<Option<(String, Snap)>> {
    let Some((guid, recorded)) = read_marker(zfs, client_ds, source)? else { return Ok(None) };
    let set = SourceSet::load(zfs, client_ds, source)?;
    if set.generation() <= recorded {
        if let Some(base) = set.find_guid(guid) {
            return Ok(Some(base.clone()));
        }
        log::warn!("{client_ds}/{source}: rebase base {guid:#x} is gone; cancelling the rebase");
    } else if let Some((head_ds, _)) = set.head() {
        // When S lives in a dataset that is itself a clone (an older abandoned branch),
        // one promotion leaves the new sibling a clone of S's grand-origin; promoting
        // until no origin is left gives it the whole history.
        for _ in 0..64 {
            if zfs.get_prop(head_ds, "origin")?.is_none() {
                break;
            }
            zfs.promote(head_ds)?;
            fault::point("zfsd.rebase.promoted");
        }
    }
    if let Some((ds, s)) = SourceSet::load(zfs, client_ds, source)?.find_guid(guid) {
        release_if_held(zfs, &full(ds, &s.name), REBASE_HOLD)?;
    }
    zfs.inherit(client_ds, &marker_prop(source))?;
    fault::point("zfsd.rebase.cleared");
    Ok(None)
}

/// Puts the `strata-base` hold on the newest snapshot and takes it off every other one.
/// The new hold goes on first, so a crash in between leaves two holds, never none.
pub fn finalize_head(zfs: &dyn Zfs, set: &SourceSet) -> anyhow::Result<()> {
    let Some((head_ds, head)) = set.head() else { return Ok(()) };
    let head_full = full(head_ds, &head.name);
    if !zfs.holds(&head_full)?.iter().any(|h| h == BASE_HOLD) {
        zfs.hold(&head_full, BASE_HOLD)?;
    }
    fault::point("zfsd.finalize.held");
    for (ds, s) in &set.snaps[..set.snaps.len() - 1] {
        if s.userrefs > 0 {
            release_if_held(zfs, &full(ds, &s.name), BASE_HOLD)?;
        }
    }
    Ok(())
}

/// Applies retention across the set, then destroys members left with no snapshots at all
/// (an abandoned branch whose snapshots were all pruned). Clone origins and snapshots
/// other tools hold are skipped. Returns what was destroyed.
pub fn prune(zfs: &dyn Zfs, set: &SourceSet, policy: Retention, now: i64) -> anyhow::Result<Vec<String>> {
    let cands: Vec<Candidate> = set
        .snaps
        .iter()
        .map(|(_, s)| Candidate { name: s.name.clone(), creation: s.creation, createtxg: s.createtxg })
        .collect();
    let doomed: Vec<String> = plan(&cands, policy, now)
        .into_iter()
        .filter_map(|n| set.find(&n))
        .filter(|(_, s)| !s.has_clones)
        .map(|(ds, s)| full(ds, &s.name))
        .collect();
    let failed = zfs.destroy_snapshots(&doomed)?;
    for (name, err) in &failed {
        log::info!("retention kept {name}: {err}");
    }
    let mut gone: Vec<String> = doomed.into_iter().filter(|d| !failed.iter().any(|(f, _)| f == d)).collect();
    let head_ds = set.head().map(|(d, _)| d.as_str());
    for m in &set.members {
        if Some(m.as_str()) == head_ds
            || !zfs.snapshots(m, &[])?.is_empty()
            || zfs.get_prop(m, "receive_resume_token")?.is_some()
        {
            continue;
        }
        match zfs.destroy(m) {
            Ok(()) => gone.push(m.clone()),
            Err(e) => log::info!("kept empty member {m}: {e}"),
        }
    }
    Ok(gone)
}

/// Whether `from_guid` is an earlier snapshot in `to`'s history: its own dataset before
/// it, or, through clone origins, the origin and anything before that.
pub fn is_ancestor(zfs: &dyn Zfs, to_ds: &str, to_txg: u64, from_guid: u64) -> Result<bool, ZfsError> {
    let (mut ds, mut upto) = (to_ds.to_string(), to_txg);
    let mut inclusive = false;
    for _ in 0..64 {
        let snaps = zfs.snapshots(&ds, &[])?;
        if snaps.iter().any(|s| s.guid == from_guid && (s.createtxg < upto || (inclusive && s.createtxg == upto))) {
            return Ok(true);
        }
        let Some(origin) = zfs.get_prop(&ds, "origin")? else { return Ok(false) };
        let Some((od, on)) = origin.split_once('@') else { return Ok(false) };
        let Some(o) = zfs.snapshots(od, &[])?.into_iter().find(|s| s.name == on) else { return Ok(false) };
        (ds, upto, inclusive) = (od.to_string(), o.createtxg, true);
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_zfs::Fake;

    #[test]
    fn member_names() {
        assert_eq!(member_source("home"), Some("home"));
        assert_eq!(member_source("home.g12"), Some("home"));
        assert_eq!(member_source("home.g"), None);
        assert_eq!(member_source("home.x1"), None);
        assert_eq!(member_source("_server"), None);
    }

    #[test]
    fn finalize_moves_the_hold() {
        let t = tempfile::tempdir().unwrap();
        let z = Fake::open(t.path()).unwrap();
        z.create_pool("p").unwrap();
        z.create("p/ds", &[]).unwrap();
        z.create("p/ds/d", &[]).unwrap();
        z.snapshot(&["p/ds/d@strata-20260101T000000Z-g1".into()], &[]).unwrap();
        finalize_head(&z, &SourceSet::load(&z, "p/ds", "d").unwrap()).unwrap();
        z.snapshot(&["p/ds/d@strata-20260101T000001Z-g2".into(), "p/ds/d@other".into()], &[]).unwrap();
        let set = SourceSet::load(&z, "p/ds", "d").unwrap();
        assert_eq!(set.snaps.len(), 2);
        finalize_head(&z, &set).unwrap();
        assert!(z.holds("p/ds/d@strata-20260101T000000Z-g1").unwrap().is_empty());
        assert_eq!(z.holds("p/ds/d@strata-20260101T000001Z-g2").unwrap(), vec![BASE_HOLD]);
        let destroyed = prune(&z, &set, Retention { keep: 1, dailies: 0 }, strata_proto::names::unix_now()).unwrap();
        assert_eq!(destroyed, vec!["p/ds/d@strata-20260101T000000Z-g1"]);
        assert_eq!(z.snapshots("p/ds/d", &[]).unwrap().len(), 2, "foreign snapshot untouched");
    }

    #[test]
    fn ancestry_follows_origins() {
        let t = tempfile::tempdir().unwrap();
        let z = Fake::open(t.path()).unwrap();
        z.create_pool("p").unwrap();
        z.create("p/a", &[]).unwrap();
        for n in ["1", "2", "3"] {
            z.snapshot(&[format!("p/a@{n}")], &[]).unwrap();
        }
        z.clone_snapshot("p/a@2", "p/b").unwrap();
        z.snapshot(&["p/b@4".into()], &[]).unwrap();
        let g = |f: &str| {
            z.snapshots(f.split('@').next().unwrap(), &[])
                .unwrap()
                .into_iter()
                .find(|s| f.ends_with(&format!("@{}", s.name)))
                .unwrap()
        };
        let b4 = g("p/b@4");
        assert!(is_ancestor(&z, "p/b", b4.createtxg, g("p/a@2").guid).unwrap());
        assert!(is_ancestor(&z, "p/b", b4.createtxg, g("p/a@1").guid).unwrap());
        assert!(!is_ancestor(&z, "p/b", b4.createtxg, g("p/a@3").guid).unwrap());
        assert!(!is_ancestor(&z, "p/a", g("p/a@2").createtxg, g("p/a@3").guid).unwrap());
    }
}
