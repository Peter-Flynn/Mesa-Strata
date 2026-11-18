use strata_proto::msg::{ResumePoint, SnapshotInfo, SourceKind};
use strata_proto::names::parse_server_snapshot_name;
use strata_zfs::{DsType, Snap, Zfs, ZfsError};
use strata_zstream::token::ResumeToken;

use crate::config::Retention;
use crate::retention::{Candidate, plan};

pub const BASE_HOLD: &str = "strata-base";
pub const USER_PROPS: [&str; 4] = ["strata:gen", "strata:time", "strata:source", "strata:interval"];

pub fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn kind_matches(kind: SourceKind, t: DsType) -> bool {
    matches!((kind, t), (SourceKind::Dataset, DsType::Filesystem) | (SourceKind::Zvol, DsType::Volume))
}

pub fn kind_of(t: DsType) -> SourceKind {
    match t {
        DsType::Filesystem => SourceKind::Dataset,
        DsType::Volume => SourceKind::Zvol,
    }
}

/// Snapshots named by Strata (`strata-<time>-g<gen>`), oldest first. Snapshots that
/// replication or other tools create in the tree are left alone.
pub fn strata_snaps(zfs: &dyn Zfs, ds: &str) -> Result<Vec<Snap>, ZfsError> {
    let mut v: Vec<Snap> = zfs
        .snapshots(ds, &USER_PROPS)?
        .into_iter()
        .filter(|s| parse_server_snapshot_name(&s.name).is_some())
        .collect();
    v.sort_by_key(|s| s.createtxg);
    Ok(v)
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

pub struct SourceState {
    pub exists: bool,
    pub snaps: Vec<Snap>,
    pub generation: u64,
    pub resume: Option<ResumePoint>,
}

impl SourceState {
    pub fn head(&self) -> Option<&Snap> {
        self.snaps.last()
    }
}

pub fn source_state(zfs: &dyn Zfs, ds: &str) -> anyhow::Result<SourceState> {
    if !zfs.exists(ds)? {
        return Ok(SourceState { exists: false, snaps: Vec::new(), generation: 0, resume: None });
    }
    let snaps = strata_snaps(zfs, ds)?;
    let generation = snaps.last().and_then(|s| parse_server_snapshot_name(&s.name)).unwrap_or(0);
    let resume = match zfs.get_prop(ds, "receive_resume_token")? {
        Some(t) => {
            let t = ResumeToken::decode(&t).map_err(|e| anyhow::anyhow!("{ds}: unreadable resume token: {e}"))?;
            Some(ResumePoint { fromguid: t.fromguid, toguid: t.toguid, object: t.object, offset: t.offset, raw: t.rawok })
        }
        None => None,
    };
    Ok(SourceState { exists: true, snaps, generation, resume })
}

/// Puts the `strata-base` hold on the newest snapshot and takes it off every other one.
/// The new hold goes on first, so a crash in between leaves two holds, never none.
pub fn finalize_head(zfs: &dyn Zfs, ds: &str, snaps: &[Snap]) -> anyhow::Result<()> {
    let Some(head) = snaps.last() else { return Ok(()) };
    let head_full = format!("{ds}@{}", head.name);
    if !zfs.holds(&head_full)?.iter().any(|h| h == BASE_HOLD) {
        zfs.hold(&head_full, BASE_HOLD)?;
    }
    strata_proto::fault::point("zfsd.finalize.held");
    for s in &snaps[..snaps.len() - 1] {
        if s.userrefs == 0 {
            continue;
        }
        let full = format!("{ds}@{}", s.name);
        if zfs.holds(&full)?.iter().any(|h| h == BASE_HOLD) {
            zfs.release(&full, BASE_HOLD)?;
        }
    }
    Ok(())
}

/// Applies retention and returns what was destroyed. Clone origins and snapshots other
/// tools hold are skipped.
pub fn prune(zfs: &dyn Zfs, ds: &str, policy: Retention, now: i64) -> anyhow::Result<Vec<String>> {
    let snaps = strata_snaps(zfs, ds)?;
    let cands: Vec<Candidate> = snaps
        .iter()
        .map(|s| Candidate { name: s.name.clone(), creation: s.creation, createtxg: s.createtxg })
        .collect();
    let doomed: Vec<String> = plan(&cands, policy, now)
        .into_iter()
        .filter(|n| snaps.iter().any(|s| &s.name == n && !s.has_clones))
        .map(|n| format!("{ds}@{n}"))
        .collect();
    let failed = zfs.destroy_snapshots(&doomed)?;
    for (name, err) in &failed {
        log::info!("retention kept {name}: {err}");
    }
    Ok(doomed.into_iter().filter(|d| !failed.iter().any(|(f, _)| f == d)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_zfs::Fake;

    #[test]
    fn finalize_moves_the_hold() {
        let t = tempfile::tempdir().unwrap();
        let z = Fake::open(t.path()).unwrap();
        z.create_pool("p").unwrap();
        z.create("p/d", &[]).unwrap();
        z.snapshot(&["p/d@strata-20260101T000000Z-g1".into()], &[]).unwrap();
        finalize_head(&z, "p/d", &strata_snaps(&z, "p/d").unwrap()).unwrap();
        z.snapshot(&["p/d@strata-20260101T000001Z-g2".into(), "p/d@other".into()], &[]).unwrap();
        let snaps = strata_snaps(&z, "p/d").unwrap();
        assert_eq!(snaps.len(), 2);
        finalize_head(&z, "p/d", &snaps).unwrap();
        assert!(z.holds("p/d@strata-20260101T000000Z-g1").unwrap().is_empty());
        assert_eq!(z.holds("p/d@strata-20260101T000001Z-g2").unwrap(), vec![BASE_HOLD]);
        let destroyed = prune(&z, "p/d", Retention { keep: 1, dailies: 0 }, now()).unwrap();
        assert_eq!(destroyed, vec!["p/d@strata-20260101T000000Z-g1"]);
        assert_eq!(z.snapshots("p/d", &[]).unwrap().len(), 2, "foreign snapshot untouched");
    }
}
