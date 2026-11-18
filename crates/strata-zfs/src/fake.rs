//! A file-backed fake ZFS for sandbox tests.
//!
//! One directory is one machine's pools: `state.bin` (postcard) holds every dataset, and
//! `lock` serializes access across threads and processes (`flock`). Every operation loads
//! the state, applies itself and replaces the file atomically (write, rename), so a process
//! killed at any point leaves the last completed operation on disk, as a power cut would
//! leave the last synced txg on a real pool.
//!
//! A dataset's content is a map of object id → bytes, each object stamped with the txg
//! that last wrote it; deletions leave tombstones with their txg. Snapshots copy the map.
//! Sends emit real send-stream records (`strata_zstream::writer`): per object an OBJECT
//! record whose 8-byte bonus is the object's length, then WRITE records of up to 128 KiB
//! padded to 512 bytes, and FREEOBJECTS for tombstones; an incremental send covers objects
//! and tombstones newer than the base's createtxg, so bookmarks work as bases. Receives run
//! the stream through the validator, apply it, and with `-s` save the partial state every
//! 16 records and on a broken stream, exposed as a real-format `receive_resume_token`.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use strata_zstream::record::*;
use strata_zstream::token::ResumeToken;
use strata_zstream::writer::{Begin, StreamWriter};
use strata_zstream::{Expect, Validator};

use crate::{Bookmark, DsType, Job, Receiving, RecvOpts, Result, SendFlags, Snap, Zfs, ZfsError};

const CHUNK: usize = 128 * 1024;
const CHECKPOINT_RECORDS: usize = 16;

type Content = BTreeMap<u64, Obj>;

/// An object as the state file records it: its bytes live in `blobs/<sha256>`, written
/// once and shared by every snapshot that holds the same bytes.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
struct Obj {
    blob: String,
    len: u64,
    birth: u64,
}

struct Live {
    data: Vec<u8>,
    birth: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FSnap {
    name: String,
    guid: u64,
    createtxg: u64,
    creation: i64,
    objects: Content,
    tombs: BTreeMap<u64, u64>,
    holds: BTreeSet<String>,
    props: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct FBook {
    name: String,
    guid: u64,
    createtxg: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Partial {
    snapname: String,
    toguid: u64,
    fromguid: u64,
    toname: String,
    objects: Content,
    tombs: BTreeMap<u64, u64>,
    lengths: BTreeMap<u64, u64>,
    resume_object: u64,
    resume_offset: u64,
    bytes: u64,
    raw: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct Ds {
    kind: DsType,
    props: BTreeMap<String, String>,
    objects: Content,
    tombs: BTreeMap<u64, u64>,
    snaps: Vec<FSnap>,
    books: Vec<FBook>,
    partial: Option<Partial>,
    origin: Option<String>,
    created_by_partial: bool,
}

impl Ds {
    fn new(kind: DsType) -> Ds {
        Ds {
            kind,
            props: BTreeMap::new(),
            objects: Content::new(),
            tombs: BTreeMap::new(),
            snaps: Vec::new(),
            books: Vec::new(),
            partial: None,
            origin: None,
            created_by_partial: false,
        }
    }
}

#[derive(Serialize, Deserialize, Default)]
struct State {
    txg: u64,
    guid_seed: u64,
    guid_counter: u64,
    datasets: BTreeMap<String, Ds>,
}

impl State {
    fn next_txg(&mut self) -> u64 {
        self.txg += 1;
        self.txg
    }
    fn new_guid(&mut self) -> u64 {
        self.guid_counter += 1;
        let mut z = self.guid_seed.wrapping_add(self.guid_counter.wrapping_mul(0x9E37_79B9_7F4A_7C15));
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn ds(&self, name: &str) -> Result<&Ds> {
        self.datasets.get(name).ok_or_else(|| ZfsError::NotFound(name.into()))
    }
    fn ds_mut(&mut self, name: &str) -> Result<&mut Ds> {
        self.datasets.get_mut(name).ok_or_else(|| ZfsError::NotFound(name.into()))
    }
    fn snap(&self, full: &str) -> Result<&FSnap> {
        let (ds, s) = full.split_once('@').ok_or_else(|| ZfsError::Failed(format!("not a snapshot: {full}")))?;
        self.ds(ds)?.snaps.iter().find(|x| x.name == s).ok_or_else(|| ZfsError::NotFound(full.into()))
    }
    fn snap_mut(&mut self, full: &str) -> Result<&mut FSnap> {
        let (ds, s) = full.split_once('@').ok_or_else(|| ZfsError::Failed(format!("not a snapshot: {full}")))?;
        self.ds_mut(ds)?.snaps.iter_mut().find(|x| x.name == s).ok_or_else(|| ZfsError::NotFound(full.into()))
    }
    /// guid and createtxg of a snapshot or bookmark name.
    fn base(&self, name: &str) -> Result<(u64, u64)> {
        if let Some((ds, b)) = name.split_once('#') {
            let bk = self.ds(ds)?.books.iter().find(|x| x.name == b).ok_or_else(|| ZfsError::NotFound(name.into()))?;
            Ok((bk.guid, bk.createtxg))
        } else {
            let s = self.snap(name)?;
            Ok((s.guid, s.createtxg))
        }
    }
    fn has_clones(&self, full: &str) -> bool {
        self.datasets.values().any(|d| d.origin.as_deref() == Some(full))
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

#[derive(Clone)]
pub struct Fake {
    root: PathBuf,
}

impl Fake {
    pub fn open(root: impl Into<PathBuf>) -> Result<Fake> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        let f = Fake { root };
        f.with(|_| Ok(()))?;
        Ok(f)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    fn with<T>(&self, f: impl FnOnce(&mut State) -> Result<T>) -> Result<T> {
        let lock = File::options().create(true).truncate(false).write(true).open(self.root.join("lock"))?;
        rustix::fs::flock(&lock, rustix::fs::FlockOperation::LockExclusive).map_err(std::io::Error::from)?;
        let path = self.root.join("state.bin");
        let mut st: State = match std::fs::read(&path) {
            Ok(b) => postcard::from_bytes(&b).map_err(|e| ZfsError::Failed(format!("fake state: {e}")))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                use std::hash::{BuildHasher, Hasher};
                let seed = std::collections::hash_map::RandomState::new().build_hasher().finish();
                State { guid_seed: seed, ..Default::default() }
            }
            Err(e) => return Err(e.into()),
        };
        let out = f(&mut st)?;
        // Write-then-rename is atomic against a killed process, which is the failure the
        // crash tests inject; the page cache outlives the process, so no fsync is needed.
        let tmp = self.root.join("state.tmp");
        std::fs::write(&tmp, postcard::to_allocvec(&st).expect("postcard"))?;
        std::fs::rename(&tmp, &path)?;
        Ok(out)
    }

    fn put_blob(&self, data: &[u8]) -> Result<String> {
        use sha2::Digest;
        let name = hex::encode(sha2::Sha256::digest(data));
        let dir = self.root.join("blobs");
        let path = dir.join(&name);
        if !path.exists() {
            std::fs::create_dir_all(&dir)?;
            let tmp = dir.join(format!("{name}.{}.tmp", std::process::id()));
            std::fs::write(&tmp, data)?;
            std::fs::rename(&tmp, &path)?;
        }
        Ok(name)
    }

    fn blob(&self, name: &str) -> Result<Vec<u8>> {
        Ok(std::fs::read(self.root.join("blobs").join(name))?)
    }

    fn load(&self, c: &Content) -> Result<BTreeMap<u64, Live>> {
        c.iter().map(|(k, o)| Ok((*k, Live { data: self.blob(&o.blob)?, birth: o.birth }))).collect()
    }

    pub fn create_pool(&self, name: &str) -> Result<()> {
        self.with(|st| {
            st.datasets.entry(name.to_string()).or_insert_with(|| Ds::new(DsType::Filesystem));
            Ok(())
        })
    }

    pub fn write_object(&self, ds: &str, object: u64, data: &[u8]) -> Result<()> {
        let blob = self.put_blob(data)?;
        self.with(|st| {
            let txg = st.next_txg();
            let d = st.ds_mut(ds)?;
            d.objects.insert(object, Obj { blob, len: data.len() as u64, birth: txg });
            d.tombs.remove(&object);
            Ok(())
        })
    }

    pub fn delete_object(&self, ds: &str, object: u64) -> Result<()> {
        self.with(|st| {
            let txg = st.next_txg();
            let d = st.ds_mut(ds)?;
            if d.objects.remove(&object).is_some() {
                d.tombs.insert(object, txg);
            }
            Ok(())
        })
    }

    /// Content of a dataset or `ds@snap`, as object id → bytes.
    pub fn content(&self, name: &str) -> Result<BTreeMap<u64, Vec<u8>>> {
        let objs = self.with(|st| {
            Ok(if name.contains('@') { st.snap(name)?.objects.clone() } else { st.ds(name)?.objects.clone() })
        })?;
        objs.iter().map(|(k, o)| Ok((*k, self.blob(&o.blob)?))).collect()
    }

    /// `zfs clone`, which zfsd never runs; tests use it to build clone trees.
    pub fn clone_snapshot(&self, snap: &str, ds: &str) -> Result<()> {
        self.with(|st| {
            let s = st.snap(snap)?.clone();
            let kind = st.ds(snap.split_once('@').unwrap().0)?.kind;
            if st.datasets.contains_key(ds) {
                return Err(ZfsError::Exists(ds.into()));
            }
            let mut d = Ds::new(kind);
            d.objects = s.objects;
            d.tombs = s.tombs;
            d.origin = Some(snap.to_string());
            st.datasets.insert(ds.to_string(), d);
            Ok(())
        })
    }

    pub fn has_partial(&self, ds: &str) -> Result<bool> {
        self.with(|st| Ok(st.datasets.get(ds).is_some_and(|d| d.partial.is_some())))
    }
}

fn gen_stream(
    fake: &Fake,
    st: &State,
    snap: &str,
    from: Option<&str>,
    flags: SendFlags,
    resume: Option<(u64, u64)>,
) -> Result<Vec<u8>> {
    let s = st.snap(snap)?;
    let (ds, _) = snap.split_once('@').unwrap();
    let kind = st.ds(ds)?.kind;
    let (fromguid, fromtxg) = match from {
        Some(f) => st.base(f)?,
        None => (0, 0),
    };
    if let Some(f) = from
        && fromtxg >= s.createtxg
    {
        return Err(ZfsError::Failed(format!("{f} is not earlier than {snap}")));
    }
    let mut b = Begin::new(s.guid, fromguid, snap);
    b.objset_type = if kind == DsType::Volume { DMU_OST_ZVOL } else { DMU_OST_ZFS };
    b.creation = s.creation as u64;
    b.features = 0;
    if flags.embed {
        b.features |= FEATURE_EMBED_DATA;
    }
    if flags.large_block {
        b.features |= FEATURE_LARGE_BLOCKS;
    }
    if flags.compress {
        b.features |= FEATURE_COMPRESSED;
    }
    if flags.raw {
        b.features |= FEATURE_RAW;
    }
    if let Some((o, off)) = resume {
        b.features |= FEATURE_RESUMING;
        let mut nv = strata_zstream::nvlist::NvList::default();
        nv.push("resume_object", strata_zstream::nvlist::Value::U64(o))
            .push("resume_offset", strata_zstream::nvlist::Value::U64(off));
        b.payload = Some(nv);
    }
    let mut w = StreamWriter::begin(Vec::new(), &b)?;
    let (ro, roff) = resume.unwrap_or((0, 0));
    for (&id, o) in &s.objects {
        if o.birth <= fromtxg || id < ro {
            continue;
        }
        let data = fake.blob(&o.blob)?;
        w.object(id, CHUNK as u32, &(data.len() as u64).to_le_bytes())?;
        let start = if id == ro { roff as usize } else { 0 };
        let mut off = start - start % CHUNK;
        while off < data.len() {
            let end = (off + CHUNK).min(data.len());
            let mut chunk = data[off..end].to_vec();
            chunk.resize(chunk.len().div_ceil(512) * 512, 0);
            w.write(id, off as u64, &chunk)?;
            off = end;
        }
    }
    for (&id, &txg) in &s.tombs {
        if txg > fromtxg && id >= ro && !s.objects.contains_key(&id) {
            w.freeobjects(id, 1)?;
        }
    }
    Ok(w.end()?)
}

struct Apply {
    objects: BTreeMap<u64, Live>,
    refs: Content,
    dirty: BTreeSet<u64>,
    tombs: BTreeMap<u64, u64>,
    lengths: BTreeMap<u64, u64>,
    resume: (u64, u64),
}

impl Apply {
    fn record(&mut self, h: &[u8], payload: &[u8]) {
        match u32_at(h, 0) {
            DRR_OBJECT => {
                let id = u64_at(h, 8);
                let len = u64::from_le_bytes(payload[..8].try_into().unwrap());
                self.lengths.insert(id, len);
                let o = self.objects.entry(id).or_insert(Live { data: Vec::new(), birth: RECEIVING_TXG });
                o.birth = RECEIVING_TXG;
                self.dirty.insert(id);
                self.tombs.remove(&id);
                self.resume = (id, 0);
            }
            DRR_WRITE => {
                let id = u64_at(h, 8);
                let off = u64_at(h, 24) as usize;
                let o = self.objects.entry(id).or_insert(Live { data: Vec::new(), birth: RECEIVING_TXG });
                self.dirty.insert(id);
                if o.data.len() < off + payload.len() {
                    o.data.resize(off + payload.len(), 0);
                }
                o.data[off..off + payload.len()].copy_from_slice(payload);
                self.resume = (id, (off + payload.len()) as u64);
            }
            DRR_FREEOBJECTS => {
                let first = u64_at(h, 8);
                let n = u64_at(h, 16);
                for id in first..first.saturating_add(n) {
                    self.refs.remove(&id);
                    self.dirty.remove(&id);
                    if self.objects.remove(&id).is_some() || n == 1 {
                        self.tombs.insert(id, RECEIVING_TXG);
                    }
                }
            }
            _ => {}
        }
    }

    fn flush(&mut self, fake: &Fake) -> Result<Content> {
        for id in std::mem::take(&mut self.dirty) {
            let o = &self.objects[&id];
            let blob = fake.put_blob(&o.data)?;
            self.refs.insert(id, Obj { blob, len: o.data.len() as u64, birth: o.birth });
        }
        Ok(self.refs.clone())
    }

    fn finish(mut self, fake: &Fake) -> Result<(Content, BTreeMap<u64, u64>)> {
        for (id, len) in self.lengths.clone() {
            if let Some(o) = self.objects.get_mut(&id) {
                o.data.truncate(len as usize);
                self.dirty.insert(id);
            }
        }
        let refs = self.flush(fake)?;
        Ok((refs, self.tombs))
    }
}

fn split_records(buf: &[u8], mut f: impl FnMut(&[u8], &[u8])) {
    let mut pos = 0;
    while pos < buf.len() {
        let h = &buf[pos..pos + HEADER];
        let t = u32_at(h, 0);
        let plen = match t {
            DRR_BEGIN => u32_at(h, 4) as usize,
            DRR_OBJECT => (u32_at(h, 28) as usize).div_ceil(8) * 8,
            DRR_WRITE => u64_at(h, 32) as usize,
            _ => 0,
        };
        f(h, &buf[pos + HEADER..pos + HEADER + plen]);
        pos += HEADER + plen;
    }
}

/// Birth txg of objects and frees a receive applies; replaced with the receiving snapshot's
/// txg when it commits. Real txgs start at 1.
const RECEIVING_TXG: u64 = 0;

fn receive_thread(fake: Fake, target: String, opts: RecvOpts, mut input: File) -> Result<()> {
    let (ds, snapname) = match target.split_once('@') {
        Some((d, s)) => (d.to_string(), Some(s.to_string())),
        None => (target.clone(), None),
    };
    let mut first = vec![0u8; HEADER];
    input.read_exact(&mut first).map_err(|_| ZfsError::Failed("receive: stream too short".into()))?;
    if u32_at(&first, 0) != DRR_BEGIN {
        return Err(ZfsError::Failed("receive: invalid stream (no BEGIN)".into()));
    }
    let fromguid = u64_at(&first, 48);
    let toguid = u64_at(&first, 40);
    let feat = features(u64_at(&first, 16));
    let resuming = feat & FEATURE_RESUMING != 0;
    let toname =
        String::from_utf8_lossy(&first[56..56 + first[56..].iter().position(|&c| c == 0).unwrap_or(0)]).into_owned();
    let snapname = snapname.unwrap_or_else(|| toname.split_once('@').map(|x| x.1.to_string()).unwrap_or_default());
    let kind = if u32_at(&first, 32) == DMU_OST_ZVOL { DsType::Volume } else { DsType::Filesystem };

    let start = fake.with(|st| {
        if st.datasets.get(&ds).is_some_and(|d| d.snaps.iter().any(|s| s.name == snapname)) && !resuming {
            return Err(ZfsError::Exists(format!("{ds}@{snapname}")));
        }
        if resuming {
            let d = st.ds(&ds)?;
            let p = d.partial.as_ref().ok_or_else(|| ZfsError::Failed(format!("{ds}: no resumable state")))?;
            if p.toguid != toguid || p.fromguid != fromguid {
                return Err(ZfsError::Failed("receive: resume stream does not match the partial state".into()));
            }
            return Ok((
                p.objects.clone(),
                p.tombs.clone(),
                p.lengths.clone(),
                (p.resume_object, p.resume_offset),
                p.bytes,
            ));
        }
        if st.datasets.get(&ds).is_some_and(|d| d.partial.is_some()) {
            return Err(ZfsError::Failed(format!(
                "{ds}: destination contains partially-complete state from \"zfs receive -s\""
            )));
        }
        let base: (Content, BTreeMap<u64, u64>) = if let Some(origin) = &opts.origin {
            if st.datasets.contains_key(&ds) {
                return Err(ZfsError::Exists(ds.clone()));
            }
            let o = st.snap(origin)?;
            if fromguid != 0 && o.guid != fromguid {
                return Err(ZfsError::Failed("receive: origin does not match the stream's base".into()));
            }
            (o.objects.clone(), o.tombs.clone())
        } else if fromguid == 0 {
            if st.datasets.get(&ds).is_some_and(|d| !d.snaps.is_empty()) {
                return Err(ZfsError::Failed(format!("{ds}: destination exists; full stream needs a new dataset")));
            }
            (Content::new(), BTreeMap::new())
        } else {
            let d = st.ds(&ds)?;
            let last = d.snaps.last().ok_or_else(|| ZfsError::Failed(format!("{ds}: no snapshot to receive onto")))?;
            if last.guid != fromguid {
                return Err(ZfsError::Failed(format!("{ds}: most recent snapshot does not match incremental source")));
            }
            (last.objects.clone(), last.tombs.clone())
        };
        Ok((base.0, base.1, BTreeMap::new(), (0, 0), 0))
    })?;
    let (refs, tombs, lengths, resume, start_bytes) = start;
    let mut apply = Apply { objects: fake.load(&refs)?, refs, dirty: BTreeSet::new(), tombs, lengths, resume };

    let mut v = Validator::new(Expect { fromguid, toguid: None, allow_raw: true });
    let mut validated = Vec::new();
    let mut pending = Vec::new();
    v.push(&first, &mut validated).map_err(|e| ZfsError::Failed(format!("receive: {e}")))?;
    let mut buf = vec![0u8; 64 * 1024];
    let mut records = 0usize;
    let mut bytes = start_bytes;
    let save_partial = |apply: &mut Apply, bytes: u64| -> Result<()> {
        if !opts.resumable {
            return Ok(());
        }
        let objects = apply.flush(&fake)?;
        fake.with(|st| {
            let exists = st.datasets.contains_key(&ds);
            let d = st.datasets.entry(ds.clone()).or_insert_with(|| {
                let mut d = Ds::new(kind);
                d.created_by_partial = true;
                d
            });
            if !exists {
                d.origin = opts.origin.clone();
            }
            d.partial = Some(Partial {
                snapname: snapname.clone(),
                toguid,
                fromguid,
                toname: toname.clone(),
                objects: objects.clone(),
                tombs: apply.tombs.clone(),
                lengths: apply.lengths.clone(),
                resume_object: apply.resume.0,
                resume_offset: apply.resume.1,
                bytes,
                raw: feat & FEATURE_RAW != 0,
            });
            Ok(())
        })
    };
    loop {
        let n = match input.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => {
                save_partial(&mut apply, bytes)?;
                return Err(e.into());
            }
        };
        bytes += n as u64;
        if let Err(e) = v.push(&buf[..n], &mut validated) {
            save_partial(&mut apply, bytes)?;
            return Err(ZfsError::Failed(format!("receive: {e}")));
        }
        pending.extend_from_slice(&validated);
        validated.clear();
        let mut consumed = 0;
        split_records(&pending, |h, p| {
            consumed += HEADER + p.len();
            records += 1;
            apply.record(h, p);
        });
        pending.drain(..consumed);
        if records >= CHECKPOINT_RECORDS {
            records = 0;
            save_partial(&mut apply, bytes)?;
        }
    }
    if v.finish().is_err() {
        save_partial(&mut apply, bytes)?;
        return Err(ZfsError::Failed("receive: stream ended early".into()));
    }
    let (objects, tombs) = apply.finish(&fake)?;
    fake.with(|st| {
        let txg = st.next_txg();
        let exists = st.datasets.contains_key(&ds);
        let d = st.datasets.entry(ds.clone()).or_insert_with(|| Ds::new(kind));
        if !exists {
            d.origin = opts.origin.clone();
        }
        let objects: Content = objects
            .into_iter()
            .map(|(k, mut o)| {
                if o.birth == RECEIVING_TXG {
                    o.birth = txg;
                }
                (k, o)
            })
            .collect();
        let tombs: BTreeMap<u64, u64> =
            tombs.into_iter().map(|(k, t)| (k, if t == RECEIVING_TXG { txg } else { t })).collect();
        d.partial = None;
        d.created_by_partial = false;
        d.objects = objects.clone();
        d.tombs = tombs.clone();
        for (k, val) in &opts.props {
            d.props.insert(k.clone(), val.clone());
        }
        d.snaps.push(FSnap {
            name: snapname.clone(),
            guid: toguid,
            createtxg: txg,
            creation: now(),
            objects,
            tombs,
            holds: BTreeSet::new(),
            props: BTreeMap::new(),
        });
        Ok(())
    })
}

impl Zfs for Fake {
    fn exists(&self, ds: &str) -> Result<bool> {
        self.with(|st| Ok(st.datasets.contains_key(ds)))
    }

    fn dataset_type(&self, ds: &str) -> Result<DsType> {
        self.with(|st| Ok(st.ds(ds)?.kind))
    }

    fn children(&self, ds: &str) -> Result<Vec<String>> {
        self.with(|st| {
            st.ds(ds)?;
            let prefix = format!("{ds}/");
            Ok(st
                .datasets
                .keys()
                .filter(|k| k.starts_with(&prefix) && !k[prefix.len()..].contains('/'))
                .cloned()
                .collect())
        })
    }

    fn snapshots(&self, ds: &str, user_props: &[&str]) -> Result<Vec<Snap>> {
        self.with(|st| {
            let d = st.ds(ds)?;
            Ok(d.snaps
                .iter()
                .map(|s| Snap {
                    name: s.name.clone(),
                    guid: s.guid,
                    createtxg: s.createtxg,
                    creation: s.creation,
                    used: s.objects.values().map(|o| o.len).sum(),
                    userrefs: s.holds.len() as u64,
                    has_clones: st.has_clones(&format!("{ds}@{}", s.name)),
                    props: s
                        .props
                        .iter()
                        .filter(|(k, _)| user_props.contains(&k.as_str()))
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect(),
                })
                .collect())
        })
    }

    fn bookmarks(&self, ds: &str) -> Result<Vec<Bookmark>> {
        self.with(|st| {
            Ok(st
                .ds(ds)?
                .books
                .iter()
                .map(|b| Bookmark { name: b.name.clone(), guid: b.guid, createtxg: b.createtxg })
                .collect())
        })
    }

    fn get_prop(&self, ds: &str, prop: &str) -> Result<Option<String>> {
        self.with(|st| {
            if ds.contains('@') {
                return Ok(st.snap(ds)?.props.get(prop).cloned());
            }
            let d = st.ds(ds)?;
            Ok(match prop {
                "receive_resume_token" => d.partial.as_ref().map(|p| {
                    ResumeToken {
                        fromguid: p.fromguid,
                        toguid: p.toguid,
                        object: p.resume_object,
                        offset: p.resume_offset,
                        bytes: p.bytes,
                        toname: p.toname.clone(),
                        largeblockok: true,
                        embedok: true,
                        compressok: true,
                        rawok: p.raw,
                    }
                    .encode()
                }),
                "type" => Some(if d.kind == DsType::Volume { "volume" } else { "filesystem" }.to_string()),
                "origin" => d.origin.clone(),
                "encryption" => Some(d.props.get("encryption").cloned().unwrap_or_else(|| "off".into())),
                _ => {
                    let mut name = ds.to_string();
                    loop {
                        if let Some(v) = st.datasets.get(&name).and_then(|d| d.props.get(prop)) {
                            break Some(v.clone());
                        }
                        match name.rsplit_once('/') {
                            Some((parent, _)) => name = parent.to_string(),
                            None => break None,
                        }
                    }
                }
            })
        })
    }

    fn set_props(&self, target: &str, props: &[(&str, &str)]) -> Result<()> {
        self.with(|st| {
            let map =
                if target.contains('@') { &mut st.snap_mut(target)?.props } else { &mut st.ds_mut(target)?.props };
            for (k, v) in props {
                map.insert(k.to_string(), v.to_string());
            }
            Ok(())
        })
    }

    fn create(&self, ds: &str, props: &[(&str, &str)]) -> Result<()> {
        self.with(|st| {
            if st.datasets.contains_key(ds) {
                return Err(ZfsError::Exists(ds.into()));
            }
            let parent = ds.rsplit_once('/').map(|x| x.0).ok_or_else(|| ZfsError::Failed(format!("{ds}: no pool")))?;
            st.ds(parent)?;
            let mut d = Ds::new(DsType::Filesystem);
            for (k, v) in props {
                d.props.insert(k.to_string(), v.to_string());
            }
            st.datasets.insert(ds.to_string(), d);
            Ok(())
        })
    }

    fn snapshot(&self, snaps: &[String], props: &[(&str, &str)]) -> Result<()> {
        self.with(|st| {
            for s in snaps {
                let (ds, name) = s.split_once('@').ok_or_else(|| ZfsError::Failed(format!("not a snapshot: {s}")))?;
                if st.ds(ds)?.snaps.iter().any(|x| x.name == name) {
                    return Err(ZfsError::Exists(s.clone()));
                }
            }
            let txg = st.next_txg();
            for s in snaps {
                let (ds, name) = s.split_once('@').unwrap();
                let guid = st.new_guid();
                let d = st.ds_mut(ds)?;
                let snap = FSnap {
                    name: name.to_string(),
                    guid,
                    createtxg: txg,
                    creation: now(),
                    objects: d.objects.clone(),
                    tombs: d.tombs.clone(),
                    holds: BTreeSet::new(),
                    props: props.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
                };
                d.snaps.push(snap);
            }
            Ok(())
        })
    }

    fn hold(&self, snap: &str, tag: &str) -> Result<()> {
        self.with(|st| {
            if !st.snap_mut(snap)?.holds.insert(tag.to_string()) {
                return Err(ZfsError::Exists(format!("{snap}: hold {tag}")));
            }
            Ok(())
        })
    }

    fn release(&self, snap: &str, tag: &str) -> Result<()> {
        self.with(|st| {
            if !st.snap_mut(snap)?.holds.remove(tag) {
                return Err(ZfsError::NotFound(format!("{snap}: hold {tag}")));
            }
            Ok(())
        })
    }

    fn holds(&self, snap: &str) -> Result<Vec<String>> {
        self.with(|st| Ok(st.snap(snap)?.holds.iter().cloned().collect()))
    }

    fn destroy_snapshots(&self, snaps: &[String]) -> Result<Vec<(String, ZfsError)>> {
        self.with(|st| {
            let mut errs = Vec::new();
            for s in snaps {
                let held = match st.snap(s) {
                    Ok(x) => !x.holds.is_empty(),
                    Err(e) => {
                        errs.push((s.clone(), e));
                        continue;
                    }
                };
                if held {
                    errs.push((s.clone(), ZfsError::Busy(s.clone())));
                } else if st.has_clones(s) {
                    errs.push((s.clone(), ZfsError::Exists(format!("{s} has dependent clones"))));
                } else {
                    let (ds, name) = s.split_once('@').unwrap();
                    st.ds_mut(ds)?.snaps.retain(|x| x.name != name);
                }
            }
            Ok(errs)
        })
    }

    fn bookmark(&self, snap: &str, bookmark: &str) -> Result<()> {
        self.with(|st| {
            let s = st.snap(snap)?;
            let (guid, txg) = (s.guid, s.createtxg);
            let (ds, b) =
                bookmark.split_once('#').ok_or_else(|| ZfsError::Failed(format!("not a bookmark: {bookmark}")))?;
            if snap.split_once('@').unwrap().0 != ds {
                return Err(ZfsError::Failed("bookmark must be in the snapshot's dataset".into()));
            }
            let d = st.ds_mut(ds)?;
            if let Some(existing) = d.books.iter().find(|x| x.name == b) {
                return if existing.guid == guid { Ok(()) } else { Err(ZfsError::Exists(bookmark.into())) };
            }
            d.books.push(FBook { name: b.to_string(), guid, createtxg: txg });
            d.books.sort_by_key(|x| x.createtxg);
            Ok(())
        })
    }

    fn destroy_bookmarks(&self, bookmarks: &[String]) -> Result<()> {
        self.with(|st| {
            for b in bookmarks {
                let (ds, name) = b.split_once('#').ok_or_else(|| ZfsError::Failed(format!("not a bookmark: {b}")))?;
                if let Some(d) = st.datasets.get_mut(ds) {
                    d.books.retain(|x| x.name != name);
                }
            }
            Ok(())
        })
    }

    fn send(
        &self,
        snap: &str,
        from: Option<&str>,
        flags: SendFlags,
        resume: Option<(u64, u64)>,
        out: OwnedFd,
    ) -> Result<Job> {
        let stream = self.with(|st| gen_stream(self, st, snap, from, flags, resume))?;
        Ok(Job::Thread(std::thread::spawn(move || {
            let mut f = File::from(out);
            f.write_all(&stream)?;
            Ok(())
        })))
    }

    fn receive(&self, target: &str, opts: &RecvOpts) -> Result<Receiving> {
        let (r, w) = crate::pipe()?;
        let fake = self.clone();
        let target = target.to_string();
        let opts = opts.clone();
        let job = std::thread::spawn(move || receive_thread(fake, target, opts, File::from(r)));
        Ok(Receiving { stdin: w, job: Job::Thread(job) })
    }

    fn receive_abort(&self, ds: &str) -> Result<()> {
        self.with(|st| {
            let d = st.ds_mut(ds)?;
            if d.partial.take().is_none() {
                return Err(ZfsError::Failed(format!("{ds}: no resumable state")));
            }
            if d.created_by_partial {
                st.datasets.remove(ds);
            }
            Ok(())
        })
    }

    fn rename(&self, from: &str, to: &str) -> Result<()> {
        self.with(|st| {
            if st.datasets.contains_key(to) {
                return Err(ZfsError::Exists(to.into()));
            }
            st.ds(from)?;
            let prefix = format!("{from}/");
            let names: Vec<String> =
                st.datasets.keys().filter(|k| *k == from || k.starts_with(&prefix)).cloned().collect();
            for n in names {
                let d = st.datasets.remove(&n).unwrap();
                st.datasets.insert(format!("{to}{}", &n[from.len()..]), d);
            }
            let snap_prefix = format!("{from}@");
            for d in st.datasets.values_mut() {
                if let Some(o) = &d.origin
                    && o.starts_with(&snap_prefix)
                {
                    d.origin = Some(format!("{to}{}", &o[from.len()..]));
                }
            }
            Ok(())
        })
    }

    fn mount(&self, ds: &str) -> Result<()> {
        self.with(|st| st.ds(ds).map(drop))
    }

    fn promote(&self, ds: &str) -> Result<()> {
        self.with(|st| {
            let origin = st.ds(ds)?.origin.clone().ok_or_else(|| ZfsError::Failed(format!("{ds} is not a clone")))?;
            let (od, oname) = origin.split_once('@').unwrap();
            let (od, oname) = (od.to_string(), oname.to_string());
            let txg = st.snap(&origin)?.createtxg;
            let o = st.ds_mut(&od)?;
            let moved: Vec<FSnap> = o.snaps.iter().filter(|s| s.createtxg <= txg).cloned().collect();
            o.snaps.retain(|s| s.createtxg > txg);
            let grand = o.origin.take();
            for d in st.datasets.values_mut() {
                if let Some(org) = &d.origin
                    && let Some((odd, s)) = org.split_once('@')
                    && odd == od
                    && moved.iter().any(|m| m.name == s)
                {
                    d.origin = Some(format!("{ds}@{s}"));
                }
            }
            st.ds_mut(&od)?.origin = Some(format!("{ds}@{oname}"));
            let m = st.ds_mut(ds)?;
            m.origin = grand;
            m.snaps.extend(moved);
            m.snaps.sort_by_key(|s| s.createtxg);
            Ok(())
        })
    }

    fn inherit(&self, ds: &str, prop: &str) -> Result<()> {
        self.with(|st| {
            st.ds_mut(ds)?.props.remove(prop);
            Ok(())
        })
    }

    fn destroy(&self, ds: &str) -> Result<()> {
        self.with(|st| {
            let d = st.ds(ds)?;
            let prefix = format!("{ds}/");
            if !d.snaps.is_empty() || st.datasets.keys().any(|k| k.starts_with(&prefix)) {
                return Err(ZfsError::Exists(format!("{ds} has children")));
            }
            st.datasets.remove(ds);
            Ok(())
        })
    }

    /// The fake has no mounts; a dataset with the test property `fake:busy=on` fails to
    /// unmount, standing in for one with open files.
    fn unmount(&self, ds: &str) -> Result<()> {
        self.with(|st| {
            if st.ds(ds)?.props.get("fake:busy").is_some_and(|v| v == "on") {
                return Err(ZfsError::Busy(format!("cannot unmount {ds}: target is busy")));
            }
            Ok(())
        })
    }

    fn local_props(&self, ds: &str) -> Result<Vec<(String, String)>> {
        self.with(|st| {
            Ok(st
                .ds(ds)?
                .props
                .iter()
                .filter(|(k, _)| !k.starts_with("fake:"))
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect())
        })
    }

    fn destroy_recursive(&self, ds: &str) -> Result<()> {
        self.with(|st| {
            st.ds(ds)?;
            let prefix = format!("{ds}/");
            st.datasets.retain(|k, _| k != ds && !k.starts_with(&prefix));
            Ok(())
        })
    }

    fn allow(&self, _user: &str, _perms: &str, ds: &str) -> Result<()> {
        self.with(|st| st.ds(ds).map(drop))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(src: &Fake, dst: &Fake, snap: &str, from: Option<&str>, target: &str) -> Result<()> {
        let rx = dst.receive(target, &RecvOpts { resumable: true, no_mount: true, ..Default::default() })?;
        let tx = src.send(snap, from, SendFlags::standard(false), None, rx.stdin)?;
        tx.wait()?;
        rx.job.wait()
    }

    #[test]
    fn full_and_incremental_from_bookmark() {
        let t = tempfile::tempdir().unwrap();
        let a = Fake::open(t.path().join("a")).unwrap();
        let b = Fake::open(t.path().join("b")).unwrap();
        a.create_pool("rpool").unwrap();
        b.create_pool("tank").unwrap();
        a.create("rpool/home", &[]).unwrap();
        a.write_object("rpool/home", 1, b"hello").unwrap();
        a.write_object("rpool/home", 2, &vec![7u8; 300_000]).unwrap();
        a.snapshot(&["rpool/home@s1".into()], &[]).unwrap();
        roundtrip(&a, &b, "rpool/home@s1", None, "tank/home@r1").unwrap();
        assert_eq!(b.content("tank/home@r1").unwrap(), a.content("rpool/home@s1").unwrap());

        a.bookmark("rpool/home@s1", "rpool/home#c1").unwrap();
        a.destroy_snapshots(&["rpool/home@s1".into()]).unwrap();
        a.write_object("rpool/home", 1, b"hi").unwrap();
        a.delete_object("rpool/home", 2).unwrap();
        a.write_object("rpool/home", 3, b"new").unwrap();
        a.snapshot(&["rpool/home@s2".into()], &[]).unwrap();
        roundtrip(&a, &b, "rpool/home@s2", Some("rpool/home#c1"), "tank/home@r2").unwrap();
        assert_eq!(b.content("tank/home@r2").unwrap(), a.content("rpool/home@s2").unwrap());
        let guids: Vec<u64> = b.snapshots("tank/home", &[]).unwrap().iter().map(|s| s.guid).collect();
        assert_eq!(guids[1], a.snapshots("rpool/home", &[]).unwrap()[0].guid);

        assert!(roundtrip(&a, &b, "rpool/home@s2", Some("rpool/home#c1"), "tank/home@r3").is_err());
    }

    #[test]
    fn interrupted_receive_resumes() {
        let t = tempfile::tempdir().unwrap();
        let a = Fake::open(t.path().join("a")).unwrap();
        let b = Fake::open(t.path().join("b")).unwrap();
        a.create_pool("rpool").unwrap();
        b.create_pool("tank").unwrap();
        a.create("rpool/d", &[]).unwrap();
        for i in 0..40 {
            a.write_object("rpool/d", i, &vec![i as u8; 200_000]).unwrap();
        }
        a.snapshot(&["rpool/d@s".into()], &[]).unwrap();
        let (r, w) = rustix::pipe::pipe().unwrap();
        let job = a.send("rpool/d@s", None, SendFlags::standard(false), None, w).unwrap();
        let mut stream = Vec::new();
        File::from(r).read_to_end(&mut stream).unwrap();
        job.wait().unwrap();

        let rx = b.receive("tank/d@r", &RecvOpts { resumable: true, ..Default::default() }).unwrap();
        let mut f = File::from(rx.stdin);
        f.write_all(&stream[..stream.len() / 2]).unwrap();
        drop(f);
        assert!(rx.job.wait().is_err());
        let token = b.get_prop("tank/d", "receive_resume_token").unwrap().unwrap();
        let tok = ResumeToken::decode(&token).unwrap();

        let rx = b.receive("tank/d@r", &RecvOpts { resumable: true, ..Default::default() }).unwrap();
        a.send("rpool/d@s", None, SendFlags::standard(false), Some((tok.object, tok.offset)), rx.stdin)
            .unwrap()
            .wait()
            .unwrap();
        rx.job.wait().unwrap();
        assert_eq!(b.content("tank/d@r").unwrap(), a.content("rpool/d@s").unwrap());
        assert!(b.get_prop("tank/d", "receive_resume_token").unwrap().is_none());
    }

    #[test]
    fn promote_moves_history_into_the_clone() {
        let t = tempfile::tempdir().unwrap();
        let z = Fake::open(t.path()).unwrap();
        z.create_pool("p").unwrap();
        z.create("p/a", &[]).unwrap();
        for n in ["1", "2", "3"] {
            z.snapshot(&[format!("p/a@{n}")], &[]).unwrap();
        }
        z.clone_snapshot("p/a@2", "p/b").unwrap();
        z.snapshot(&["p/b@4".into()], &[]).unwrap();
        assert!(z.destroy_snapshots(&["p/a@2".into()]).unwrap().len() == 1, "origin can't go");
        z.promote("p/b").unwrap();
        let names = |d: &str| z.snapshots(d, &[]).unwrap().into_iter().map(|s| s.name).collect::<Vec<_>>();
        assert_eq!(names("p/b"), vec!["1", "2", "4"]);
        assert_eq!(names("p/a"), vec!["3"]);
        assert_eq!(z.get_prop("p/a", "origin").unwrap().as_deref(), Some("p/b@2"));
        assert_eq!(z.get_prop("p/b", "origin").unwrap(), None);
        assert!(z.destroy("p/a").is_err(), "a still has a snapshot");
        z.destroy_snapshots(&["p/a@3".into()]).unwrap();
        z.destroy("p/a").unwrap();
        assert!(z.destroy_snapshots(&["p/b@2".into()]).unwrap().is_empty(), "no clone left on 2");
    }

    #[test]
    fn holds_and_clones_block_destroy() {
        let t = tempfile::tempdir().unwrap();
        let a = Fake::open(t.path()).unwrap();
        a.create_pool("p").unwrap();
        a.create("p/d", &[]).unwrap();
        a.snapshot(&["p/d@1".into(), "p/d@2".into()], &[("strata:gen", "1")]).unwrap();
        a.hold("p/d@1", "x").unwrap();
        let errs = a.destroy_snapshots(&["p/d@1".into(), "p/d@2".into()]).unwrap();
        assert_eq!(errs.len(), 1);
        assert_eq!(a.snapshots("p/d", &["strata:gen"]).unwrap()[0].props["strata:gen"], "1");
    }
}
