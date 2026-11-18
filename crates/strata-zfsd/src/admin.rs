//! strata-server: the admin CLI (root).

use std::fmt::Write as _;
use std::io::{BufRead, Write};

use anyhow::{Context, bail};
use strata_proto::names::{utc_readable, valid_name};
use strata_zfs::Zfs;

use crate::config::ServerConfig;
use crate::ops::{BASE_HOLD, REBASE_HOLD, SourceSet, member_source};

pub struct SourceStatus {
    pub client: String,
    pub source: String,
    pub snapshots: usize,
    pub newest: Option<(String, i64)>,
    pub interval: Option<u64>,
    pub used: u64,
    pub configured: bool,
}

impl SourceStatus {
    /// Stale: the newest snapshot is older than twice the interval the client reported
    /// with it.
    pub fn stale(&self, now: i64) -> bool {
        match (&self.newest, self.interval) {
            (Some((_, t)), Some(i)) => now - t > 2 * i as i64,
            _ => false,
        }
    }
}

pub fn collect(cfg: &ServerConfig, zfs: &dyn Zfs) -> anyhow::Result<Vec<SourceStatus>> {
    let root = cfg.root();
    let mut out = Vec::new();
    if !zfs.exists(&root)? {
        return Ok(out);
    }
    for cds in zfs.children(&root)? {
        let client = cds.rsplit('/').next().unwrap_or_default().to_string();
        if !valid_name(&client) {
            continue;
        }
        let parent = cfg.client_ds(&client);
        if !zfs.exists(&parent)? {
            continue;
        }
        let names: std::collections::BTreeSet<String> = zfs
            .children(&parent)?
            .iter()
            .filter_map(|c| member_source(c.rsplit('/').next().unwrap_or_default()).map(str::to_string))
            .collect();
        for source in names {
            let set = SourceSet::load(zfs, &parent, &source)?;
            let newest = set.head().map(|(_, s)| s);
            let mut used = 0;
            for m in &set.members {
                used += zfs.get_prop(m, "used")?.and_then(|u| u.parse::<u64>().ok()).unwrap_or(0);
            }
            out.push(SourceStatus {
                configured: cfg.clients.contains_key(&client),
                interval: newest.and_then(|s| s.props.get("strata:interval")).and_then(|v| v.parse().ok()),
                newest: newest.map(|s| (s.name.clone(), s.creation)),
                snapshots: set.snaps.len(),
                used,
                client: client.clone(),
                source,
            });
        }
    }
    Ok(out)
}

pub fn status_table(st: &[SourceStatus], now: i64) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "{:<16} {:<16} {:>5} {:<22} {:>12}  STATE", "CLIENT", "SOURCE", "SNAPS", "NEWEST", "USED");
    for x in st {
        let newest = x.newest.as_ref().map(|(_, t)| utc_readable(*t)).unwrap_or_else(|| "-".into());
        let state = if !x.configured {
            "unconfigured"
        } else if x.stale(now) {
            "STALE"
        } else {
            "ok"
        };
        let _ =
            writeln!(s, "{:<16} {:<16} {:>5} {:<22} {:>12}  {state}", x.client, x.source, x.snapshots, newest, x.used);
    }
    s
}

/// node_exporter textfile-collector format.
pub fn textfile(st: &[SourceStatus], now: i64) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "# TYPE strata_source_last_success_timestamp_seconds gauge");
    for x in st {
        if let Some((_, t)) = &x.newest {
            let _ = writeln!(
                s,
                "strata_source_last_success_timestamp_seconds{{client=\"{}\",source=\"{}\"}} {t}",
                x.client, x.source
            );
        }
    }
    let _ = writeln!(s, "# TYPE strata_source_used_bytes gauge");
    for x in st {
        let _ = writeln!(s, "strata_source_used_bytes{{client=\"{}\",source=\"{}\"}} {}", x.client, x.source, x.used);
    }
    let _ = writeln!(s, "# TYPE strata_source_snapshots gauge");
    for x in st {
        let _ =
            writeln!(s, "strata_source_snapshots{{client=\"{}\",source=\"{}\"}} {}", x.client, x.source, x.snapshots);
    }
    let _ = writeln!(s, "# TYPE strata_source_stale gauge");
    for x in st {
        let _ = writeln!(
            s,
            "strata_source_stale{{client=\"{}\",source=\"{}\"}} {}",
            x.client,
            x.source,
            x.stale(now) as u8
        );
    }
    s
}

pub fn check_stale(cfg: &ServerConfig, zfs: &dyn Zfs, textfile_path: Option<&std::path::Path>) -> anyhow::Result<bool> {
    let st = collect(cfg, zfs)?;
    let t = strata_proto::names::unix_now();
    let mut any = false;
    for x in st.iter().filter(|x| x.configured && x.stale(t)) {
        any = true;
        let newest = x.newest.as_ref().map(|(_, t)| utc_readable(*t)).unwrap_or_default();
        eprintln!("<4>{}/{} is stale: newest snapshot from {newest}", x.client, x.source);
    }
    if let Some(p) = textfile_path {
        let tmp = p.with_extension("tmp");
        std::fs::write(&tmp, textfile(&st, t))?;
        std::fs::rename(&tmp, p)?;
    }
    Ok(any)
}

pub fn read_password() -> anyhow::Result<Vec<u8>> {
    use rustix::termios::{LocalModes, OptionalActions, tcgetattr, tcsetattr};
    let stdin = std::io::stdin();
    let tty = rustix::termios::isatty(&stdin);
    let saved = if tty { tcgetattr(&stdin).ok() } else { None };
    if let Some(t) = &saved {
        eprint!("Password: ");
        let mut quiet = t.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(&stdin, OptionalActions::Now, &quiet)?;
    }
    let mut line = String::new();
    let r = stdin.lock().read_line(&mut line);
    if let Some(t) = &saved {
        tcsetattr(&stdin, OptionalActions::Now, t)?;
        eprintln!();
    }
    r?;
    let pw = strata_proto::kdf::password_from_file(line.as_bytes()).to_vec();
    if pw.is_empty() {
        bail!("empty password");
    }
    Ok(pw)
}

pub fn derive_key(cfg: &ServerConfig, client: &str) -> anyhow::Result<String> {
    if !valid_name(client) {
        bail!("invalid client name {client:?}");
    }
    let sid = cfg.read_server_id()?;
    let pw = read_password()?;
    Ok(strata_proto::kdf::encode_key(&strata_proto::kdf::derive_key(&pw, &sid, client)))
}

pub fn forget(cfg: &ServerConfig, zfs: &dyn Zfs, target: &str, yes: bool) -> anyhow::Result<()> {
    let (client, source) = target.split_once('/').context("expected <client>/<source>")?;
    if !valid_name(client) || !valid_name(source) {
        bail!("invalid name {target:?}");
    }
    let client_ds = cfg.client_ds(client);
    let set = SourceSet::load(zfs, &client_ds, source)?;
    if set.members.is_empty() {
        bail!("{client_ds}/{source} does not exist");
    }
    if !yes {
        eprint!(
            "Destroy {} and all {} of its snapshots? Type the source name to confirm: ",
            set.members.join(", "),
            set.snaps.len()
        );
        std::io::stderr().flush()?;
        let mut line = String::new();
        std::io::stdin().lock().read_line(&mut line)?;
        if line.trim() != target && line.trim() != source {
            bail!("not confirmed");
        }
    }
    for (ds, s) in &set.snaps {
        let full = format!("{ds}@{}", s.name);
        for h in zfs.holds(&full)? {
            if h == BASE_HOLD || h == REBASE_HOLD {
                zfs.release(&full, &h)?;
            }
        }
    }
    let _ = zfs.inherit(&client_ds, &format!("strata:rebase:{source}"));
    // Clones go before their origins; a pass that destroys nothing ends the loop.
    let mut left = set.members.clone();
    while !left.is_empty() {
        let before = left.len();
        left.retain(|m| zfs.destroy_recursive(m).is_err());
        if left.len() == before {
            bail!("could not destroy {}", left.join(", "));
        }
    }
    Ok(())
}
