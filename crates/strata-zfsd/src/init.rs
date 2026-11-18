//! strata-init: builds the dataset tree under `<pool>/strata` and delegates zfsd's
//! operations. Runs as root on every activation; every step is idempotent.

use std::io::Write;
use std::path::Path;

use anyhow::Context;
use strata_zfs::Zfs;

use crate::config::ServerConfig;

pub const ZFSD_PERMISSIONS: &str = "create,destroy,mount,receive,send,snapshot,rollback,clone,promote,hold,release,userprop,readonly,recordsize,compression,checksum,dedup,direct";

fn ensure(zfs: &dyn Zfs, ds: &str, create_props: &[(&str, &str)]) -> anyhow::Result<()> {
    if !zfs.exists(ds)? {
        zfs.create(ds, create_props).with_context(|| format!("creating {ds}"))?;
        log::info!("created {ds}");
    }
    Ok(())
}

pub fn init(cfg: &ServerConfig, zfs: &dyn Zfs, zfsd_user: &str) -> anyhow::Result<()> {
    if !zfs.exists(&cfg.pool)? {
        anyhow::bail!("pool {} is not imported", cfg.pool);
    }
    let root = cfg.root();
    let inherited = [
        ("canmount", "off"),
        ("exec", "off"),
        ("setuid", "off"),
        ("devices", "off"),
        ("atime", "off"),
        ("volmode", "none"),
        ("checksum", "blake3"),
    ];
    ensure(zfs, &root, &inherited)?;
    zfs.set_props(&root, &inherited).with_context(|| format!("setting properties on {root}"))?;
    zfs.set_props(&root, &[("quota", cfg.quota.as_deref().unwrap_or("none"))])?;

    let server_ds = format!("{root}/_server");
    let server_dir = cfg.server_dir.to_string_lossy().into_owned();
    ensure(zfs, &server_ds, &[("mountpoint", &server_dir), ("canmount", "on")])?;
    zfs.set_props(&server_ds, &[("mountpoint", &server_dir), ("canmount", "on")])?;
    if zfs.get_prop(&server_ds, "mounted")?.as_deref() == Some("no") {
        zfs.mount(&server_ds)?;
    }
    write_server_id(&cfg.server_id_path())?;

    for (name, c) in &cfg.clients {
        let cds = format!("{root}/{name}");
        ensure(zfs, &cds, &[("canmount", "off")])?;
        zfs.set_props(&cds, &[("quota", c.quota.as_deref().unwrap_or("none"))])?;
        ensure(zfs, &cfg.client_ds(name), &[("mountpoint", "none")])?;
    }

    zfs.allow(zfsd_user, ZFSD_PERMISSIONS, &root).context("delegating to the zfsd user")?;
    Ok(())
}

/// Creates the server id on first run only: every client's derived key is salted with
/// it, so replacing it would invalidate every key.
pub fn write_server_id(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        return Ok(());
    }
    let id = strata_proto::hs::random16();
    let tmp = path.with_extension("tmp");
    let mut f = std::fs::File::create(&tmp).with_context(|| format!("creating {}", tmp.display()))?;
    writeln!(f, "{}", strata_proto::kdf::encode_server_id(&id))?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    log::info!("created server id at {}", path.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use strata_zfs::Fake;

    #[test]
    fn idempotent_tree() {
        let t = tempfile::tempdir().unwrap();
        let z = Fake::open(t.path().join("zfs")).unwrap();
        z.create_pool("tank").unwrap();
        let cfg: ServerConfig = serde_json::from_value(serde_json::json!({
            "pool": "tank", "listenPort": 7420, "serverDir": t.path().join("server"),
            "clients": {"nas": {"keyFile": "k", "quota": "1T"}}
        }))
        .unwrap();
        std::fs::create_dir(t.path().join("server")).unwrap();
        init(&cfg, &z, "strata-zfs").unwrap();
        let id = std::fs::read_to_string(cfg.server_id_path()).unwrap();
        init(&cfg, &z, "strata-zfs").unwrap();
        assert_eq!(std::fs::read_to_string(cfg.server_id_path()).unwrap(), id);
        assert!(z.exists("tank/strata/nas/ds").unwrap());
        assert_eq!(z.get_prop("tank/strata/nas/ds", "volmode").unwrap().as_deref(), Some("none"));
        assert_eq!(z.get_prop("tank/strata/nas", "quota").unwrap().as_deref(), Some("1T"));
    }
}
