use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use strata_proto::kdf::{DerivedKey, ServerId};
use strata_proto::names::check_name;

#[derive(Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Retention {
    pub keep: u32,
    pub dailies: u32,
}

impl Default for Retention {
    fn default() -> Self {
        Retention { keep: 30, dailies: 14 }
    }
}

#[derive(Deserialize, Debug, Clone, Default)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientConfig {
    pub key_file: Option<PathBuf>,
    pub quota: Option<String>,
    pub keep: Option<u32>,
    pub dailies: Option<u32>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub allow_from: Vec<String>,
}

fn default_max_sessions() -> usize {
    4
}

fn default_server_dir() -> PathBuf {
    PathBuf::from("/var/lib/strata/server")
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ServerConfig {
    pub pool: String,
    /// TCP port netd's listening socket uses; zfsd checks it on every accepted socket.
    pub listen_port: u16,
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,
    #[serde(default)]
    pub defaults: Retention,
    pub quota: Option<String>,
    #[serde(default)]
    pub clients: BTreeMap<String, ClientConfig>,
    #[serde(default = "default_server_dir")]
    pub server_dir: PathBuf,
    pub socket: Option<PathBuf>,
}

impl ServerConfig {
    pub fn load(path: &Path) -> anyhow::Result<ServerConfig> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: ServerConfig = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.pool.is_empty() || self.pool.contains('@') || self.pool.contains('#') {
            bail!("invalid pool {:?}", self.pool);
        }
        if self.max_sessions == 0 {
            bail!("maxSessions must be at least 1");
        }
        for (name, c) in &self.clients {
            check_name("client", name).map_err(anyhow::Error::msg)?;
            if c.insecure && c.allow_from.is_empty() {
                bail!("client {name} is insecure, so it needs allowFrom");
            }
            if !c.insecure && c.key_file.is_none() {
                bail!("client {name} needs a keyFile (or insecure = true with allowFrom)");
            }
            for a in &c.allow_from {
                parse_cidr(a).with_context(|| format!("client {name}: bad allowFrom entry {a:?}"))?;
            }
        }
        Ok(())
    }

    pub fn root(&self) -> String {
        format!("{}/strata", self.pool)
    }

    pub fn client_ds(&self, client: &str) -> String {
        format!("{}/strata/{client}/ds", self.pool)
    }

    pub fn retention(&self, client: &str) -> Retention {
        let c = self.clients.get(client);
        Retention {
            keep: c.and_then(|c| c.keep).unwrap_or(self.defaults.keep).max(1),
            dailies: c.and_then(|c| c.dailies).unwrap_or(self.defaults.dailies),
        }
    }

    pub fn server_id_path(&self) -> PathBuf {
        self.server_dir.join("server-id")
    }

    pub fn read_server_id(&self) -> anyhow::Result<ServerId> {
        let p = self.server_id_path();
        let t =
            std::fs::read_to_string(&p).with_context(|| format!("reading {} (has strata-init run?)", p.display()))?;
        strata_proto::kdf::parse_server_id(&t).map_err(anyhow::Error::msg)
    }

    /// Reads every client's derived key. A relative `keyFile` is looked up in systemd's
    /// `$CREDENTIALS_DIRECTORY`, which is how the NixOS module hands keys to zfsd.
    pub fn read_keys(&self) -> anyhow::Result<BTreeMap<String, DerivedKey>> {
        let creds = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
        let mut keys = BTreeMap::new();
        for (name, c) in &self.clients {
            let Some(kf) = &c.key_file else { continue };
            let path = match (&creds, kf.is_relative()) {
                (Some(dir), true) => dir.join(kf),
                _ => kf.clone(),
            };
            let text = std::fs::read_to_string(&path).with_context(|| format!("reading key for {name}"))?;
            let key = strata_proto::kdf::parse_key(&text).map_err(|e| anyhow::anyhow!("key for {name}: {e}"))?;
            keys.insert(name.clone(), key);
        }
        Ok(keys)
    }
}

pub fn parse_cidr(s: &str) -> anyhow::Result<(IpAddr, u8)> {
    let (addr, len) = match s.split_once('/') {
        Some((a, l)) => (a, Some(l)),
        None => (s, None),
    };
    let ip: IpAddr = addr.parse()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let len = match len {
        Some(l) => l.parse::<u8>()?,
        None => max,
    };
    if len > max {
        bail!("prefix length {len} too long");
    }
    Ok((ip, len))
}

fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
        v4 => v4,
    }
}

pub fn allowed(allow_from: &[String], peer: IpAddr) -> bool {
    let peer = canonical(peer);
    allow_from.iter().filter_map(|a| parse_cidr(a).ok()).any(|(net, len)| match (canonical(net), peer) {
        (IpAddr::V4(n), IpAddr::V4(p)) => {
            let mask = if len == 0 { 0 } else { u32::MAX << (32 - len) };
            u32::from(n) & mask == u32::from(p) & mask
        }
        (IpAddr::V6(n), IpAddr::V6(p)) => {
            let mask = if len == 0 { 0 } else { u128::MAX << (128 - len) };
            u128::from(n) & mask == u128::from(p) & mask
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cidr_matching() {
        let a = vec!["192.168.1.0/24".to_string(), "fd00::5".to_string()];
        assert!(allowed(&a, "192.168.1.77".parse().unwrap()));
        assert!(allowed(&a, "::ffff:192.168.1.9".parse().unwrap()));
        assert!(!allowed(&a, "192.168.2.1".parse().unwrap()));
        assert!(allowed(&a, "fd00::5".parse().unwrap()));
        assert!(!allowed(&a, "fd00::6".parse().unwrap()));
        assert!(allowed(&["0.0.0.0/0".to_string()], "8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn config_rules() {
        let cfg: ServerConfig = serde_json::from_str(
            r#"{"pool":"tank","listenPort":7420,"clients":{"nas":{"insecure":true,"allowFrom":["10.0.0.2"]}}}"#,
        )
        .unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.retention("nas"), Retention { keep: 30, dailies: 14 });
        let bad: ServerConfig =
            serde_json::from_str(r#"{"pool":"tank","listenPort":7420,"clients":{"nas":{"insecure":true}}}"#).unwrap();
        assert!(bad.validate().is_err());
        let bad: ServerConfig =
            serde_json::from_str(r#"{"pool":"tank","listenPort":7420,"clients":{"_server":{"keyFile":"x"}}}"#).unwrap();
        assert!(bad.validate().is_err());
    }
}
