use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use serde::Deserialize;
use strata_proto::hs::ClientSecret;
use strata_proto::msg::AuthMode;
use strata_proto::names::check_name;

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceConfig {
    pub dataset: String,
    pub interval: Option<String>,
    #[serde(default = "yes")]
    pub create_snapshots: bool,
    pub snapshot_pattern: Option<String>,
    #[serde(default)]
    pub raw: bool,
}

fn yes() -> bool {
    true
}

fn default_net_socket() -> PathBuf {
    PathBuf::from("/run/strata/client-net.sock")
}

#[derive(Deserialize, Debug, Clone)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct ClientConfig {
    pub server: String,
    pub name: String,
    pub password_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default = "default_net_socket")]
    pub net_socket: PathBuf,
    #[serde(default)]
    pub sources: BTreeMap<String, SourceConfig>,
}

impl ClientConfig {
    pub fn load(path: &Path) -> anyhow::Result<ClientConfig> {
        let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let c: ClientConfig = serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        c.validate()?;
        Ok(c)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        check_name("client", &self.name).map_err(anyhow::Error::msg)?;
        if self.server.len() > 255 {
            bail!("server address too long");
        }
        match (self.insecure, &self.password_file, &self.key_file) {
            (true, None, None) | (false, Some(_), None) | (false, None, Some(_)) => {}
            (true, _, _) => bail!("an insecure client has no password or key"),
            (false, None, None) => bail!("set passwordFile or keyFile (or insecure = true)"),
            (false, Some(_), Some(_)) => bail!("set only one of passwordFile and keyFile"),
        }
        for (name, s) in &self.sources {
            check_name("source", name).map_err(anyhow::Error::msg)?;
            if s.dataset.is_empty() || s.dataset.contains('@') || s.dataset.contains('#') {
                bail!("source {name}: invalid dataset {:?}", s.dataset);
            }
            if !s.create_snapshots && s.snapshot_pattern.is_none() {
                bail!("source {name}: createSnapshots = false needs a snapshotPattern");
            }
        }
        Ok(())
    }

    pub fn mode(&self) -> AuthMode {
        if self.insecure { AuthMode::None } else { AuthMode::Psk }
    }

    pub fn source(&self, name: &str) -> anyhow::Result<&SourceConfig> {
        self.sources.get(name).with_context(|| format!("no source {name:?} in the client config"))
    }

    /// Reads the secret from `dir` (systemd's credentials directory, file `secret`) when
    /// given, otherwise from the configured path.
    pub fn read_secret(&self, dir: Option<&Path>) -> anyhow::Result<Option<ClientSecret>> {
        let path = match (&self.password_file, &self.key_file) {
            (None, None) => return Ok(None),
            (Some(p), _) | (_, Some(p)) => match dir {
                Some(d) => d.join("secret"),
                None => p.clone(),
            },
        };
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        if self.key_file.is_some() {
            let text = std::str::from_utf8(&bytes).context("key file is not text")?;
            Ok(Some(ClientSecret::Key(strata_proto::kdf::parse_key(text).map_err(anyhow::Error::msg)?)))
        } else {
            Ok(Some(ClientSecret::Password(strata_proto::kdf::password_from_file(&bytes).to_vec())))
        }
    }
}

/// Matches a snapshot name against a pattern where `*` stands for any run of characters.
pub fn glob(pattern: &str, name: &str) -> bool {
    let (p, n) = (pattern.as_bytes(), name.as_bytes());
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == b'*' {
            star = Some((pi, ni));
            pi += 1;
        } else if pi < p.len() && p[pi] == n[ni] {
            pi += 1;
            ni += 1;
        } else if let Some((sp, sn)) = star {
            pi = sp + 1;
            ni = sn + 1;
            star = Some((sp, sn + 1));
        } else {
            return false;
        }
    }
    p[pi..].iter().all(|&c| c == b'*')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn globbing() {
        assert!(glob("autosnap_*_hourly", "autosnap_2026-11-17_13:00:00_hourly"));
        assert!(!glob("autosnap_*_hourly", "autosnap_2026-11-17_daily"));
        assert!(glob("*", "x"));
        assert!(glob("a*b*c", "aXbYc"));
        assert!(!glob("a*b*c", "aXbY"));
    }

    #[test]
    fn config_rules() {
        let c: ClientConfig = serde_json::from_str(
            r#"{"server":"b:7420","name":"nas2","passwordFile":"/p","sources":{"home":{"dataset":"rpool/home"}}}"#,
        )
        .unwrap();
        c.validate().unwrap();
        assert!(c.sources["home"].create_snapshots);
        let bad: ClientConfig =
            serde_json::from_str(r#"{"server":"b:7420","name":"nas2","sources":{"home":{"dataset":"rpool/home"}}}"#)
                .unwrap();
        assert!(bad.validate().is_err());
    }
}
