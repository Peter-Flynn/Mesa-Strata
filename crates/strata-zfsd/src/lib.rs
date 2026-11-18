pub mod admin;
pub mod auth;
pub mod config;
pub mod init;
pub mod ops;
pub mod retention;
pub mod server;

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use strata_proto::local::LocalListener;
use strata_zfs::Zfs;

pub fn init_logging() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).format_timestamp(None).init();
}

pub fn run(cfg_path: &Path, zfs: Arc<dyn Zfs>) -> anyhow::Result<()> {
    let cfg = config::ServerConfig::load(cfg_path)?;
    let listener = match strata_proto::sd::listen_fds().into_iter().next() {
        Some(fd) => LocalListener::from_fd(fd),
        None => {
            let path = cfg.socket.as_ref().context("no socket passed by systemd and no \"socket\" in the config")?;
            LocalListener::bind(path)?
        }
    };
    let keys = cfg.read_keys()?;
    let server_id = cfg.read_server_id()?;
    log::info!("strata-zfsd serving {} client(s) on pool {}", cfg.clients.len(), cfg.pool);
    server::serve(server::Server::new(cfg, zfs, keys, server_id), listener)
}
