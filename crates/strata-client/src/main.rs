use std::path::PathBuf;

use anyhow::Context;
use clap::{Parser, Subcommand};
use strata_client::config::ClientConfig;
use strata_client::ipc::{CReq, CResp};
use strata_client::net::{NetClient, Settings, secret_to_ipc, serve};
use strata_client::{backup, interval, restore, spawn};
use strata_proto::local::LocalSock;

#[derive(Parser)]
#[command(name = "strata", about = "Strata backup client")]
struct Args {
    #[arg(long, default_value = "/etc/strata/client.json")]
    config: PathBuf,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Backs up one source (the ZFS half; the timer unit runs this).
    Backup {
        source: String,
        /// Start a network-half child instead of using the socket-activated one.
        #[arg(long)]
        spawn_net: bool,
    },
    /// The socket-activated network half (one connection per process).
    Net,
    #[command(hide = true)]
    NetChild,
    /// Lists the sources the server holds for this client.
    Sources,
    /// Lists the server's snapshots of a source.
    Snapshots { source: String },
    /// Restores a snapshot into a new dataset (or over the original with --replace).
    Restore {
        source: String,
        /// Snapshot name, or "latest".
        snapshot: Option<String>,
        #[arg(long)]
        target: Option<String>,
        #[arg(long)]
        replace: bool,
        #[arg(long)]
        yes: bool,
        /// Always send the full snapshot, even if a local snapshot could serve as a base.
        #[arg(long)]
        full: bool,
    },
}

fn spawn_child(cfg: &ClientConfig, config_path: &std::path::Path) -> anyhow::Result<(NetClient, std::process::Child)> {
    let exe = std::env::current_exe()?;
    let path = config_path.to_string_lossy().into_owned();
    let (net, child) = spawn::spawn_net_child(&exe, &["--config", &path, "net-child"])?;
    let secret = cfg.read_secret(None)?;
    match net.call(&CReq::Init {
        server: cfg.server.clone(),
        client: cfg.name.clone(),
        mode: cfg.mode(),
        secret: secret_to_ipc(secret.as_ref()),
    })? {
        CResp::Ok => Ok((net, child)),
        other => anyhow::bail!("network half refused Init: {other:?}"),
    }
}

fn main() -> anyhow::Result<()> {
    let fds = strata_proto::sd::listen_fds();
    strata_client::init_logging();
    let args = Args::parse();
    match args.cmd {
        Cmd::NetChild => serve(spawn::net_child_socket()?, None),
        Cmd::Net => {
            let cfg = ClientConfig::load(&args.config)?;
            let fd = fds.into_iter().next().context("no connection passed by systemd (Accept=yes)")?;
            let creds = std::env::var_os("CREDENTIALS_DIRECTORY").map(PathBuf::from);
            let settings = Settings {
                server: cfg.server.clone(),
                client: cfg.name.clone(),
                mode: cfg.mode(),
                secret: cfg.read_secret(creds.as_deref())?,
                compress_threads: std::thread::available_parallelism().map_or(2, |n| n.get()),
            };
            serve(LocalSock::from_fd(fd), Some(settings))
        }
        Cmd::Backup { source, spawn_net } => {
            let cfg = ClientConfig::load(&args.config)?;
            let src = cfg.source(&source)?.clone();
            let zfs = strata_zfs::Real::default();
            let (net, child) = if spawn_net {
                let (n, c) = spawn_child(&cfg, &args.config)?;
                (n, Some(c))
            } else {
                let sock = LocalSock::connect(&cfg.net_socket)
                    .with_context(|| format!("connecting to the network half at {}", cfg.net_socket.display()))?;
                (NetClient::new(sock), None)
            };
            let interval = src.interval.as_deref().and_then(interval::interval_secs);
            let out = backup::backup(&zfs, &net, &source, &src, interval, 1.0);
            drop(net);
            if let Some(mut c) = child {
                let _ = c.wait();
            }
            let out = out?;
            if out.committed.is_empty() {
                eprintln!("{source}: nothing new to back up");
            }
            Ok(())
        }
        Cmd::Sources => {
            let cfg = ClientConfig::load(&args.config)?;
            let (net, _child) = spawn_child(&cfg, &args.config)?;
            print!("{}", restore::sources_table(&net)?);
            Ok(())
        }
        Cmd::Snapshots { source } => {
            let cfg = ClientConfig::load(&args.config)?;
            let (net, _child) = spawn_child(&cfg, &args.config)?;
            print!("{}", restore::snapshots_table(&restore::list_snapshots(&net, &source)?));
            Ok(())
        }
        Cmd::Restore { source, snapshot, target, replace, yes, full } => {
            let cfg = ClientConfig::load(&args.config)?;
            let src = cfg.source(&source)?.clone();
            let (net, _child) = spawn_child(&cfg, &args.config)?;
            let zfs = strata_zfs::Real::default();
            let opts = restore::RestoreOpts { source, snapshot, target, replace, yes, full };
            let ds = restore::restore(&zfs, &net, &src, &opts)?;
            println!("{ds}");
            Ok(())
        }
    }
}
