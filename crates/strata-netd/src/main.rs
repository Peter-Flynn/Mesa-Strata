use std::net::TcpStream;
use std::path::PathBuf;

use anyhow::Context;
use clap::Parser;

#[derive(Parser)]
#[command(about = "Strata network daemon: serves one socket-activated client connection")]
struct Args {
    #[arg(long, default_value = "/run/strata/zfsd.sock")]
    zfsd_socket: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let fds = strata_proto::sd::listen_fds();
    strata_netd::init_logging();
    let args = Args::parse();
    let fd = fds.into_iter().next().context("no connection passed by systemd (Accept=yes)")?;
    strata_netd::serve(TcpStream::from(fd), &args.zfsd_socket)
}
