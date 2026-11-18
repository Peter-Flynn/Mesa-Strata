//! End-to-end tests. zfsd, one netd per connection, the client's ZFS half and its network
//! half all run as separate processes (this binary re-executed in a role), over two fake
//! pools: the server's and the client's. The crash tests kill processes at every fault
//! point a normal backup passes, then kill everything else as a power cut would, restart,
//! and check that the next backup converges.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpListener, TcpStream};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, bail, ensure};
use strata_client::config::ClientConfig;
use strata_client::ipc::{CReq, CResp};
use strata_client::net::secret_to_ipc;
use strata_zfs::{Fake, Zfs};
use strata_zfsd::config::ServerConfig;

const ROLE: &str = "STRATA_E2E_ROLE";
const PASSWORD: &[u8] = b"correct horse battery staple";

fn role_main(role: &str) -> anyhow::Result<()> {
    strata_client::init_logging();
    let env = |k: &str| std::env::var(k).with_context(|| format!("{k} not set"));
    match role {
        "zfsd" => {
            let cfg = ServerConfig::load(Path::new(&env("STRATA_E2E_CFG")?))?;
            let zfs = Arc::new(Fake::open(env("STRATA_E2E_ZFS")?)?);
            let keys = cfg.read_keys()?;
            let sid = cfg.read_server_id()?;
            let listener = strata_proto::local::LocalListener::bind(cfg.socket.as_ref().unwrap())?;
            strata_zfsd::server::serve(strata_zfsd::server::Server::new(cfg, zfs, keys, sid), listener)
        }
        "netd" => {
            let fd = rustix::io::fcntl_dupfd_cloexec(std::io::stdin(), 3)?;
            strata_netd::serve(TcpStream::from(fd), Path::new(&env("STRATA_E2E_SOCK")?))
        }
        "client" => client_role(),
        _ => bail!("unknown role {role}"),
    }
}

fn spawn_net(cfg: &ClientConfig) -> anyhow::Result<(strata_client::net::NetClient, Child)> {
    let exe = std::env::current_exe()?;
    let (net, child) = strata_client::spawn::spawn_net_child(&exe, &["net-child"])?;
    let secret = cfg.read_secret(None)?;
    let r = net.call(&CReq::Init {
        server: cfg.server.clone(),
        client: cfg.name.clone(),
        mode: cfg.mode(),
        secret: secret_to_ipc(secret.as_ref()),
    })?;
    ensure!(r == CResp::Ok, "Init: {r:?}");
    Ok((net, child))
}

fn client_role() -> anyhow::Result<()> {
    let cfg = ClientConfig::load(Path::new(&std::env::var("STRATA_E2E_CFG")?))?;
    let zfs = Fake::open(std::env::var("STRATA_E2E_ZFS")?)?;
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (net, mut child) = spawn_net(&cfg)?;
    let r = match args[0].as_str() {
        "backup" => {
            let src = cfg.source(&args[1])?;
            let out = strata_client::backup::backup(&zfs, &net, &args[1], src, Some(3600), 0.01)?;
            println!("{}", out.committed.join(" "));
            Ok(())
        }
        "sources" => {
            print!("{}", strata_client::restore::sources_table(&net)?);
            Ok(())
        }
        "restore" => {
            let src = cfg.source(&args[1])?;
            let opts = strata_client::restore::RestoreOpts {
                source: args[1].clone(),
                snapshot: Some(args[2].clone()),
                target: args.iter().position(|a| a == "--target").map(|i| args[i + 1].clone()),
                replace: args.iter().any(|a| a == "--replace"),
                yes: true,
                full: args.iter().any(|a| a == "--full"),
            };
            println!("{}", strata_client::restore::restore(&zfs, &net, src, &opts)?);
            Ok(())
        }
        other => Err(anyhow::anyhow!("unknown client command {other}")),
    };
    drop(net);
    let _ = child.wait();
    r
}

fn quiet() -> String {
    std::env::var("E2E_SERVER_LOG").unwrap_or_else(|_| "error".into())
}

struct World {
    dir: tempfile::TempDir,
    port: u16,
    server: Fake,
    client: Fake,
    zfsd: Option<Child>,
    netds: Arc<Mutex<Vec<Child>>>,
    stop: Arc<AtomicBool>,
    env: Vec<(String, String)>,
    server_cfg: serde_json::Value,
}

impl World {
    fn new() -> anyhow::Result<World> {
        Self::with(|_| {})
    }

    fn with(tweak: impl FnOnce(&mut serde_json::Value)) -> anyhow::Result<World> {
        let dir = tempfile::tempdir()?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        let port = listener.local_addr()?.port();
        let server = Fake::open(dir.path().join("server-zfs"))?;
        server.create_pool("tank")?;
        let client = Fake::open(dir.path().join("client-zfs"))?;
        client.create_pool("rpool")?;
        client.create("rpool/home", &[])?;
        std::fs::create_dir(dir.path().join("server-dir"))?;
        let mut cfg = serde_json::json!({
            "pool": "tank",
            "listenPort": port,
            "maxSessions": 4,
            "defaults": {"keep": 30, "dailies": 14},
            "serverDir": dir.path().join("server-dir"),
            "socket": dir.path().join("zfsd.sock"),
            "clients": {
                "nas": {"keyFile": dir.path().join("nas.key")},
                "lab": {"insecure": true, "allowFrom": ["127.0.0.1"]},
                "far": {"insecure": true, "allowFrom": ["10.9.9.9"]}
            }
        });
        tweak(&mut cfg);
        let mut w = World {
            dir,
            port,
            server,
            client,
            zfsd: None,
            netds: Arc::new(Mutex::new(Vec::new())),
            stop: Arc::new(AtomicBool::new(false)),
            env: Vec::new(),
            server_cfg: cfg,
        };
        w.write_server_cfg()?;
        let scfg = ServerConfig::load(&w.path("server.json"))?;
        strata_zfsd::init::init(&scfg, &w.server, "strata-zfs")?;
        let key = strata_proto::kdf::derive_key(PASSWORD, &scfg.read_server_id()?, "nas");
        std::fs::write(w.path("nas.key"), strata_proto::kdf::encode_key(&key))?;
        std::fs::write(w.path("nas.password"), PASSWORD)?;
        w.write_client_cfg("nas.json", "nas", serde_json::json!({"keyFile": w.path("nas.key")}), serde_json::json!({}))?;
        w.start_acceptor(listener);
        w.start_zfsd()?;
        Ok(w)
    }

    fn path(&self, p: &str) -> PathBuf {
        self.dir.path().join(p)
    }

    fn write_server_cfg(&self) -> anyhow::Result<()> {
        std::fs::write(self.path("server.json"), serde_json::to_vec_pretty(&self.server_cfg)?)?;
        Ok(())
    }

    fn write_client_cfg(&self, file: &str, name: &str, auth: serde_json::Value, extra_sources: serde_json::Value) -> anyhow::Result<()> {
        let mut c = serde_json::json!({
            "server": format!("127.0.0.1:{}", self.port),
            "name": name,
            "sources": {"home": {"dataset": "rpool/home"}}
        });
        for (k, v) in auth.as_object().unwrap() {
            c[k] = v.clone();
        }
        for (k, v) in extra_sources.as_object().unwrap() {
            c["sources"][k] = v.clone();
        }
        std::fs::write(self.path(file), serde_json::to_vec_pretty(&c)?)?;
        Ok(())
    }

    fn start_zfsd(&mut self) -> anyhow::Result<()> {
        let sock = self.path("zfsd.sock");
        let _ = std::fs::remove_file(&sock);
        let mut cmd = Command::new(std::env::current_exe()?);
        cmd.env(ROLE, "zfsd")
            .env("RUST_LOG", quiet())
            .env("STRATA_E2E_CFG", self.path("server.json"))
            .env("STRATA_E2E_ZFS", self.path("server-zfs"))
            .envs(self.env.iter().map(|(a, b)| (a, b)))
            .stdin(Stdio::null());
        self.zfsd = Some(cmd.spawn()?);
        let t = Instant::now();
        while !sock.exists() {
            ensure!(t.elapsed() < Duration::from_secs(10), "zfsd did not start");
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn start_acceptor(&self, listener: TcpListener) {
        let netds = self.netds.clone();
        let stop = self.stop.clone();
        let sock = self.path("zfsd.sock");
        let env_file = self.path("netd.env");
        std::thread::spawn(move || {
            for conn in listener.incoming() {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let Ok(conn) = conn else { continue };
                let env: Vec<(String, String)> = std::fs::read_to_string(&env_file)
                    .unwrap_or_default()
                    .lines()
                    .filter_map(|l| l.split_once('=').map(|(a, b)| (a.to_string(), b.to_string())))
                    .collect();
                let child = Command::new(std::env::current_exe().unwrap())
                    .env(ROLE, "netd")
                    .env("RUST_LOG", quiet())
                    .env("STRATA_E2E_SOCK", &sock)
                    .envs(env)
                    .stdin(Stdio::from(OwnedFd::from(conn)))
                    .spawn();
                if let Ok(c) = child {
                    netds.lock().unwrap().push(c);
                }
            }
        });
    }

    /// Environment for every process started from now on (fault injection, traces).
    fn set_env(&mut self, env: &[(&str, &str)]) -> anyhow::Result<()> {
        self.env = env.iter().map(|(a, b)| (a.to_string(), b.to_string())).collect();
        let text: String = self.env.iter().map(|(a, b)| format!("{a}={b}\n")).collect();
        std::fs::write(self.path("netd.env"), text)?;
        Ok(())
    }

    fn client_cmd(&self, cfg: &str, args: &[&str]) -> anyhow::Result<(ExitStatus, String, String)> {
        let out = Command::new(std::env::current_exe()?)
            .env(ROLE, "client")
            .env("STRATA_E2E_CFG", self.path(cfg))
            .env("STRATA_E2E_ZFS", self.path("client-zfs"))
            .envs(self.env.iter().map(|(a, b)| (a, b)))
            .args(args)
            .stdin(Stdio::null())
            .output()?;
        Ok((out.status, String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned()))
    }

    fn backup(&self) -> anyhow::Result<String> {
        self.backup_as("nas.json", "home")
    }

    fn backup_as(&self, cfg: &str, source: &str) -> anyhow::Result<String> {
        let (st, out, err) = self.client_cmd(cfg, &["backup", source])?;
        ensure!(st.success(), "backup failed ({st}):\n{err}");
        Ok(out.trim().to_string())
    }

    /// Kills every process, as a power cut on both machines would.
    fn power_cut(&mut self) {
        if let Some(mut z) = self.zfsd.take() {
            let _ = z.kill();
            let _ = z.wait();
        }
        for mut c in self.netds.lock().unwrap().drain(..) {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn reap_netds(&self) {
        let t = Instant::now();
        loop {
            let mut v = self.netds.lock().unwrap();
            v.retain_mut(|c| c.try_wait().ok().flatten().is_none());
            if v.is_empty() || t.elapsed() > Duration::from_secs(5) {
                return;
            }
            drop(v);
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn server_ds(&self) -> &'static str {
        "tank/strata/nas/ds/home"
    }

    fn server_snaps(&self) -> anyhow::Result<Vec<strata_zfs::Snap>> {
        Ok(self.server_set()?.snaps.into_iter().map(|(_, s)| s).collect())
    }

    fn server_set(&self) -> anyhow::Result<strata_zfsd::ops::SourceSet> {
        Ok(strata_zfsd::ops::SourceSet::load(&self.server, "tank/strata/nas/ds", "home")?)
    }

    /// Checks the invariants every finished backup must leave behind.
    fn check_converged(&self) -> anyhow::Result<()> {
        let set = self.server_set()?;
        let (head_ds, head) = set.head().context("server has no snapshot")?;
        let live = self.client.content("rpool/home")?;
        let backed = self.server.content(&format!("{head_ds}@{}", head.name))?;
        ensure!(live == backed, "server head {} differs from the client's data", head.name);
        let cursors = self.client.bookmarks("rpool/home")?;
        ensure!(cursors.len() == 1, "expected one cursor, found {:?}", cursors);
        ensure!(cursors[0].guid == head.guid, "cursor is not at the server head");
        let own = self.client.snapshots("rpool/home", &[])?;
        ensure!(own.is_empty(), "client kept snapshots: {:?}", own.iter().map(|s| &s.name).collect::<Vec<_>>());
        for (ds, s) in &set.snaps {
            let holds = self.server.holds(&format!("{ds}@{}", s.name))?;
            let want: Vec<String> = if s.name == head.name { vec!["strata-base".into()] } else { vec![] };
            ensure!(holds == want, "{ds}@{} holds {:?}", s.name, holds);
        }
        for m in &set.members {
            ensure!(!self.server.has_partial(m)?, "partial receive left on {m}");
        }
        ensure!(self.server.get_prop(head_ds, "origin")?.is_none(), "head dataset {head_ds} is still a clone");
        ensure!(
            self.server.get_prop("tank/strata/nas/ds", "strata:rebase:home")?.is_none(),
            "rebase marker left behind"
        );
        Ok(())
    }

    /// Restores `snapshot` over rpool/home through a fresh target, which records a rebase.
    fn replace_with(&self, snapshot: &str, target: &str) -> anyhow::Result<()> {
        let (st, _, err) = self.client_cmd("nas.json", &["restore", "home", snapshot, "--target", target, "--replace"])?;
        ensure!(st.success(), "restore --replace {snapshot}: {err}");
        Ok(())
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        self.power_cut();
    }
}

fn fill(z: &Fake, ds: &str, seed: u8, objects: u64, size: usize) -> anyhow::Result<()> {
    for o in 0..objects {
        let data: Vec<u8> = (0..size).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed).wrapping_add(o as u8)).collect();
        z.write_object(ds, o + 1, &data)?;
    }
    Ok(())
}

fn t_full_then_incremental() -> anyhow::Result<()> {
    let w = World::new()?;
    fill(&w.client, "rpool/home", 1, 5, 50_000)?;
    let first = w.backup()?;
    ensure!(first.ends_with("-g1"), "first snapshot {first}");
    w.check_converged()?;
    w.client.write_object("rpool/home", 2, b"changed")?;
    w.client.delete_object("rpool/home", 3)?;
    let second = w.backup()?;
    ensure!(second.ends_with("-g2"), "second snapshot {second}");
    w.check_converged()?;
    let snaps = w.server_snaps()?;
    ensure!(snaps.len() == 2);
    ensure!(snaps[1].props.get("strata:gen").map(String::as_str) == Some("2"), "{:?}", snaps[1].props);
    ensure!(snaps[1].props.get("strata:interval").map(String::as_str) == Some("3600"));
    ensure!(w.server.get_prop(w.server_ds(), "readonly")?.as_deref() == Some("on"));
    let (st, out, err) = w.client_cmd("nas.json", &["sources"])?;
    ensure!(st.success() && out.contains("home") && out.contains("Dataset"), "sources: {out}{err}");
    Ok(())
}

fn t_password_and_wrong_password() -> anyhow::Result<()> {
    let w = World::new()?;
    fill(&w.client, "rpool/home", 2, 2, 1000)?;
    w.write_client_cfg("pw.json", "nas", serde_json::json!({"passwordFile": w.path("nas.password")}), serde_json::json!({}))?;
    w.backup_as("pw.json", "home")?;
    std::fs::write(w.path("bad.password"), b"wrong")?;
    w.write_client_cfg("bad.json", "nas", serde_json::json!({"passwordFile": w.path("bad.password")}), serde_json::json!({}))?;
    let (st, _, err) = w.client_cmd("bad.json", &["backup", "home"])?;
    ensure!(!st.success() && err.contains("authentication failed"), "wrong password: {err}");
    let (st, _, err) = w.client_cmd("bad.json", &["backup", "home"])?;
    ensure!(!st.success() && err.contains("BackingOff"), "expected backoff: {err}");
    std::thread::sleep(Duration::from_millis(2100));
    w.backup_as("pw.json", "home")?;
    Ok(())
}

fn t_insecure_clients() -> anyhow::Result<()> {
    let w = World::new()?;
    w.client.create("rpool/lab", &[])?;
    fill(&w.client, "rpool/lab", 3, 2, 1000)?;
    w.write_client_cfg("lab.json", "lab", serde_json::json!({"insecure": true}), serde_json::json!({"labdata": {"dataset": "rpool/lab"}}))?;
    w.backup_as("lab.json", "labdata")?;
    ensure!(w.server.exists("tank/strata/lab/ds/labdata")?);
    w.write_client_cfg("far.json", "far", serde_json::json!({"insecure": true}), serde_json::json!({"labdata": {"dataset": "rpool/lab"}}))?;
    let (st, _, err) = w.client_cmd("far.json", &["backup", "labdata"])?;
    ensure!(!st.success() && err.contains("AddressNotAllowed"), "far: {err}");
    w.write_client_cfg("mismatch.json", "nas", serde_json::json!({"insecure": true}), serde_json::json!({}))?;
    let (st, _, err) = w.client_cmd("mismatch.json", &["backup", "home"])?;
    ensure!(!st.success() && err.contains("AuthModeMismatch"), "mismatch: {err}");
    w.write_client_cfg("lab-psk.json", "lab", serde_json::json!({"keyFile": w.path("nas.key")}), serde_json::json!({}))?;
    let (st, _, err) = w.client_cmd("lab-psk.json", &["backup", "home"])?;
    ensure!(!st.success() && err.contains("AuthModeMismatch"), "lab with psk: {err}");
    Ok(())
}

fn t_retention() -> anyhow::Result<()> {
    let w = World::with(|c| c["clients"]["nas"]["keep"] = serde_json::json!(3))?;
    for i in 0..5u8 {
        w.client.write_object("rpool/home", 1, &[i; 100])?;
        w.backup()?;
    }
    let snaps = w.server_snaps()?;
    let gens: Vec<u64> = snaps.iter().map(|s| strata_proto::names::parse_server_snapshot_name(&s.name).unwrap()).collect();
    // The dailies window keeps the newest snapshot of today too, which is already among
    // the three newest.
    ensure!(gens == vec![3, 4, 5], "kept generations {gens:?}");
    w.check_converged()?;
    Ok(())
}

fn t_snapshot_pattern() -> anyhow::Result<()> {
    let w = World::new()?;
    w.write_client_cfg(
        "pat.json",
        "nas",
        serde_json::json!({"keyFile": w.path("nas.key")}),
        serde_json::json!({"home": {"dataset": "rpool/home", "createSnapshots": false, "snapshotPattern": "autosnap_*_hourly"}}),
    )?;
    fill(&w.client, "rpool/home", 4, 2, 1000)?;
    w.client.snapshot(&["rpool/home@autosnap_1_hourly".into()], &[])?;
    w.client.snapshot(&["rpool/home@autosnap_1_daily".into()], &[])?;
    let out = w.backup_as("pat.json", "home")?;
    ensure!(out.ends_with("-g1"));
    let out = w.backup_as("pat.json", "home")?;
    ensure!(out.is_empty(), "nothing new expected, got {out}");
    w.client.write_object("rpool/home", 9, b"later")?;
    w.client.snapshot(&["rpool/home@autosnap_2_hourly".into()], &[])?;
    let out = w.backup_as("pat.json", "home")?;
    ensure!(out.ends_with("-g2"));
    let snaps = w.client.snapshots("rpool/home", &[])?;
    ensure!(snaps.len() == 3, "the client's own snapshots stay");
    ensure!(snaps.iter().all(|s| s.userrefs == 0), "send holds released");
    let head = w.server_snaps()?.last().unwrap().clone();
    ensure!(head.guid == snaps[2].guid, "server head is autosnap_2");

    let (st, out, err) = w.client_cmd("pat.json", &["restore", "home", &head.name, "--target", "rpool/home-r"])?;
    ensure!(st.success(), "restore: {err}");
    ensure!(out.trim() == "rpool/home-r");
    let origin = w.client.get_prop("rpool/home-r", "origin")?;
    ensure!(origin.as_deref() == Some("rpool/home@autosnap_1_hourly"), "expected an incremental restore, origin {origin:?}: {err}");
    ensure!(w.client.content("rpool/home-r")? == w.client.content("rpool/home@autosnap_2_hourly")?);
    Ok(())
}

fn t_restore_full_and_replace() -> anyhow::Result<()> {
    let w = World::new()?;
    fill(&w.client, "rpool/home", 5, 4, 20_000)?;
    let first = w.backup()?;
    let before = w.client.content("rpool/home")?;
    w.client.write_object("rpool/home", 1, b"oops")?;
    w.backup()?;
    let (st, out, err) = w.client_cmd("nas.json", &["restore", "home", &first])?;
    ensure!(st.success(), "restore: {err}");
    ensure!(out.trim() == "rpool/home-restore-g1", "{out}");
    ensure!(w.client.content("rpool/home-restore-g1")? == before);

    w.client.set_props("rpool/home", &[("mountpoint", "/srv/home"), ("com.example:tag", "kept")])?;
    w.client.create("rpool/home/child", &[])?;
    let (st, _, err) = w.client_cmd("nas.json", &["restore", "home", &first, "--target", "rpool/home2", "--replace"])?;
    ensure!(!st.success() && err.contains("child datasets"), "children must refuse: {err}");
    ensure!(!w.client.exists("rpool/home2")?, "nothing restored when refused");
    w.client.destroy_recursive("rpool/home/child")?;

    w.client.set_props("rpool/home", &[("fake:busy", "on")])?;
    let (st, _, err) = w.client_cmd("nas.json", &["restore", "home", &first, "--target", "rpool/home3", "--replace"])?;
    ensure!(!st.success() && err.contains("nothing was changed"), "busy must refuse: {err}");
    ensure!(w.client.content("rpool/home")?[&1] == b"oops", "original untouched");
    ensure!(w.client.get_prop("rpool/home", "canmount")?.is_none(), "canmount untouched");
    ensure!(w.client.exists("rpool/home3")?, "restored copy left for the user");
    w.client.set_props("rpool/home", &[("fake:busy", "off")])?;

    let (st, _, err) = w.client_cmd("nas.json", &["restore", "home", &first, "--target", "rpool/home2", "--replace"])?;
    ensure!(st.success(), "replace: {err}");
    ensure!(w.client.content("rpool/home")? == before);
    ensure!(w.client.get_prop("rpool/home", "mountpoint")?.as_deref() == Some("/srv/home"), "mountpoint carried over");
    ensure!(w.client.get_prop("rpool/home", "com.example:tag")?.as_deref() == Some("kept"), "user property carried over");
    let olds: Vec<String> = w.client.children("rpool")?.into_iter().filter(|c| c.contains("-strata-old-")).collect();
    ensure!(olds.len() == 1, "old copy kept: {olds:?}");
    ensure!(w.client.get_prop(&olds[0], "canmount")?.as_deref() == Some("noauto"), "old copy can't automount");
    ensure!(w.client.content(&olds[0])?[&1] == b"oops", "old copy holds the previous data");
    Ok(())
}

fn t_restore_errors() -> anyhow::Result<()> {
    let w = World::new()?;
    fill(&w.client, "rpool/home", 6, 2, 1000)?;
    let s = w.backup()?;
    let (st, _, err) = w.client_cmd("nas.json", &["restore", "home", "strata-20000101T000000Z-g9"])?;
    ensure!(!st.success() && err.contains("no snapshot"), "{err}");
    let (st, _, _) = w.client_cmd("nas.json", &["restore", "home", &s, "--target", "rpool/x"])?;
    ensure!(st.success());
    Ok(())
}

fn t_resume_after_interrupted_stream() -> anyhow::Result<()> {
    let mut w = World::new()?;
    fill(&w.client, "rpool/home", 7, 30, 200_000)?;
    w.set_env(&[("STRATA_FAULT", "netd.receive.midstream")])?;
    let (st, _, _) = w.client_cmd("nas.json", &["backup", "home"])?;
    ensure!(!st.success(), "backup should have been cut off");
    w.reap_netds();
    w.set_env(&[])?;
    let t = Instant::now();
    while !w.server.has_partial(w.server_ds())? {
        ensure!(t.elapsed() < Duration::from_secs(10), "no partial receive state on the server");
        std::thread::sleep(Duration::from_millis(50));
    }
    let tok = w.server.get_prop(w.server_ds(), "receive_resume_token")?.unwrap();
    let tok = strata_zstream::token::ResumeToken::decode(&tok)?;
    ensure!(tok.object > 0, "partial state has progress");
    w.client.write_object("rpool/home", 99, b"written after the cut")?;
    let out = w.backup()?;
    let parts: Vec<&str> = out.split_whitespace().collect();
    ensure!(parts.len() == 2, "resume plus a fresh incremental expected: {out}");
    w.check_converged()?;
    Ok(())
}

fn t_busy_and_one_session_per_source() -> anyhow::Result<()> {
    let w = World::with(|c| c["maxSessions"] = serde_json::json!(1))?;
    fill(&w.client, "rpool/home", 8, 2, 1000)?;
    let cfg = ClientConfig::load(&w.path("nas.json"))?;
    let (net, mut child) = spawn_net(&cfg)?;
    let r = net.call(&CReq::Backup { source: "home".into(), kind: strata_proto::msg::SourceKind::Dataset })?;
    ensure!(matches!(r, CResp::Ready { .. }), "{r:?}");
    let (net2, mut child2) = spawn_net(&cfg)?;
    let r = net2.call(&CReq::Backup { source: "other".into(), kind: strata_proto::msg::SourceKind::Dataset })?;
    ensure!(matches!(r, CResp::Busy { .. }), "second session should be busy: {r:?}");
    drop(net);
    drop(net2);
    let _ = child.wait();
    let _ = child2.wait();
    w.reap_netds();
    w.backup()?;
    Ok(())
}

fn fault_points(w: &mut World, prepare: &dyn Fn(&World, usize) -> anyhow::Result<()>) -> anyhow::Result<Vec<String>> {
    // The client's network half drops to `nobody` when the tests run as root, so the
    // trace file lives outside the 0700 temp dir and is world-writable.
    let trace = std::env::temp_dir().join(format!("strata-e2e-trace-{}", std::process::id()));
    std::fs::write(&trace, "")?;
    std::fs::set_permissions(&trace, std::os::unix::fs::PermissionsExt::from_mode(0o666))?;
    prepare(w, 1000)?;
    w.power_cut();
    w.set_env(&[("STRATA_FAULT_TRACE", trace.to_str().unwrap())])?;
    w.start_zfsd()?;
    w.client.write_object("rpool/home", 50, b"trace run")?;
    w.backup()?;
    w.set_env(&[])?;
    let text = std::fs::read_to_string(&trace)?;
    let _ = std::fs::remove_file(&trace);
    let mut seen = BTreeSet::new();
    Ok(text.lines().filter(|l| seen.insert(l.to_string())).map(str::to_string).collect())
}

fn crash_loop(w: &mut World, prepare: &dyn Fn(&World, usize) -> anyhow::Result<()>) -> anyhow::Result<()> {
    let points = fault_points(w, prepare)?;
    ensure!(points.len() >= 8, "too few fault points traced: {points:?}");
    let mut results = BTreeMap::new();
    for (i, p) in points.iter().enumerate() {
        w.power_cut();
        w.set_env(&[])?;
        w.start_zfsd()?;
        prepare(w, i)?;
        w.power_cut();
        w.set_env(&[("STRATA_FAULT", p)])?;
        w.start_zfsd()?;
        w.client.write_object("rpool/home", 1, format!("change {i} before crash at {p}").as_bytes())?;
        let (st, _, _) = w.client_cmd("nas.json", &["backup", "home"])?;
        w.power_cut();
        w.set_env(&[])?;
        w.start_zfsd()?;
        w.client.write_object("rpool/home", 2, format!("change {i} after crash at {p}").as_bytes())?;
        let r = w.backup().and_then(|_| w.check_converged());
        results.insert(p.clone(), st.success());
        r.with_context(|| format!("did not converge after a crash at {p}"))?;
    }
    for (p, ok) in &results {
        eprintln!("    crash at {p:<28} first run {}", if *ok { "completed" } else { "died" });
    }
    Ok(())
}

fn t_crash_at_every_point() -> anyhow::Result<()> {
    let mut w = World::new()?;
    fill(&w.client, "rpool/home", 9, 6, 300_000)?;
    w.backup()?;
    crash_loop(&mut w, &|_, _| Ok(()))
}

/// Every crash point again, during the backup that follows a rebase onto the
/// second-newest snapshot.
fn t_crash_during_rebase() -> anyhow::Result<()> {
    let mut w = World::new()?;
    fill(&w.client, "rpool/home", 10, 4, 100_000)?;
    w.backup()?;
    w.client.write_object("rpool/home", 3, b"second")?;
    w.backup()?;
    crash_loop(&mut w, &|w, i| {
        let snaps = w.server_snaps()?;
        let older = &snaps[snaps.len() - 2];
        w.replace_with(&older.name, &format!("rpool/rb{i}"))?;
        ensure!(w.server.get_prop("tank/strata/nas/ds", "strata:rebase:home")?.is_some(), "no rebase recorded");
        Ok(())
    })
}

/// The client dies inside `restore --replace` after the server recorded the rebase, before
/// and after it bookmarked S; the next backup must still land on S's clone.
fn t_crash_inside_replace() -> anyhow::Result<()> {
    for (i, point) in ["client.rebase.recorded", "client.rebase.bookmarked"].iter().enumerate() {
        let mut w = World::new()?;
        fill(&w.client, "rpool/home", 11, 2, 1000)?;
        let first = w.backup()?;
        w.client.write_object("rpool/home", 1, b"newer")?;
        w.backup()?;
        w.set_env(&[("STRATA_FAULT", point)])?;
        let (st, _, _) = w.client_cmd("nas.json", &["restore", "home", &first, "--target", &format!("rpool/rb{i}"), "--replace"])?;
        ensure!(!st.success(), "restore should have died at {point}");
        w.power_cut();
        w.set_env(&[])?;
        w.start_zfsd()?;
        w.client.write_object("rpool/home", 2, b"after")?;
        w.backup().with_context(|| format!("backup after a crash at {point}"))?;
        w.check_converged().with_context(|| format!("after a crash at {point}"))?;
        ensure!(w.server.exists("tank/strata/nas/ds/home.g3")?, "rebased after a crash at {point}");
    }
    Ok(())
}

fn t_rebase_after_replace() -> anyhow::Result<()> {
    let w = World::with(|c| {
        c["defaults"]["keep"] = serde_json::json!(3);
        c["defaults"]["dailies"] = serde_json::json!(0);
    })?;
    let mut names = Vec::new();
    for i in 1..=4u8 {
        w.client.write_object("rpool/home", 1, &[i; 1000])?;
        names.push(w.backup()?);
    }
    w.replace_with(&names[1], "rpool/rb")?;
    ensure!(w.client.content("rpool/home")?[&1] == vec![2u8; 1000], "replaced with g2's data");
    let s = w.server_set()?.find(&names[1]).context("S missing")?.clone();
    let cursors = w.client.bookmarks("rpool/home")?;
    ensure!(cursors.len() == 1 && cursors[0].guid == s.1.guid, "cursor at S: {cursors:?}");
    ensure!(w.client.snapshots("rpool/home", &[])?.is_empty(), "local S destroyed");
    ensure!(w.server.holds(&format!("{}@{}", s.0, s.1.name))?.contains(&"strata-rebase".to_string()));

    w.client.write_object("rpool/home", 2, b"after the rebase")?;
    let g5 = w.backup()?;
    ensure!(g5.ends_with("-g5"), "{g5}");
    w.check_converged()?;
    ensure!(w.server.exists("tank/strata/nas/ds/home.g5")?, "rebased into a sibling");
    let origin = w.server.get_prop("tank/strata/nas/ds/home", "origin")?;
    ensure!(origin == Some(format!("tank/strata/nas/ds/home.g5@{}", names[1])), "promoted; old origin {origin:?}");
    ensure!(w.server.holds(&format!("tank/strata/nas/ds/home.g5@{}", names[1]))?.is_empty(), "S released");

    // keep = 3: g6 prunes g3 and g7 prunes g4, the abandoned branch's last snapshot,
    // which leaves the old dataset empty.
    w.client.write_object("rpool/home", 3, b"g6")?;
    w.backup()?;
    ensure!(w.server.exists("tank/strata/nas/ds/home")?, "abandoned branch still holds g4");
    w.client.write_object("rpool/home", 3, b"g7")?;
    w.backup()?;
    w.check_converged()?;
    ensure!(!w.server.exists("tank/strata/nas/ds/home")?, "abandoned branch's dataset destroyed once its snapshots were pruned");
    let (st, out, err) = w.client_cmd("nas.json", &["sources"])?;
    ensure!(st.success() && out.matches("home").count() == 1, "sources: {out}{err}");
    let latest = w.server_snaps()?.last().unwrap().name.clone();
    let (st, _, err) = w.client_cmd("nas.json", &["restore", "home", &latest, "--target", "rpool/check"])?;
    ensure!(st.success(), "{err}");
    ensure!(w.client.content("rpool/check")? == w.client.content("rpool/home")?);

    w.replace_with(&latest, "rpool/rb-head")?;
    ensure!(w.server.get_prop("tank/strata/nas/ds", "strata:rebase:home")?.is_none(), "rebase onto the head is a no-op");
    w.client.write_object("rpool/home", 4, b"g8")?;
    w.backup()?;
    w.check_converged()?;
    let members = w.server_set()?.members;
    ensure!(members == vec!["tank/strata/nas/ds/home.g5".to_string()], "no new sibling: {members:?}");
    Ok(())
}

type TestFn = fn() -> anyhow::Result<()>;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("net-child") {
        strata_client::init_logging();
        let r = strata_client::spawn::net_child_socket().and_then(|s| strata_client::net::serve(s, None));
        std::process::exit(if r.is_ok() { 0 } else { 1 });
    }
    if let Ok(role) = std::env::var(ROLE) {
        if let Err(e) = role_main(&role) {
            eprintln!("{role}: {e:#}");
            std::process::exit(1);
        }
        return;
    }
    let tests: &[(&str, TestFn)] = &[
        ("full_then_incremental", t_full_then_incremental),
        ("password_and_wrong_password", t_password_and_wrong_password),
        ("insecure_clients", t_insecure_clients),
        ("retention", t_retention),
        ("snapshot_pattern", t_snapshot_pattern),
        ("restore_full_and_replace", t_restore_full_and_replace),
        ("restore_errors", t_restore_errors),
        ("resume_after_interrupted_stream", t_resume_after_interrupted_stream),
        ("busy_and_one_session_per_source", t_busy_and_one_session_per_source),
        ("rebase_after_replace", t_rebase_after_replace),
        ("crash_inside_replace", t_crash_inside_replace),
        ("crash_at_every_point", t_crash_at_every_point),
        ("crash_during_rebase", t_crash_during_rebase),
    ];
    let filter: Vec<String> = std::env::args().skip(1).filter(|a| !a.starts_with('-')).collect();
    let mut failed = 0;
    for (name, f) in tests {
        if !filter.is_empty() && !filter.iter().any(|x| name.contains(x.as_str())) {
            continue;
        }
        let t = Instant::now();
        match f() {
            Ok(()) => eprintln!("test {name} ... ok ({:.1?})", t.elapsed()),
            Err(e) => {
                failed += 1;
                eprintln!("test {name} ... FAILED\n{e:#}");
            }
        }
    }
    if failed > 0 {
        eprintln!("{failed} e2e test(s) failed");
        std::process::exit(1);
    }
}
