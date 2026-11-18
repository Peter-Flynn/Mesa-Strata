# Real ZFS end to end: dataset and zvol backups, incrementals, holds, retention, server
# isolation properties, listing, restore, the snapshotPattern mode, auth failures and an
# insecure client.
self:
{ lib, ... }:
let
  zfsNode =
    { pkgs, ... }:
    {
      virtualisation.emptyDiskImages = [ 2048 ];
      virtualisation.memorySize = 2048;
      boot.supportedFilesystems = [ "zfs" ];
      boot.zfs.devNodes = "/dev/disk/by-uuid";
      boot.zfs.forceImportRoot = false;
      environment.systemPackages = [
        pkgs.diffutils
        pkgs.jq
      ];
    };
in
{
  name = "strata-backup-restore";

  nodes = {
    server =
      { nodes, ... }:
      {
        imports = [
          self.nixosModules.server
          zfsNode
        ];
        networking.hostId = "5e1f0001";
        services.strata.server = {
          enable = true;
          pool = "tank";
          openFirewall = true;
          defaults = {
            keep = 3;
            dailies = 0;
          };
          clients.client.keyFile = "/var/lib/strata-test/client.key";
          clients.lab = {
            insecure = true;
            allowFrom = [ nodes.lab.networking.primaryIPAddress ];
          };
        };
      };

    client =
      { ... }:
      {
        imports = [
          self.nixosModules.client
          zfsNode
        ];
        networking.hostId = "5e1f0002";
        environment.etc."strata-password".text = "hunter2";
        services.strata.client = {
          enable = true;
          server = "server:7420";
          name = "client";
          passwordFile = "/etc/strata-password";
          sources = {
            home = {
              dataset = "rpool/home";
              interval = "hourly";
            };
            vol.dataset = "rpool/vol";
            secret = {
              dataset = "rpool/secret";
              raw = true;
            };
            snaps = {
              dataset = "rpool/snaps";
              createSnapshots = false;
              snapshotPattern = "autosnap_*_hourly";
            };
          };
        };
      };

    lab =
      { ... }:
      {
        imports = [
          self.nixosModules.client
          zfsNode
        ];
        networking.hostId = "5e1f0003";
        services.strata.client = {
          enable = true;
          server = "server:7420";
          name = "lab";
          insecure = true;
          sources.data.dataset = "lpool/data";
        };
      };
  };

  testScript = ''
    start_all()
    for m in (server, client, lab):
        m.wait_for_unit("multi-user.target")

    server.succeed("zpool create -o feature@blake3=enabled tank /dev/vdb")
    server.succeed("systemctl restart strata-init")
    server.succeed("echo hunter2 | strata-server derive-key client > /tmp/client.key")
    server.succeed("install -D -m 0400 /tmp/client.key /var/lib/strata-test/client.key")

    with subtest("tree and isolation properties"):
        server.succeed("zfs list tank/strata/_server tank/strata/client/ds tank/strata/lab/ds")
        assert server.succeed("zfs get -H -o value volmode tank/strata").strip() == "none"
        assert server.succeed("zfs get -H -o value canmount tank/strata").strip() == "off"
        assert server.succeed("zfs get -H -o value checksum tank/strata").strip() == "blake3"
        server.succeed("test -s /var/lib/strata/server/server-id")
        perms = server.succeed("zfs allow tank/strata")
        for p in ["create", "destroy", "mount", "receive", "send", "snapshot", "hold", "release", "userprop", "readonly"]:
            assert p in perms, f"{p} not delegated: {perms}"

    client.succeed(
        "zpool create rpool /dev/vdb",
        "zfs create rpool/home",
        "zfs create rpool/snaps",
        "zfs create -V 64M rpool/vol",
        "echo strata-test-passphrase | zfs create -o encryption=on -o keyformat=passphrase -o keylocation=prompt rpool/secret",
        "echo classified > /rpool/secret/f",
        "udevadm settle",
        "dd if=/dev/urandom of=/rpool/home/a bs=1M count=20",
        "echo hello > /rpool/home/b",
        "dd if=/dev/urandom of=/dev/zvol/rpool/vol bs=1M count=16 conv=fsync",
        "systemctl restart strata-client-init",
    )

    with subtest("first backup is full"):
        client.succeed("systemctl start strata-backup@home.service")
        out = client.succeed("strata snapshots home")
        assert "-g1" in out, out
        server.succeed("zfs list -t snapshot tank/strata/client/ds/home")
        assert server.succeed("zfs get -H -o value readonly tank/strata/client/ds/home").strip() == "on"
        assert server.succeed("zfs get -H -o value mounted tank/strata/client/ds/home").strip() == "no"
        # The client keeps no snapshot between runs, only its cursor bookmark.
        assert client.succeed("zfs list -H -t snapshot -o name rpool/home").strip() == ""
        assert "#strata_home_G_" in client.succeed("zfs list -H -t bookmark -o name rpool/home")

    with subtest("incrementals, holds and retention"):
        for i in range(4):
            client.succeed(f"echo {i} >> /rpool/home/b")
            client.succeed("systemctl start strata-backup@home.service")
        snaps = server.succeed("zfs list -H -t snapshot -o name -s createtxg tank/strata/client/ds/home").split()
        assert len(snaps) == 3, snaps
        assert snaps[-1].endswith("-g5"), snaps
        held = server.succeed(f"zfs holds -H {' '.join(snaps)}")
        assert held.count("strata-base") == 1 and snaps[-1] in held, held
        assert server.succeed(f"zfs get -H -o value strata:gen {snaps[-1]}").strip() == "5"
        assert server.succeed(f"zfs get -H -o value strata:interval {snaps[-1]}").strip() == "3600"

    with subtest("zvol source: received, but no device node on the server"):
        client.succeed("systemctl start strata-backup@vol.service")
        assert server.succeed("zfs get -H -o value type tank/strata/client/ds/vol").strip() == "volume"
        server.succeed("udevadm settle")
        server.fail("ls /dev/zvol/tank")
        server.fail("ls /dev/zd0")

    with subtest("raw send of an encrypted dataset stays encrypted on the server"):
        client.succeed("systemctl start strata-backup@secret.service")
        assert server.succeed("zfs get -H -o value encryption tank/strata/client/ds/secret").strip() != "off"
        assert server.succeed("zfs get -H -o value keystatus tank/strata/client/ds/secret").strip() == "unavailable"
        client.succeed("strata restore secret latest --target rpool/secret-restored")
        client.succeed("echo strata-test-passphrase | zfs load-key rpool/secret-restored", "zfs mount rpool/secret-restored")
        client.succeed("diff -r /rpool/secret /rpool/secret-restored")

    with subtest("snapshotPattern mode sends existing snapshots and leaves them"):
        client.succeed("echo x > /rpool/snaps/x", "zfs snapshot rpool/snaps@autosnap_1_hourly", "zfs snapshot rpool/snaps@autosnap_1_daily")
        client.succeed("systemctl start strata-backup@snaps.service")
        client.succeed("systemctl start strata-backup@snaps.service")
        assert len(server.succeed("zfs list -H -t snapshot -o name tank/strata/client/ds/snaps").split()) == 1
        assert client.succeed("zfs get -H -o value userrefs rpool/snaps@autosnap_1_hourly").strip() == "0"
        client.succeed("echo y > /rpool/snaps/y", "zfs snapshot rpool/snaps@autosnap_2_hourly")
        client.succeed("systemctl start strata-backup@snaps.service")
        assert len(server.succeed("zfs list -H -t snapshot -o name tank/strata/client/ds/snaps").split()) == 2
        assert len(client.succeed("zfs list -H -t snapshot -o name rpool/snaps").split()) == 3

    with subtest("list and restore"):
        out = client.succeed("strata sources")
        assert "home" in out and "vol" in out, out
        client.succeed("strata restore home latest --target rpool/restored")
        client.succeed("diff -r /rpool/home /rpool/restored")
        client.succeed("strata restore vol latest --target rpool/vol-restored")
        client.succeed("udevadm settle")
        client.succeed("cmp -n 16777216 /dev/zvol/rpool/vol /dev/zvol/rpool/vol-restored")
        client.succeed("strata restore snaps latest --target rpool/snaps-restored 2>&1 | grep -q incrementally")
        client.succeed("diff -r /rpool/snaps/.zfs/snapshot/autosnap_2_hourly /rpool/snaps-restored")

    with subtest("replace refuses a busy original and keeps it under a new name"):
        client.succeed("echo scribble > /rpool/home/b", "zfs set com.example:tag=kept rpool/home")
        client.succeed("systemd-run --unit=holder --working-directory=/rpool/home sleep 600")
        out = client.fail("strata restore home latest --target rpool/home-busy --replace --yes 2>&1")
        assert "nothing was changed" in out, out
        client.fail("zfs list -H -o name | grep -q '^rpool/home-strata-old-'")
        assert client.succeed("zfs get -H -o value mounted rpool/home").strip() == "yes"
        client.succeed("systemctl stop holder", "zfs destroy -r rpool/home-busy")
        client.succeed("strata restore home latest --target rpool/home-new --replace --yes")
        client.succeed("diff -r /rpool/restored /rpool/home")
        old = client.succeed("zfs list -H -o name | grep '^rpool/home-strata-old-'").strip()
        assert client.succeed(f"zfs get -H -o value canmount {old}").strip() == "noauto"
        assert client.succeed("zfs get -H -o value com.example:tag rpool/home").strip() == "kept"

    with subtest("server status"):
        out = server.succeed("strata-server status")
        assert "home" in out and "ok" in out, out
        server.succeed("strata-server check-stale")

    with subtest("privilege split"):
        assert server.succeed("systemctl show -p User --value strata-zfsd").strip() == "strata-zfs"
        server.succeed("systemctl show -p DynamicUser --value strata-netd@0.service | grep -q yes")
        client.succeed("systemctl show -p User --value strata-backup@home | grep -q strata")

    with subtest("wrong password fails and backs off"):
        client.succeed("echo wrong > /tmp/bad && jq '.passwordFile = \"/tmp/bad\"' /etc/strata/client.json > /tmp/bad.json")
        client.fail("strata --config /tmp/bad.json sources")
        server.succeed("journalctl -u strata-zfsd | grep -q 'client client failed authentication'")
        out = client.fail("strata --config /tmp/bad.json sources 2>&1")
        assert "BackingOff" in out or "authentication failed" in out, out

    with subtest("insecure client from its allowed address"):
        lab.succeed("zpool create lpool /dev/vdb", "zfs create lpool/data", "echo lab > /lpool/data/f", "systemctl restart strata-client-init")
        lab.succeed("systemctl start strata-backup@data.service")
        server.succeed("zfs list tank/strata/lab/ds/data")
        client.succeed("jq '.name = \"lab\" | del(.passwordFile) | .insecure = true' /etc/strata/client.json > /tmp/lab.json")
        out = client.fail("strata --config /tmp/lab.json sources 2>&1")
        assert "AddressNotAllowed" in out, out
  '';
}
