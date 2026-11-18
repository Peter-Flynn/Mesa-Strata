# Power cuts on real ZFS: the server crashes in the middle of a full backup, then the
# client crashes in the middle of the resumed one. Each next run must resume the partial
# `zfs receive -s` state instead of starting over, and the result must restore intact.
self:
{ lib, ... }:
let
  zfsNode =
    { pkgs, ... }:
    {
      virtualisation.emptyDiskImages = [ 4096 ];
      virtualisation.memorySize = 2048;
      boot.supportedFilesystems = [ "zfs" ];
      boot.zfs.devNodes = "/dev/disk/by-uuid";
      boot.zfs.forceImportRoot = false;
      environment.systemPackages = [ pkgs.diffutils ];
    };
in
{
  name = "strata-crash-resume";

  nodes = {
    server =
      { ... }:
      {
        imports = [
          self.nixosModules.server
          zfsNode
        ];
        networking.hostId = "5e1f0011";
        boot.zfs.extraPools = [ "tank" ];
        services.strata.server = {
          enable = true;
          pool = "tank";
          openFirewall = true;
          clients.client.keyFile = "/var/lib/strata-test/client.key";
        };
      };
    client =
      { ... }:
      {
        imports = [
          self.nixosModules.client
          zfsNode
        ];
        networking.hostId = "5e1f0012";
        boot.zfs.extraPools = [ "rpool" ];
        services.strata.client = {
          enable = true;
          server = "server:7420";
          name = "client";
          keyFile = "/var/lib/strata-test/client.key";
          sources.big.dataset = "rpool/big";
        };
      };
  };

  testScript = ''
    import time

    def receive_token():
        return server.succeed("zfs get -H -o value receive_resume_token tank/strata/client/ds/big || echo -").strip()

    def wait_for_receive_progress():
        server.wait_until_succeeds("zfs list tank/strata/client/ds/big", timeout=120)
        time.sleep(8)

    start_all()
    server.wait_for_unit("multi-user.target")
    client.wait_for_unit("multi-user.target")
    server.succeed("zpool create tank /dev/vdb", "systemctl restart strata-init")
    server.succeed("echo hunter2 | strata-server derive-key client > /tmp/k", "install -D -m 0400 /tmp/k /var/lib/strata-test/client.key")
    key = server.succeed("cat /var/lib/strata-test/client.key").strip()
    client.succeed(f"install -d /var/lib/strata-test && echo {key} > /var/lib/strata-test/client.key && chmod 0400 /var/lib/strata-test/client.key")

    client.succeed(
        "zpool create rpool /dev/vdb",
        "zfs create -o compression=off rpool/big",
        "for i in $(seq 1 12); do dd if=/dev/urandom of=/rpool/big/f$i bs=1M count=100 status=none; done",
        "systemctl restart strata-client-init",
    )

    with subtest("server power cut mid-stream leaves resumable state"):
        client.succeed("systemctl start --no-block strata-backup@big.service")
        wait_for_receive_progress()
        server.crash()
        server.start()
        server.wait_for_unit("multi-user.target")
        assert receive_token() != "-", "no resume token after the server crash"
        client.wait_until_fails("systemctl is-active strata-backup@big.service", timeout=600)

    with subtest("client power cut during the resumed run"):
        client.succeed("systemctl start --no-block strata-backup@big.service")
        client.wait_until_succeeds("journalctl -u strata-backup@big.service | grep -q resuming", timeout=120)
        time.sleep(5)
        client.crash()
        client.start()
        client.wait_for_unit("multi-user.target")
        assert receive_token() != "-", "no resume token after the client crash"

    with subtest("next run resumes and completes"):
        client.succeed("systemctl start strata-backup@big.service")
        client.succeed("journalctl -b -u strata-backup@big.service | grep -q resuming")
        assert receive_token() == "-"
        assert client.succeed("zfs list -H -t snapshot -o name rpool/big").strip() == ""
        assert len(client.succeed("zfs list -H -t bookmark -o name rpool/big").split()) == 1

    with subtest("restored data matches"):
        client.succeed("strata restore big latest --target rpool/big-restored")
        client.succeed("diff -r /rpool/big /rpool/big-restored")
  '';
}
