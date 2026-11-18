self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkOption
    mkEnableOption
    mkIf
    types
    ;
  cfg = config.services.strata.server;
  zfsPkg = config.boot.zfs.package;
  port = lib.toInt (lib.last (lib.splitString ":" cfg.listen));
  secureClients = lib.filterAttrs (_: c: !c.insecure) cfg.clients;

  serverJson = pkgs.writeText "strata-server.json" (
    builtins.toJSON {
      inherit (cfg) pool maxSessions defaults;
      listenPort = port;
      quota = cfg.quota;
      clients = lib.mapAttrs (
        name: c:
        lib.filterAttrs (_: v: v != null) {
          # Relative: zfsd reads it from $CREDENTIALS_DIRECTORY (LoadCredential below).
          keyFile = if c.insecure then null else "client-${name}";
          inherit (c)
            quota
            keep
            dailies
            insecure
            allowFrom
            ;
        }
      ) cfg.clients;
    }
  );

  # The hardening the plan requires for both daemons.
  hardening = {
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    NoNewPrivileges = true;
    CapabilityBoundingSet = "";
    SystemCallFilter = [ "@system-service" ];
    SystemCallArchitectures = "native";
    MemoryDenyWriteExecute = true;
    ProtectKernelTunables = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    RestrictNamespaces = true;
  };

  clientModule =
    { name, ... }:
    {
      options = {
        keyFile = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "File with the client's derived key, as printed by `strata-server derive-key ${name}`.";
        };
        quota = mkOption {
          type = types.nullOr types.str;
          default = null;
          example = "4T";
        };
        keep = mkOption {
          type = types.nullOr types.ints.positive;
          default = null;
        };
        dailies = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
        };
        insecure = mkOption {
          type = types.bool;
          default = false;
          description = "Accept this client without authentication or encryption, only from `allowFrom`.";
        };
        allowFrom = mkOption {
          type = types.listOf types.str;
          default = [ ];
          example = [ "192.168.1.20" ];
        };
      };
    };
in
{
  options.services.strata.server = {
    enable = mkEnableOption "the Strata backup server";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.strata;
    };
    pool = mkOption {
      type = types.str;
      example = "tank";
    };
    listen = mkOption {
      type = types.str;
      default = "0.0.0.0:7420";
    };
    maxSessions = mkOption {
      type = types.ints.positive;
      default = 4;
    };
    maxConnections = mkOption {
      type = types.ints.positive;
      default = 64;
    };
    maxConnectionsPerSource = mkOption {
      type = types.ints.positive;
      default = 8;
    };
    defaults = {
      keep = mkOption {
        type = types.ints.positive;
        default = 30;
      };
      dailies = mkOption {
        type = types.ints.unsigned;
        default = 14;
      };
    };
    quota = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Overall quota on <pool>/strata.";
    };
    clients = mkOption {
      type = types.attrsOf (types.submodule clientModule);
      default = { };
    };
    openFirewall = mkOption {
      type = types.bool;
      default = false;
    };
    bbr = mkEnableOption "BBR congestion control with the fq qdisc for WAN clients (changes host-wide settings)";
    staleCheck = {
      onCalendar = mkOption {
        type = types.str;
        default = "hourly";
      };
      textfile = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "/var/lib/prometheus-node-exporter-text-files/strata.prom";
        description = "Where to write node_exporter textfile metrics.";
      };
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = lib.versionAtLeast zfsPkg.version "2.4.4";
        message = "services.strata.server needs OpenZFS 2.4.4 or newer (CVE-2026-79619); boot.zfs.package is ${zfsPkg.version}.";
      }
    ]
    ++ lib.mapAttrsToList (n: c: {
      assertion = c.insecure -> c.allowFrom != [ ];
      message = "services.strata.server.clients.${n} is insecure, so it needs allowFrom.";
    }) cfg.clients
    ++ lib.mapAttrsToList (n: c: {
      assertion = !c.insecure -> c.keyFile != null;
      message = "services.strata.server.clients.${n} needs a keyFile.";
    }) cfg.clients;

    environment.etc."strata/server.json".source = serverJson;
    environment.systemPackages = [ cfg.package ];

    users.users.strata-zfs = {
      isSystemUser = true;
      group = "strata-zfs";
    };
    users.groups.strata-zfs = { };
    users.groups.strata-net = { };

    systemd.services.strata-init = {
      description = "Strata dataset tree and delegation";
      wantedBy = [ "multi-user.target" ];
      requires = [ "zfs-import.target" ];
      after = [
        "zfs-import.target"
        "zfs-mount.service"
      ];
      before = [ "strata-zfsd.service" ];
      restartTriggers = [ serverJson ];
      path = [ zfsPkg ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStart = "${cfg.package}/bin/strata-init --config /etc/strata/server.json";
      };
    };

    systemd.sockets.strata-zfsd = {
      description = "Strata zfsd socket";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenSequentialPacket = "/run/strata/zfsd.sock";
        SocketUser = "strata-zfs";
        SocketGroup = "strata-net";
        SocketMode = "0660";
        DirectoryMode = "0755";
      };
    };

    systemd.services.strata-zfsd = {
      description = "Strata ZFS helper";
      requires = [ "strata-init.service" ];
      after = [ "strata-init.service" ];
      restartTriggers = [ serverJson ];
      path = [ zfsPkg ];
      serviceConfig = hardening // {
        ExecStart = "${cfg.package}/bin/strata-zfsd --config /etc/strata/server.json";
        User = "strata-zfs";
        Group = "strata-zfs";
        LoadCredential = lib.mapAttrsToList (n: c: "client-${n}:${c.keyFile}") secureClients;
        DeviceAllow = [ "/dev/zfs rw" ];
        DevicePolicy = "closed";
        RestrictAddressFamilies = [ "AF_UNIX" ];
        ReadWritePaths = [ "-/var/lib/strata/blk" ];
        Restart = "on-failure";
      };
    };

    systemd.sockets.strata-netd = {
      description = "Strata listener";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenStream = cfg.listen;
        Accept = true;
        MaxConnections = cfg.maxConnections;
        MaxConnectionsPerSource = cfg.maxConnectionsPerSource;
      };
    };

    systemd.services."strata-netd@" = {
      description = "Strata network daemon (one connection)";
      serviceConfig = hardening // {
        ExecStart = "${cfg.package}/bin/strata-netd --zfsd-socket /run/strata/zfsd.sock";
        DynamicUser = true;
        SupplementaryGroups = [ "strata-net" ];
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
      };
    };

    systemd.services.strata-stale = {
      description = "Strata staleness check";
      path = [ zfsPkg ];
      serviceConfig = {
        Type = "oneshot";
        ExecStart =
          "${cfg.package}/bin/strata-server --config /etc/strata/server.json check-stale"
          + lib.optionalString (cfg.staleCheck.textfile != null) " --textfile ${cfg.staleCheck.textfile}";
      };
    };
    systemd.timers.strata-stale = {
      wantedBy = [ "timers.target" ];
      timerConfig = {
        OnCalendar = cfg.staleCheck.onCalendar;
        Persistent = true;
      };
    };

    networking.firewall.allowedTCPPorts = lib.optional cfg.openFirewall port;

    boot.kernelModules = lib.optional cfg.bbr "tcp_bbr";
    boot.kernel.sysctl = lib.mkIf cfg.bbr {
      "net.ipv4.tcp_congestion_control" = "bbr";
      "net.core.default_qdisc" = "fq";
    };
  };
}
