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
  cfg = config.services.strata.client;
  zfsPkg = config.boot.zfs.package;
  netSocket = "/run/strata/client-net.sock";
  secret = if cfg.passwordFile != null then cfg.passwordFile else cfg.keyFile;
  # zfs-allow(8) requires `mount` alongside `snapshot` and `destroy`; the strata user still
  # can't mount anything, because Linux doesn't let non-root users mount.
  delegation = "snapshot,send,bookmark,hold,release,destroy,mount";

  clientJson = pkgs.writeText "strata-client.json" (
    builtins.toJSON (
      lib.filterAttrs (_: v: v != null) {
        inherit (cfg)
          server
          name
          passwordFile
          keyFile
          insecure
          ;
        inherit netSocket;
        sources = lib.mapAttrs (
          _: s:
          lib.filterAttrs (_: v: v != null) {
            inherit (s)
              dataset
              interval
              createSnapshots
              snapshotPattern
              raw
              ;
          }
        ) cfg.sources;
      }
    )
  );

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

  sourceModule = {
    options = {
      dataset = mkOption {
        type = types.str;
        example = "rpool/home";
        description = "ZFS filesystem or volume to back up.";
      };
      interval = mkOption {
        type = types.str;
        default = "daily";
        description = "systemd OnCalendar expression.";
      };
      createSnapshots = mkOption {
        type = types.bool;
        default = true;
      };
      snapshotPattern = mkOption {
        type = types.nullOr types.str;
        default = null;
        example = "autosnap_*_hourly";
      };
      raw = mkOption {
        type = types.bool;
        default = false;
        description = "Send a natively encrypted dataset raw (zfs send -w).";
      };
      randomizedDelaySec = mkOption {
        type = types.str;
        default = "5min";
      };
    };
  };
in
{
  options.services.strata.client = {
    enable = mkEnableOption "the Strata backup client";
    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.strata;
    };
    server = mkOption {
      type = types.str;
      example = "backup.lan:7420";
    };
    name = mkOption {
      type = types.str;
      example = "nas2";
    };
    passwordFile = mkOption {
      type = types.nullOr types.str;
      default = null;
    };
    keyFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "File with the derived key (`strata-server derive-key`), instead of a password.";
    };
    insecure = mkOption {
      type = types.bool;
      default = false;
    };
    sources = mkOption {
      type = types.attrsOf (types.submodule sourceModule);
      default = { };
    };
    nice = mkOption {
      type = types.int;
      default = 10;
    };
    ioSchedulingPriority = mkOption {
      type = types.ints.between 0 7;
      default = 7;
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.insecure || ((cfg.passwordFile == null) != (cfg.keyFile == null));
        message = "services.strata.client needs exactly one of passwordFile and keyFile (or insecure = true).";
      }
    ]
    ++ lib.mapAttrsToList (n: s: {
      assertion = s.createSnapshots || s.snapshotPattern != null;
      message = "services.strata.client.sources.${n}: createSnapshots = false needs a snapshotPattern.";
    }) cfg.sources;

    environment.etc."strata/client.json".source = clientJson;
    environment.systemPackages = [ cfg.package ];

    users.users.strata = {
      isSystemUser = true;
      group = "strata";
    };
    users.groups.strata = { };

    systemd.services.strata-client-init = {
      description = "Strata client delegation";
      wantedBy = [ "multi-user.target" ];
      requires = [ "zfs-import.target" ];
      after = [ "zfs-import.target" ];
      path = [ zfsPkg ];
      restartTriggers = [ clientJson ];
      serviceConfig = {
        Type = "oneshot";
        RemainAfterExit = true;
      };
      script = lib.concatMapStringsSep "\n" (
        s: "zfs allow -u strata ${delegation} ${lib.escapeShellArg s.dataset}"
      ) (lib.attrValues cfg.sources);
    };

    systemd.sockets.strata-client-net = {
      description = "Strata client network half";
      wantedBy = [ "sockets.target" ];
      socketConfig = {
        ListenSequentialPacket = netSocket;
        Accept = true;
        SocketUser = "strata";
        SocketMode = "0600";
        DirectoryMode = "0755";
      };
    };

    systemd.services."strata-client-net@" = {
      description = "Strata client network half (one backup)";
      restartTriggers = [ clientJson ];
      serviceConfig = hardening // {
        ExecStart = "${cfg.package}/bin/strata --config /etc/strata/client.json net";
        DynamicUser = true;
        LoadCredential = lib.optional (secret != null) "secret:${secret}";
        PrivateDevices = true;
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
      };
    };

    systemd.services."strata-backup@" = {
      description = "Strata backup of %i";
      requires = [ "strata-client-init.service" ];
      after = [
        "strata-client-init.service"
        "network-online.target"
      ];
      wants = [ "network-online.target" ];
      path = [
        zfsPkg
        config.systemd.package
      ];
      serviceConfig = hardening // {
        Type = "oneshot";
        ExecStart = "${cfg.package}/bin/strata --config /etc/strata/client.json backup %i";
        User = "strata";
        Group = "strata";
        Nice = cfg.nice;
        IOSchedulingClass = "best-effort";
        IOSchedulingPriority = cfg.ioSchedulingPriority;
        DeviceAllow = [ "/dev/zfs rw" ];
        DevicePolicy = "closed";
        RestrictAddressFamilies = [ "AF_UNIX" ];
        IPAddressDeny = "any";
      };
    };

    systemd.timers = lib.mapAttrs' (
      name: s:
      lib.nameValuePair "strata-backup@${name}" {
        wantedBy = [ "timers.target" ];
        timerConfig = {
          OnCalendar = s.interval;
          Persistent = true;
          RandomizedDelaySec = s.randomizedDelaySec;
        };
      }
    ) cfg.sources;
  };
}
