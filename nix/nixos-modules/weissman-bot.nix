# NixOS module: Weissman binaries + systemd (journald logging, restart on failure).
{ config, lib, pkgs, ... }:

let
  cfg = config.services.weissman-bot;
in
{
  options.services.weissman-bot = {
    enable = lib.mkEnableOption "Weissman security-assessment API server and optional worker";

    package = lib.mkOption {
      type = lib.types.package;
      description = ''
        Package containing `weissman-server`, `weissman-worker`, and `fingerprint_engine` (e.g.
        `inputs.security-assessment-bot.packages.''${pkgs.system}.default` from this flake).
      '';
    };

    environmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        systemd `EnvironmentFile=` path (root-owned, chmod 600). Put `DATABASE_URL`, `PADDLE_*`,
        `NVD_API_KEY`, `PORT`, etc. here — never bake secrets into the Nix store.
      '';
    };

    server = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = "Run `weissman-server` (recommended production entrypoint).";
      };

      port = lib.mkOption {
        type = lib.types.port;
        default = 8080;
        description = "HTTP listen port (passed as `PORT` to the process).";
      };
    };

    worker = {
      enable = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Run `weissman-worker`. **Enable this in production** whenever HTTP endpoints enqueue
          `weissman_async_jobs` (Command Center scans, deep fuzz, pipeline, swarm, etc.); otherwise
          jobs stay pending. Same `DATABASE_URL` / env as the server.
        '';
      };
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.weissman = {
      isSystemUser = true;
      group = "weissman";
      home = "/var/lib/weissman";
      createHome = true;
      description = "Weissman security-assessment-bot service user";
    };

    users.groups.weissman = { };

    systemd.services.weissman-server = lib.mkIf cfg.server.enable {
      description = "Weissman enterprise API (weissman-server)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "exec";
        User = "weissman";
        Group = "weissman";
        WorkingDirectory = "/var/lib/weissman";
        StateDirectory = "weissman";
        ExecStart = "${cfg.package}/bin/weissman-server";
        Restart = "on-failure";
        RestartSec = "5s";
        # Logs: journalctl -u weissman-server -f
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "weissman-server";
        Environment = [ "PORT=${toString cfg.server.port}" ];
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
        # Hardening (compatible with typical TLS + Postgres clients)
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = true;
        ProtectHome = true;
        ReadWritePaths = [ "/var/lib/weissman" ];
      };
    };

    systemd.services.weissman-worker = lib.mkIf cfg.worker.enable {
      description = "Weissman background worker";
      after = [ "network-online.target" ] ++ lib.optional cfg.server.enable "weissman-server.service";
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      serviceConfig = {
        Type = "exec";
        User = "weissman";
        Group = "weissman";
        WorkingDirectory = "/var/lib/weissman";
        StateDirectory = "weissman";
        ExecStart = "${cfg.package}/bin/weissman-worker";
        Restart = "on-failure";
        RestartSec = "5s";
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "weissman-worker";
        EnvironmentFile = lib.mkIf (cfg.environmentFile != null) cfg.environmentFile;
        NoNewPrivileges = true;
        PrivateTmp = true;
        ProtectSystem = true;
        ProtectHome = true;
        ReadWritePaths = [ "/var/lib/weissman" ];
      };
    };
  };
}
