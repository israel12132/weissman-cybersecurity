# Optional HPC-oriented host tuning (THP, NUMA-friendly VM). Import alongside `weissman-bot`.
{ config, lib, ... }:

let
  cfg = config.services.weissman-hpc;
in
{
  options.services.weissman-hpc = {
    enable = lib.mkEnableOption ''
      Write transparent hugepage policy at boot (tmpfiles) and set vm.zone_reclaim_mode=0
      for typical multi-socket NUMA hosts. Review workload: `always` can increase latency for some apps.
    '';

    transparentHugePagePolicy = lib.mkOption {
      type = lib.types.str;
      default = "always";
      description = ''
        Value written to `/sys/kernel/mm/transparent_hugepage/enabled` (e.g. `always`, `madvise`, `never`).
        Use `madvise` if you only want THP for madvise-backed regions.
      '';
    };

    zoneReclaimMode = lib.mkOption {
      type = lib.types.int;
      default = 0;
      description = ''
        `vm.zone_reclaim_mode` (0 = reclaim remote pages less aggressively; common on NUMA servers).
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.tmpfiles.rules = [
      "w /sys/kernel/mm/transparent_hugepage/enabled - - - - ${cfg.transparentHugePagePolicy}"
    ];

    boot.kernel.sysctl."vm.zone_reclaim_mode" = cfg.zoneReclaimMode;
  };
}
