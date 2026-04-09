Nix / NixOS deployment (no Docker)

1) Pin inputs (creates or updates flake.lock):
   nix flake lock

2) Build optimized workspace binaries (Cargo profile `release-nix`: LTO from `release` + panic=abort; outputs under target/release-nix):
   nix build .#default
   ./result/bin/weissman-server

3) NixOS: import the flake module and set package + secrets file, e.g.:
   imports = [ inputs.your-flake.nixosModules.weissman-bot ];
   services.weissman-bot = {
     enable = true;
     package = inputs.your-flake.packages.${pkgs.system}.default;
     environmentFile = "/run/secrets/weissman.env";
   };

4) Direnv: install nix-direnv, run `direnv allow`, copy `.envrc.private.example` to `.envrc.private`.

5) Optional HPC host tuning (Transparent Huge Pages + NUMA-friendly vm.zone_reclaim_mode):
   imports = [ inputs.your-flake.nixosModules.weissman-hpc ];
   services.weissman-hpc.enable = true;
   # Optional: services.weissman-hpc.transparentHugePagePolicy = "madvise";
