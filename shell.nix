# Legacy `nix-shell` entry: same environment as `nix develop` (requires Nix 2.13+ with flakes).
let
  flake = builtins.getFlake (toString ./.);
  sys = builtins.currentSystem;
in
flake.devShells.${sys}.default
