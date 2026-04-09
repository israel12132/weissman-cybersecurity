{
  description = "Weissman security-assessment-bot — reproducible Rust workspace (Nix, no Docker); includes governor/moka via Cargo.lock for edge limits and intel HTTP caching";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    crane = {
      url = "github:ipetkov/crane";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
      fenix,
      flake-utils,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Pinned via flake.lock; includes rustc, cargo, clippy, rustfmt, rust-src (for rust-analyzer).
        rustToolchain = fenix.packages.${system}.stable.toolchain;

        craneLib = (crane.mkLib pkgs).overrideToolchain rustToolchain;

        # commonCargoSources is .rs/.toml/Cargo.lock; also keep include! fragments and sqlx migrations.
        src = pkgs.lib.fileset.toSource {
          root = ./.;
          fileset = pkgs.lib.fileset.unions [
            (craneLib.fileset.commonCargoSources ./.)
            (pkgs.lib.fileset.fileFilter (
              file:
              let
                n = file.name;
              in
              pkgs.lib.hasSuffix ".inc" n || pkgs.lib.hasSuffix ".sql" n
            ) ./.)
          ];
        };

        commonArgs = {
          inherit src;
          # crane's cargoWithProfile uses --release when CARGO_PROFILE=release (default).
          # Custom profile must be set here — do not also pass --profile in cargoExtraArgs (conflicts with --release).
          CARGO_PROFILE = "release-nix";
          strictDeps = true;
          # pkg-config + hwloc: discover/link hwlocality; openssl for sqlx proc-macros at rustc load time.
          # systemdMinimal: libudev (link -ludev) for crates that depend on udev without pulling full systemd.
          nativeBuildInputs = with pkgs; [ pkg-config openssl hwloc systemdMinimal ];
          buildInputs = with pkgs; [
            pkg-config
            openssl
            zlib
            postgresql
            hwloc # runtime: libhwloc.so.* for weissman-server / fingerprint_engine
            systemdMinimal
          ];
          preBuild = ''
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl pkgs.hwloc pkgs.systemdMinimal ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
          '';
          doCheck = false;
        };

        cargoArtifacts = craneLib.buildDepsOnly (
          commonArgs
          // {
            pname = "security-assessment-bot-deps";
            version = "0.1.0";
            cargoExtraArgs = "--workspace";
          }
        );

        security-assessment-bot = craneLib.buildPackage (
          commonArgs
          // {
            inherit cargoArtifacts;
            pname = "security-assessment-bot";
            version = "0.1.0";
            cargoExtraArgs = "--workspace";
            # Manual install skips default patchelf; ensure $out/bin/* RPATH pulls in hwloc (and peers).
            nativeBuildInputs = commonArgs.nativeBuildInputs ++ [ pkgs.autoPatchelfHook ];
            buildInputs = commonArgs.buildInputs ++ [ pkgs.stdenv.cc.cc.lib ];
            installPhaseCommand = ''
              mkdir -p "$out/bin"
              for bin in weissman-server weissman-worker fingerprint_engine; do
                if [[ -f "target/release-nix/$bin" ]]; then
                  install -m0755 "target/release-nix/$bin" "$out/bin/"
                else
                  echo "error: missing target/release-nix/$bin (profile release-nix)" >&2
                  exit 1
                fi
              done
            '';
          }
        );
      in
      {
        packages = {
          default = security-assessment-bot;
          inherit security-assessment-bot;
        };

        apps.default = flake-utils.lib.mkApp {
          drv = security-assessment-bot;
          exePath = "/bin/weissman-server";
        };

        devShells.default = pkgs.mkShell {
          # Deps-only drv keeps direnv/snappy; run `nix build` for full optimized workspace.
          inputsFrom = [ cargoArtifacts ];
          packages =
            with pkgs;
            [
              rustToolchain
              openssl
              hwloc
              systemdMinimal
              postgresql
              sqlx-cli
              cargo-edit
              cargo-watch
            ];
          shellHook = ''
            export RUST_SRC_PATH="${rustToolchain}/lib/rustlib/src/rust/library"
            export PGHOST="''${PGHOST:-127.0.0.1}"
            export LD_LIBRARY_PATH="${pkgs.lib.makeLibraryPath [ pkgs.openssl pkgs.hwloc pkgs.systemdMinimal ]}''${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
            echo "Weissman devShell (Rust workspace): $(rustc --version)"
          '';
        };

      }
    )
    // {
      nixosModules.weissman-bot = import ./nix/nixos-modules/weissman-bot.nix;
      nixosModules.weissman-vllm = import ./nix/nixos-modules/weissman-vllm.nix;
      nixosModules.weissman-hpc = import ./nix/nixos-modules/weissman-hpc.nix;
      nixosModules.default = import ./nix/nixos-modules/weissman-bot.nix;
    };
}
