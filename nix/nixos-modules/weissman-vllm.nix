# NixOS module: vLLM OpenAI-compatible API for Weissman (local inference via nixpkgs vllm).
# Tuned for high-core CPU hosts (e.g. Ryzen 9 5950X, 32 threads, ample RAM): INT8 weights,
# continuous batching limits, and BLAS/OpenMP thread caps aligned with physical threads.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.weissman-vllm;
  defaultPythonVllm = pkgs.python312.withPackages (ps: [ ps.vllm ]);
  defaultCpuVllmArgs = [
    "--device"
    "cpu"
    # Weight-only / W8A8-style path on CPU (requires a checkpoint vLLM can load as int8; override extraArgs if your model needs AWQ/GPTQ files instead).
    "--quantization"
    "int8"
    "--max-num-seqs"
    "32"
    "--max-model-len"
    "16384"
    # model_len * 4 — continuous batching cap for concurrent scan/fuzz prompts (tune down if KV OOM)
    "--max-num-batched-tokens"
    "65536"
  ];
  startScript = pkgs.writeShellScript "weissman-vllm-start" ''
    set -euo pipefail
    exec ${cfg.package}/bin/vllm serve ${lib.escapeShellArg cfg.model} \
      --host ${lib.escapeShellArg cfg.host} \
      --port ${toString cfg.port} \
      ${lib.escapeShellArgs cfg.extraArgs}
  '';
in
{
  options.services.weissman-vllm = {
    enable = lib.mkEnableOption "vLLM OpenAI-compatible HTTP API for Weissman";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPythonVllm;
      description = "Python environment that provides `vllm` on PATH (e.g. nixpkgs `python312Packages.vllm`).";
    };

    model = lib.mkOption {
      type = lib.types.str;
      default = "meta-llama/Llama-3.2-3B-Instruct";
      description = "Model id or path for `vllm serve`.";
    };

    host = lib.mkOption {
      type = lib.types.str;
      default = "127.0.0.1";
    };

    port = lib.mkOption {
      type = lib.types.port;
      default = 8000;
    };

    extraArgs = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = defaultCpuVllmArgs;
      description = ''
        CLI flags after `vllm serve MODEL --host … --port …`.
        Default enables CPU device, int8 quantization, max_num_seqs=32, max_model_len=16384,
        max_num_batched_tokens=65536. Replace entirely if you use GPU or a model that rejects int8.
      '';
    };

    secretsFile = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        systemd `EnvironmentFile=` (root-owned, chmod 600). Set `HUGGING_FACE_HUB_TOKEN`
        for gated Hugging Face models. Never put secrets in the Nix store.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "weissman-vllm";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "weissman-vllm";
    };
  };

  config = lib.mkIf cfg.enable {
    users.users.${cfg.user} = {
      isSystemUser = true;
      group = cfg.group;
      home = "/var/lib/weissman-vllm";
      createHome = true;
      description = "vLLM service user (Weissman)";
    };

    users.groups.${cfg.group} = { };

    systemd.services.weissman-vllm = {
      description = "vLLM OpenAI-compatible API (Weissman)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        OMP_NUM_THREADS = "32";
        MKL_NUM_THREADS = "32";
        OPENBLAS_NUM_THREADS = "32";
        NUMEXPR_NUM_THREADS = "32";
        TORCH_NUM_INTRAOP_THREADS = "32";
        TORCH_NUM_INTEROP_THREADS = "4";
      };

      serviceConfig = {
        Type = "exec";
        User = cfg.user;
        Group = cfg.group;
        StateDirectory = "weissman-vllm";
        WorkingDirectory = "/var/lib/weissman-vllm";
        ExecStart = "${startScript}";
        EnvironmentFile = lib.mkIf (cfg.secretsFile != null) cfg.secretsFile;
        Restart = "on-failure";
        RestartSec = "10s";
        StandardOutput = "journal";
        StandardError = "journal";
        SyslogIdentifier = "weissman-vllm";
        # vLLM / PyTorch worker processes inherit the OMP/MKL caps above
        LimitNOFILE = 1048576;
      };
    };
  };
}
