# Weissman DR/PITR backup toolbox image.
#
# Bundles exactly what the encrypted backup + restore scripts need and nothing else:
#   * pg_basebackup / psql  (from the pgvector/postgres 16 base — version-matched to production)
#   * age                   (envelope encryption/decryption)
#   * bash, coreutils, tar, gzip, curl, ca-certificates
#   * (optional) awscli / rclone for off-site replication — add the one your bucket uses
#
# Build:
#   docker build -f deploy/backup.Dockerfile -t ghcr.io/your-org/weissman-backup:pg16 .
#
# It carries the scripts/ tree so a CronJob just runs e.g.:
#   scripts/dr_orchestrator.sh cycle
#   scripts/dr_orchestrator.sh drill
FROM pgvector/pgvector:pg16

USER root
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        age bash coreutils tar gzip curl ca-certificates tzdata; \
    # awscli is large; uncomment if your off-site backend is S3 and you are not using rclone:
    # apt-get install -y --no-install-recommends awscli; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /opt/weissman
# Only the DR scripts are needed at runtime; copy the whole scripts/ tree so the shared
# lib/backup_crypto.sh and the wrappers resolve by their relative paths.
COPY scripts/ /opt/weissman/scripts/
RUN chmod +x /opt/weissman/scripts/*.sh /opt/weissman/scripts/tests/*.sh 2>/dev/null || true

# Runs unprivileged. The restore drill needs Docker OR local pg_ctl; in K8s use the pg_ctl path
# (WEISSMAN_RESTORE_USE_LOCAL=1) since there is no Docker-in-Docker.
USER 999
ENTRYPOINT ["/bin/bash"]
