# Legacy Python layer (deprecated)

**Status:** Deprecated as of 2026-06-27. Scheduled removal after pytest contract migration.

Production runtime is **Rust-only** (`weissman-server`, `weissman-worker`, `fingerprint_engine`).

| Path | Purpose |
|------|---------|
| `legacy/python-src/` | Former `src/` — Python engine shims calling `fingerprint_engine` binary |
| `legacy/python-tests/` | Former `tests/` — unit/integration pytest suite |

Symlinks `src/` and `tests/` at repo root point here for CI backward compatibility.

Do not add new scan logic here. Implement engines in `fingerprint_engine/src/`.
