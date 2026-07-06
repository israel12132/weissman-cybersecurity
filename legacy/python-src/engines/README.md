# Python engine bridge (legacy)

All scan logic lives in Rust (`fingerprint_engine`). This directory is a **thin delegation layer** only.

## Preferred API

```python
from src.engines.registry import run_engine

result = run_engine("asm", "https://example.com", timeout=90)
```

## Deprecated

Individual `*_engine.py` modules emit `DeprecationWarning` on import. They remain for backward-compatible imports only.

## Full catalog

563+ production engines — authoritative registry: `backend/weissman-core/src/models/engine.rs`
