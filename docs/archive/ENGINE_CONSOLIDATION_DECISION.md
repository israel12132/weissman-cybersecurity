# Engine Consolidation Decision Document

## Overview

Following the comprehensive security audit (May 2026), a critical duplication was identified:
- **54 Python engines** in `src/engines/`
- **72 Rust engines** in `fingerprint_engine/src/*_engine.rs`
- **~40-50 engines overlap** between both implementations

This document provides guidance for deciding which implementation to keep.

## Current State Analysis

### Python Engines (`src/engines/`)
- **Pros:**
  - Fast prototyping and iteration
  - Rich ecosystem (requests, beautifulsoup, etc.)
  - Easy integration with existing Python services
  - Dynamic typing allows flexible payloads

- **Cons:**
  - GIL limits parallelism
  - Higher memory usage
  - Slower execution (10-100x vs Rust)
  - Runtime errors (no compile-time checks)

### Rust Engines (`fingerprint_engine/src/*_engine.rs`)
- **Pros:**
  - Memory safety without GC overhead
  - True parallelism with async/await
  - 10-100x faster than Python
  - Compile-time error detection
  - Lower memory footprint

- **Cons:**
  - Steeper learning curve
  - Longer compilation times
  - Less flexible for rapid prototyping
  - Smaller ecosystem for some use cases

## Overlapping Engines (Examples)

| Engine | Python | Rust | Notes |
|--------|--------|------|-------|
| JWT Attack | ✅ `jwt_attack_engine.py` | ✅ `jwt_attack_engine.rs` | Full duplicate |
| SSRF Advanced | ✅ `ssrf_advanced_engine.py` | ✅ `ssrf_advanced_engine.rs` | Full duplicate |
| OAuth/OIDC | ✅ `oauth_oidc_engine.py` | ✅ `oauth_oidc_engine.rs` | Full duplicate |
| GraphQL | ❌ | ✅ `graphql_attack_engine.rs` | Rust only |
| Kill Chain | ✅ `kill_chain_engine.py` | ✅ `kill_chain_engine.rs` | Full duplicate |

## Recommendation: **Keep Rust, Migrate Python**

### Rationale

1. **Performance is Critical**
   - Security scanning requires high throughput
   - Customers scan thousands of endpoints
   - Rust's parallelism = better scalability

2. **Memory Safety Matters**
   - Security tools must be secure themselves
   - Rust prevents memory vulnerabilities
   - Production stability is crucial

3. **Long-term Investment**
   - Rust ecosystem is growing rapidly
   - Better async support than Python
   - Industry trend (Cloudflare, Discord, etc.)

4. **Current Momentum**
   - 72 Rust engines vs 54 Python engines
   - Core infrastructure already in Rust
   - Frontend expects Rust backend

## Migration Strategy

### Phase 1: Audit & Catalog (1 week)
1. List all 54 Python engines
2. Identify which have Rust equivalents
3. Mark Python-only engines for migration
4. Document any Python-specific features

### Phase 2: Feature Parity (2-3 weeks)
For each Python-only engine:
1. Implement Rust equivalent
2. Add integration tests
3. Verify output matches Python
4. Update frontend registry

### Phase 3: Deprecation (1 week)
1. Mark Python engines as deprecated
2. Add warnings in logs
3. Redirect calls to Rust equivalents
4. Monitor for issues

### Phase 4: Removal (1 week)
1. Remove Python engine files
2. Remove Python dependencies
3. Update documentation
4. Clean up imports

## Alternative: Keep Both (Not Recommended)

If keeping both:
1. **Clearly separate use cases**:
   - Python: Rapid prototyping, research, PoC
   - Rust: Production scans, performance-critical

2. **Prevent future duplication**:
   - New engines ONLY in Rust
   - Python for experiments only
   - Clear naming convention

3. **Maintain consistency**:
   - Shared output format
   - Unified error handling
   - Common metrics

## Decision Timeline

- [ ] **Week 1**: Team decision on Python vs Rust
- [ ] **Week 2-4**: If Rust chosen, start migration
- [ ] **Week 5-6**: Complete Python-only engines in Rust
- [ ] **Week 7**: Deprecate Python engines
- [ ] **Week 8**: Remove Python engines

## Impact Assessment

### If We Keep Rust
- **Effort**: 4-6 weeks (migrate ~15 Python-only engines)
- **Risk**: Medium (need thorough testing)
- **Benefit**: 2x+ performance, single codebase, easier maintenance

### If We Keep Python
- **Effort**: 2-3 weeks (remove Rust engines)
- **Risk**: Low (Python is familiar)
- **Benefit**: Easier development, but worse performance

### If We Keep Both
- **Effort**: 0 weeks (status quo)
- **Risk**: High (ongoing maintenance burden)
- **Benefit**: None (only downsides)

## Metrics to Track

Post-migration, measure:
1. **Performance**: Scan time per target
2. **Memory**: Peak memory usage
3. **Reliability**: Error rates, crash rates
4. **Velocity**: Time to add new engines

## Conclusion

**Recommendation: Migrate all engines to Rust**

This is the best long-term investment. The initial migration effort (4-6 weeks) pays dividends in:
- Better performance
- Lower operational costs
- Easier maintenance
- More robust security

The Python engines can remain temporarily for backward compatibility, but all new development should be Rust-only.

---

**Last Updated**: 2026-05-17
**Author**: Security Audit Implementation Team
**Status**: Awaiting stakeholder decision
