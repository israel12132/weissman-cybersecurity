//! MurmurHash3 x64 (low 64 bits of x64_128) for the SOC eat-hook inventory.
//!
//! Not used for SSN dispatch (that stays truncated SHA-256). A per-process
//! random seed stops an off-host attacker from precomputing collisions against
//! the five agent NT APIs.

use std::sync::OnceLock;

const C1: u64 = 0x87c3_7b91_1142_53d5;
const C2: u64 = 0x4cf5_ad43_2745_937f;

fn fmix64(mut k: u64) -> u64 {
    k ^= k >> 33;
    k = k.wrapping_mul(0xff51_afd7_ed55_8ccd);
    k ^= k >> 33;
    k = k.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    k ^= k >> 33;
    k
}

/// MurmurHash3 x64_128, returning the low 64 bits.
#[must_use]
pub fn murmur3_x64_64(key: &[u8], seed: u32) -> u64 {
    let nblocks = key.len() / 16;
    let mut h1 = u64::from(seed);
    let mut h2 = u64::from(seed);

    for i in 0..nblocks {
        let off = i * 16;
        let mut k1 = u64::from_le_bytes(key[off..off + 8].try_into().unwrap());
        let mut k2 = u64::from_le_bytes(key[off + 8..off + 16].try_into().unwrap());

        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
        h1 = h1.rotate_left(27);
        h1 = h1.wrapping_add(h2);
        h1 = h1.wrapping_mul(5).wrapping_add(0x52dce729);

        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
        h2 = h2.rotate_left(31);
        h2 = h2.wrapping_add(h1);
        h2 = h2.wrapping_mul(5).wrapping_add(0x38495ab5);
    }

    let tail = &key[nblocks * 16..];
    let mut k1 = 0u64;
    let mut k2 = 0u64;
    if tail.len() >= 15 {
        k2 ^= u64::from(tail[14]) << 48;
    }
    if tail.len() >= 14 {
        k2 ^= u64::from(tail[13]) << 40;
    }
    if tail.len() >= 13 {
        k2 ^= u64::from(tail[12]) << 32;
    }
    if tail.len() >= 12 {
        k2 ^= u64::from(tail[11]) << 24;
    }
    if tail.len() >= 11 {
        k2 ^= u64::from(tail[10]) << 16;
    }
    if tail.len() >= 10 {
        k2 ^= u64::from(tail[9]) << 8;
    }
    if tail.len() >= 9 {
        k2 ^= u64::from(tail[8]);
        k2 = k2.wrapping_mul(C2);
        k2 = k2.rotate_left(33);
        k2 = k2.wrapping_mul(C1);
        h2 ^= k2;
    }
    if tail.len() >= 8 {
        k1 ^= u64::from(tail[7]) << 56;
    }
    if tail.len() >= 7 {
        k1 ^= u64::from(tail[6]) << 48;
    }
    if tail.len() >= 6 {
        k1 ^= u64::from(tail[5]) << 40;
    }
    if tail.len() >= 5 {
        k1 ^= u64::from(tail[4]) << 32;
    }
    if tail.len() >= 4 {
        k1 ^= u64::from(tail[3]) << 24;
    }
    if tail.len() >= 3 {
        k1 ^= u64::from(tail[2]) << 16;
    }
    if tail.len() >= 2 {
        k1 ^= u64::from(tail[1]) << 8;
    }
    if !tail.is_empty() {
        k1 ^= u64::from(tail[0]);
        k1 = k1.wrapping_mul(C1);
        k1 = k1.rotate_left(31);
        k1 = k1.wrapping_mul(C2);
        h1 ^= k1;
    }

    h1 ^= key.len() as u64;
    h2 ^= key.len() as u64;
    h1 = h1.wrapping_add(h2);
    h2 = h2.wrapping_add(h1);
    h1 = fmix64(h1);
    h2 = fmix64(h2);
    h1.wrapping_add(h2)
}

/// Per-process seed. Not exported in SOC extras (leaking it would let an
/// on-wire observer precompute collisions for this host).
#[must_use]
pub fn hook_map_seed() -> u32 {
    static SEED: OnceLock<u32> = OnceLock::new();
    *SEED.get_or_init(|| {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let mut h = RandomState::new().build_hasher();
        h.write(b"weissman-hookmap-v1");
        (h.finish() as u32) | 1
    })
}

#[must_use]
pub fn hook_map_hash(name: &str) -> u64 {
    murmur3_x64_64(name.as_bytes(), hook_map_seed())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_changes_digest() {
        let a = murmur3_x64_64(b"NtAllocateVirtualMemory", 1);
        let b = murmur3_x64_64(b"NtAllocateVirtualMemory", 2);
        assert_ne!(a, b);
        assert_eq!(murmur3_x64_64(b"NtClose", 7), murmur3_x64_64(b"NtClose", 7));
    }

    #[test]
    fn process_hash_is_stable_in_process() {
        assert_eq!(hook_map_hash("NtClose"), hook_map_hash("NtClose"));
        assert_ne!(hook_map_hash("NtClose"), hook_map_hash("NtCreateSection"));
    }
}
