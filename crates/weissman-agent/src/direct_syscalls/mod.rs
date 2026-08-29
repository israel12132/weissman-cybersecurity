//! Direct syscalls: Hell's Gate + Halo's Gate SSN resolution for weissman-agent.
//!
//! The agent uses this path on Windows x64 so **its own** NT operations (process
//! inspection buffers, local virtual-memory allocation) do not go through user-mode
//! ntdll stubs that EDR products hook. It is not a payload-injection toolkit:
//! callers allocate in the current process with `PAGE_READWRITE`.
//!
//! Pipeline:
//! 1. PEB walk (`GS:[0x60]`) locates `ntdll.dll` without `GetModuleHandle`.
//!    Mapping size comes from `LDR_DATA_TABLE_ENTRY.SizeOfImage`, not PE headers.
//! 2. Export Address Table is parsed. SHA-256 runs only for the pre-computed
//!    agent target set (not every Nt/Zw export). If DOS/NT headers were stomped,
//!    the EAT is recovered by signature-scanning committed pages for
//!    `NtAllocateVirtualMemory` (and sibling Nt* names) in an
//!    `IMAGE_EXPORT_DIRECTORY` names table — not by reading the optional-header
//!    data directory. `.text` is inferred from syscall prologue / JMP-hook
//!    opcodes at those export RVAs.
//! 3. Clean stubs yield the SSN via Hell's Gate (`mov eax, SSN`).
//! 4. Hooked stubs (`jmp` / `0xE9`) recover the SSN via Halo's Gate neighbor scan
//!    confined to the `.text` window.
//! 5. Windows x64 `syscall` is issued with the Microsoft calling convention.

pub mod dispatch;
pub mod fixtures;
pub mod pe;
pub mod peb;
pub mod ssn;

#[cfg(all(windows, target_arch = "x86_64"))]
use crate::direct_syscalls::pe::MAX_IMAGE_SIZE;
use crate::direct_syscalls::pe::{recover_ntdll_export_directory, PeView, MAX_EXPORT_NAMES};
use crate::direct_syscalls::ssn::{infer_text_span_from_eat, resolve_stub_ssn};
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::ffi::c_void;
use std::sync::{LazyLock, OnceLock};

/// Truncated SHA-256 (first 8 bytes, little-endian) of an EAT name.
///
/// djb2 and MurmurHash3 are not second-preimage resistant: an injected export
/// whose name collides with `NtAllocateVirtualMemory` would hijack the SSN.
/// SHA-256 truncated to 64 bits, plus fail-closed duplicate-hash rejection at
/// parse time, closes that resolver-bypass class.
#[must_use]
pub fn hash_api_name(name: &str) -> u64 {
    let digest = Sha256::digest(name.as_bytes());
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&digest[..8]);
    u64::from_le_bytes(buf)
}

/// Nt* routines this process actually issues. SHA-256 runs once per name at
/// process start (LazyLock), not once per EAT export on every parse.
pub const TARGET_SYSCALL_NAMES: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtQuerySystemInformation",
    "NtQueryInformationProcess",
    "NtClose",
];

pub static NT_ALLOCATE_VIRTUAL_MEMORY: LazyLock<u64> =
    LazyLock::new(|| hash_api_name("NtAllocateVirtualMemory"));
pub static NT_PROTECT_VIRTUAL_MEMORY: LazyLock<u64> =
    LazyLock::new(|| hash_api_name("NtProtectVirtualMemory"));
pub static NT_QUERY_SYSTEM_INFORMATION: LazyLock<u64> =
    LazyLock::new(|| hash_api_name("NtQuerySystemInformation"));
pub static NT_QUERY_INFORMATION_PROCESS: LazyLock<u64> =
    LazyLock::new(|| hash_api_name("NtQueryInformationProcess"));
pub static NT_CLOSE: LazyLock<u64> = LazyLock::new(|| hash_api_name("NtClose"));

/// Pre-computed target hashes. EAT walk compares names against
/// [`TARGET_SYSCALL_NAMES`] and uses these constants — it does not SHA-256
/// every Nt/Zw export on cold start.
#[must_use]
pub fn precomputed_target_hash(name: &str) -> Option<u64> {
    Some(match name {
        "NtAllocateVirtualMemory" => *NT_ALLOCATE_VIRTUAL_MEMORY,
        "NtProtectVirtualMemory" => *NT_PROTECT_VIRTUAL_MEMORY,
        "NtQuerySystemInformation" => *NT_QUERY_SYSTEM_INFORMATION,
        "NtQueryInformationProcess" => *NT_QUERY_INFORMATION_PROCESS,
        "NtClose" => *NT_CLOSE,
        _ => return None,
    })
}

/// FNV-1a 64-bit. Used only for the SOC eat-hook inventory — never for SSN
/// dispatch. SHA-256 remains the fail-closed resolver hash for the five
/// syscalls this process actually issues.
#[must_use]
pub fn fnv1a_64(name: &str) -> u64 {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0100_0000_01b3;
    let mut h = OFFSET;
    for b in name.as_bytes() {
        h ^= u64::from(*b);
        h = h.wrapping_mul(PRIME);
    }
    h
}

/// One resolved Nt/Zw export hashed with truncated SHA-256 (dispatch table).
#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    pub hash: u64,
    pub ssn: u16,
    pub hooked: bool,
    pub rva: u32,
}

/// One Nt/Zw export in the eat-hook inventory (FNV-1a, telemetry only).
#[derive(Debug, Clone, Copy)]
pub struct HookMapEntry {
    pub fnv: u64,
    pub ssn: u16,
    pub hooked: bool,
    pub rva: u32,
}

/// Hell's Gate / Halo's Gate resolver populated from a PE image (live ntdll or fixture).
#[derive(Debug, Clone)]
pub struct SyscallResolver {
    entries: Vec<SyscallEntry>,
    hook_map: Vec<HookMapEntry>,
    scanned: usize,
    hooked_total: usize,
}

impl SyscallResolver {
    /// Parse Nt/Zw exports from a PE32+ image already in memory.
    ///
    /// Prefers PE headers. If DOS/NT headers or the data directory were erased,
    /// recovers the EAT by signature-scanning for `NtAllocateVirtualMemory` in
    /// the names table and infers `.text` from Hell's Gate prologues.
    #[must_use]
    pub fn from_pe_bytes(image: &[u8]) -> Option<Self> {
        let pe_opt = PeView::new(image);
        let view = pe_opt.unwrap_or_else(|| PeView::raw(image));
        let export = view
            .export_directory()
            .or_else(|| recover_ntdll_export_directory(image))?;
        if export.number_of_names == 0 || export.number_of_names > MAX_EXPORT_NAMES {
            return None;
        }
        // Prefer PE `.text`. If the section table was stomped, infer the window
        // from Nt/Zw EAT stubs (prologue / JMP-hook opcodes) so Halo's Gate
        // never walks a poison gadget planted outside the export cluster.
        let text = pe_opt
            .and_then(|p| p.text_section_span())
            .or_else(|| infer_text_span_from_eat(view, &export))?;
        let mut entries = Vec::new();
        let mut hook_map = Vec::new();
        let mut scanned = 0usize;
        let mut hooked_total = 0usize;
        for i in 0..export.number_of_names as usize {
            let name_rva = match view.u32_at(export.address_of_names, i) {
                Some(v) => v,
                None => continue,
            };
            let name = match view.cstr_at(name_rva) {
                Some(n) => n,
                None => continue,
            };
            if !(name.starts_with("Nt") || name.starts_with("Zw")) {
                continue;
            }
            let ordinal = match view.u16_at(export.address_of_name_ordinals, i) {
                Some(v) => v as usize,
                None => continue,
            };
            let func_rva = match view.u32_at(export.address_of_functions, ordinal) {
                Some(v) => v,
                None => continue,
            };
            let Some(resolved) = resolve_stub_ssn(view.bytes(), func_rva as usize, text) else {
                continue;
            };
            scanned += 1;
            if resolved.hooked {
                hooked_total += 1;
            }
            hook_map.push(HookMapEntry {
                fnv: fnv1a_64(name),
                ssn: resolved.ssn,
                hooked: resolved.hooked,
                rva: func_rva,
            });
            // SHA-256 only for the pre-computed target set — not every Nt/Zw name.
            if let Some(hash) = precomputed_target_hash(name) {
                entries.push(SyscallEntry {
                    hash,
                    ssn: resolved.ssn,
                    hooked: resolved.hooked,
                    rva: func_rva,
                });
            }
        }
        Self::from_entries(entries, hook_map, scanned, hooked_total)
    }

    fn from_entries(
        entries: Vec<SyscallEntry>,
        hook_map: Vec<HookMapEntry>,
        scanned: usize,
        hooked_total: usize,
    ) -> Option<Self> {
        if entries.is_empty() && scanned == 0 {
            return None;
        }
        let mut seen: HashSet<u64> = HashSet::new();
        let mut poisoned: HashSet<u64> = HashSet::new();
        for e in &entries {
            if !seen.insert(e.hash) {
                poisoned.insert(e.hash);
            }
        }
        let entries: Vec<SyscallEntry> = entries
            .into_iter()
            .filter(|e| !poisoned.contains(&e.hash))
            .collect();
        let mut fnv_seen: HashSet<u64> = HashSet::new();
        let mut fnv_poisoned: HashSet<u64> = HashSet::new();
        for e in &hook_map {
            if !fnv_seen.insert(e.fnv) {
                fnv_poisoned.insert(e.fnv);
            }
        }
        let hook_map: Vec<HookMapEntry> = hook_map
            .into_iter()
            .filter(|e| !fnv_poisoned.contains(&e.fnv))
            .collect();
        if entries.is_empty() {
            return None;
        }
        Some(Self {
            entries,
            hook_map,
            scanned: scanned.max(1),
            hooked_total,
        })
    }

    /// Walk the live process PEB, map ntdll, parse the EAT.
    ///
    /// # Safety
    /// Windows x64 only. Reads the PEB and ntdll's mapped image.
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub unsafe fn from_live_ntdll() -> Option<Self> {
        let map = peb::ntdll_mapping()?;
        let size = map.size_of_image;
        if size < 0x400 || size > MAX_IMAGE_SIZE {
            return None;
        }
        let mut image = vec![0u8; size];
        copy_ntdll_image(map.base, size, &mut image);
        Self::from_pe_bytes(&image)
    }

    #[must_use]
    pub fn resolve_by_hash(&self, hash: u64) -> Option<SyscallEntry> {
        self.entries.iter().copied().find(|e| e.hash == hash)
    }

    #[must_use]
    pub fn resolve_ssn(&self, hash: u64) -> Option<u16> {
        self.resolve_by_hash(hash).map(|e| e.ssn)
    }

    #[must_use]
    pub fn entries(&self) -> &[SyscallEntry] {
        &self.entries
    }

    #[must_use]
    pub fn hook_map(&self) -> &[HookMapEntry] {
        &self.hook_map
    }

    #[must_use]
    pub fn hooked_count(&self) -> usize {
        self.hooked_total
    }

    #[must_use]
    pub fn exports_scanned(&self) -> usize {
        self.scanned
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Copy committed pages of live ntdll. Uses `VirtualQuery` so stomped headers
/// (no section table) do not cause a SizeOfImage-wide read of a guard page.
#[cfg(all(windows, target_arch = "x86_64"))]
unsafe fn copy_ntdll_image(base: *const u8, size: usize, out: &mut [u8]) {
    use windows_sys::Win32::System::Memory::{VirtualQuery, MEMORY_BASIC_INFORMATION, MEM_COMMIT};

    let copy_len = size.min(out.len());
    let mut off = 0usize;
    while off < copy_len {
        let mut mbi = std::mem::zeroed::<MEMORY_BASIC_INFORMATION>();
        let queried = VirtualQuery(
            base.add(off).cast(),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        );
        if queried == 0 {
            break;
        }
        let region = mbi.RegionSize.max(0x1000).min(copy_len - off);
        if mbi.State == MEM_COMMIT {
            let src = std::slice::from_raw_parts(base.add(off), region);
            out[off..off + region].copy_from_slice(src);
        }
        off = off.saturating_add(region);
        if region == 0 {
            break;
        }
    }
}

/// Process-wide resolver (parsed once). Windows only; `None` on other platforms.
pub fn global_resolver() -> Option<&'static SyscallResolver> {
    static CELL: OnceLock<Option<SyscallResolver>> = OnceLock::new();
    CELL.get_or_init(|| {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            // SAFETY: from_live_ntdll only reads the current process PEB + ntdll image.
            unsafe { SyscallResolver::from_live_ntdll() }
        }
        #[cfg(not(all(windows, target_arch = "x86_64")))]
        {
            None
        }
    })
    .as_ref()
}

/// Allocate a `PAGE_READWRITE` region in the **current** process via a direct syscall
/// when the resolver is available; otherwise return `STATUS_NOT_IMPLEMENTED`.
///
/// # Safety
/// On Windows the syscall is issued against the live SSN. `region_size` is both in
/// and out (NTAPI). The returned pointer, if success, must be released by the caller.
pub unsafe fn weissman_allocate_virtual_memory(
    process_handle: usize,
    base_address: &mut *mut c_void,
    zero_bits: usize,
    region_size: &mut usize,
    allocation_type: u32,
    protect: u32,
) -> u32 {
    #[cfg(not(all(windows, target_arch = "x86_64")))]
    {
        let _ = (
            process_handle,
            base_address,
            zero_bits,
            region_size,
            allocation_type,
            protect,
        );
        return dispatch::STATUS_NOT_IMPLEMENTED;
    }
    #[cfg(all(windows, target_arch = "x86_64"))]
    {
        let Some(resolver) = global_resolver() else {
            return dispatch::STATUS_UNSUCCESSFUL;
        };
        let Some(entry) = resolver.resolve_by_hash(*NT_ALLOCATE_VIRTUAL_MEMORY) else {
            return dispatch::STATUS_UNSUCCESSFUL;
        };
        dispatch::syscall6(
            entry.ssn,
            [
                process_handle,
                base_address as *mut _ as usize,
                zero_bits,
                region_size as *mut _ as usize,
                allocation_type as usize,
                protect as usize,
            ],
        )
    }
}

/// Convenience: reserve+commit RW memory in the current process for agent buffers.
///
/// # Safety
/// Delegates to [`weissman_allocate_virtual_memory`]. On Windows the region is live
/// NT-allocated memory the caller must free; on other platforms this always errors.
pub unsafe fn allocate_agent_buffer(size: usize) -> Result<(*mut c_void, usize), u32> {
    let mut base: *mut c_void = std::ptr::null_mut();
    let mut region = size;
    let status = weissman_allocate_virtual_memory(
        dispatch::NT_CURRENT_PROCESS,
        &mut base,
        0,
        &mut region,
        dispatch::MEM_COMMIT | dispatch::MEM_RESERVE,
        dispatch::PAGE_READWRITE,
    );
    if status == dispatch::STATUS_SUCCESS && !base.is_null() {
        Ok((base, region))
    } else {
        Err(status)
    }
}

pub use dispatch::{
    MEM_COMMIT, MEM_RESERVE, NT_CURRENT_PROCESS, PAGE_READWRITE, STATUS_NOT_IMPLEMENTED,
    STATUS_SUCCESS, STATUS_UNSUCCESSFUL,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_syscalls::fixtures::{
        synthetic_ntdll, synthetic_ntdll_header_stomped,
        synthetic_ntdll_headers_and_dllname_stomped, synthetic_ntdll_hooks, FIXTURE_SSN_ALLOCATE,
        FIXTURE_SSN_CLOSE, FIXTURE_SSN_CREATE_SECTION, FIXTURE_SSN_PROTECT, FIXTURE_STUBS_RVA,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn sha256_truncated_hash_is_stable_and_distinct() {
        assert_eq!(
            *NT_ALLOCATE_VIRTUAL_MEMORY,
            hash_api_name("NtAllocateVirtualMemory")
        );
        assert_eq!(*NT_CLOSE, hash_api_name("NtClose"));
        assert_ne!(
            *NT_ALLOCATE_VIRTUAL_MEMORY,
            hash_api_name("ZwAllocateVirtualMemory")
        );
        assert_ne!(
            hash_api_name("NtAllocateVirtualMemory"),
            hash_api_name("NtAllocateVirtualMemoryX")
        );
    }

    #[test]
    fn duplicate_hashes_fail_closed() {
        let a = SyscallEntry {
            hash: 0x1111,
            ssn: 0x18,
            hooked: false,
            rva: 0x400,
        };
        let b = SyscallEntry {
            hash: 0x1111,
            ssn: 0x99,
            hooked: false,
            rva: 0x500,
        };
        let c = SyscallEntry {
            hash: 0x2222,
            ssn: 0x1A,
            hooked: false,
            rva: 0x600,
        };
        let resolver =
            SyscallResolver::from_entries(vec![a, b, c], Vec::new(), 3, 0).expect("keep unique");
        assert!(resolver.resolve_by_hash(0x1111).is_none());
        assert_eq!(resolver.resolve_ssn(0x2222), Some(0x1A));
    }

    #[test]
    fn precomputed_map_covers_agent_targets_only() {
        assert_eq!(TARGET_SYSCALL_NAMES.len(), 5);
        for name in TARGET_SYSCALL_NAMES {
            assert_eq!(precomputed_target_hash(name), Some(hash_api_name(name)));
        }
        assert!(precomputed_target_hash("NtQueryVirtualMemory").is_none());
        assert!(precomputed_target_hash("ZwClose").is_none());
        assert!(precomputed_target_hash("RtlGetVersion").is_none());
        assert_ne!(
            fnv1a_64("NtCreateSection"),
            hash_api_name("NtCreateSection")
        );
        assert_eq!(fnv1a_64("NtClose"), fnv1a_64("NtClose"));
    }

    #[test]
    fn parses_clean_fixture_and_resolves_ssns() {
        let img = synthetic_ntdll(false);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        assert_eq!(resolver.len(), 3);
        assert_eq!(resolver.hooked_count(), 0);
        assert_eq!(resolver.exports_scanned(), 4);
        assert_eq!(resolver.hook_map().len(), 4);
        assert!(resolver
            .hook_map()
            .iter()
            .any(|e| e.fnv == fnv1a_64("NtCreateSection") && !e.hooked));
        assert_eq!(
            resolver.resolve_ssn(fnv1a_64("NtCreateSection")),
            None,
            "FNV hashes must not be used for SSN dispatch"
        );
        assert_eq!(
            resolver.resolve_ssn(*NT_ALLOCATE_VIRTUAL_MEMORY),
            Some(FIXTURE_SSN_ALLOCATE)
        );
        assert_eq!(
            resolver.resolve_ssn(hash_api_name("NtProtectVirtualMemory")),
            Some(FIXTURE_SSN_PROTECT)
        );
        assert_eq!(resolver.resolve_ssn(*NT_CLOSE), Some(FIXTURE_SSN_CLOSE));
    }

    #[test]
    fn halos_gate_recovers_hooked_allocate_ssn() {
        let img = synthetic_ntdll(true);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        let entry = resolver
            .resolve_by_hash(*NT_ALLOCATE_VIRTUAL_MEMORY)
            .expect("allocate");
        assert!(entry.hooked, "JMP hook must be flagged");
        assert_eq!(entry.ssn, FIXTURE_SSN_ALLOCATE);
        assert_eq!(resolver.hooked_count(), 1);
        assert_eq!(resolver.exports_scanned(), 4);
        // Neighbors stay clean.
        let protect = resolver
            .resolve_by_hash(hash_api_name("NtProtectVirtualMemory"))
            .expect("protect");
        assert!(!protect.hooked);
        assert_eq!(protect.ssn, FIXTURE_SSN_PROTECT);
    }

    #[test]
    fn resolve_latency_is_sub_millisecond() {
        let img = synthetic_ntdll(true);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        let start = Instant::now();
        for _ in 0..10_000 {
            let ssn = resolver
                .resolve_ssn(*NT_ALLOCATE_VIRTUAL_MEMORY)
                .expect("ssn");
            assert_eq!(ssn, FIXTURE_SSN_ALLOCATE);
        }
        let elapsed = start.elapsed();
        // 10k hash lookups must stay well under 1 ms on CI; gate at 1 ms for a single lookup
        // by measuring the batch and dividing.
        let per = elapsed / 10_000;
        assert!(
            per < Duration::from_millis(1),
            "per-resolve {per:?} (batch {elapsed:?}) must be sub-millisecond"
        );
        assert!(
            elapsed < Duration::from_millis(50),
            "10k resolves took {elapsed:?}"
        );
    }

    #[test]
    fn full_eat_parse_latency_is_fast() {
        let img = synthetic_ntdll(true);
        let _ = SyscallResolver::from_pe_bytes(&img).expect("warmup");
        let mut samples = Vec::with_capacity(16);
        let mut resolver = None;
        for _ in 0..16 {
            let start = Instant::now();
            resolver = Some(SyscallResolver::from_pe_bytes(&img).expect("resolver"));
            samples.push(start.elapsed());
        }
        samples.sort();
        let median = samples[samples.len() / 2];
        // Same 10 ms CI-noise ceiling as tests/direct_syscall_ci.rs — quiet hosts
        // stay in tens of microseconds; a 1 ms single-sample gate flakes on GHA.
        assert!(
            median < Duration::from_millis(10),
            "synthetic EAT parse median {median:?} (min {:?}, max {:?}), want < 10ms",
            samples[0],
            samples[samples.len() - 1]
        );
        assert_eq!(
            resolver
                .expect("resolver")
                .resolve_ssn(*NT_ALLOCATE_VIRTUAL_MEMORY),
            Some(FIXTURE_SSN_ALLOCATE)
        );
    }

    #[test]
    fn header_stomped_image_still_resolves_via_signature_fallback() {
        let img = synthetic_ntdll_header_stomped(true);
        assert!(
            crate::direct_syscalls::pe::PeView::new(&img).is_none(),
            "stomped DOS/NT headers must fail the PE parser"
        );
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("header-stomp fallback");
        let entry = resolver
            .resolve_by_hash(*NT_ALLOCATE_VIRTUAL_MEMORY)
            .expect("allocate");
        assert!(entry.hooked);
        assert_eq!(entry.ssn, FIXTURE_SSN_ALLOCATE);
        assert_eq!(
            resolver.resolve_ssn(*NT_PROTECT_VIRTUAL_MEMORY),
            Some(FIXTURE_SSN_PROTECT)
        );
        assert_eq!(resolver.resolve_ssn(*NT_CLOSE), Some(FIXTURE_SSN_CLOSE));
        assert_eq!(resolver.hooked_count(), 1);
        assert_eq!(resolver.exports_scanned(), 4);
    }

    #[test]
    fn complete_header_erase_and_dllname_stomp_still_resolves() {
        let img = synthetic_ntdll_headers_and_dllname_stomped(true);
        assert!(crate::direct_syscalls::pe::PeView::new(&img).is_none());
        assert!(crate::direct_syscalls::pe::find_ntdll_export_directory(&img).is_none());
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("API-name EAT recovery");
        assert_eq!(
            resolver.resolve_ssn(*NT_ALLOCATE_VIRTUAL_MEMORY),
            Some(FIXTURE_SSN_ALLOCATE)
        );
        assert!(
            resolver
                .resolve_by_hash(*NT_ALLOCATE_VIRTUAL_MEMORY)
                .expect("alloc")
                .hooked
        );
        assert_eq!(resolver.exports_scanned(), 4);
    }

    #[test]
    fn fnv_hook_map_reports_non_target_eat_hooks() {
        let img = synthetic_ntdll_hooks(false, true);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        assert_eq!(
            resolver.len(),
            3,
            "SHA-256 dispatch table stays the 3 targets"
        );
        assert_eq!(resolver.hooked_count(), 1);
        let create = resolver
            .hook_map()
            .iter()
            .find(|e| e.fnv == fnv1a_64("NtCreateSection"))
            .expect("NtCreateSection in eat map");
        assert!(create.hooked);
        assert_eq!(create.ssn, FIXTURE_SSN_CREATE_SECTION);
        assert!(resolver
            .resolve_by_hash(*NT_ALLOCATE_VIRTUAL_MEMORY)
            .is_some());
        assert!(resolver
            .entries()
            .iter()
            .all(|e| e.hash != fnv1a_64("NtCreateSection")));
    }

    #[test]
    fn header_stomp_halos_gate_ignores_poison_after_eat_stubs() {
        let mut img = synthetic_ntdll_header_stomped(false);
        let close_off = FIXTURE_STUBS_RVA as usize + 2 * crate::direct_syscalls::ssn::STUB_LEN;
        img[close_off..close_off + crate::direct_syscalls::ssn::STUB_LEN]
            .copy_from_slice(&crate::direct_syscalls::ssn::encode_jmp_hook_stub());
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("fallback");
        // Poison stub after .text is SSN 0x99. If Halo's Gate walked it, Close
        // would resolve to 0x98 instead of 0x1A.
        assert_eq!(resolver.resolve_ssn(*NT_CLOSE), Some(FIXTURE_SSN_CLOSE));
        let close = resolver.resolve_by_hash(*NT_CLOSE).expect("close");
        assert!(close.hooked);
        assert_ne!(close.ssn, 0x98);
    }

    #[test]
    fn allocate_on_non_windows_returns_not_implemented() {
        if cfg!(all(windows, target_arch = "x86_64")) {
            return;
        }
        unsafe {
            let mut base = std::ptr::null_mut();
            let mut size = 4096usize;
            let status = weissman_allocate_virtual_memory(
                NT_CURRENT_PROCESS,
                &mut base,
                0,
                &mut size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            );
            assert_eq!(status, STATUS_NOT_IMPLEMENTED);
            assert!(base.is_null());
        }
    }

    #[test]
    fn global_resolver_is_none_off_windows() {
        if !cfg!(all(windows, target_arch = "x86_64")) {
            assert!(global_resolver().is_none());
        }
    }
}
