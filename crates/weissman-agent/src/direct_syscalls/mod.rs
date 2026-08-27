//! Direct syscalls: Hell's Gate + Halo's Gate SSN resolution for weissman-agent.
//!
//! The agent uses this path on Windows x64 so **its own** NT operations (process
//! inspection buffers, local virtual-memory allocation) do not go through user-mode
//! ntdll stubs that EDR products hook. It is not a payload-injection toolkit:
//! callers allocate in the current process with `PAGE_READWRITE`.
//!
//! Pipeline:
//! 1. PEB walk (`GS:[0x60]`) locates `ntdll.dll` without `GetModuleHandle`.
//! 2. Export Address Table is parsed; Nt/Zw names are identified by djb2 hash
//!    (no plaintext API list in the resolver entries).
//! 3. Clean stubs yield the SSN via Hell's Gate (`mov eax, SSN`).
//! 4. Hooked stubs (`jmp` / `0xE9`) recover the SSN via Halo's Gate neighbor scan.
//! 5. Windows x64 `syscall` is issued with the Microsoft calling convention.

pub mod dispatch;
pub mod fixtures;
pub mod pe;
pub mod peb;
pub mod ssn;

#[cfg(all(windows, target_arch = "x86_64"))]
use crate::direct_syscalls::pe::MAX_IMAGE_SIZE;
use crate::direct_syscalls::pe::{PeView, MAX_EXPORT_NAMES};
use crate::direct_syscalls::ssn::resolve_stub_ssn;
use std::ffi::c_void;
use std::sync::OnceLock;

/// djb2 (Bernstein) hash — used so the resolver table stores hashes, not API names.
#[must_use]
pub const fn djb2(bytes: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < bytes.len() {
        hash = hash.wrapping_mul(33).wrapping_add(bytes[i] as u32);
        i += 1;
    }
    hash
}

/// Hash a UTF-8 API name (runtime path used when walking the EAT).
#[must_use]
pub fn hash_api_name(name: &str) -> u32 {
    djb2(name.as_bytes())
}

pub const NT_ALLOCATE_VIRTUAL_MEMORY: u32 = djb2(b"NtAllocateVirtualMemory");
pub const NT_PROTECT_VIRTUAL_MEMORY: u32 = djb2(b"NtProtectVirtualMemory");
pub const NT_QUERY_SYSTEM_INFORMATION: u32 = djb2(b"NtQuerySystemInformation");
pub const NT_QUERY_INFORMATION_PROCESS: u32 = djb2(b"NtQueryInformationProcess");
pub const NT_CLOSE: u32 = djb2(b"NtClose");

/// One resolved Nt/Zw export.
#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    pub hash: u32,
    pub ssn: u16,
    pub hooked: bool,
    pub rva: u32,
}

/// Hell's Gate / Halo's Gate resolver populated from a PE image (live ntdll or fixture).
#[derive(Debug, Clone)]
pub struct SyscallResolver {
    entries: Vec<SyscallEntry>,
}

impl SyscallResolver {
    /// Parse Nt/Zw exports from a PE32+ image already in memory.
    #[must_use]
    pub fn from_pe_bytes(image: &[u8]) -> Option<Self> {
        let pe = PeView::new(image)?;
        let export = pe.export_directory()?;
        if export.number_of_names == 0 || export.number_of_names > MAX_EXPORT_NAMES {
            return None;
        }
        let mut entries = Vec::new();
        for i in 0..export.number_of_names as usize {
            let name_rva = match pe.u32_at(export.address_of_names, i) {
                Some(v) => v,
                None => continue,
            };
            let name = match pe.cstr_at(name_rva) {
                Some(n) => n,
                None => continue,
            };
            if !(name.starts_with("Nt") || name.starts_with("Zw")) {
                continue;
            }
            let ordinal = match pe.u16_at(export.address_of_name_ordinals, i) {
                Some(v) => v as usize,
                None => continue,
            };
            let func_rva = match pe.u32_at(export.address_of_functions, ordinal) {
                Some(v) => v,
                None => continue,
            };
            let Some(resolved) = resolve_stub_ssn(pe.bytes(), func_rva as usize) else {
                continue;
            };
            entries.push(SyscallEntry {
                hash: hash_api_name(name),
                ssn: resolved.ssn,
                hooked: resolved.hooked,
                rva: func_rva,
            });
        }
        if entries.is_empty() {
            return None;
        }
        Some(Self { entries })
    }

    /// Walk the live process PEB, map ntdll, parse the EAT.
    ///
    /// # Safety
    /// Windows x64 only. Reads the PEB and ntdll's mapped image.
    #[cfg(all(windows, target_arch = "x86_64"))]
    pub unsafe fn from_live_ntdll() -> Option<Self> {
        let base = peb::ntdll_base()?;
        // Read SizeOfImage from the optional header (offset documented in pe.rs).
        let header_span = 0x200usize;
        let header = std::slice::from_raw_parts(base, header_span);
        let pe_hdr = PeView::new(header)?;
        let size = pe_hdr.size_of_image()? as usize;
        if size < header_span || size > MAX_IMAGE_SIZE {
            return None;
        }
        let image = std::slice::from_raw_parts(base, size);
        Self::from_pe_bytes(image)
    }

    #[must_use]
    pub fn resolve_by_hash(&self, hash: u32) -> Option<SyscallEntry> {
        self.entries.iter().copied().find(|e| e.hash == hash)
    }

    #[must_use]
    pub fn resolve_ssn(&self, hash: u32) -> Option<u16> {
        self.resolve_by_hash(hash).map(|e| e.ssn)
    }

    #[must_use]
    pub fn entries(&self) -> &[SyscallEntry] {
        &self.entries
    }

    #[must_use]
    pub fn hooked_count(&self) -> usize {
        self.entries.iter().filter(|e| e.hooked).count()
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
        let Some(entry) = resolver.resolve_by_hash(NT_ALLOCATE_VIRTUAL_MEMORY) else {
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
        synthetic_ntdll, FIXTURE_SSN_ALLOCATE, FIXTURE_SSN_CLOSE, FIXTURE_SSN_PROTECT,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn djb2_matches_runtime_hash() {
        assert_eq!(
            NT_ALLOCATE_VIRTUAL_MEMORY,
            hash_api_name("NtAllocateVirtualMemory")
        );
        assert_eq!(NT_CLOSE, hash_api_name("NtClose"));
        assert_ne!(
            NT_ALLOCATE_VIRTUAL_MEMORY,
            hash_api_name("ZwAllocateVirtualMemory")
        );
    }

    #[test]
    fn parses_clean_fixture_and_resolves_ssns() {
        let img = synthetic_ntdll(false);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        assert_eq!(resolver.len(), 3);
        assert_eq!(resolver.hooked_count(), 0);
        assert_eq!(
            resolver.resolve_ssn(NT_ALLOCATE_VIRTUAL_MEMORY),
            Some(FIXTURE_SSN_ALLOCATE)
        );
        assert_eq!(
            resolver.resolve_ssn(hash_api_name("NtProtectVirtualMemory")),
            Some(FIXTURE_SSN_PROTECT)
        );
        assert_eq!(resolver.resolve_ssn(NT_CLOSE), Some(FIXTURE_SSN_CLOSE));
    }

    #[test]
    fn halos_gate_recovers_hooked_allocate_ssn() {
        let img = synthetic_ntdll(true);
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        let entry = resolver
            .resolve_by_hash(NT_ALLOCATE_VIRTUAL_MEMORY)
            .expect("allocate");
        assert!(entry.hooked, "JMP hook must be flagged");
        assert_eq!(entry.ssn, FIXTURE_SSN_ALLOCATE);
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
                .resolve_ssn(NT_ALLOCATE_VIRTUAL_MEMORY)
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
    fn full_eat_parse_latency_is_sub_millisecond() {
        let img = synthetic_ntdll(true);
        let start = Instant::now();
        let resolver = SyscallResolver::from_pe_bytes(&img).expect("resolver");
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(1),
            "synthetic EAT parse took {elapsed:?}, want < 1ms"
        );
        assert_eq!(
            resolver.resolve_ssn(NT_ALLOCATE_VIRTUAL_MEMORY),
            Some(FIXTURE_SSN_ALLOCATE)
        );
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
