//! Minimal PE32+ view used to walk ntdll's Export Address Table without Win32 APIs.
//!
//! All reads are bounds-checked against the supplied image slice. Live ntdll is
//! sized from the PEB loader (`SizeOfImage` at LDR +0x40), not the optional header,
//! so PE header stomping cannot shrink the mapping.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::mem;

pub const DOS_MAGIC: u16 = 0x5A4D; // MZ
pub const NT_SIGNATURE: u32 = 0x0000_4550; // PE\0\0
pub const OPTIONAL_MAGIC_PE32PLUS: u16 = 0x20B;
pub const DIR_EXPORT: usize = 0;
pub const MAX_IMAGE_SIZE: usize = 16 * 1024 * 1024;
/// Hard ceiling for ntdll copy + signature scan. LDR SizeOfImage above this
/// is treated as EDR memory bloating — we never walk tens of GiB.
pub const MAX_NTDLL_SCAN_LIMIT: usize = MAX_IMAGE_SIZE;
pub const MAX_EXPORT_NAMES: u32 = 16_384;
pub const MAX_NAME_LEN: usize = 256;
pub const MAX_SECTIONS: u16 = 96;
pub const IMAGE_SIZEOF_SECTION_HEADER: usize = 40;
pub const IMAGE_SCN_CNT_CODE: u32 = 0x0000_0020;
pub const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Inclusive-start / exclusive-end RVA window of ntdll `.text`.
/// Halo's Gate neighbor walks must stay strictly inside this span.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextSpan {
    pub rva_start: usize,
    pub rva_end: usize,
}

impl TextSpan {
    /// True when `[rva, rva+len)` lies entirely inside `.text` (no wrap, no overshoot).
    #[must_use]
    pub fn contains_bytes(&self, rva: usize, len: usize) -> bool {
        let Some(end) = rva.checked_add(len) else {
            return false;
        };
        rva >= self.rva_start && end <= self.rva_end
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_SECTION_HEADER {
    pub name: [u8; 8],
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub size_of_raw_data: u32,
    pub pointer_to_raw_data: u32,
    pub pointer_to_relocations: u32,
    pub pointer_to_linenumbers: u32,
    pub number_of_relocations: u16,
    pub number_of_linenumbers: u16,
    pub characteristics: u32,
}

/// One PE section after bounds-checked parse.
#[derive(Debug, Clone, Copy)]
pub struct Section {
    pub name: [u8; 8],
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub characteristics: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: u16,
    pub e_cblp: u16,
    pub e_cp: u16,
    pub e_crlc: u16,
    pub e_cparhdr: u16,
    pub e_minalloc: u16,
    pub e_maxalloc: u16,
    pub e_ss: u16,
    pub e_sp: u16,
    pub e_csum: u16,
    pub e_ip: u16,
    pub e_cs: u16,
    pub e_lfarlc: u16,
    pub e_ovno: u16,
    pub e_res: [u16; 4],
    pub e_oemid: u16,
    pub e_oeminfo: u16,
    pub e_res2: [u16; 10],
    pub e_lfanew: i32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_FILE_HEADER {
    pub machine: u16,
    pub number_of_sections: u16,
    pub time_date_stamp: u32,
    pub pointer_to_symbol_table: u32,
    pub number_of_symbols: u32,
    pub size_of_optional_header: u16,
    pub characteristics: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub virtual_address: u32,
    pub size: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub magic: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub size_of_code: u32,
    pub size_of_initialized_data: u32,
    pub size_of_uninitialized_data: u32,
    pub address_of_entry_point: u32,
    pub base_of_code: u32,
    pub image_base: u64,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub major_operating_system_version: u16,
    pub minor_operating_system_version: u16,
    pub major_image_version: u16,
    pub minor_image_version: u16,
    pub major_subsystem_version: u16,
    pub minor_subsystem_version: u16,
    pub win32_version_value: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub check_sum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub size_of_stack_reserve: u64,
    pub size_of_stack_commit: u64,
    pub size_of_heap_reserve: u64,
    pub size_of_heap_commit: u64,
    pub loader_flags: u32,
    pub number_of_rva_and_sizes: u32,
    pub data_directory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_NT_HEADERS64 {
    pub signature: u32,
    pub file_header: IMAGE_FILE_HEADER,
    pub optional_header: IMAGE_OPTIONAL_HEADER64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub characteristics: u32,
    pub time_date_stamp: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub name: u32,
    pub base: u32,
    pub number_of_functions: u32,
    pub number_of_names: u32,
    pub address_of_functions: u32,
    pub address_of_names: u32,
    pub address_of_name_ordinals: u32,
}

/// Bounds-checked view over a PE32+ image in memory.
#[derive(Clone, Copy)]
pub struct PeView<'a> {
    bytes: &'a [u8],
}

impl<'a> PeView<'a> {
    pub fn new(bytes: &'a [u8]) -> Option<Self> {
        if bytes.len() < mem::size_of::<IMAGE_DOS_HEADER>() {
            return None;
        }
        let magic = read_u16(bytes, 0)?;
        if magic != DOS_MAGIC {
            return None;
        }
        let e_lfanew = read_i32(bytes, 0x3C)? as usize;
        if e_lfanew
            .checked_add(mem::size_of::<IMAGE_NT_HEADERS64>())
            .filter(|end| *end <= bytes.len())
            .is_none()
        {
            return None;
        }
        let sig = read_u32(bytes, e_lfanew)?;
        if sig != NT_SIGNATURE {
            return None;
        }
        let opt_off = e_lfanew + 4 + mem::size_of::<IMAGE_FILE_HEADER>();
        let magic = read_u16(bytes, opt_off)?;
        if magic != OPTIONAL_MAGIC_PE32PLUS {
            return None;
        }
        Some(Self { bytes })
    }

    pub fn size_of_image(&self) -> Option<u32> {
        let e_lfanew = read_i32(self.bytes, 0x3C)? as usize;
        let opt_off = e_lfanew + 4 + mem::size_of::<IMAGE_FILE_HEADER>();
        // IMAGE_OPTIONAL_HEADER64.size_of_image is at offset 56.
        read_u32(self.bytes, opt_off + 56)
    }

    pub fn size_of_headers(&self) -> Option<u32> {
        let e_lfanew = read_i32(self.bytes, 0x3C)? as usize;
        let opt_off = e_lfanew + 4 + mem::size_of::<IMAGE_FILE_HEADER>();
        // IMAGE_OPTIONAL_HEADER64.size_of_headers is at offset 60.
        read_u32(self.bytes, opt_off + 60)
    }

    fn section_table_offset(&self) -> Option<(usize, u16)> {
        let e_lfanew = read_i32(self.bytes, 0x3C)? as usize;
        let file_hdr = e_lfanew + 4;
        let number_of_sections = read_u16(self.bytes, file_hdr + 2)?;
        if number_of_sections == 0 || number_of_sections > MAX_SECTIONS {
            return None;
        }
        let size_of_optional_header = read_u16(self.bytes, file_hdr + 16)? as usize;
        let table = file_hdr
            .checked_add(mem::size_of::<IMAGE_FILE_HEADER>())?
            .checked_add(size_of_optional_header)?;
        Some((table, number_of_sections))
    }

    /// Bounds-checked section table. Used to locate `.text` and to copy live
    /// ntdll without reading unmapped gaps between sections.
    pub fn sections(&self) -> Option<Vec<Section>> {
        let (table, nsec) = self.section_table_offset()?;
        let mut out = Vec::with_capacity(nsec as usize);
        for i in 0..nsec as usize {
            let off = table.checked_add(i.checked_mul(IMAGE_SIZEOF_SECTION_HEADER)?)?;
            if off.checked_add(IMAGE_SIZEOF_SECTION_HEADER)? > self.bytes.len() {
                return None;
            }
            let mut name = [0u8; 8];
            name.copy_from_slice(self.bytes.get(off..off + 8)?);
            out.push(Section {
                name,
                virtual_size: read_u32(self.bytes, off + 8)?,
                virtual_address: read_u32(self.bytes, off + 12)?,
                characteristics: read_u32(self.bytes, off + 36)?,
            });
        }
        Some(out)
    }

    /// `.text` RVA window from PE headers. Prefers the named `.text` section;
    /// falls back to the first executable/code section. `None` if the image
    /// has no usable code section — callers must fail closed (no Halo's Gate).
    pub fn text_section_span(&self) -> Option<TextSpan> {
        let sections = self.sections()?;
        let chosen = sections
            .iter()
            .find(|s| section_name_is(s.name, b".text"))
            .or_else(|| {
                sections
                    .iter()
                    .find(|s| s.characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE) != 0)
            })?;
        let start = chosen.virtual_address as usize;
        let size = chosen.virtual_size as usize;
        if size == 0 {
            return None;
        }
        let end = start.checked_add(size)?;
        let end = end.min(self.bytes.len());
        if start >= end || start >= self.bytes.len() {
            return None;
        }
        Some(TextSpan {
            rva_start: start,
            rva_end: end,
        })
    }

    pub fn export_directory(&self) -> Option<IMAGE_EXPORT_DIRECTORY> {
        let e_lfanew = read_i32(self.bytes, 0x3C)? as usize;
        let opt_off = e_lfanew + 4 + mem::size_of::<IMAGE_FILE_HEADER>();
        // data_directory[0] starts at optional-header offset 112.
        let dir_off = opt_off + 112;
        let va = read_u32(self.bytes, dir_off)? as usize;
        let size = read_u32(self.bytes, dir_off + 4)? as usize;
        if va == 0 || size < mem::size_of::<IMAGE_EXPORT_DIRECTORY>() {
            return None;
        }
        Some(read_export_directory(self.bytes, va)?)
    }

    /// Header-agnostic view. Used when DOS/NT headers were stomped but `.rdata`
    /// (EAT) and `.text` (stubs) are still mapped.
    #[must_use]
    pub fn raw(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }

    pub fn cstr_at(&self, rva: u32) -> Option<&str> {
        cstr_at_bytes(self.bytes, rva)
    }

    pub fn u32_at(&self, rva: u32, index: usize) -> Option<u32> {
        let off = (rva as usize).checked_add(index.checked_mul(4)?)?;
        read_u32(self.bytes, off)
    }

    pub fn u16_at(&self, rva: u32, index: usize) -> Option<u16> {
        let off = (rva as usize).checked_add(index.checked_mul(2)?)?;
        read_u16(self.bytes, off)
    }

    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

pub fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let slice = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes([slice[0], slice[1]]))
}

pub fn read_u32(buf: &[u8], off: usize) -> Option<u32> {
    let slice = buf.get(off..off + 4)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub fn read_i32(buf: &[u8], off: usize) -> Option<i32> {
    Some(read_u32(buf, off)? as i32)
}

pub fn cstr_at_bytes(buf: &[u8], rva: u32) -> Option<&str> {
    let start = rva as usize;
    if start >= buf.len() {
        return None;
    }
    let window = &buf[start..buf.len().min(start + MAX_NAME_LEN)];
    let end = window.iter().position(|&b| b == 0)?;
    std::str::from_utf8(&window[..end]).ok()
}

pub fn read_export_directory(buf: &[u8], va: usize) -> Option<IMAGE_EXPORT_DIRECTORY> {
    if va
        .checked_add(mem::size_of::<IMAGE_EXPORT_DIRECTORY>())
        .filter(|end| *end <= buf.len())
        .is_none()
    {
        return None;
    }
    Some(IMAGE_EXPORT_DIRECTORY {
        characteristics: read_u32(buf, va)?,
        time_date_stamp: read_u32(buf, va + 4)?,
        major_version: read_u16(buf, va + 8)?,
        minor_version: read_u16(buf, va + 10)?,
        name: read_u32(buf, va + 12)?,
        base: read_u32(buf, va + 16)?,
        number_of_functions: read_u32(buf, va + 20)?,
        number_of_names: read_u32(buf, va + 24)?,
        address_of_functions: read_u32(buf, va + 28)?,
        address_of_names: read_u32(buf, va + 32)?,
        address_of_name_ordinals: read_u32(buf, va + 36)?,
    })
}

fn export_dir_plausible(buf: &[u8], dir: &IMAGE_EXPORT_DIRECTORY) -> bool {
    if dir.number_of_names == 0 || dir.number_of_names > MAX_EXPORT_NAMES {
        return false;
    }
    if dir.number_of_functions < dir.number_of_names {
        return false;
    }
    let names = dir.address_of_names as usize;
    let funcs = dir.address_of_functions as usize;
    let ords = dir.address_of_name_ordinals as usize;
    let names_end = names.saturating_add((dir.number_of_names as usize).saturating_mul(4));
    let funcs_end = funcs.saturating_add((dir.number_of_functions as usize).saturating_mul(4));
    let ords_end = ords.saturating_add((dir.number_of_names as usize).saturating_mul(2));
    names_end <= buf.len() && funcs_end <= buf.len() && ords_end <= buf.len()
}

/// Recover ntdll's export directory without PE headers.
///
/// Complete header erasure (first 1024 bytes zeroed) deletes the data directory
/// RVA. This scanner locates `IMAGE_EXPORT_DIRECTORY` from the names table:
/// find a critical Nt* string, then the directory whose `AddressOfNames` slot
/// points at it. `"ntdll.dll"` is a secondary signal if the API strings moved.
/// Never scans past [`MAX_NTDLL_SCAN_LIMIT`].
pub fn recover_ntdll_export_directory(buf: &[u8]) -> Option<IMAGE_EXPORT_DIRECTORY> {
    let buf = scan_window(buf);
    const API_NEEDLES: [&[u8]; 3] = [
        b"NtAllocateVirtualMemory",
        b"NtProtectVirtualMemory",
        b"NtClose",
    ];
    for needle in API_NEEDLES {
        if let Some(dir) = find_export_directory_by_api_name(buf, needle) {
            return Some(dir);
        }
    }
    find_ntdll_export_directory(buf)
}

fn scan_window(buf: &[u8]) -> &[u8] {
    let n = buf.len().min(MAX_NTDLL_SCAN_LIMIT);
    &buf[..n]
}

/// Locate an export directory whose names table contains `api` (NUL-terminated).
pub fn find_export_directory_by_api_name(buf: &[u8], api: &[u8]) -> Option<IMAGE_EXPORT_DIRECTORY> {
    if api.is_empty() {
        return None;
    }
    let mut search_from = 0usize;
    while search_from + api.len() < buf.len() {
        let rest = &buf[search_from..];
        let Some(rel) = rest.windows(api.len()).position(|w| w == api) else {
            break;
        };
        let name_off = search_from + rel;
        let terminated = buf.get(name_off + api.len()) == Some(&0);
        let token_start = name_off == 0 || buf.get(name_off - 1) == Some(&0);
        if !terminated || !token_start {
            search_from = name_off + 1;
            continue;
        }
        let name_rva = name_off as u32;
        let name_le = name_rva.to_le_bytes();
        let mut slot = 0usize;
        while slot + 4 <= buf.len() {
            if buf.get(slot..slot + 4) == Some(&name_le[..]) {
                if let Some(dir) = dir_from_names_slot(buf, slot) {
                    return Some(dir);
                }
            }
            slot = match slot.checked_add(4) {
                Some(v) => v,
                None => break,
            };
        }
        search_from = name_off + 1;
    }
    None
}

/// Given one AddressOfNames slot, find the `IMAGE_EXPORT_DIRECTORY` whose
/// `address_of_names` field points at that table. The table is a separate RVA
/// (not packed at directory+32), so we match the pointer field, then validate.
fn dir_from_names_slot(buf: &[u8], slot_off: usize) -> Option<IMAGE_EXPORT_DIRECTORY> {
    const ADDR_OF_NAMES_OFF: usize = 32;
    let max = buf
        .len()
        .saturating_sub(mem::size_of::<IMAGE_EXPORT_DIRECTORY>());
    let mut field = ADDR_OF_NAMES_OFF;
    while field <= max + ADDR_OF_NAMES_OFF && field + 4 <= buf.len() {
        let Some(names_base) = read_u32(buf, field).map(|v| v as usize) else {
            field = match field.checked_add(4) {
                Some(v) => v,
                None => break,
            };
            continue;
        };
        if names_base <= slot_off && (slot_off - names_base).is_multiple_of(4) {
            let idx = (slot_off - names_base) / 4;
            let Some(dir_off) = field.checked_sub(ADDR_OF_NAMES_OFF) else {
                field = match field.checked_add(4) {
                    Some(v) => v,
                    None => break,
                };
                continue;
            };
            if let Some(dir) = read_export_directory(buf, dir_off) {
                if dir.address_of_names as usize == names_base
                    && idx < dir.number_of_names as usize
                    && export_dir_plausible(buf, &dir)
                {
                    return Some(dir);
                }
            }
        }
        field = match field.checked_add(4) {
            Some(v) => v,
            None => break,
        };
    }
    None
}

/// Locate ntdll's export directory by finding the `"ntdll.dll"` name string,
/// then the `IMAGE_EXPORT_DIRECTORY` whose `name` RVA points at it.
/// Survives PE header stomping: DOS/NT headers may be zeroed while `.rdata`
/// still holds the EAT.
pub fn find_ntdll_export_directory(buf: &[u8]) -> Option<IMAGE_EXPORT_DIRECTORY> {
    const NEEDLE: &[u8] = b"ntdll.dll";
    let mut search_from = 0usize;
    while search_from + NEEDLE.len() < buf.len() {
        let rest = &buf[search_from..];
        let Some(rel) = rest
            .windows(NEEDLE.len())
            .position(|w| w.eq_ignore_ascii_case(NEEDLE))
        else {
            break;
        };
        let name_off = search_from + rel;
        if buf.get(name_off + NEEDLE.len()) != Some(&0) {
            search_from = name_off + 1;
            continue;
        }
        let name_rva = name_off as u32;
        let name_le = name_rva.to_le_bytes();
        let max = buf
            .len()
            .saturating_sub(mem::size_of::<IMAGE_EXPORT_DIRECTORY>());
        let mut off = 0usize;
        while off <= max {
            if buf.get(off + 12..off + 16) == Some(&name_le[..]) {
                if let Some(dir) = read_export_directory(buf, off) {
                    if dir.name == name_rva && export_dir_plausible(buf, &dir) {
                        return Some(dir);
                    }
                }
            }
            off = match off.checked_add(4) {
                Some(v) => v,
                None => break,
            };
        }
        search_from = name_off + 1;
    }
    None
}

fn section_name_is(name: [u8; 8], want: &[u8]) -> bool {
    if want.len() > 8 {
        return false;
    }
    name[..want.len()] == *want && name[want.len()..].iter().all(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn win32_header_sizes_match_spec() {
        assert_eq!(mem::size_of::<IMAGE_DOS_HEADER>(), 64);
        assert_eq!(mem::size_of::<IMAGE_FILE_HEADER>(), 20);
        assert_eq!(mem::size_of::<IMAGE_OPTIONAL_HEADER64>(), 240);
        assert_eq!(mem::size_of::<IMAGE_NT_HEADERS64>(), 264);
        assert_eq!(mem::size_of::<IMAGE_EXPORT_DIRECTORY>(), 40);
        assert_eq!(mem::size_of::<IMAGE_DATA_DIRECTORY>(), 8);
        assert_eq!(
            mem::size_of::<IMAGE_SECTION_HEADER>(),
            IMAGE_SIZEOF_SECTION_HEADER
        );
    }

    #[test]
    fn text_span_rejects_overshoot() {
        let span = TextSpan {
            rva_start: 0x400,
            rva_end: 0x460,
        };
        assert!(span.contains_bytes(0x400, 8));
        assert!(span.contains_bytes(0x458, 8));
        assert!(!span.contains_bytes(0x45C, 8)); // would cross .text end
        assert!(!span.contains_bytes(0x3E0, 8)); // before .text
        assert!(!span.contains_bytes(0x460, 8));
        assert!(!span.contains_bytes(usize::MAX, 1));
    }

    #[test]
    fn stomped_headers_recover_eat_via_ntdll_name() {
        let img = crate::direct_syscalls::fixtures::synthetic_ntdll_header_stomped(false);
        assert!(PeView::new(&img).is_none(), "DOS/NT headers must be gone");
        let eat = find_ntdll_export_directory(&img).expect("EAT via ntdll.dll name");
        assert_eq!(eat.number_of_names, 4);
        assert_eq!(cstr_at_bytes(&img, eat.name), Some("ntdll.dll"));
    }

    #[test]
    fn complete_header_erase_recovers_eat_via_api_name_chain() {
        let img = crate::direct_syscalls::fixtures::synthetic_ntdll_complete_header_erase(false);
        assert!(PeView::new(&img).is_none());
        assert!(
            img[..0x400].iter().all(|&b| b == 0),
            "first 1024 bytes must be gone"
        );
        let eat = find_export_directory_by_api_name(&img, b"NtAllocateVirtualMemory")
            .expect("EAT via NtAllocateVirtualMemory names chain (not ntdll.dll fallback)");
        assert_eq!(eat.number_of_names, 4);
        let name0 = cstr_at_bytes(&img, read_u32(&img, eat.address_of_names as usize).unwrap());
        assert_eq!(name0, Some("NtAllocateVirtualMemory"));
    }

    #[test]
    fn dll_name_stomp_still_recovers_eat_via_nt_allocate() {
        let img =
            crate::direct_syscalls::fixtures::synthetic_ntdll_headers_and_dllname_stomped(false);
        assert!(find_ntdll_export_directory(&img).is_none());
        let eat = find_export_directory_by_api_name(&img, b"NtAllocateVirtualMemory")
            .expect("API-name signature scan");
        assert_eq!(eat.number_of_names, 4);
    }
}
