//! Minimal PE32+ view used to walk ntdll's Export Address Table without Win32 APIs.
//!
//! All reads are bounds-checked against the supplied image slice. Live ntdll is mapped
//! into this view after reading `SizeOfImage` from the optional header.

#![allow(non_camel_case_types, non_snake_case, dead_code)]

use std::mem;

pub const DOS_MAGIC: u16 = 0x5A4D; // MZ
pub const NT_SIGNATURE: u32 = 0x0000_4550; // PE\0\0
pub const OPTIONAL_MAGIC_PE32PLUS: u16 = 0x20B;
pub const DIR_EXPORT: usize = 0;
pub const MAX_IMAGE_SIZE: usize = 16 * 1024 * 1024;
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
        Some(IMAGE_EXPORT_DIRECTORY {
            characteristics: read_u32(self.bytes, va)?,
            time_date_stamp: read_u32(self.bytes, va + 4)?,
            major_version: read_u16(self.bytes, va + 8)?,
            minor_version: read_u16(self.bytes, va + 10)?,
            name: read_u32(self.bytes, va + 12)?,
            base: read_u32(self.bytes, va + 16)?,
            number_of_functions: read_u32(self.bytes, va + 20)?,
            number_of_names: read_u32(self.bytes, va + 24)?,
            address_of_functions: read_u32(self.bytes, va + 28)?,
            address_of_names: read_u32(self.bytes, va + 32)?,
            address_of_name_ordinals: read_u32(self.bytes, va + 36)?,
        })
    }

    pub fn cstr_at(&self, rva: u32) -> Option<&str> {
        let start = rva as usize;
        if start >= self.bytes.len() {
            return None;
        }
        let window = &self.bytes[start..self.bytes.len().min(start + MAX_NAME_LEN)];
        let end = window.iter().position(|&b| b == 0)?;
        std::str::from_utf8(&window[..end]).ok()
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
}
