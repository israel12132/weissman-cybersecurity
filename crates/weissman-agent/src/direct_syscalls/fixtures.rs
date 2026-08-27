//! In-memory PE32+ fixture that mimics ntdll's Export Address Table + syscall stubs.
//! Used by CI on Linux (no PEB / no ntdll) to exercise Hell's Gate and Halo's Gate.

use super::pe::{
    DOS_MAGIC, IMAGE_DATA_DIRECTORY, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY, IMAGE_FILE_HEADER,
    IMAGE_NT_HEADERS64, IMAGE_OPTIONAL_HEADER64, NT_SIGNATURE, OPTIONAL_MAGIC_PE32PLUS,
};
use super::ssn::{encode_clean_stub, encode_jmp_hook_stub, STUB_LEN};

const E_LFANEW: usize = 0x80;
const EXPORT_RVA: u32 = 0x200;
const FUNCS_RVA: u32 = 0x2C0;
const NAMES_RVA: u32 = 0x2E0;
const ORDS_RVA: u32 = 0x2F0;
const STRINGS_RVA: u32 = 0x300;
const STUBS_RVA: u32 = 0x400;
const IMAGE_SIZE: usize = 0x800;

const EXPORTS: &[&str] = &[
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtClose",
];

/// Base SSNs laid out in stub order (adjacent stubs differ by 1 — Halo's Gate invariant).
pub const FIXTURE_SSN_ALLOCATE: u16 = 0x18;
pub const FIXTURE_SSN_PROTECT: u16 = 0x19;
pub const FIXTURE_SSN_CLOSE: u16 = 0x1A;

/// Build a compact PE32+ image with three Nt* exports.
///
/// When `hook_allocate` is true, `NtAllocateVirtualMemory`'s stub is overwritten with
/// `jmp rel32` so Halo's Gate must recover SSN `0x18` from the neighbor.
pub fn synthetic_ntdll(hook_allocate: bool) -> Vec<u8> {
    let mut buf = vec![0u8; IMAGE_SIZE];

    let dos = IMAGE_DOS_HEADER {
        e_magic: DOS_MAGIC,
        e_cblp: 0,
        e_cp: 0,
        e_crlc: 0,
        e_cparhdr: 0,
        e_minalloc: 0,
        e_maxalloc: 0,
        e_ss: 0,
        e_sp: 0,
        e_csum: 0,
        e_ip: 0,
        e_cs: 0,
        e_lfarlc: 0,
        e_ovno: 0,
        e_res: [0; 4],
        e_oemid: 0,
        e_oeminfo: 0,
        e_res2: [0; 10],
        e_lfanew: E_LFANEW as i32,
    };
    write_val(&mut buf, 0, dos);

    let mut data_directory = [IMAGE_DATA_DIRECTORY {
        virtual_address: 0,
        size: 0,
    }; 16];
    data_directory[0] = IMAGE_DATA_DIRECTORY {
        virtual_address: EXPORT_RVA,
        size: 40,
    };

    let nt = IMAGE_NT_HEADERS64 {
        signature: NT_SIGNATURE,
        file_header: IMAGE_FILE_HEADER {
            machine: 0x8664,
            number_of_sections: 0,
            time_date_stamp: 0,
            pointer_to_symbol_table: 0,
            number_of_symbols: 0,
            size_of_optional_header: 240,
            characteristics: 0x2000, // IMAGE_FILE_DLL
        },
        optional_header: IMAGE_OPTIONAL_HEADER64 {
            magic: OPTIONAL_MAGIC_PE32PLUS,
            major_linker_version: 0,
            minor_linker_version: 0,
            size_of_code: 0,
            size_of_initialized_data: 0,
            size_of_uninitialized_data: 0,
            address_of_entry_point: 0,
            base_of_code: 0,
            image_base: 0x1800_0000_0000,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            major_operating_system_version: 10,
            minor_operating_system_version: 0,
            major_image_version: 0,
            minor_image_version: 0,
            major_subsystem_version: 10,
            minor_subsystem_version: 0,
            win32_version_value: 0,
            size_of_image: IMAGE_SIZE as u32,
            size_of_headers: 0x200,
            check_sum: 0,
            subsystem: 3,
            dll_characteristics: 0,
            size_of_stack_reserve: 0,
            size_of_stack_commit: 0,
            size_of_heap_reserve: 0,
            size_of_heap_commit: 0,
            loader_flags: 0,
            number_of_rva_and_sizes: 16,
            data_directory,
        },
    };
    write_val(&mut buf, E_LFANEW, nt);

    let export = IMAGE_EXPORT_DIRECTORY {
        characteristics: 0,
        time_date_stamp: 0,
        major_version: 0,
        minor_version: 0,
        name: STRINGS_RVA,
        base: 1,
        number_of_functions: EXPORTS.len() as u32,
        number_of_names: EXPORTS.len() as u32,
        address_of_functions: FUNCS_RVA,
        address_of_names: NAMES_RVA,
        address_of_name_ordinals: ORDS_RVA,
    };
    write_val(&mut buf, EXPORT_RVA as usize, export);

    // DLL name
    write_cstr(&mut buf, STRINGS_RVA as usize, "ntdll.dll");
    let mut str_cur = STRINGS_RVA as usize + 16;

    for (i, name) in EXPORTS.iter().enumerate() {
        let stub_rva = STUBS_RVA + (i as u32) * (STUB_LEN as u32);
        write_u32(&mut buf, FUNCS_RVA as usize + i * 4, stub_rva);
        write_u32(&mut buf, NAMES_RVA as usize + i * 4, str_cur as u32);
        write_u16(&mut buf, ORDS_RVA as usize + i * 2, i as u16);
        write_cstr(&mut buf, str_cur, name);
        str_cur += name.len() + 1;

        let ssn = FIXTURE_SSN_ALLOCATE + i as u16;
        let stub = if hook_allocate && i == 0 {
            encode_jmp_hook_stub()
        } else {
            encode_clean_stub(ssn)
        };
        let start = stub_rva as usize;
        buf[start..start + STUB_LEN].copy_from_slice(&stub);
    }

    buf
}

fn write_val<T: Copy>(buf: &mut [u8], off: usize, val: T) {
    let size = std::mem::size_of::<T>();
    // SAFETY: T is a #[repr(C)] Copy header; we read its object representation as bytes.
    let bytes = unsafe { std::slice::from_raw_parts((&val as *const T).cast::<u8>(), size) };
    buf[off..off + size].copy_from_slice(bytes);
}

fn write_u16(buf: &mut [u8], off: usize, v: u16) {
    buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

fn write_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn write_cstr(buf: &mut [u8], off: usize, s: &str) {
    buf[off..off + s.len()].copy_from_slice(s.as_bytes());
    buf[off + s.len()] = 0;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direct_syscalls::pe::PeView;

    #[test]
    fn fixture_parses_as_pe32_plus() {
        let img = synthetic_ntdll(false);
        let pe = PeView::new(&img).expect("PE view");
        let exp = pe.export_directory().expect("export dir");
        assert_eq!(exp.number_of_names, 3);
        assert_eq!(pe.cstr_at(exp.name), Some("ntdll.dll"));
        assert_eq!(
            pe.cstr_at(pe.u32_at(exp.address_of_names, 0).unwrap()),
            Some("NtAllocateVirtualMemory")
        );
    }
}
