//! PEB walk — locate ntdll.dll base without calling GetModuleHandle / Ldr*.
//!
//! Windows x64: `GS:[0x60]` is the PEB. `PEB.Ldr.InLoadOrderModuleList` is a
//! circular doubly-linked list of `LDR_DATA_TABLE_ENTRY` records.

#![allow(dead_code)]

/// Maximum modules walked before aborting (circular-list guard).
const MAX_MODULES: usize = 256;

/// Return the in-memory base of `ntdll.dll`, or `None` if the walk fails.
///
/// # Safety
/// Caller must run on Windows x64. The PEB and loader lists are process-lifetime
/// kernel structures; we only read them.
#[cfg(all(windows, target_arch = "x86_64"))]
pub unsafe fn ntdll_base() -> Option<*const u8> {
    use std::arch::asm;

    let peb: *const u8;
    asm!(
        "mov {}, gs:[0x60]",
        out(reg) peb,
        options(nostack, preserves_flags, readonly),
    );
    if peb.is_null() {
        return None;
    }

    // PEB.Ldr at +0x18
    let ldr = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() {
        return None;
    }

    // PEB_LDR_DATA.InLoadOrderModuleList at +0x10 (LIST_ENTRY head)
    let list_head = ldr.add(0x10);
    let mut current = *(list_head as *const *const u8);
    let head = list_head;

    for _ in 0..MAX_MODULES {
        if current.is_null() || current == head {
            break;
        }
        // LDR_DATA_TABLE_ENTRY.BaseDllName UNICODE_STRING at +0x58
        //   Length: u16 at +0x58
        //   Buffer: PWSTR at +0x60
        let name_len_bytes = *(current.add(0x58) as *const u16) as usize;
        let name_buf = *(current.add(0x60) as *const *const u16);
        if !name_buf.is_null() && name_len_bytes >= 2 {
            let n_chars = (name_len_bytes / 2).min(64);
            let name = std::slice::from_raw_parts(name_buf, n_chars);
            if utf16_eq_ignore_ascii_case(name, "ntdll.dll") {
                let dll_base = *(current.add(0x30) as *const *const u8);
                if !dll_base.is_null() {
                    return Some(dll_base);
                }
            }
        }
        current = *(current as *const *const u8); // InLoadOrderLinks.Flink
    }
    None
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub unsafe fn ntdll_base() -> Option<*const u8> {
    None
}

fn utf16_eq_ignore_ascii_case(a: &[u16], b: &str) -> bool {
    let mut b_iter = b.encode_utf16();
    for &x in a {
        match b_iter.next() {
            Some(y) => {
                let xl = ascii_lower_u16(x);
                let yl = ascii_lower_u16(y);
                if xl != yl {
                    return false;
                }
            }
            None => return false,
        }
    }
    b_iter.next().is_none()
}

fn ascii_lower_u16(c: u16) -> u16 {
    if c < 128 {
        u16::from((c as u8).to_ascii_lowercase())
    } else {
        c
    }
}

#[cfg(test)]
mod tests {
    use super::utf16_eq_ignore_ascii_case;

    #[test]
    fn ntdll_name_matches_case_insensitive() {
        let name: Vec<u16> = "NtDll.DLL".encode_utf16().collect();
        assert!(utf16_eq_ignore_ascii_case(&name, "ntdll.dll"));
        assert!(!utf16_eq_ignore_ascii_case(&name, "kernel32.dll"));
    }
}
