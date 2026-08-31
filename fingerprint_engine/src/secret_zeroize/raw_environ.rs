//! Read vault-key bytes from the OS environment block — never `std::env::var` / `var_os`.
//!
//! `std::env::var_os` allocates an `OsString` on the process heap before the caller
//! can pin the bytes. Those pages are not zeroized when the `OsString` is dropped.
//! Walking `libc::environ` (Linux/Unix) or `GetEnvironmentStringsW` (Windows) copies
//! the value **directly** into [`super::LockedBytes`].
//!
//! This module is **read-only**. Mutating the shared `environ` C-strings and then
//! calling `remove_var` desynchronizes libc's allocator-owned map (UB / SIGSEGV).
//! Scrub is [`std::env::remove_var`] in [`super::scrub_env_var`].
//!
//! Callers run this at boot (single-threaded) or in tests that own the process env.

use super::LockedBytes;

/// Copy `NAME=value` **value** bytes into a locked buffer. `None` if unset.
#[must_use]
pub(super) fn take_env_value_locked(name: &str) -> Option<LockedBytes> {
    if name.is_empty() || name.as_bytes().contains(&b'=') {
        return None;
    }
    #[cfg(unix)]
    {
        return unix_take(name.as_bytes());
    }
    #[cfg(windows)]
    {
        return windows_take(name);
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = name;
        None
    }
}

#[cfg(unix)]
fn unix_environ() -> *mut *mut std::os::raw::c_char {
    // POSIX process environment vector (`libc::environ` / glibc `environ`).
    // Declared here instead of `libc::environ` so the same walk works on
    // glibc and musl without relying on a libc crate export.
    extern "C" {
        static mut environ: *mut *mut std::os::raw::c_char;
    }
    // SAFETY: POSIX `environ` is the process environment vector. We only
    // **read** matching entries while the caller guarantees no concurrent
    // `setenv` from another thread — boot + tests. We never write the
    // C-strings or the vector itself.
    unsafe { environ }
}

#[cfg(unix)]
fn unix_take(name: &[u8]) -> Option<LockedBytes> {
    let value = unix_find_value(name)?;
    // SAFETY: `value` points at the NUL-terminated value of a live environ
    // entry we just located. We copy those bytes into a fresh Vec, then pin.
    let bytes = unsafe { copy_cstr_bytes(value) };
    Some(LockedBytes::from_vec(bytes))
}

#[cfg(unix)]
fn unix_find_value(name: &[u8]) -> Option<*const std::os::raw::c_char> {
    let mut vec = unix_environ();
    if vec.is_null() {
        return None;
    }
    // SAFETY: `vec` is `environ`; entries are NUL-terminated `NAME=value` until a
    // NULL pointer. We never write the vector itself here.
    unsafe {
        loop {
            let entry = *vec;
            if entry.is_null() {
                return None;
            }
            if let Some(val) = entry_value_ptr(entry, name) {
                return Some(val as *const std::os::raw::c_char);
            }
            vec = vec.add(1);
        }
    }
}

/// If `entry` is `name=`…, return pointer to the first value byte (may be NUL).
#[cfg(unix)]
unsafe fn entry_value_ptr(
    entry: *mut std::os::raw::c_char,
    name: &[u8],
) -> Option<*mut std::os::raw::c_char> {
    let mut i = 0usize;
    loop {
        let b = *entry.add(i) as u8;
        if i < name.len() {
            if b != name[i] {
                return None;
            }
        } else if i == name.len() {
            return if b == b'=' {
                Some(entry.add(i + 1))
            } else {
                None
            };
        }
        if b == 0 {
            return None;
        }
        i = i.saturating_add(1);
        if i > 4096 {
            return None;
        }
    }
}

#[cfg(unix)]
unsafe fn copy_cstr_bytes(ptr: *const std::os::raw::c_char) -> Vec<u8> {
    let mut n = 0usize;
    while *ptr.add(n) != 0 {
        n += 1;
        if n > 1024 * 1024 {
            break;
        }
    }
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        out.push(*ptr.add(i) as u8);
    }
    out
}

#[cfg(windows)]
fn windows_take(name: &str) -> Option<LockedBytes> {
    windows_walk(name)
}

#[cfg(windows)]
fn windows_walk(name: &str) -> Option<LockedBytes> {
    let wanted: Vec<u16> = name.encode_utf16().collect();
    // SAFETY: `GetEnvironmentStringsW` returns a caller-owned UTF-16 block
    // freed with `FreeEnvironmentStringsW`. Entries are `NAME=value` separated
    // by NUL, terminated by a double NUL. Read-only: we copy the value then
    // free the snapshot. `remove_var` unsets the live PEB entry.
    unsafe {
        let start = GetEnvironmentStringsW();
        if start.is_null() {
            return None;
        }
        let mut p = start;
        let mut found: Option<LockedBytes> = None;
        loop {
            if *p == 0 {
                break;
            }
            let mut end = p;
            while *end != 0 {
                end = end.add(1);
            }
            let len = end.offset_from(p) as usize;
            let slice = std::slice::from_raw_parts(p, len);
            if let Some(eq) = slice.iter().position(|&c| c == b'=' as u16) {
                if slice[..eq] == wanted[..] {
                    found = Some(LockedBytes::from_vec(utf16_to_utf8(&slice[eq + 1..])));
                    break;
                }
            }
            p = end.add(1);
        }
        let _ = FreeEnvironmentStringsW(start);
        found
    }
}

#[cfg(windows)]
fn utf16_to_utf8(units: &[u16]) -> Vec<u8> {
    let mut out = Vec::with_capacity(units.len());
    let mut i = 0;
    while i < units.len() {
        let u = units[i];
        if (0xD800..=0xDBFF).contains(&u) && i + 1 < units.len() {
            let l = units[i + 1];
            if (0xDC00..=0xDFFF).contains(&l) {
                let cp = 0x10000 + (((u as u32 - 0xD800) << 10) | (l as u32 - 0xDC00));
                push_utf8(&mut out, cp);
                i += 2;
                continue;
            }
        }
        if (0xD800..=0xDFFF).contains(&u) {
            out.extend_from_slice("\u{FFFD}".as_bytes());
        } else {
            push_utf8(&mut out, u as u32);
        }
        i += 1;
    }
    out
}

#[cfg(windows)]
fn push_utf8(out: &mut Vec<u8>, cp: u32) {
    if let Some(c) = char::from_u32(cp) {
        let mut buf = [0u8; 4];
        out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
    } else {
        out.extend_from_slice("\u{FFFD}".as_bytes());
    }
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn GetEnvironmentStringsW() -> *mut u16;
    fn FreeEnvironmentStringsW(penv: *mut u16) -> i32;
}
