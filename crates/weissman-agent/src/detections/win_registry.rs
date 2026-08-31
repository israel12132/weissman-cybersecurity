//! In-process Windows registry reads via Win32 (`RegOpenKeyExW` / `RegQueryValueExW`).
//!
//! Never spawn `reg.exe`. A new process would trip EDR behavioral detections
//! (MITRE T1012). `windows-sys` FFI is wrapped in a safe function.

use windows_sys::Win32::System::Registry::{
    RegCloseKey, RegOpenKeyExW, RegQueryValueExW, HKEY, HKEY_LOCAL_MACHINE, KEY_READ, REG_DWORD,
};

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Read a REG_DWORD from HKLM. Safe wrapper around the Win32 registry API.
pub fn query_hklm_dword(subkey: &str, value_name: &str) -> Result<u32, String> {
    let sub = wide(subkey);
    let val = wide(value_name);
    let mut hkey: HKEY = std::ptr::null_mut();
    // SAFETY: `sub` is a NUL-terminated UTF-16 buffer that lives across the call.
    // KEY_READ only. We close `hkey` on every path after a successful open.
    let status = unsafe {
        RegOpenKeyExW(
            HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            0,
            KEY_READ,
            &mut hkey,
        )
    };
    if status != 0 {
        return Err(format!("RegOpenKeyExW failed with code {status}"));
    }
    let mut value: u32 = 0;
    let mut value_type: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: `hkey` was returned by RegOpenKeyExW. Output buffer is a live u32.
    // lpReserved is *const u32 and must be NULL per Win32.
    let query_status = unsafe {
        RegQueryValueExW(
            hkey,
            val.as_ptr(),
            std::ptr::null(),
            &mut value_type,
            &mut value as *mut u32 as *mut u8,
            &mut size,
        )
    };
    unsafe { RegCloseKey(hkey) };
    if query_status != 0 {
        return Err(format!("RegQueryValueExW failed with code {query_status}"));
    }
    if value_type != REG_DWORD {
        return Err(format!("unexpected registry type {value_type}"));
    }
    Ok(value)
}

pub fn uac_lsa_wdigest() -> Vec<(&'static str, &'static str, &'static str, Result<u32, String>)> {
    vec![
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA",
            "PAC-183 EnableLUA",
            query_hklm_dword(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "EnableLUA",
            ),
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "ConsentPromptBehaviorAdmin",
            "PAC-163 ConsentPromptBehaviorAdmin",
            query_hklm_dword(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "ConsentPromptBehaviorAdmin",
            ),
        ),
        (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "PromptOnSecureDesktop",
            "PAC-176 PromptOnSecureDesktop",
            query_hklm_dword(
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
                "PromptOnSecureDesktop",
            ),
        ),
        (
            r"SYSTEM\CurrentControlSet\Control\Lsa",
            "RunAsPPL",
            "PAC-052 RunAsPPL",
            query_hklm_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL"),
        ),
        (
            r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
            "UseLogonCredential",
            "PAC-081 WDigest UseLogonCredential",
            query_hklm_dword(
                r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                "UseLogonCredential",
            ),
        ),
    ]
}
