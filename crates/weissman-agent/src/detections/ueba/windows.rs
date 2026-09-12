//! Windows Event Log 4625 + process snapshot. Linux CI compiles the empty stubs.

use super::ProcessSnapshot;

#[cfg(windows)]
use super::NetSummary;

#[cfg(windows)]
pub fn listening_tcp_ports() -> Vec<u16> {
    windows_impl::listening_tcp_ports()
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn listening_tcp_ports() -> Vec<u16> {
    Vec::new()
}

#[cfg(windows)]
pub fn process_snapshot(lite: bool) -> ProcessSnapshot {
    windows_impl::process_snapshot(lite)
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn process_snapshot(_lite: bool) -> ProcessSnapshot {
    ProcessSnapshot {
        process_count: 0,
        unique_users: 0,
        top: Vec::new(),
        paths: Vec::new(),
        sha256: Vec::new(),
        listen_map: Vec::new(),
        ghost_ppids: Vec::new(),
        thread_count: 0,
    }
}

#[cfg(windows)]
pub fn failed_logins_24h() -> (bool, u32) {
    windows_impl::failed_logins_24h()
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn failed_logins_24h() -> (bool, u32) {
    (false, 0)
}

#[cfg(windows)]
pub fn hardware_id() -> Option<String> {
    windows_impl::hardware_id()
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn hardware_id() -> Option<String> {
    None
}

#[cfg(windows)]
pub fn network_summary() -> NetSummary {
    NetSummary {
        conn_count: 0,
        conn_fail_count: 0,
        unique_remote_ips: 0,
    }
}

#[cfg(windows)]
mod windows_impl {
    use super::*;
    use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::EventLog::*;

    pub fn listening_tcp_ports() -> Vec<u16> {
        // No netstat. A full IP Helper GetExtendedTcpTable binding would add a large
        // windows-sys surface; until that lands, Windows agents report an empty listen
        // set rather than shelling out.
        Vec::new()
    }

    pub fn process_snapshot(_lite: bool) -> ProcessSnapshot {
        ProcessSnapshot {
            process_count: 0,
            unique_users: 0,
            top: Vec::new(),
            paths: Vec::new(),
            sha256: Vec::new(),
            listen_map: Vec::new(),
            ghost_ppids: Vec::new(),
            thread_count: 0,
        }
    }

    pub fn hardware_id() -> Option<String> {
        None
    }

    pub fn failed_logins_24h() -> (bool, u32) {
        // Event ID 4625 (Failed Logon). Returns (false, 0) when the Security log is denied.
        unsafe {
            let src: Vec<u16> = "Security\0".encode_utf16().collect();
            let h = OpenEventLogW(std::ptr::null(), src.as_ptr());
            if h.is_null() || h == INVALID_HANDLE_VALUE {
                return (false, 0);
            }
            let mut buf = vec![0u8; 64 * 1024];
            let mut read = 0u32;
            let mut needed = 0u32;
            let ok = ReadEventLogW(
                h,
                EVENTLOG_SEQUENTIAL_READ | EVENTLOG_BACKWARDS_READ,
                0,
                buf.as_mut_ptr() as *mut _,
                buf.len() as u32,
                &mut read,
                &mut needed,
            );
            CloseHandle(h);
            if ok == 0 {
                return (false, 0);
            }
            let mut count = 0u32;
            let mut offset = 0usize;
            while offset + std::mem::size_of::<EVENTLOGRECORD>() <= read as usize {
                let rec = &*(buf.as_ptr().add(offset) as *const EVENTLOGRECORD);
                if rec.EventID & 0xFFFF == 4625 {
                    count += 1;
                }
                if rec.Length == 0 {
                    break;
                }
                offset += rec.Length as usize;
                if count > 10_000 {
                    break;
                }
            }
            (true, count)
        }
    }
}
