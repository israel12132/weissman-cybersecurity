//! Windows process + listener inventory via ntdll / iphlpapi.
//!
//! Primary (and only) process path: `NtQuerySystemInformation(SystemProcessInformation)` —
//! the same kernel table Task Manager uses, without spawning `tasklist.exe`.
//! There is **no** ToolHelp fallback: the ToolHelp snapshot family is a loud EDR
//! tripwire on unsigned binaries. If NTAPI is blocked, report an empty sample
//! rather than lighting up the host EDR.
//! Listeners: `GetExtendedTcpTable` (AF_INET + AF_INET6), never `netstat`/`lsof`.

use super::{ListenPort, ProcessRecord};
use std::ptr;

const SYSTEM_PROCESS_INFORMATION: i32 = 5;
const TCP_TABLE_OWNER_PID_LISTENER: u32 = 3;
const AF_INET: u32 = 2;
const AF_INET6: u32 = 23;
const ERROR_INSUFFICIENT_BUFFER: u32 = 122;
const STATUS_INFO_LENGTH_MISMATCH: i32 = -1073741820; // 0xC0000004 as i32
const STATUS_SUCCESS: i32 = 0;

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        class: i32,
        info: *mut u8,
        length: u32,
        return_length: *mut u32,
    ) -> i32;
}

#[link(name = "iphlpapi")]
extern "system" {
    fn GetExtendedTcpTable(
        table: *mut u8,
        size: *mut u32,
        order: i32,
        af: u32,
        table_class: u32,
        reserved: u32,
    ) -> u32;
}

#[cfg(target_arch = "x86_64")]
mod nt_layout {
    pub const NEXT_ENTRY: usize = 0x00;
    pub const IMAGE_NAME_LEN: usize = 0x38;
    pub const IMAGE_NAME_BUF: usize = 0x40;
    pub const UNIQUE_PID: usize = 0x50;
    pub const PARENT_PID: usize = 0x58;
    pub const VIRTUAL_SIZE: usize = 0x78;
    pub const WORKING_SET: usize = 0x90;
    pub const MIN_SIZE: usize = 0x98;
}

pub fn list_processes(full: bool) -> Vec<ProcessRecord> {
    nt_query_processes(full).unwrap_or_default()
}

pub fn list_listen_ports() -> Vec<ListenPort> {
    let mut out = Vec::new();
    collect_tcp_table(AF_INET, &mut out);
    collect_tcp_table(AF_INET6, &mut out);
    out
}

fn nt_query_processes(full: bool) -> Option<Vec<ProcessRecord>> {
    let mut needed: u32 = 0;
    let st = unsafe {
        NtQuerySystemInformation(SYSTEM_PROCESS_INFORMATION, ptr::null_mut(), 0, &mut needed)
    };
    if st != STATUS_INFO_LENGTH_MISMATCH && needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize + 4096];
    let mut ret: u32 = 0;
    let st = unsafe {
        NtQuerySystemInformation(
            SYSTEM_PROCESS_INFORMATION,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut ret,
        )
    };
    if st != STATUS_SUCCESS {
        return None;
    }
    Some(parse_nt_process_buffer(&buf[..ret as usize], full))
}

fn parse_nt_process_buffer(buf: &[u8], full: bool) -> Vec<ProcessRecord> {
    #[cfg(not(target_arch = "x86_64"))]
    {
        let _ = (buf, full);
        Vec::new()
    }
    #[cfg(target_arch = "x86_64")]
    {
        use nt_layout::*;
        let mut out = Vec::new();
        let mut off = 0usize;
        while off + MIN_SIZE <= buf.len() {
            let next = u32_at(buf, off + NEXT_ENTRY).unwrap_or(0) as usize;
            let pid = usize_at(buf, off + UNIQUE_PID).unwrap_or(0) as u32;
            let ppid = usize_at(buf, off + PARENT_PID).unwrap_or(0) as u32;
            let name =
                unicode_at(buf, off + IMAGE_NAME_LEN, off + IMAGE_NAME_BUF).unwrap_or_default();
            if pid != 0 {
                let vmem = usize_at(buf, off + VIRTUAL_SIZE).unwrap_or(0) as u64;
                let rss = usize_at(buf, off + WORKING_SET).unwrap_or(0) as u64;
                out.push(ProcessRecord {
                    pid,
                    ppid: if ppid == 0 { None } else { Some(ppid) },
                    name,
                    exe: String::new(),
                    uid: None,
                    rss_bytes: rss,
                    vmem_bytes: vmem,
                });
            }
            if next == 0 {
                break;
            }
            off = off.saturating_add(next);
            if off >= buf.len() {
                break;
            }
        }
        let _ = full;
        out
    }
}

fn collect_tcp_table(af: u32, out: &mut Vec<ListenPort>) {
    let mut size: u32 = 0;
    let st = unsafe {
        GetExtendedTcpTable(
            ptr::null_mut(),
            &mut size,
            1,
            af,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if st != ERROR_INSUFFICIENT_BUFFER || size == 0 {
        return;
    }
    let mut buf = vec![0u8; size as usize];
    let st = unsafe {
        GetExtendedTcpTable(
            buf.as_mut_ptr(),
            &mut size,
            1,
            af,
            TCP_TABLE_OWNER_PID_LISTENER,
            0,
        )
    };
    if st != 0 || buf.len() < 4 {
        return;
    }
    let count = u32::from_le_bytes(buf[0..4].try_into().unwrap_or([0; 4])) as usize;
    // MIB_TCPROW_OWNER_PID: 6 * u32 = 24 bytes. Local port is the second DWORD,
    // stored in network byte order in the low 16 bits.
    // MIB_TCP6ROW_OWNER_PID: local addr 16 + dwLocalScopeId 4 + dwLocalPort 4 + ...
    let (row, port_off) = if af == AF_INET {
        (24usize, 4usize)
    } else {
        (56usize, 20usize)
    };
    let mut off = 4usize;
    for _ in 0..count {
        if off + row > buf.len() {
            break;
        }
        let raw = u32::from_le_bytes(
            buf[off + port_off..off + port_off + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        let port = u16::from_be((raw & 0xFFFF) as u16);
        if port != 0 {
            out.push(ListenPort { port });
        }
        off += row;
    }
}

fn u32_at(buf: &[u8], off: usize) -> Option<u32> {
    buf.get(off..off + 4)
        .and_then(|s| s.try_into().ok())
        .map(u32::from_le_bytes)
}

fn usize_at(buf: &[u8], off: usize) -> Option<usize> {
    buf.get(off..off + 8)
        .and_then(|s| s.try_into().ok())
        .map(u64::from_le_bytes)
        .map(|v| v as usize)
}

fn unicode_at(buf: &[u8], len_off: usize, buf_off: usize) -> Option<String> {
    let byte_len = u16::from_le_bytes(buf.get(len_off..len_off + 2)?.try_into().ok()?) as usize;
    if byte_len == 0 || byte_len > 512 || byte_len % 2 != 0 {
        return Some(String::new());
    }
    let ptr = usize_at(buf, buf_off)?;
    if ptr == 0 {
        return Some(String::new());
    }
    // ImageName.Buffer is an absolute pointer into the NT buffer we hold.
    let base = buf.as_ptr() as usize;
    if ptr < base {
        return Some(String::new());
    }
    let rel = ptr - base;
    let bytes = buf.get(rel..rel + byte_len)?;
    let mut u16s = Vec::with_capacity(byte_len / 2);
    for chunk in bytes.chunks_exact(2) {
        u16s.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }
    Some(String::from_utf16_lossy(&u16s))
}
