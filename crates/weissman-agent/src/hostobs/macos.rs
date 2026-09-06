//! macOS process + listener inventory via `sysctl(KERN_PROC)` and `proc_pidinfo`.
//!
//! Never shells out to `ps`, `lsof`, or `netstat`.

use super::{ListenPort, ProcessRecord, SampleError};
use libc::{c_int, c_void, kinfo_proc, sysctl, CTL_KERN, KERN_PROC, KERN_PROC_ALL};
use std::mem;
use std::ptr;

const PROC_PIDLISTFDS: c_int = 1;
const PROC_PIDFDSOCKETINFO: c_int = 3;
const PROX_FDTYPE_SOCKET: u32 = 2;
const SOCKINFO_TCP: i32 = 2;
// `struct socket_fdinfo` is not in libc; we only need the TCP local port which
// sits at a stable offset after the `proc_fileinfo` + `socket_info` headers.
// `psi.soi_kind` is at offset 0xA0 of `socket_fdinfo` on both x64 and arm64
// Darwin (proc_info.h). TCP `tcpsi_ini.insi_lport` follows shortly after.
const SOI_KIND_OFFSET: usize = 0xA0;
const TCP_LPORT_OFFSET: usize = 0xE4;

#[repr(C)]
struct ProcFdInfo {
    proc_fd: i32,
    proc_fdtype: u32,
}

extern "C" {
    fn proc_pidinfo(
        pid: c_int,
        flavor: c_int,
        arg: u64,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
    fn proc_pidfdinfo(
        pid: c_int,
        fd: c_int,
        flavor: c_int,
        buffer: *mut c_void,
        buffersize: c_int,
    ) -> c_int;
}

pub fn list_processes(full: bool) -> Vec<ProcessRecord> {
    sample_process_table(full).unwrap_or_default()
}

pub fn sample_process_table(full: bool) -> Result<Vec<ProcessRecord>, SampleError> {
    let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
    let mut size: usize = 0;
    let rc = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            4,
            ptr::null_mut(),
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size == 0 {
        return Err(SampleError::syscall("sysctl_KERN_PROC"));
    }
    let mut buf = vec![0u8; size];
    let rc = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            4,
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            ptr::null_mut(),
            0,
        )
    };
    if rc != 0 {
        return Err(SampleError::syscall("sysctl_KERN_PROC_read"));
    }
    let n = size / mem::size_of::<kinfo_proc>();
    let slice = unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const kinfo_proc, n) };
    let mut out = Vec::with_capacity(n);
    for kp in slice {
        let pid = kp.kp_proc.p_pid as u32;
        if pid == 0 {
            continue;
        }
        let name = cstr_from_comm(&kp.kp_proc.p_comm);
        if name.is_empty() {
            continue;
        }
        let ppid = kp.kp_eproc.e_ppid as u32;
        let mut rec = ProcessRecord {
            pid,
            ppid: if ppid == 0 { None } else { Some(ppid) },
            name,
            exe: String::new(),
            uid: Some(kp.kp_eproc.e_pcred.p_ruid),
            rss_bytes: 0,
            vmem_bytes: 0,
        };
        if full {
            rec.exe = macos_exe(pid).unwrap_or_default();
        }
        out.push(rec);
    }
    if out.is_empty() {
        Err(SampleError::empty_table())
    } else {
        Ok(out)
    }
}

pub fn list_listen_ports() -> Vec<ListenPort> {
    let procs = list_processes(false);
    let mut out = Vec::new();
    for p in procs {
        collect_pid_listeners(p.pid as c_int, &mut out);
    }
    out
}

fn collect_pid_listeners(pid: c_int, out: &mut Vec<ListenPort>) {
    let needed = unsafe { proc_pidinfo(pid, PROC_PIDLISTFDS, 0, ptr::null_mut(), 0) };
    if needed <= 0 {
        return;
    }
    let cap = needed as usize;
    let mut fds = vec![
        ProcFdInfo {
            proc_fd: 0,
            proc_fdtype: 0
        };
        cap / mem::size_of::<ProcFdInfo>() + 4
    ];
    let got = unsafe {
        proc_pidinfo(
            pid,
            PROC_PIDLISTFDS,
            0,
            fds.as_mut_ptr() as *mut c_void,
            (fds.len() * mem::size_of::<ProcFdInfo>()) as c_int,
        )
    };
    if got <= 0 {
        return;
    }
    let n = (got as usize) / mem::size_of::<ProcFdInfo>();
    let mut sockbuf = [0u8; 1024];
    for fd in fds.iter().take(n) {
        if fd.proc_fdtype != PROX_FDTYPE_SOCKET {
            continue;
        }
        let nread = unsafe {
            proc_pidfdinfo(
                pid,
                fd.proc_fd,
                PROC_PIDFDSOCKETINFO,
                sockbuf.as_mut_ptr() as *mut c_void,
                sockbuf.len() as c_int,
            )
        };
        if nread < (TCP_LPORT_OFFSET as c_int) + 2 {
            continue;
        }
        let kind = i32::from_ne_bytes(
            sockbuf[SOI_KIND_OFFSET..SOI_KIND_OFFSET + 4]
                .try_into()
                .unwrap_or([0; 4]),
        );
        if kind != SOCKINFO_TCP {
            continue;
        }
        // in_port_t stored network-byte-order on Darwin pcb.
        let raw = u16::from_ne_bytes(
            sockbuf[TCP_LPORT_OFFSET..TCP_LPORT_OFFSET + 2]
                .try_into()
                .unwrap_or([0; 2]),
        );
        let port = u16::from_be(raw);
        if port != 0 {
            out.push(ListenPort { port });
        }
    }
}

fn macos_exe(pid: u32) -> Option<String> {
    // PROC_PIDPATHINFO_MAXSIZE is 4 * MAXPATHLEN.
    let mut buf = vec![0u8; 4096];
    extern "C" {
        fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffersize: u32) -> c_int;
    }
    let n = unsafe {
        proc_pidpath(
            pid as c_int,
            buf.as_mut_ptr() as *mut c_void,
            buf.len() as u32,
        )
    };
    if n <= 0 {
        return None;
    }
    let n = n as usize;
    let end = buf[..n].iter().position(|&b| b == 0).unwrap_or(n);
    Some(String::from_utf8_lossy(&buf[..end]).into_owned())
}

fn cstr_from_comm(comm: &[i8]) -> String {
    let bytes: Vec<u8> = comm
        .iter()
        .map(|c| *c as u8)
        .take_while(|b| *b != 0)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}
