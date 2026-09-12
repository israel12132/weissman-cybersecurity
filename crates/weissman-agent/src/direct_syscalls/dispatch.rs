//! Direct `syscall` dispatch for Windows x64 (Hell's Gate descent).
//!
//! Extra arguments (5 and 6) are placed on the stack at the Microsoft x64
//! positions (`[rsp+0x28]`, `[rsp+0x30]`) so Nt* functions with more than four
//! parameters work. This module is compiled only for Windows x86_64.

#![allow(dead_code)]

/// Issue a Windows x64 syscall with up to six arguments.
///
/// # Safety
/// `ssn` must be the real System Service Number for the intended Nt* routine
/// on this OS build. Arguments must match that routine's NTAPI contract.
/// The agent uses this only for **its own process** (memory inspection buffers).
#[cfg(all(windows, target_arch = "x86_64"))]
#[inline(never)]
pub unsafe fn syscall6(ssn: u16, args: [usize; 6]) -> u32 {
    let mut status: u32;
    core::arch::asm!(
        "sub rsp, 0x38",
        "mov qword ptr [rsp + 0x28], {a5}",
        "mov qword ptr [rsp + 0x30], {a6}",
        "mov r10, rcx",
        "syscall",
        "add rsp, 0x38",
        a5 = in(reg) args[4],
        a6 = in(reg) args[5],
        in("rcx") args[0],
        in("rdx") args[1],
        in("r8") args[2],
        in("r9") args[3],
        inlateout("rax") u32::from(ssn) => status,
        out("r10") _,
        out("r11") _,
        clobber_abi("system"),
    );
    status
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
pub unsafe fn syscall6(_ssn: u16, _args: [usize; 6]) -> u32 {
    // STATUS_NOT_IMPLEMENTED — never issue a Linux `syscall` with a Windows SSN.
    0xC000_0002
}

/// NTSTATUS success.
pub const STATUS_SUCCESS: u32 = 0;
/// NTSTATUS unsuccessful.
pub const STATUS_UNSUCCESSFUL: u32 = 0xC000_0001;
/// NTSTATUS not implemented (non-Windows builds).
pub const STATUS_NOT_IMPLEMENTED: u32 = 0xC000_0002;

/// `NtCurrentProcess()` pseudo-handle (`(HANDLE)-1`).
pub const NT_CURRENT_PROCESS: usize = usize::MAX;

pub const MEM_COMMIT: u32 = 0x1000;
pub const MEM_RESERVE: u32 = 0x2000;
pub const PAGE_READWRITE: u32 = 0x04;
