//! Hell's Gate + Halo's Gate System Service Number (SSN) recovery.
//!
//! A clean ntdll Nt/Zw stub on Windows x64 begins:
//!
//! ```text
//! 4C 8B D1          mov r10, rcx
//! B8 xx xx 00 00    mov eax, SSN
//! 0F 05             syscall
//! C3                ret
//! ```
//!
//! User-mode EDR hooks typically overwrite the first bytes with `jmp rel32` (`0xE9`)
//! or `jmp qword ptr [rip]` (`FF 25`). Halo's Gate then walks neighboring 32-byte
//! stubs (ntdll lays them out in SSN order) and reconstructs the hooked SSN as
//! `neighbor_ssn ∓ index`.

pub const STUB_LEN: usize = 32;
pub const MAX_HALOS_DEPTH: usize = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSsn {
    pub ssn: u16,
    /// True when the target stub itself was hooked and the SSN came from a neighbor.
    pub hooked: bool,
}

/// True when `stub` matches the canonical unhooked syscall prologue.
#[must_use]
pub fn is_hells_gate_prologue(stub: &[u8]) -> bool {
    stub.len() >= 8 && stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1 && stub[3] == 0xB8
}

/// Extract the SSN from a clean Hell's Gate stub (`mov eax, imm16`).
#[must_use]
pub fn hells_gate_ssn(stub: &[u8]) -> Option<u16> {
    if is_hells_gate_prologue(stub) {
        Some(u16::from_le_bytes([stub[4], stub[5]]))
    } else {
        None
    }
}

/// True when the stub starts with a user-mode detour (JMP) rather than `mov r10, rcx`.
#[must_use]
pub fn is_user_mode_hook(stub: &[u8]) -> bool {
    if stub.is_empty() {
        return false;
    }
    match stub[0] {
        0xE9 | 0xEB => true,                               // jmp rel32 / jmp rel8
        0xFF if stub.len() > 1 && stub[1] == 0x25 => true, // jmp qword ptr [rip]
        0x48 if stub.len() > 1 && stub[1] == 0xB8 => true, // mov rax, imm64 (typical push-ret/jmp rax hook)
        _ => false,
    }
}

/// Halo's Gate: recover the SSN of a hooked stub from clean neighbors at ±32-byte stride.
#[must_use]
pub fn halos_gate_recover(image: &[u8], func_offset: usize) -> Option<u16> {
    for idx in 1..=MAX_HALOS_DEPTH {
        let delta = idx * STUB_LEN;
        if let Some(upper) = func_offset.checked_add(delta) {
            if let Some(stub) = image.get(upper..upper.saturating_add(8)) {
                if let Some(ssn) = hells_gate_ssn(stub) {
                    return ssn.checked_sub(idx as u16);
                }
            }
        }
        if func_offset >= delta {
            let lower = func_offset - delta;
            if let Some(stub) = image.get(lower..lower.saturating_add(8)) {
                if let Some(ssn) = hells_gate_ssn(stub) {
                    return ssn.checked_add(idx as u16);
                }
            }
        }
    }
    None
}

/// Resolve an SSN from a function RVA inside a mapped PE image.
#[must_use]
pub fn resolve_stub_ssn(image: &[u8], func_offset: usize) -> Option<ResolvedSsn> {
    let stub = image.get(func_offset..)?;
    if let Some(ssn) = hells_gate_ssn(stub) {
        return Some(ResolvedSsn { ssn, hooked: false });
    }
    if is_user_mode_hook(stub) || stub.first() != Some(&0x4C) {
        let ssn = halos_gate_recover(image, func_offset)?;
        return Some(ResolvedSsn { ssn, hooked: true });
    }
    None
}

/// Encode a canonical 32-byte Nt/Zw syscall stub for tests and fixtures.
#[must_use]
pub fn encode_clean_stub(ssn: u16) -> [u8; STUB_LEN] {
    let mut stub = [0xCCu8; STUB_LEN];
    stub[0] = 0x4C;
    stub[1] = 0x8B;
    stub[2] = 0xD1;
    stub[3] = 0xB8;
    let s = ssn.to_le_bytes();
    stub[4] = s[0];
    stub[5] = s[1];
    stub[6] = 0x00;
    stub[7] = 0x00;
    stub[8] = 0x0F;
    stub[9] = 0x05;
    stub[10] = 0xC3;
    stub
}

/// Encode a hooked stub whose first byte is `jmp rel32` (`0xE9`).
#[must_use]
pub fn encode_jmp_hook_stub() -> [u8; STUB_LEN] {
    let mut stub = [0x90u8; STUB_LEN];
    stub[0] = 0xE9;
    // rel32 = +0x1000 (dummy; Halo's Gate does not follow the jump)
    stub[1] = 0x00;
    stub[2] = 0x10;
    stub[3] = 0x00;
    stub[4] = 0x00;
    stub
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hells_gate_reads_ssn_from_prologue() {
        let stub = encode_clean_stub(0x18);
        assert_eq!(hells_gate_ssn(&stub), Some(0x18));
        assert!(!is_user_mode_hook(&stub));
    }

    #[test]
    fn jmp_e9_is_detected_as_hook() {
        let stub = encode_jmp_hook_stub();
        assert!(is_user_mode_hook(&stub));
        assert_eq!(hells_gate_ssn(&stub), None);
    }

    #[test]
    fn halos_gate_recovers_ssn_from_upper_neighbor() {
        let mut image = vec![0u8; STUB_LEN * 4];
        image[..STUB_LEN].copy_from_slice(&encode_jmp_hook_stub());
        image[STUB_LEN..STUB_LEN * 2].copy_from_slice(&encode_clean_stub(0x19));
        image[STUB_LEN * 2..STUB_LEN * 3].copy_from_slice(&encode_clean_stub(0x1A));
        let recovered = halos_gate_recover(&image, 0).expect("neighbor SSN");
        assert_eq!(recovered, 0x18);
        let resolved = resolve_stub_ssn(&image, 0).expect("resolved");
        assert_eq!(resolved.ssn, 0x18);
        assert!(resolved.hooked);
    }

    #[test]
    fn halos_gate_recovers_ssn_from_lower_neighbor() {
        let mut image = vec![0u8; STUB_LEN * 4];
        image[..STUB_LEN].copy_from_slice(&encode_clean_stub(0x30));
        image[STUB_LEN..STUB_LEN * 2].copy_from_slice(&encode_jmp_hook_stub());
        let recovered = halos_gate_recover(&image, STUB_LEN).expect("neighbor SSN");
        assert_eq!(recovered, 0x31);
    }

    #[test]
    fn halos_gate_gives_up_without_neighbors() {
        let mut image = vec![0u8; STUB_LEN];
        image.copy_from_slice(&encode_jmp_hook_stub());
        assert!(halos_gate_recover(&image, 0).is_none());
    }
}
