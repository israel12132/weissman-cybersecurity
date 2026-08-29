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
//! stubs (ntdll lays syscall stubs out in SSN order inside `.text`) and reconstructs
//! the hooked SSN as `neighbor_ssn ∓ index`.
//!
//! Neighbor reads are **strictly confined** to the PE `.text` section parsed from
//! headers. EAT names are alphabetical, not address-sorted; a stub at a page or
//! section edge must never cause a `±32` walk to touch unmapped memory.

use crate::direct_syscalls::pe::{PeView, TextSpan, IMAGE_EXPORT_DIRECTORY};

pub const STUB_LEN: usize = 32;
pub const MAX_HALOS_DEPTH: usize = 100;
const PROLOGUE_LEN: usize = 8;

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
///
/// `text` is the `.text` section of the same PE. Neighbors that would leave that
/// window (page/section edge) are skipped — they are never read.
#[must_use]
pub fn halos_gate_recover(image: &[u8], func_offset: usize, text: TextSpan) -> Option<u16> {
    for idx in 1..=MAX_HALOS_DEPTH {
        let delta = idx * STUB_LEN;
        if let Some(upper) = func_offset.checked_add(delta) {
            if let Some(ssn) = read_hells_gate_in_text(image, upper, text) {
                return ssn.checked_sub(idx as u16);
            }
        }
        if func_offset >= delta {
            let lower = func_offset - delta;
            if let Some(ssn) = read_hells_gate_in_text(image, lower, text) {
                return ssn.checked_add(idx as u16);
            }
        }
    }
    None
}

fn read_hells_gate_in_text(image: &[u8], rva: usize, text: TextSpan) -> Option<u16> {
    if !text.contains_bytes(rva, PROLOGUE_LEN) {
        return None;
    }
    let stub = image.get(rva..rva + PROLOGUE_LEN)?;
    hells_gate_ssn(stub)
}

/// Resolve an SSN from a function RVA inside a mapped PE image.
///
/// Returns `None` when the RVA is not fully inside `.text` — the caller must
/// not dereference a stub that sits on a section/page edge.
#[must_use]
pub fn resolve_stub_ssn(image: &[u8], func_offset: usize, text: TextSpan) -> Option<ResolvedSsn> {
    if !text.contains_bytes(func_offset, 1) {
        return None;
    }
    // Read at most what `.text` still covers so a stub on the last bytes of
    // the section cannot overshoot into the next (possibly unmapped) page.
    let max_len = text.rva_end.saturating_sub(func_offset);
    let stub = image.get(func_offset..func_offset.saturating_add(max_len))?;
    if stub.is_empty() {
        return None;
    }
    if let Some(ssn) = hells_gate_ssn(stub) {
        return Some(ResolvedSsn { ssn, hooked: false });
    }
    if is_user_mode_hook(stub) || stub.first() != Some(&0x4C) {
        let ssn = halos_gate_recover(image, func_offset, text)?;
        return Some(ResolvedSsn { ssn, hooked: true });
    }
    None
}

/// Infer `.text` from Nt/Zw export stubs when PE section headers were stomped.
///
/// Only RVAs that appear in the EAT and match a Hell's Gate prologue or a
/// user-mode JMP hook are included — a poison stub planted after the real
/// syscall cluster cannot expand the window (and cannot feed Halo's Gate).
#[must_use]
pub fn infer_text_span_from_eat(
    view: PeView<'_>,
    export: &IMAGE_EXPORT_DIRECTORY,
) -> Option<TextSpan> {
    let image = view.bytes();
    let mut min_rva = usize::MAX;
    let mut max_end = 0usize;
    let mut hits = 0usize;
    for i in 0..export.number_of_names as usize {
        let Some(name_rva) = view.u32_at(export.address_of_names, i) else {
            continue;
        };
        let Some(name) = view.cstr_at(name_rva) else {
            continue;
        };
        if !(name.starts_with("Nt") || name.starts_with("Zw")) {
            continue;
        }
        let Some(ordinal) = view.u16_at(export.address_of_name_ordinals, i) else {
            continue;
        };
        let Some(func_rva) = view.u32_at(export.address_of_functions, ordinal as usize) else {
            continue;
        };
        let func_rva = func_rva as usize;
        let Some(stub) = image.get(func_rva..) else {
            continue;
        };
        if !(is_hells_gate_prologue(stub) || is_user_mode_hook(stub)) {
            continue;
        }
        hits += 1;
        min_rva = min_rva.min(func_rva);
        max_end = max_end.max(func_rva.saturating_add(STUB_LEN).min(image.len()));
    }
    if hits == 0 || min_rva >= max_end {
        return None;
    }
    Some(TextSpan {
        rva_start: min_rva,
        rva_end: max_end,
    })
}

/// Infer the `.text` window from Hell's Gate / hooked-stub opcodes when PE
/// section headers were stomped. Never reads outside `image`.
#[must_use]
pub fn infer_text_span_from_stubs(image: &[u8]) -> Option<TextSpan> {
    if image.len() < PROLOGUE_LEN {
        return None;
    }
    let mut hits: Vec<usize> = Vec::new();
    let mut off = 0usize;
    while off + PROLOGUE_LEN <= image.len() {
        let stub = &image[off..off + PROLOGUE_LEN];
        if is_hells_gate_prologue(stub) {
            hits.push(off);
            off = off.saturating_add(STUB_LEN);
            continue;
        }
        off = off.saturating_add(16);
    }
    if hits.len() < 2 {
        return None;
    }
    let mut start = hits[0];
    let mut end = hits[hits.len() - 1].saturating_add(STUB_LEN);
    while start >= STUB_LEN {
        let prev = start - STUB_LEN;
        if is_user_mode_hook(image.get(prev..).unwrap_or(&[])) {
            start = prev;
        } else {
            break;
        }
    }
    while end < image.len() {
        if is_user_mode_hook(image.get(end..).unwrap_or(&[])) {
            end = end.saturating_add(STUB_LEN).min(image.len());
        } else {
            break;
        }
    }
    if start >= end {
        return None;
    }
    Some(TextSpan {
        rva_start: start,
        rva_end: end.min(image.len()),
    })
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

    fn text(image: &[u8]) -> TextSpan {
        TextSpan {
            rva_start: 0,
            rva_end: image.len(),
        }
    }

    #[test]
    fn halos_gate_recovers_ssn_from_upper_neighbor() {
        let mut image = vec![0u8; STUB_LEN * 4];
        image[..STUB_LEN].copy_from_slice(&encode_jmp_hook_stub());
        image[STUB_LEN..STUB_LEN * 2].copy_from_slice(&encode_clean_stub(0x19));
        image[STUB_LEN * 2..STUB_LEN * 3].copy_from_slice(&encode_clean_stub(0x1A));
        let recovered = halos_gate_recover(&image, 0, text(&image)).expect("neighbor SSN");
        assert_eq!(recovered, 0x18);
        let resolved = resolve_stub_ssn(&image, 0, text(&image)).expect("resolved");
        assert_eq!(resolved.ssn, 0x18);
        assert!(resolved.hooked);
    }

    #[test]
    fn halos_gate_recovers_ssn_from_lower_neighbor() {
        let mut image = vec![0u8; STUB_LEN * 4];
        image[..STUB_LEN].copy_from_slice(&encode_clean_stub(0x30));
        image[STUB_LEN..STUB_LEN * 2].copy_from_slice(&encode_jmp_hook_stub());
        let recovered = halos_gate_recover(&image, STUB_LEN, text(&image)).expect("neighbor SSN");
        assert_eq!(recovered, 0x31);
    }

    #[test]
    fn halos_gate_gives_up_without_neighbors() {
        let mut image = vec![0u8; STUB_LEN];
        image.copy_from_slice(&encode_jmp_hook_stub());
        assert!(halos_gate_recover(&image, 0, text(&image)).is_none());
    }

    #[test]
    fn halos_gate_does_not_read_outside_text_section() {
        // Layout: [poison clean SSN 0x99][hooked][poison clean SSN 0x02]
        // `.text` covers only the hooked stub. Poison neighbors would yield
        // the wrong SSN if Halo's Gate walked past the section edge.
        let mut image = vec![0u8; STUB_LEN * 3];
        image[..STUB_LEN].copy_from_slice(&encode_clean_stub(0x99));
        image[STUB_LEN..STUB_LEN * 2].copy_from_slice(&encode_jmp_hook_stub());
        image[STUB_LEN * 2..STUB_LEN * 3].copy_from_slice(&encode_clean_stub(0x02));
        let text = TextSpan {
            rva_start: STUB_LEN,
            rva_end: STUB_LEN * 2,
        };
        assert!(halos_gate_recover(&image, STUB_LEN, text).is_none());
        assert!(resolve_stub_ssn(&image, STUB_LEN, text).is_none());
        // A stub whose prologue would cross .text end is not resolved.
        let edge = TextSpan {
            rva_start: STUB_LEN,
            rva_end: STUB_LEN + 4,
        };
        assert!(resolve_stub_ssn(&image, STUB_LEN, edge).is_none());
    }

    #[test]
    fn infer_text_span_from_prologues_includes_hooked_slot() {
        let mut image = vec![0u8; STUB_LEN * 3];
        image[..STUB_LEN].copy_from_slice(&encode_clean_stub(0x18));
        image[STUB_LEN..STUB_LEN * 2].copy_from_slice(&encode_jmp_hook_stub());
        image[STUB_LEN * 2..STUB_LEN * 3].copy_from_slice(&encode_clean_stub(0x1A));
        let span = infer_text_span_from_stubs(&image).expect("span");
        assert_eq!(span.rva_start, 0);
        assert_eq!(span.rva_end, STUB_LEN * 3);
    }

    #[test]
    fn infer_text_span_from_eat_excludes_poison_after_stubs() {
        let img = crate::direct_syscalls::fixtures::synthetic_ntdll(false);
        let view = crate::direct_syscalls::pe::PeView::new(&img).expect("pe");
        let eat = view.export_directory().expect("eat");
        let span = infer_text_span_from_eat(view, &eat).expect("span");
        assert_eq!(span.rva_start, 0x600);
        assert_eq!(span.rva_end, 0x600 + STUB_LEN * 4);
        assert!(!span.contains_bytes(0x600 + STUB_LEN * 4, 8));
    }
}
