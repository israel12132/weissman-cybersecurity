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
//! or `jmp qword ptr [rip]` (`FF 25`). The SSN is recovered first from the
//! remaining `mov eax, SSN; syscall; ret` tail (`B8 .. 0F 05 C3`) — EDR rarely
//! patches the syscall opcode itself — then from Halo's Gate neighbors.
//!
//! Neighbor reads are **strictly confined** to the PE `.text` section parsed from
//! headers. EAT names are alphabetical, not address-sorted; a stub at a page or
//! section edge must never cause a `±32` walk to touch unmapped memory.

use crate::direct_syscalls::pe::{PeView, TextSpan, IMAGE_EXPORT_DIRECTORY};

pub const STUB_LEN: usize = 32;
/// Hard cap on Halo's Gate neighbor depth in each direction. EDR cascade
/// hooks paint whole Nt* clusters; walking tens of stubs would recover an
/// unrelated export's SSN (`ssn ± depth`) and dispatch would fire it.
/// Depth 5 is enough for a single isolated JMP; beyond that we fail closed.
pub const MAX_HALOS_GATE_NEIGHBOR_DEPTH: usize = 5;
const PROLOGUE_LEN: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedSsn {
    pub ssn: u16,
    /// True when the target stub itself was hooked and the SSN came from a neighbor
    /// or from the remaining `syscall;ret` tail.
    pub hooked: bool,
    /// Hooked stub, no clean neighbor inside [`MAX_HALOS_GATE_NEIGHBOR_DEPTH`].
    /// `ssn` is unused; dispatch must not issue a syscall for this export.
    pub cascade_blocked: bool,
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

/// Recover SSN from the unhooked tail `B8 xx xx 00 00 0F 05 C3` inside one stub.
///
/// EDR JMP/CALL hooks rewrite the prologue (`4C 8B D1 B8…`). They almost never
/// rewrite `syscall; ret`. Scanning the stub from the end — never the whole
/// ntdll mapping — finds that tail and reads the `mov eax, imm32` immediately
/// before it.
#[must_use]
pub fn retrograde_ssn_from_stub(stub: &[u8]) -> Option<u16> {
    if stub.len() < 8 {
        return None;
    }
    let mut i = stub.len() - 3;
    loop {
        if stub[i] == 0x0F && stub[i + 1] == 0x05 && stub[i + 2] == 0xC3 && i >= 5 {
            // `mov eax, imm32` immediately before syscall;ret.
            if stub[i - 5] == 0xB8 && stub[i - 2] == 0x00 && stub[i - 1] == 0x00 {
                return Some(u16::from_le_bytes([stub[i - 4], stub[i - 3]]));
            }
        }
        if i == 0 {
            break;
        }
        i -= 1;
    }
    None
}

/// Halo's Gate: recover the SSN of a hooked stub from clean neighbors at ±32-byte stride.
///
/// `text` is the `.text` section of the same PE. Neighbors that would leave that
/// window (page/section edge) are skipped — they are never read. Only a clean
/// Hell's Gate prologue counts — a hooked neighbor is not treated as a source
/// of SSN bytes (the architect snippet that reads `*(stub+4)` on any non-`0xE9`
/// byte would steal a CALL-hooked export's register immediate).
#[must_use]
pub fn halos_gate_recover(image: &[u8], func_offset: usize, text: TextSpan) -> Option<u16> {
    for idx in 1..=MAX_HALOS_GATE_NEIGHBOR_DEPTH {
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
        return Some(ResolvedSsn {
            ssn,
            hooked: false,
            cascade_blocked: false,
        });
    }
    // A slice shorter than the prologue cannot be classified as a hook vs
    // garbage sitting on a section edge — fail closed without a cascade flag.
    if stub.len() < PROLOGUE_LEN {
        return None;
    }
    if is_user_mode_hook(stub) || stub.first() != Some(&0x4C) {
        // Retrograde is per-stub (32 bytes). Scanning the rest of `.text` would
        // pick up a later export's syscall;ret and steal its SSN.
        let slot = stub.get(..STUB_LEN).unwrap_or(stub);
        if let Some(ssn) = retrograde_ssn_from_stub(slot) {
            return Some(ResolvedSsn {
                ssn,
                hooked: true,
                cascade_blocked: false,
            });
        }
        return match halos_gate_recover(image, func_offset, text) {
            Some(ssn) => Some(ResolvedSsn {
                ssn,
                hooked: true,
                cascade_blocked: false,
            }),
            None => Some(ResolvedSsn {
                ssn: 0,
                hooked: true,
                cascade_blocked: true,
            }),
        };
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
        let slot = stub.get(..STUB_LEN).unwrap_or(stub);
        if !(is_hells_gate_prologue(slot)
            || is_user_mode_hook(slot)
            || retrograde_ssn_from_stub(slot).is_some())
        {
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

/// JMP at the prologue, original `mov eax, SSN; syscall; ret` left at the tail.
/// Retrograde recovery must find the SSN without Halo's Gate neighbors.
#[must_use]
pub fn encode_jmp_hook_with_syscall_tail(ssn: u16) -> [u8; STUB_LEN] {
    let mut stub = encode_jmp_hook_stub();
    // Place the unhooked tail at the end of the 32-byte slot (past the 5-byte JMP).
    let i = STUB_LEN - 3; // syscall;ret
    stub[i] = 0x0F;
    stub[i + 1] = 0x05;
    stub[i + 2] = 0xC3;
    stub[i - 5] = 0xB8;
    let s = ssn.to_le_bytes();
    stub[i - 4] = s[0];
    stub[i - 3] = s[1];
    stub[i - 2] = 0x00;
    stub[i - 1] = 0x00;
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
    fn retrograde_recovers_ssn_from_syscall_ret_tail() {
        let stub = encode_jmp_hook_with_syscall_tail(0x18);
        assert!(is_user_mode_hook(&stub));
        assert_eq!(hells_gate_ssn(&stub), None);
        assert_eq!(retrograde_ssn_from_stub(&stub), Some(0x18));
        let mut image = vec![0u8; STUB_LEN];
        image.copy_from_slice(&stub);
        let resolved = resolve_stub_ssn(&image, 0, text(&image)).expect("tail SSN");
        assert_eq!(resolved.ssn, 0x18);
        assert!(resolved.hooked);
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
        let blocked = resolve_stub_ssn(&image, STUB_LEN, text).expect("inventory the hook");
        assert!(blocked.hooked);
        assert!(
            blocked.cascade_blocked,
            "must not steal poison SSN outside .text"
        );
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

    #[test]
    fn halos_gate_stops_at_five_neighbors() {
        // 6 hooked stubs then a clean one. Depth 6 would recover 0x20-6=0x1A
        // and dispatch a poisoned SSN. Cap is 5 — fail closed.
        let n = MAX_HALOS_GATE_NEIGHBOR_DEPTH + 2;
        let mut image = vec![0u8; STUB_LEN * n];
        for i in 0..=MAX_HALOS_GATE_NEIGHBOR_DEPTH {
            let off = i * STUB_LEN;
            image[off..off + STUB_LEN].copy_from_slice(&encode_jmp_hook_stub());
        }
        let clean_off = (MAX_HALOS_GATE_NEIGHBOR_DEPTH + 1) * STUB_LEN;
        image[clean_off..clean_off + STUB_LEN].copy_from_slice(&encode_clean_stub(0x20));
        assert!(halos_gate_recover(&image, 0, text(&image)).is_none());
        let r = resolve_stub_ssn(&image, 0, text(&image)).expect("cascade");
        assert!(r.cascade_blocked);
        assert!(r.hooked);
    }

    #[test]
    fn halos_gate_still_recovers_at_depth_five() {
        let n = MAX_HALOS_GATE_NEIGHBOR_DEPTH + 1;
        let mut image = vec![0u8; STUB_LEN * n];
        for i in 0..MAX_HALOS_GATE_NEIGHBOR_DEPTH {
            let off = i * STUB_LEN;
            image[off..off + STUB_LEN].copy_from_slice(&encode_jmp_hook_stub());
        }
        let clean_off = MAX_HALOS_GATE_NEIGHBOR_DEPTH * STUB_LEN;
        image[clean_off..clean_off + STUB_LEN].copy_from_slice(&encode_clean_stub(
            0x18 + MAX_HALOS_GATE_NEIGHBOR_DEPTH as u16,
        ));
        let recovered = halos_gate_recover(&image, 0, text(&image)).expect("depth-5 neighbor");
        assert_eq!(recovered, 0x18);
        let r = resolve_stub_ssn(&image, 0, text(&image)).expect("resolved");
        assert_eq!(r.ssn, 0x18);
        assert!(r.hooked);
        assert!(!r.cascade_blocked);
    }
}
