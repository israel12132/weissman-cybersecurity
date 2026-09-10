//! Dynamic PLC decoy — Modbus/S7 look-alike replies that never drive a real process.
//!
//! Writes, CPU-stop, and Direct Operate are answered with protocol exceptions.
//! SafeRead (FC03/04, COTP CR) returns canned registers / CC so a scanner
//! wastes time on bait while SOAR records the source.

use super::parsers::{parse_modbus_frame, parse_s7_iso_on_tcp};
use super::policy::MODBUS_WRITE_BLOCKED;

/// Canned holding-register bytes (looks like a 42 °C / 0x002A analog).
const DECOY_REG: [u8; 2] = [0x00, 0x2A];

#[must_use]
pub fn decoy_modbus_reply(request: &[u8]) -> Option<Vec<u8>> {
    let frame = parse_modbus_frame(request).ok()?;
    let fc = frame.pdu.function & 0x7f;
    if MODBUS_WRITE_BLOCKED.contains(&fc) {
        return Some(modbus_exception(
            frame.header.transaction_id,
            frame.header.unit_id,
            fc,
            0x01,
        ));
    }
    match fc {
        0x03 | 0x04 => Some(modbus_read_ok(
            frame.header.transaction_id,
            frame.header.unit_id,
            fc,
            &DECOY_REG,
        )),
        0x01 | 0x02 => Some(modbus_read_ok(
            frame.header.transaction_id,
            frame.header.unit_id,
            fc,
            &[0x01],
        )),
        _ => Some(modbus_exception(
            frame.header.transaction_id,
            frame.header.unit_id,
            fc,
            0x01,
        )),
    }
}

fn modbus_exception(tx: u16, unit: u8, fc: u8, code: u8) -> Vec<u8> {
    let pdu = [fc | 0x80, code];
    wrap_mbap(tx, unit, &pdu)
}

fn modbus_read_ok(tx: u16, unit: u8, fc: u8, data: &[u8]) -> Vec<u8> {
    let mut pdu = Vec::with_capacity(2 + data.len());
    pdu.push(fc);
    pdu.push(u8::try_from(data.len()).unwrap_or(0));
    pdu.extend_from_slice(data);
    wrap_mbap(tx, unit, &pdu)
}

fn wrap_mbap(tx: u16, unit: u8, pdu: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(7 + pdu.len());
    f.extend_from_slice(&tx.to_be_bytes());
    f.extend_from_slice(&[0x00, 0x00]);
    let length = u16::try_from(pdu.len() + 1).unwrap_or(1);
    f.extend_from_slice(&length.to_be_bytes());
    f.push(unit);
    f.extend_from_slice(pdu);
    f
}

/// COTP CR (0xE0) → CC (0xD0). Never follows with CPU-control.
#[must_use]
pub fn decoy_s7_reply(request: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_s7_iso_on_tcp(request).ok()?;
    if parsed.cotp.pdu_type != 0xe0 {
        return None;
    }
    // RFC 1006 TPKT + COTP CC. dst/src refs swapped vs CR.
    Some(vec![
        0x03, 0x00, 0x00, 0x16, 0x11, 0xd0, 0x00, 0x01, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00,
        0xc2, 0x02, 0x01, 0x00, 0xc0, 0x01, 0x09,
    ])
}

#[must_use]
pub fn decoy_for_port(port: u16, request: &[u8]) -> Option<Vec<u8>> {
    match port {
        502 => decoy_modbus_reply(request),
        102 => decoy_s7_reply(request),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ot_ics_hardening::parsers::parse_modbus_frame;

    fn fc03(tx: u16, unit: u8) -> Vec<u8> {
        let pdu = [0x03, 0x00, 0x00, 0x00, 0x01];
        wrap_mbap(tx, unit, &pdu)
    }

    #[test]
    fn decoy_answers_read_not_write() {
        let reply = decoy_modbus_reply(&fc03(1, 1)).expect("read");
        let parsed = parse_modbus_frame(&reply).expect("mbap");
        assert_eq!(parsed.pdu.function, 0x03);
        assert!(!parsed.pdu.exception);

        let write = wrap_mbap(2, 1, &[0x06, 0x00, 0x00, 0x00, 0x01]);
        let denied = decoy_modbus_reply(&write).expect("exc");
        let p = parse_modbus_frame(&denied).expect("exc parse");
        assert!(p.pdu.exception);
        assert_eq!(p.pdu.exception_code, Some(0x01));
    }

    #[test]
    fn decoy_s7_cc_on_cr() {
        let cr: [u8; 22] = [
            0x03, 0x00, 0x00, 0x16, 0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01,
            0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x09,
        ];
        let cc = decoy_s7_reply(&cr).expect("cc");
        assert_eq!(cc[5], 0xd0);
    }
}
