//! OT/ICS protocol state machines. Any frame that violates the expected
//! transition aborts the probe immediately so a fragile PLC is not fuzzed.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OtProtocol {
    ModbusTcp,
    Dnp3,
    S7,
    Iec61850,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FsmVerdict {
    Accept,
    Abort { reason: &'static str },
}

/// MBAP: proto_id MUST be 0, length MUST match remaining bytes, unit id SHOULD echo.
pub fn validate_modbus_tcp(request: &[u8], response: &[u8]) -> FsmVerdict {
    if response.len() < 8 {
        return FsmVerdict::Abort {
            reason: "modbus_truncated",
        };
    }
    let proto = u16::from_be_bytes([response[2], response[3]]);
    if proto != 0 {
        return FsmVerdict::Abort {
            reason: "modbus_non_zero_protocol_id",
        };
    }
    let declared = u16::from_be_bytes([response[4], response[5]]) as usize;
    // MBAP length = bytes after the length field (unit id + PDU).
    if declared < 2 || 6 + declared > response.len() {
        return FsmVerdict::Abort {
            reason: "modbus_length_mismatch",
        };
    }
    if request.len() >= 7 && response.len() >= 7 {
        let req_unit = request[6];
        let resp_unit = response[6];
        if req_unit != 0 && resp_unit != 0 && req_unit != resp_unit {
            return FsmVerdict::Abort {
                reason: "modbus_unit_id_mismatch",
            };
        }
    }
    FsmVerdict::Accept
}

/// DNP3 link-layer start bytes 0x05 0x64.
pub fn validate_dnp3(response: &[u8]) -> FsmVerdict {
    if response.len() < 10 {
        return FsmVerdict::Abort {
            reason: "dnp3_truncated",
        };
    }
    if response[0] != 0x05 || response[1] != 0x64 {
        return FsmVerdict::Abort {
            reason: "dnp3_bad_start",
        };
    }
    FsmVerdict::Accept
}

/// S7 / IEC 61850 ride ISO-on-TCP (TPKT version 3, reserved 0).
pub fn validate_tpkt(response: &[u8]) -> FsmVerdict {
    if response.len() < 4 {
        return FsmVerdict::Abort {
            reason: "tpkt_truncated",
        };
    }
    if response[0] != 0x03 || response[1] != 0x00 {
        return FsmVerdict::Abort {
            reason: "tpkt_version",
        };
    }
    let len = u16::from_be_bytes([response[2], response[3]]) as usize;
    if len < 4 || len > response.len() + 1024 {
        return FsmVerdict::Abort {
            reason: "tpkt_length",
        };
    }
    FsmVerdict::Accept
}

pub fn validate(protocol: OtProtocol, request: &[u8], response: &[u8]) -> FsmVerdict {
    match protocol {
        OtProtocol::ModbusTcp => validate_modbus_tcp(request, response),
        OtProtocol::Dnp3 => validate_dnp3(response),
        OtProtocol::S7 | OtProtocol::Iec61850 => validate_tpkt(response),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modbus_exception_is_valid_state() {
        // MBAP + unit 1 + exception 0x81 + illegal function
        let req = [0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x01, 0xFF];
        let resp = [0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x01, 0x81, 0x01];
        assert_eq!(validate_modbus_tcp(&req, &resp), FsmVerdict::Accept);
    }

    #[test]
    fn modbus_wrong_proto_aborts() {
        let req = [0u8; 8];
        let resp = [0x00, 0x01, 0x00, 0x01, 0x00, 0x03, 0x01, 0x81, 0x01];
        assert!(matches!(
            validate_modbus_tcp(&req, &resp),
            FsmVerdict::Abort {
                reason: "modbus_non_zero_protocol_id"
            }
        ));
    }

    #[test]
    fn dnp3_requires_start_bytes() {
        assert!(matches!(
            validate_dnp3(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
            FsmVerdict::Abort {
                reason: "dnp3_bad_start"
            }
        ));
        assert_eq!(
            validate_dnp3(&[0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00]),
            FsmVerdict::Accept
        );
    }

    #[test]
    fn tpkt_rejects_garbage() {
        assert!(matches!(
            validate_tpkt(&[0xFF, 0x00, 0x00, 0x04]),
            FsmVerdict::Abort {
                reason: "tpkt_version"
            }
        ));
    }
}
