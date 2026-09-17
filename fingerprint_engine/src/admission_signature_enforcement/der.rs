//! Minimal, panic-free DER (ASN.1) reader for the one thing OpenSSL's Rust binding does not
//! expose: reading an X.509v3 extension value by arbitrary OID.
//!
//! Sigstore's Fulcio binds the OIDC *issuer* of a keyless signer into a custom certificate
//! extension (OID `1.3.6.1.4.1.57264.1.1`, and the v2 form `…​.1.8`). Without the issuer we can
//! only prove *who* signed (the SAN), not *which identity provider* vouched for them — and a
//! policy that pins `subject == ci@example.com` without pinning the issuer is trivially forged by
//! anyone who can get a Fulcio cert for that SAN from a different, attacker-controlled OIDC
//! provider. So we parse the certificate DER ourselves, walking exactly the TLV path to the
//! extensions, with every length and bound checked. No allocation of untrusted length, no
//! recursion on attacker-controlled depth beyond the fixed certificate shape.

/// Fulcio "Issuer" extension, v1: raw UTF-8 issuer string in the OCTET STRING.
pub const FULCIO_ISSUER_OID_V1: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x01];
/// Fulcio "Issuer" extension, v2 (`1.3.6.1.4.1.57264.1.8`): a DER-encoded UTF8String value.
pub const FULCIO_ISSUER_OID_V2: &[u8] =
    &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x83, 0xBF, 0x30, 0x01, 0x08];

/// One parsed TLV: tag byte, value bytes, and the offset just past the whole element.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    end: usize,
}

/// Read a single TLV starting at `pos`. Returns `None` on any truncation or illegal length.
fn read_tlv(buf: &[u8], pos: usize) -> Option<Tlv<'_>> {
    let tag = *buf.get(pos)?;
    let len_byte = *buf.get(pos + 1)?;
    let (len, header) = if len_byte < 0x80 {
        (len_byte as usize, 2)
    } else {
        let num = (len_byte & 0x7F) as usize;
        // Reject indefinite-length (num == 0) and absurd length encodings.
        if num == 0 || num > 4 {
            return None;
        }
        let mut value = 0usize;
        for i in 0..num {
            value = (value << 8) | (*buf.get(pos + 2 + i)? as usize);
        }
        (value, 2 + num)
    };
    let start = pos + header;
    let end = start.checked_add(len)?;
    if end > buf.len() {
        return None;
    }
    Some(Tlv {
        tag,
        value: &buf[start..end],
        end,
    })
}

/// Iterate the child TLVs of a constructed value.
fn children(value: &[u8]) -> impl Iterator<Item = Tlv<'_>> {
    let mut pos = 0usize;
    std::iter::from_fn(move || {
        if pos >= value.len() {
            return None;
        }
        let tlv = read_tlv(value, pos)?;
        pos = tlv.end;
        Some(tlv)
    })
}

/// Extract the value of the extension identified by `oid` from a DER-encoded X.509 certificate.
/// The returned bytes are the raw contents of the extension's `extnValue` OCTET STRING.
#[must_use]
pub fn certificate_extension<'a>(cert_der: &'a [u8], oid: &[u8]) -> Option<&'a [u8]> {
    // Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
    let cert = read_tlv(cert_der, 0)?;
    if cert.tag != 0x30 {
        return None;
    }
    // tbsCertificate is the first child SEQUENCE.
    let tbs = children(cert.value).next()?;
    if tbs.tag != 0x30 {
        return None;
    }
    // Within the TBS the extensions live inside an EXPLICIT [3] context tag (0xA3).
    let ext_container = children(tbs.value).find(|t| t.tag == 0xA3)?;
    // [3] wraps a single SEQUENCE OF Extension.
    let ext_seq = children(ext_container.value).find(|t| t.tag == 0x30)?;
    for ext in children(ext_seq.value) {
        if ext.tag != 0x30 {
            continue;
        }
        let mut fields = children(ext.value);
        let extn_id = fields.next()?;
        if extn_id.tag != 0x06 || extn_id.value != oid {
            continue;
        }
        // Optional `critical BOOLEAN`, then the OCTET STRING extnValue.
        let mut next = fields.next()?;
        if next.tag == 0x01 {
            next = fields.next()?;
        }
        if next.tag != 0x04 {
            return None;
        }
        return Some(next.value);
    }
    None
}

/// Decode a Fulcio issuer extension value into a string, handling both the v1 (raw UTF-8) and v2
/// (DER UTF8String) encodings.
#[must_use]
pub fn decode_issuer_value(raw: &[u8]) -> Option<String> {
    // v2: the OCTET STRING contains a UTF8String (tag 0x0C).
    if let Some(tlv) = read_tlv(raw, 0) {
        if tlv.tag == 0x0C && tlv.end == raw.len() {
            return String::from_utf8(tlv.value.to_vec()).ok();
        }
    }
    // v1: the OCTET STRING is the raw issuer string.
    String::from_utf8(raw.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a length prefix (short/long form) for `len`.
    fn len_bytes(len: usize) -> Vec<u8> {
        if len < 0x80 {
            vec![len as u8]
        } else if len < 0x100 {
            vec![0x81, len as u8]
        } else {
            vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
        }
    }

    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(len_bytes(value.len()));
        out.extend_from_slice(value);
        out
    }

    /// Assemble a minimal Certificate DER whose TBS carries an extensions block with two
    /// extensions, one of which is the Fulcio issuer v1 extension.
    fn synthetic_cert(oid: &[u8], issuer_octets: &[u8]) -> Vec<u8> {
        let ext_issuer = tlv(0x30, &[tlv(0x06, oid), tlv(0x04, issuer_octets)].concat());
        // A decoy extension with a different OID, to prove OID matching actually discriminates.
        let decoy = tlv(
            0x30,
            &[
                tlv(0x06, &[0x55, 0x1D, 0x0F]),
                tlv(0x04, &[0x03, 0x02, 0x05, 0xA0]),
            ]
            .concat(),
        );
        let ext_seq = tlv(0x30, &[decoy, ext_issuer].concat());
        let ext_container = tlv(0xA3, &ext_seq);
        // Preceding TBS fields we do not read — a version [0] and a serial INTEGER — to make the
        // extensions genuinely the last of several children rather than the first.
        let version = tlv(0xA0, &tlv(0x02, &[0x02]));
        let serial = tlv(0x02, &[0x2A]);
        let tbs = tlv(0x30, &[version, serial, ext_container].concat());
        let sig_alg = tlv(0x30, &tlv(0x06, &[0x2A]));
        let sig_val = tlv(0x03, &[0x00, 0x01]);
        tlv(0x30, &[tbs, sig_alg, sig_val].concat())
    }

    #[test]
    fn extracts_v1_issuer_extension() {
        let cert = synthetic_cert(FULCIO_ISSUER_OID_V1, b"https://accounts.google.com");
        let raw = certificate_extension(&cert, FULCIO_ISSUER_OID_V1).expect("extension present");
        assert_eq!(
            decode_issuer_value(raw).unwrap(),
            "https://accounts.google.com"
        );
    }

    #[test]
    fn extracts_v2_utf8string_issuer_extension() {
        let inner = tlv(0x0C, b"https://token.actions.githubusercontent.com");
        let cert = synthetic_cert(FULCIO_ISSUER_OID_V2, &inner);
        let raw = certificate_extension(&cert, FULCIO_ISSUER_OID_V2).expect("extension present");
        assert_eq!(
            decode_issuer_value(raw).unwrap(),
            "https://token.actions.githubusercontent.com"
        );
    }

    #[test]
    fn missing_oid_returns_none() {
        let cert = synthetic_cert(FULCIO_ISSUER_OID_V1, b"https://accounts.google.com");
        assert!(certificate_extension(&cert, FULCIO_ISSUER_OID_V2).is_none());
    }

    #[test]
    fn truncated_der_never_panics() {
        let cert = synthetic_cert(FULCIO_ISSUER_OID_V1, b"issuer");
        for cut in 0..cert.len() {
            // Must return None (or the value) but never panic on any prefix.
            let _ = certificate_extension(&cert[..cut], FULCIO_ISSUER_OID_V1);
        }
    }

    #[test]
    fn rejects_absurd_length_prefix() {
        // Tag 0x30, long-form length claiming 5 length bytes (num > 4) -> refused.
        let buf = [0x30, 0x85, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert!(certificate_extension(&buf, FULCIO_ISSUER_OID_V1).is_none());
    }
}
