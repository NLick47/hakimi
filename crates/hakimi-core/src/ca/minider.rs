//! Minimal DER reader for the fields hakimi needs from its own CA: the
//! subject rendering, the validity instants and the subject key identifier.
//! Semantics mirror x509-parser (subject display format, RFC 5280 UTCTime
//! year pivot, UTF8String-only CN values); the test suite cross-checks both
//! parsers against each other and against asn1-rs primitives.

use anyhow::{anyhow, bail, Result};
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset};

pub(super) const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_SUBJECT_KEY_IDENTIFIER: &[u8] = &[0x55, 0x1d, 0x0e];

pub(super) struct CaFields {
    pub(super) subject: String,
    pub(super) subject_attrs: Vec<SubjectAttr>,
    pub(super) not_before: OffsetDateTime,
    pub(super) not_after: OffsetDateTime,
    pub(super) ski: Option<Vec<u8>>,
}

pub(super) struct SubjectAttr {
    pub(super) oid: Vec<u8>,
    pub(super) tag: u8,
    pub(super) value: Vec<u8>,
}

pub(super) fn parse_ca_fields(der: &[u8]) -> Result<CaFields> {
    let certificate = tlv(der)?;
    if certificate.tag != 0x30 {
        bail!("not a DER certificate");
    }
    let tbs = tlv(certificate.content)?;
    if tbs.tag != 0x30 {
        bail!("missing tbsCertificate");
    }

    let mut cursor = tbs.content;
    let mut field = tlv(cursor)?;
    if field.tag == 0xa0 {
        cursor = field.rest;
        field = tlv(cursor)?;
    }
    if field.tag != 0x02 {
        bail!("missing serialNumber");
    }
    cursor = field.rest;
    field = tlv(cursor)?;
    if field.tag != 0x30 {
        bail!("missing signature algorithm");
    }
    cursor = field.rest;
    field = tlv(cursor)?;
    if field.tag != 0x30 {
        bail!("missing issuer");
    }
    cursor = field.rest;
    field = tlv(cursor)?;
    if field.tag != 0x30 {
        bail!("missing validity");
    }
    let (not_before, not_after) = parse_validity(field.content)?;
    cursor = field.rest;
    field = tlv(cursor)?;
    if field.tag != 0x30 {
        bail!("missing subject");
    }
    let (subject_attrs, subject) = parse_name(field.content)?;
    cursor = field.rest;
    field = tlv(cursor)?;
    if field.tag != 0x30 {
        bail!("missing subjectPublicKeyInfo");
    }
    cursor = field.rest;
    let mut ski = None;
    while !cursor.is_empty() {
        field = tlv(cursor)?;
        cursor = field.rest;
        match field.tag {
            0x81 | 0x82 => {}
            0xa3 => ski = parse_ski(field.content)?,
            _ => bail!("unexpected tbsCertificate field"),
        }
    }

    Ok(CaFields {
        subject,
        subject_attrs,
        not_before,
        not_after,
        ski,
    })
}

/// Mirrors asn1-rs's `Any::as_str`: UTF8String is the only accepted type.
pub(super) fn utf8_string(tag: u8, value: &[u8]) -> Result<&str> {
    if tag != 0x0c {
        bail!("value is not a UTF8String");
    }
    std::str::from_utf8(value).map_err(|_| anyhow!("invalid UTF8String"))
}

struct Tlv<'a> {
    tag: u8,
    content: &'a [u8],
    rest: &'a [u8],
}

fn tlv(bytes: &[u8]) -> Result<Tlv<'_>> {
    let Some((&tag, after_tag)) = bytes.split_first() else {
        bail!("truncated DER");
    };
    let Some((&first, after_len)) = after_tag.split_first() else {
        bail!("truncated DER");
    };
    let (len_bytes, length) = if first < 0x80 {
        (&[][..], first as usize)
    } else {
        let count = (first & 0x7f) as usize;
        if count == 0 || count > 4 {
            bail!("unsupported DER length");
        }
        if after_len.len() < count {
            bail!("truncated DER");
        }
        if after_len[0] == 0 {
            bail!("non-minimal DER length");
        }
        let mut length = 0usize;
        for &digit in &after_len[..count] {
            length = (length << 8) | digit as usize;
        }
        (&after_len[..count], length)
    };
    let start = len_bytes.len();
    let content = after_len
        .get(start..start + length)
        .ok_or_else(|| anyhow!("truncated DER"))?;
    Ok(Tlv {
        tag,
        content,
        rest: &after_len[start + length..],
    })
}

fn parse_validity(content: &[u8]) -> Result<(OffsetDateTime, OffsetDateTime)> {
    let first = tlv(content)?;
    let second = tlv(first.rest)?;
    if !second.rest.is_empty() {
        bail!("trailing validity bytes");
    }
    Ok((
        parse_time(first.tag, first.content)?,
        parse_time(second.tag, second.content)?,
    ))
}

pub(super) fn parse_time(tag: u8, content: &[u8]) -> Result<OffsetDateTime> {
    match tag {
        0x17 => parse_utc_time(content),
        0x18 => parse_generalized_time(content),
        _ => bail!("unsupported validity time"),
    }
}

fn digits(hi: u8, lo: u8) -> Result<u8> {
    if !hi.is_ascii_digit() || !lo.is_ascii_digit() {
        bail!("malformed time");
    }
    Ok((hi - b'0') * 10 + (lo - b'0'))
}

fn digit_pairs(content: &[u8], count: usize) -> Result<Vec<u8>> {
    if content.len() < count * 2 {
        bail!("malformed time");
    }
    (0..count)
        .map(|i| digits(content[2 * i], content[2 * i + 1]))
        .collect()
}

fn parse_zone(content: &[u8]) -> Result<UtcOffset> {
    let (hours, minutes) = match content {
        [b'Z'] => return Ok(UtcOffset::UTC),
        [b'+', h1, h2, m1, m2] => (digits(*h1, *h2)? as i8, digits(*m1, *m2)? as i8),
        // asn1-rs negates only the hours component for '-'
        [b'-', h1, h2, m1, m2] => (-(digits(*h1, *h2)? as i8), digits(*m1, *m2)? as i8),
        _ => bail!("malformed time zone"),
    };
    Ok(UtcOffset::from_hms(hours, minutes, 0)?)
}

fn parse_utc_time(content: &[u8]) -> Result<OffsetDateTime> {
    let d = digit_pairs(content, 5)?;
    let (second, tail) = match content.len() {
        11 => (0u8, &content[10..]),
        // asn1-rs always reads two bytes here as seconds and requires digits
        len if len > 11 => (digits(content[10], content[11])?, &content[12..]),
        _ => bail!("malformed time"),
    };
    let offset = parse_zone(tail)?;
    let year: i32 = if d[0] >= 50 {
        1900 + d[0] as i32
    } else {
        2000 + d[0] as i32
    };
    assemble(year, d[1], d[2], d[3], d[4], second, 0, offset)
}

fn parse_generalized_time(content: &[u8]) -> Result<OffsetDateTime> {
    let d = digit_pairs(content, 6)?;
    let mut cursor = &content[12..];
    let mut second = 0u8;
    if cursor.len() >= 2 {
        second = digits(cursor[0], cursor[1])?;
        cursor = &cursor[2..];
    }
    let mut millisecond = 0u16;
    if let Some((&marker, rest)) = cursor.split_first() {
        if marker == b'.' {
            let mut value = 0u16;
            let mut digits_read = 0usize;
            let mut tail = rest;
            for idx in 0..=4usize {
                let Some(&byte) = tail.first() else {
                    if idx == 0 {
                        bail!("malformed time fraction");
                    }
                    digits_read = idx;
                    break;
                };
                if idx == 4 {
                    bail!("malformed time fraction");
                }
                match byte {
                    b'0'..=b'9' => {
                        value = value * 10 + (byte - b'0') as u16;
                        tail = &tail[1..];
                    }
                    b'Z' | b'+' | b'-' => {
                        digits_read = idx;
                        break;
                    }
                    _ => bail!("malformed time fraction"),
                }
            }
            millisecond = match digits_read {
                1 => value * 100,
                2 => value * 10,
                _ => value,
            };
            cursor = tail;
        }
    }
    // asn1-rs's DER constraints require a trailing 'Z' on GeneralizedTime
    let offset = match cursor {
        [b'Z'] => UtcOffset::UTC,
        _ => bail!("malformed time zone"),
    };
    let year = (d[0] as i32) * 100 + d[1] as i32;
    assemble(year, d[2], d[3], d[4], d[5], second, millisecond, offset)
}

#[allow(clippy::too_many_arguments)]
fn assemble(
    year: i32,
    month: u8,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
    millisecond: u16,
    offset: UtcOffset,
) -> Result<OffsetDateTime> {
    let date = Date::from_calendar_date(year, Month::try_from(month)?, day)?;
    let time = Time::from_hms_milli(hour, minute, second, millisecond)?;
    Ok(PrimitiveDateTime::new(date, time).assume_offset(offset))
}

fn parse_name(content: &[u8]) -> Result<(Vec<SubjectAttr>, String)> {
    let mut attrs = Vec::new();
    let mut display = String::new();
    let mut cursor = content;
    while !cursor.is_empty() {
        let rdn = tlv(cursor)?;
        if rdn.tag != 0x31 {
            bail!("expected RDN set");
        }
        cursor = rdn.rest;
        if !display.is_empty() {
            display.push_str(", ");
        }
        let mut inner = rdn.content;
        let mut first = true;
        while !inner.is_empty() {
            let atv = tlv(inner)?;
            if atv.tag != 0x30 {
                bail!("expected attribute");
            }
            inner = atv.rest;
            let oid = tlv(atv.content)?;
            if oid.tag != 0x06 {
                bail!("expected attribute OID");
            }
            let value = tlv(oid.rest)?;
            if !first {
                display.push_str(" + ");
            }
            first = false;
            display.push_str(&oid_label(oid.content));
            display.push('=');
            display.push_str(&attr_display(&value)?);
            attrs.push(SubjectAttr {
                oid: oid.content.to_vec(),
                tag: value.tag,
                value: value.content.to_vec(),
            });
        }
    }
    Ok((attrs, display))
}

fn attr_display(value: &Tlv<'_>) -> Result<String> {
    match value.tag {
        // asn1-rs renders every single-byte string type as raw UTF-8
        0x07 | 0x0c | 0x12 | 0x13 | 0x14 | 0x15 | 0x16 | 0x19 | 0x1a | 0x1b => {
            String::from_utf8(value.content.to_vec()).map_err(|_| anyhow!("invalid attribute"))
        }
        0x1e => {
            let units: Vec<u16> = value
                .content
                .chunks_exact(2)
                .map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).map_err(|_| anyhow!("invalid BMPString"))
        }
        _ => Ok(hex::encode_upper(value.content)),
    }
}

fn oid_label(oid: &[u8]) -> String {
    match oid {
        [0x55, 0x04, 0x03] => "CN".into(),
        [0x55, 0x04, 0x06] => "C".into(),
        [0x55, 0x04, 0x07] => "L".into(),
        [0x55, 0x04, 0x08] => "ST".into(),
        [0x55, 0x04, 0x0a] => "O".into(),
        [0x55, 0x04, 0x0b] => "OU".into(),
        [0x09, 0x92, 0x26, 0x89, 0x93, 0xf2, 0x2c, 0x64, 0x01, 0x19] => "DC".into(),
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x01] => "Email".into(),
        _ => format!("OID({})", oid_dotted(oid)),
    }
}

fn oid_dotted(oid: &[u8]) -> String {
    let mut subs = Vec::new();
    let mut acc: u64 = 0;
    for &byte in oid {
        acc = (acc << 7) | (byte & 0x7f) as u64;
        if byte & 0x80 == 0 {
            subs.push(acc);
            acc = 0;
        }
    }
    let mut parts: Vec<String> = match subs.first() {
        Some(&first) if first < 40 => vec!["0".into(), first.to_string()],
        Some(&first) if first < 80 => vec!["1".into(), (first - 40).to_string()],
        Some(&first) => vec!["2".into(), (first - 80).to_string()],
        None => Vec::new(),
    };
    parts.extend(subs.iter().skip(1).map(|sub| sub.to_string()));
    parts.join(".")
}

fn parse_ski(content: &[u8]) -> Result<Option<Vec<u8>>> {
    let extensions = tlv(content)?;
    if extensions.tag != 0x30 {
        bail!("expected extension list");
    }
    let mut cursor = extensions.content;
    while !cursor.is_empty() {
        let extension = tlv(cursor)?;
        if extension.tag != 0x30 {
            bail!("expected extension");
        }
        cursor = extension.rest;
        let oid = tlv(extension.content)?;
        if oid.tag != 0x06 {
            bail!("expected extension OID");
        }
        let mut field = tlv(oid.rest)?;
        if field.tag == 0x01 {
            field = tlv(field.rest)?;
        }
        if field.tag != 0x04 {
            bail!("expected extension value");
        }
        if oid.content == OID_SUBJECT_KEY_IDENTIFIER {
            let key_id = tlv(field.content)?;
            if key_id.tag != 0x04 {
                bail!("malformed subject key identifier");
            }
            return Ok(Some(key_id.content.to_vec()));
        }
    }
    Ok(None)
}
