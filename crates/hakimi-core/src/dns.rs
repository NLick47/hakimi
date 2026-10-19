//! Minimal RFC 1035 / RFC 9460 wire codec, enough for DoH A, AAAA and HTTPS queries.
//!
//! We deliberately keep this in-tree instead of pulling a full DNS stack: the proxy only
//! needs wire-format POST (RFC 8484), and a small auditable parser is easier to harden against
//! malformed remote data.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, Context, Result};

pub const TYPE_A: u16 = 1;
pub const TYPE_CNAME: u16 = 5;
pub const TYPE_AAAA: u16 = 28;
pub const TYPE_HTTPS: u16 = 65;
pub const CLASS_IN: u16 = 1;

const MAX_RECORDS: usize = 512;
const MAX_NAME_HOPS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpsRecord {
    pub priority: u16,
    pub target: String,
    pub alpn: Vec<String>,
    pub no_default_alpn: bool,
    pub port: Option<u16>,
    pub ipv4_hints: Vec<Ipv4Addr>,
    pub ipv6_hints: Vec<Ipv6Addr>,
    pub ech: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RData {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Cname(String),
    Https(HttpsRecord),
    Other(Vec<u8>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: RData,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub id: u16,
    pub flags: u16,
    pub rcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authority: Vec<DnsRecord>,
    pub additional: Vec<DnsRecord>,
}

impl DnsResponse {
    pub fn is_nxdomain(&self) -> bool {
        self.rcode == 3
    }

    pub fn is_servfail(&self) -> bool {
        self.rcode == 2
    }

    pub fn rcode_text(&self) -> &'static str {
        match self.rcode {
            0 => "NOERROR",
            1 => "FORMERR",
            2 => "SERVFAIL",
            3 => "NXDOMAIN",
            4 => "NOTIMP",
            5 => "REFUSED",
            _ => "OTHER",
        }
    }
}

/// Parsed result for one name/type pair after following CNAMEs inside a response.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedAnswer {
    pub ips: Vec<IpAddr>,
    pub hints: Vec<IpAddr>,
    pub ech: Option<Vec<u8>>,
    pub ttl: u32,
    pub cname: Option<String>,
    pub https_present: bool,
}

/// Build a recursive query. `name` must already be ASCII (IDNA-normalized).
pub fn build_query(name: &str, qtype: u16, id: u16) -> Result<Vec<u8>> {
    let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.is_empty() || name.len() > 253 {
        bail!("invalid query name `{name}`");
    }
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    for label in name.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in `{name}`");
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(out)
}

pub fn parse_response(bytes: &[u8]) -> Result<DnsResponse> {
    if bytes.len() < 12 {
        bail!("DNS response is shorter than the header");
    }
    let id = u16::from_be_bytes([bytes[0], bytes[1]]);
    let flags = u16::from_be_bytes([bytes[2], bytes[3]]);
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let nscount = u16::from_be_bytes([bytes[8], bytes[9]]) as usize;
    let arcount = u16::from_be_bytes([bytes[10], bytes[11]]) as usize;
    for (count, label) in [
        (qdcount, "question"),
        (ancount, "answer"),
        (nscount, "authority"),
        (arcount, "additional"),
    ] {
        if count > MAX_RECORDS {
            bail!("DNS response has too many {label} records ({count})");
        }
    }

    let mut pos = 12usize;
    let mut questions = Vec::with_capacity(qdcount);
    for _ in 0..qdcount {
        let name = read_name(bytes, &mut pos)?;
        let qtype = read_u16(bytes, &mut pos)?;
        let _class = read_u16(bytes, &mut pos)?;
        questions.push(DnsQuestion { name, qtype });
    }
    let answers = read_records(bytes, &mut pos, ancount)?;
    let authority = read_records(bytes, &mut pos, nscount)?;
    let additional = read_records(bytes, &mut pos, arcount)?;

    Ok(DnsResponse {
        id,
        flags,
        rcode: (flags & 0x000f) as u8,
        questions,
        answers,
        authority,
        additional,
    })
}

fn read_records(bytes: &[u8], pos: &mut usize, count: usize) -> Result<Vec<DnsRecord>> {
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(read_record(bytes, pos)?);
    }
    Ok(records)
}

fn read_record(bytes: &[u8], pos: &mut usize) -> Result<DnsRecord> {
    let name = read_name(bytes, pos)?;
    let rtype = read_u16(bytes, pos)?;
    let class = read_u16(bytes, pos)?;
    let ttl = read_u32(bytes, pos)?;
    let rdlen = read_u16(bytes, pos)? as usize;
    let start = *pos;
    let end = start
        .checked_add(rdlen)
        .filter(|end| *end <= bytes.len())
        .context("DNS record extends past the message")?;
    let data = match rtype {
        TYPE_A => {
            if rdlen != 4 {
                bail!("A record has length {rdlen}, expected 4");
            }
            RData::A(Ipv4Addr::new(
                bytes[start],
                bytes[start + 1],
                bytes[start + 2],
                bytes[start + 3],
            ))
        }
        TYPE_AAAA => {
            if rdlen != 16 {
                bail!("AAAA record has length {rdlen}, expected 16");
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[start..end]);
            RData::Aaaa(Ipv6Addr::from(octets))
        }
        TYPE_CNAME => {
            let mut cursor = start;
            let target = read_name(bytes, &mut cursor)?;
            if cursor != end {
                bail!("CNAME record has trailing bytes");
            }
            RData::Cname(target)
        }
        TYPE_HTTPS => RData::Https(read_https(bytes, start, end)?),
        _ => RData::Other(bytes[start..end].to_vec()),
    };
    *pos = end;
    Ok(DnsRecord {
        name,
        rtype,
        class,
        ttl,
        data,
    })
}

fn read_https(bytes: &[u8], start: usize, end: usize) -> Result<HttpsRecord> {
    let mut pos = start;
    if pos + 2 > end {
        bail!("HTTPS record is truncated");
    }
    let priority = read_u16(bytes, &mut pos)?;
    let target = read_name(bytes, &mut pos)?;
    if pos > end {
        bail!("HTTPS target name escapes the record");
    }
    let mut record = HttpsRecord {
        priority,
        target,
        alpn: Vec::new(),
        no_default_alpn: false,
        port: None,
        ipv4_hints: Vec::new(),
        ipv6_hints: Vec::new(),
        ech: None,
    };
    while pos < end {
        if pos + 4 > end {
            bail!("HTTPS SvcParam is truncated");
        }
        let key = read_u16(bytes, &mut pos)?;
        let len = read_u16(bytes, &mut pos)? as usize;
        let value_end = pos
            .checked_add(len)
            .filter(|value_end| *value_end <= end)
            .context("HTTPS SvcParam escapes the record")?;
        let value = &bytes[pos..value_end];
        match key {
            1 => {
                // alpn: sequence of length-prefixed identifiers
                let mut cursor = 0usize;
                while cursor < value.len() {
                    let item_len = value[cursor] as usize;
                    cursor += 1;
                    if cursor + item_len > value.len() {
                        bail!("HTTPS alpn value is malformed");
                    }
                    record.alpn.push(
                        std::str::from_utf8(&value[cursor..cursor + item_len])
                            .context("HTTPS alpn is not UTF-8")?
                            .to_string(),
                    );
                    cursor += item_len;
                }
            }
            2 => record.no_default_alpn = true,
            3 => {
                if value.len() != 2 {
                    bail!("HTTPS port has length {}", value.len());
                }
                record.port = Some(u16::from_be_bytes([value[0], value[1]]));
            }
            4 => {
                if value.len() % 4 != 0 {
                    bail!("HTTPS ipv4hint is malformed");
                }
                for chunk in value.chunks_exact(4) {
                    record
                        .ipv4_hints
                        .push(Ipv4Addr::new(chunk[0], chunk[1], chunk[2], chunk[3]));
                }
            }
            5 => {
                if !value.is_empty() {
                    record.ech = Some(value.to_vec());
                }
            }
            6 => {
                if value.len() % 16 != 0 {
                    bail!("HTTPS ipv6hint is malformed");
                }
                for chunk in value.chunks_exact(16) {
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(chunk);
                    record.ipv6_hints.push(Ipv6Addr::from(octets));
                }
            }
            _ => {}
        }
        pos = value_end;
    }
    Ok(record)
}

fn read_name(bytes: &[u8], pos: &mut usize) -> Result<String> {
    let start = *pos;
    let mut cursor = start;
    let mut jumped = false;
    let mut hops = 0usize;
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *bytes
            .get(cursor)
            .context("DNS name is truncated or points outside the message")?;
        match len & 0xc0 {
            0xc0 => {
                let low = *bytes
                    .get(cursor + 1)
                    .context("DNS compression pointer is truncated")?;
                let pointer = (((len & 0x3f) as usize) << 8) | low as usize;
                if !jumped {
                    *pos = cursor + 2;
                    jumped = true;
                }
                if pointer >= cursor {
                    bail!("DNS compression pointer does not point backwards");
                }
                hops += 1;
                if hops > MAX_NAME_HOPS {
                    bail!("DNS name has too many compression hops");
                }
                cursor = pointer;
            }
            0x00 => {
                cursor += 1;
                if len == 0 {
                    break;
                }
                let end = cursor + len as usize;
                if end > bytes.len() {
                    bail!("DNS label extends past the message");
                }
                let label = std::str::from_utf8(&bytes[cursor..end])
                    .context("DNS label is not ASCII")?
                    .to_ascii_lowercase();
                if !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                {
                    bail!("DNS label contains unsupported characters");
                }
                labels.push(label);
                cursor = end;
                if labels.iter().map(|l| l.len() + 1).sum::<usize>() > 254 {
                    bail!("DNS name is too long");
                }
            }
            _ => bail!("unsupported DNS label encoding"),
        }
    }
    if !jumped {
        *pos = cursor;
    }
    Ok(labels.join("."))
}

fn read_u16(bytes: &[u8], pos: &mut usize) -> Result<u16> {
    if *pos + 2 > bytes.len() {
        bail!("unexpected end of DNS message");
    }
    let value = u16::from_be_bytes([bytes[*pos], bytes[*pos + 1]]);
    *pos += 2;
    Ok(value)
}

fn read_u32(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    if *pos + 4 > bytes.len() {
        bail!("unexpected end of DNS message");
    }
    let value = u32::from_be_bytes([
        bytes[*pos],
        bytes[*pos + 1],
        bytes[*pos + 2],
        bytes[*pos + 3],
    ]);
    *pos += 4;
    Ok(value)
}

/// Follow CNAMEs inside a response and collect the requested record type.
pub fn extract_answer(response: &DnsResponse, name: &str, qtype: u16) -> ResolvedAnswer {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let mut by_name: HashMap<&str, Vec<&DnsRecord>> = HashMap::new();
    for record in response.answers.iter() {
        by_name
            .entry(record.name.as_str())
            .or_default()
            .push(record);
    }

    let mut result = ResolvedAnswer::default();
    let mut current = name;
    let mut ttl: Option<u32> = None;
    let mut cname_hops = 0usize;
    let mut visited = std::collections::HashSet::new();
    loop {
        if !visited.insert(current.clone()) || cname_hops > 16 {
            break;
        }
        let Some(records) = by_name.get(current.as_str()) else {
            break;
        };
        let mut found = false;
        let mut next: Option<String> = None;
        for record in records {
            let take_ttl = |ttl: &mut Option<u32>| {
                *ttl = Some(ttl.map_or(record.ttl, |old| old.min(record.ttl)));
            };
            match (&record.data, qtype) {
                (RData::A(ip), TYPE_A) => {
                    take_ttl(&mut ttl);
                    let ip = IpAddr::V4(*ip);
                    if !result.ips.contains(&ip) {
                        result.ips.push(ip);
                    }
                    found = true;
                }
                (RData::Aaaa(ip), TYPE_AAAA) => {
                    take_ttl(&mut ttl);
                    let ip = IpAddr::V6(*ip);
                    if !result.ips.contains(&ip) {
                        result.ips.push(ip);
                    }
                    found = true;
                }
                (RData::Https(https), TYPE_HTTPS) => {
                    result.https_present = true;
                    if https.priority == 0 {
                        if !https.target.is_empty() {
                            next = Some(https.target.clone());
                        }
                        take_ttl(&mut ttl);
                        continue;
                    }
                    take_ttl(&mut ttl);
                    for ip in &https.ipv4_hints {
                        let ip = IpAddr::V4(*ip);
                        if !result.hints.contains(&ip) {
                            result.hints.push(ip);
                        }
                    }
                    for ip in &https.ipv6_hints {
                        let ip = IpAddr::V6(*ip);
                        if !result.hints.contains(&ip) {
                            result.hints.push(ip);
                        }
                    }
                    if result.ech.is_none() {
                        result.ech = https.ech.clone();
                    }
                    found = true;
                }
                (RData::Cname(target), _) => {
                    take_ttl(&mut ttl);
                    if next.is_none() {
                        next = Some(target.clone());
                    }
                    // A CNAME is not the requested type; keep walking.
                }
                _ => {}
            }
        }
        if found {
            break;
        }
        match next {
            Some(target) if !target.is_empty() && target != current => {
                result.cname.get_or_insert_with(|| target.clone());
                current = target;
                cname_hops += 1;
            }
            _ => break,
        }
    }
    result.ttl = ttl.unwrap_or(0);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn push_name(out: &mut Vec<u8>, name: &str) {
        for label in name.split('.').filter(|l| !l.is_empty()) {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
    }

    fn response_for(query: &[u8], rcode: u8, answers: &[u8], ancount: u16) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&query[0..2]); // id
        out.extend_from_slice(&(0x8180u16 | rcode as u16).to_be_bytes()); // QR, RD, RA
        out.extend_from_slice(&1u16.to_be_bytes());
        out.extend_from_slice(&ancount.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&0u16.to_be_bytes());
        out.extend_from_slice(&query[12..]);
        out.extend_from_slice(answers);
        out
    }

    fn answer_a(name: &str, ttl: u32, ip: [u8; 4]) -> Vec<u8> {
        let mut out = Vec::new();
        push_name(&mut out, name);
        out.extend_from_slice(&TYPE_A.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ttl.to_be_bytes());
        out.extend_from_slice(&4u16.to_be_bytes());
        out.extend_from_slice(&ip);
        out
    }

    #[test]
    fn builds_query_and_parses_a() {
        let query = build_query("example.com", TYPE_A, 0x1234).unwrap();
        let answers = answer_a("example.com", 300, [93, 184, 216, 34]);
        let wire = response_for(&query, 0, &answers, 1);
        let response = parse_response(&wire).unwrap();
        assert_eq!(response.id, 0x1234);
        assert_eq!(response.questions[0].name, "example.com");
        let answer = extract_answer(&response, "example.com", TYPE_A);
        assert_eq!(answer.ips, vec!["93.184.216.34".parse::<IpAddr>().unwrap()]);
        assert_eq!(answer.ttl, 300);
    }

    #[test]
    fn follows_cname_chain() {
        let query = build_query("www.example.com", TYPE_A, 1).unwrap();
        let mut answers = Vec::new();
        push_name(&mut answers, "www.example.com");
        answers.extend_from_slice(&TYPE_CNAME.to_be_bytes());
        answers.extend_from_slice(&CLASS_IN.to_be_bytes());
        answers.extend_from_slice(&120u32.to_be_bytes());
        let mut rdata = Vec::new();
        push_name(&mut rdata, "edge.example.com");
        answers.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answers.extend_from_slice(&rdata);
        answers.extend_from_slice(&answer_a("edge.example.com", 60, [1, 2, 3, 4]));
        let wire = response_for(&query, 0, &answers, 2);
        let response = parse_response(&wire).unwrap();
        let answer = extract_answer(&response, "www.example.com", TYPE_A);
        assert_eq!(answer.ips, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(answer.cname.as_deref(), Some("edge.example.com"));
        assert_eq!(answer.ttl, 60);
    }

    #[test]
    fn parses_https_ech_and_hints() {
        let query = build_query("pixiv.net", TYPE_HTTPS, 7).unwrap();
        let mut answers = Vec::new();
        push_name(&mut answers, "pixiv.net");
        answers.extend_from_slice(&TYPE_HTTPS.to_be_bytes());
        answers.extend_from_slice(&CLASS_IN.to_be_bytes());
        answers.extend_from_slice(&600u32.to_be_bytes());
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority
        rdata.push(0); // root target
                       // alpn h2
        rdata.extend_from_slice(&1u16.to_be_bytes());
        rdata.extend_from_slice(&3u16.to_be_bytes());
        rdata.push(2);
        rdata.extend_from_slice(b"h2");
        // ipv4hint 203.0.113.1 (catalog validation is separate; wire parser accepts it)
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&4u16.to_be_bytes());
        rdata.extend_from_slice(&[203, 0, 113, 1]);
        // ech raw bytes
        let ech = [0xfe, 0x0d, 0, 1, 2, 3];
        rdata.extend_from_slice(&5u16.to_be_bytes());
        rdata.extend_from_slice(&(ech.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&ech);
        answers.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        answers.extend_from_slice(&rdata);
        let wire = response_for(&query, 0, &answers, 1);
        let response = parse_response(&wire).unwrap();
        let answer = extract_answer(&response, "pixiv.net", TYPE_HTTPS);
        assert!(answer.https_present);
        assert_eq!(answer.ech.as_deref(), Some(ech.as_slice()));
        assert_eq!(answer.hints, vec!["203.0.113.1".parse::<IpAddr>().unwrap()]);
        assert_eq!(answer.ttl, 600);
    }

    #[test]
    fn rejects_forward_compression_pointer() {
        let mut wire = vec![0u8; 12];
        wire[4..6].copy_from_slice(&1u16.to_be_bytes());
        // A label that points forward (invalid).
        wire.push(0xc0);
        wire.push(0x0c);
        wire.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_response(&wire).is_err());
    }

    #[test]
    fn nxdomain_sets_rcode() {
        let query = build_query("nope.example", TYPE_A, 9).unwrap();
        let wire = response_for(&query, 3, &[], 0);
        let response = parse_response(&wire).unwrap();
        assert!(response.is_nxdomain());
        assert_eq!(response.rcode_text(), "NXDOMAIN");
    }
}
