// Licensed under the Apache-2.0 license

//! A small DER reader and writer: enough for PKCS#10 requests, X.509
//! certificates and CRLs. The reader is strict (definite, minimal lengths,
//! single-byte tags) and keeps each element's raw bytes, so names, keys and
//! extensions can be copied from a request into a certificate unchanged.

pub const BOOLEAN: u8 = 0x01;
pub const INTEGER: u8 = 0x02;
pub const BIT_STRING: u8 = 0x03;
pub const OCTET_STRING: u8 = 0x04;
pub const OID: u8 = 0x06;
pub const ENUMERATED: u8 = 0x0a;
pub const UTF8_STRING: u8 = 0x0c;
pub const PRINTABLE_STRING: u8 = 0x13;
pub const T61_STRING: u8 = 0x14;
pub const IA5_STRING: u8 = 0x16;
pub const UTC_TIME: u8 = 0x17;
pub const GENERALIZED_TIME: u8 = 0x18;
pub const SEQUENCE: u8 = 0x30;
pub const SET: u8 = 0x31;

/// Context-specific constructed tag `[n]`.
pub const fn context(n: u8) -> u8 {
    0xa0 | n
}

/// Context-specific primitive tag `[n]` (IMPLICIT over a primitive type).
pub const fn context_primitive(n: u8) -> u8 {
    0x80 | n
}

/// One DER element.
#[derive(Clone, Copy, Debug)]
pub struct Tlv<'a> {
    pub tag: u8,
    /// The contents.
    pub value: &'a [u8],
    /// Tag, length and contents.
    pub raw: &'a [u8],
}

/// Reads elements off the front of a buffer.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    pub fn new(input: &'a [u8]) -> Self {
        Reader { rest: input }
    }

    pub fn is_empty(&self) -> bool {
        self.rest.is_empty()
    }

    pub fn peek_tag(&self) -> Option<u8> {
        self.rest.first().copied()
    }

    /// The next element, whatever its tag.
    pub fn any(&mut self) -> Result<Tlv<'a>, String> {
        let input = self.rest;
        let (&tag, after_tag) = input.split_first().ok_or("unexpected end of DER data")?;
        if tag & 0x1f == 0x1f {
            return Err(format!("unsupported multi-byte DER tag 0x{tag:02x}"));
        }
        let (&first, after_len) = after_tag.split_first().ok_or("truncated DER length")?;
        let (len, body) = if first < 0x80 {
            (first as usize, after_len)
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 {
                return Err("indefinite DER length".into());
            }
            if n > 4 || after_len.len() < n {
                return Err("unsupported or truncated DER length".into());
            }
            let len = after_len[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | b as usize);
            if after_len[0] == 0 || len < 0x80 {
                return Err("non-minimal DER length".into());
            }
            (len, &after_len[n..])
        };
        if body.len() < len {
            return Err(format!(
                "DER element of {len} bytes runs past the end of the data ({} left)",
                body.len()
            ));
        }
        let consumed = input.len() - body.len() + len;
        self.rest = &input[consumed..];
        Ok(Tlv {
            tag,
            value: &body[..len],
            raw: &input[..consumed],
        })
    }

    /// The next element, which must have this tag.
    pub fn expect(&mut self, tag: u8, what: &str) -> Result<Tlv<'a>, String> {
        let tlv = self.any().map_err(|e| format!("{what}: {e}"))?;
        if tlv.tag != tag {
            return Err(format!(
                "{what}: expected tag 0x{tag:02x}, found 0x{:02x}",
                tlv.tag
            ));
        }
        Ok(tlv)
    }

    /// The next element if it has this tag.
    pub fn optional(&mut self, tag: u8) -> Result<Option<Tlv<'a>>, String> {
        if self.peek_tag() == Some(tag) {
            self.any().map(Some)
        } else {
            Ok(None)
        }
    }

    /// Fails if anything is left.
    pub fn finish(&self, what: &str) -> Result<(), String> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "{what}: {} unexpected trailing bytes",
                self.rest.len()
            ))
        }
    }
}

/// Reads exactly one element with the given tag from `input`.
pub fn single<'a>(input: &'a [u8], tag: u8, what: &str) -> Result<Tlv<'a>, String> {
    let mut r = Reader::new(input);
    let tlv = r.expect(tag, what)?;
    r.finish(what)?;
    Ok(tlv)
}

/// All the elements in `input`.
pub fn elements(input: &[u8]) -> Result<Vec<Tlv<'_>>, String> {
    let mut r = Reader::new(input);
    let mut out = Vec::new();
    while !r.is_empty() {
        out.push(r.any()?);
    }
    Ok(out)
}

/// The length of the element at the start of `input` (tag, length and
/// contents), for data with trailing padding.
pub fn first_element_len(input: &[u8]) -> Result<usize, String> {
    Ok(Reader::new(input).any()?.raw.len())
}

/// The bytes of a BIT STRING with no unused bits.
pub fn bit_string_bytes<'a>(tlv: &Tlv<'a>, what: &str) -> Result<&'a [u8], String> {
    match tlv.value.split_first() {
        Some((0, bytes)) if tlv.tag == BIT_STRING => Ok(bytes),
        _ => Err(format!("{what}: expected a BIT STRING with no unused bits")),
    }
}

/// An INTEGER's value as an unsigned big-endian magnitude (leading zero
/// removed). Negative values are rejected.
pub fn unsigned_integer<'a>(tlv: &Tlv<'a>, what: &str) -> Result<&'a [u8], String> {
    if tlv.tag != INTEGER || tlv.value.is_empty() {
        return Err(format!("{what}: expected an INTEGER"));
    }
    if tlv.value[0] & 0x80 != 0 {
        return Err(format!("{what}: negative INTEGER"));
    }
    let v = tlv.value;
    Ok(if v.len() > 1 && v[0] == 0 { &v[1..] } else { v })
}

/// Dotted-decimal form of an OID's contents.
pub fn oid_to_string(value: &[u8]) -> String {
    let mut arcs: Vec<u64> = Vec::new();
    let mut acc: u64 = 0;
    for (i, &b) in value.iter().enumerate() {
        acc = (acc << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let first = if acc < 80 { acc / 40 } else { 2 };
                arcs.push(first);
                arcs.push(acc - first * 40);
            } else {
                arcs.push(acc);
            }
            acc = 0;
        } else if i == value.len() - 1 {
            return format!("(malformed OID {})", hex(value));
        }
    }
    arcs.iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(".")
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Parses hex, ignoring whitespace, colons and an optional `0x` prefix.
pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .trim()
        .trim_start_matches("0x")
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("hex string has an odd number of digits".into());
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| format!("invalid hex digits \"{}\"", &cleaned[i..i + 2]))
        })
        .collect()
}

// --- Writer ---

/// Encodes one element.
pub fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    let len = value.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = (len as u32).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        out.push(0x80 | (4 - skip) as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
    out.extend_from_slice(value);
    out
}

/// A constructed element holding `parts` back to back.
pub fn constructed(tag: u8, parts: &[&[u8]]) -> Vec<u8> {
    tlv(tag, &parts.concat())
}

pub fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    constructed(SEQUENCE, parts)
}

/// An INTEGER from an unsigned big-endian magnitude.
pub fn integer(magnitude: &[u8]) -> Vec<u8> {
    let skip = magnitude.iter().take_while(|&&b| b == 0).count();
    let m = &magnitude[skip..];
    let mut v = Vec::with_capacity(m.len() + 1);
    if m.is_empty() || m[0] & 0x80 != 0 {
        v.push(0);
    }
    v.extend_from_slice(m);
    tlv(INTEGER, &v)
}

pub fn integer_u64(n: u64) -> Vec<u8> {
    integer(&n.to_be_bytes())
}

/// A BIT STRING with no unused bits.
pub fn bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(bytes.len() + 1);
    v.push(0);
    v.extend_from_slice(bytes);
    tlv(BIT_STRING, &v)
}

/// A named-bit BIT STRING (e.g. KeyUsage) from the set bit numbers, with
/// trailing zero bits removed as DER requires.
pub fn named_bits(bits: &[u8]) -> Vec<u8> {
    let Some(&max) = bits.iter().max() else {
        return tlv(BIT_STRING, &[0]);
    };
    let mut bytes = vec![0u8; max as usize / 8 + 1];
    for &b in bits {
        bytes[b as usize / 8] |= 0x80 >> (b % 8);
    }
    let unused = 7 - max % 8;
    let mut v = vec![unused];
    v.extend_from_slice(&bytes);
    tlv(BIT_STRING, &v)
}

pub fn octet_string(bytes: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, bytes)
}

pub fn boolean(b: bool) -> Vec<u8> {
    tlv(BOOLEAN, &[if b { 0xff } else { 0 }])
}

/// An OBJECT IDENTIFIER from dotted-decimal text. Panics on malformed input;
/// only called with the constants in this crate.
pub fn oid(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|a| a.parse().expect("OID arc"))
        .collect();
    assert!(arcs.len() >= 2, "OID needs at least two arcs");
    let mut v = Vec::new();
    let mut push = |mut n: u64| {
        let mut tmp = vec![(n & 0x7f) as u8];
        n >>= 7;
        while n > 0 {
            tmp.push(0x80 | (n & 0x7f) as u8);
            n >>= 7;
        }
        tmp.reverse();
        v.extend_from_slice(&tmp);
    };
    push(arcs[0] * 40 + arcs[1]);
    for &a in &arcs[2..] {
        push(a);
    }
    tlv(OID, &v)
}

/// A point in time as `YYYYMMDDHHMMSS` (UTC).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Time(String);

impl Time {
    /// Accepts `YYYYMMDDHHMMSS`, optionally with a trailing `Z` and with
    /// `-`, `:`, `T` or space separators (so ISO 8601 `2023-01-01T00:00:00Z`
    /// works too).
    pub fn parse(s: &str) -> Result<Time, String> {
        let digits: String = s
            .trim()
            .trim_end_matches('Z')
            .chars()
            .filter(|c| !matches!(c, '-' | ':' | 'T' | ' '))
            .collect();
        if digits.len() != 14 || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return Err(format!(
                "\"{s}\" is not a UTC time of the form YYYY-MM-DD HH:MM:SS"
            ));
        }
        let num = |a: usize, b: usize| digits[a..b].parse::<u32>().unwrap();
        let (month, day, hour, min, sec) =
            (num(4, 6), num(6, 8), num(8, 10), num(10, 12), num(12, 14));
        if !(1..=12).contains(&month)
            || !(1..=31).contains(&day)
            || hour > 23
            || min > 59
            || sec > 59
        {
            return Err(format!("\"{s}\" is not a valid date and time"));
        }
        Ok(Time(digits))
    }

    /// Encodes as RFC 5280 requires: UTCTime through 2049, GeneralizedTime
    /// from 2050.
    pub fn to_der(&self) -> Vec<u8> {
        let year: u32 = self.0[..4].parse().unwrap();
        if (1950..2050).contains(&year) {
            tlv(UTC_TIME, format!("{}Z", &self.0[2..]).as_bytes())
        } else {
            tlv(GENERALIZED_TIME, format!("{}Z", self.0).as_bytes())
        }
    }

    /// Decodes a UTCTime or GeneralizedTime element.
    pub fn from_der(tlv: &Tlv<'_>) -> Result<Time, String> {
        let text = std::str::from_utf8(tlv.value).map_err(|_| "time is not ASCII")?;
        match tlv.tag {
            UTC_TIME if text.len() == 13 => {
                let yy: u32 = text[..2].parse().map_err(|_| "malformed UTCTime")?;
                let century = if yy >= 50 { "19" } else { "20" };
                Time::parse(&format!("{century}{text}"))
            }
            GENERALIZED_TIME if text.len() == 15 => Time::parse(text),
            _ => Err(format!("unsupported time encoding \"{text}\"")),
        }
    }

    /// `YYYY-MM-DD HH:MM:SS UTC`.
    pub fn display(&self) -> String {
        let d = &self.0;
        format!(
            "{}-{}-{} {}:{}:{} UTC",
            &d[..4],
            &d[4..6],
            &d[6..8],
            &d[8..10],
            &d[10..12],
            &d[12..14]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lengths_round_trip() {
        for len in [0usize, 1, 127, 128, 255, 256, 65535, 65536, 70000] {
            let encoded = tlv(OCTET_STRING, &vec![0xab; len]);
            let parsed = single(&encoded, OCTET_STRING, "test").unwrap();
            assert_eq!(parsed.value.len(), len);
            assert_eq!(parsed.raw.len(), encoded.len());
        }
    }

    #[test]
    fn rejects_malformed_lengths() {
        assert!(Reader::new(&[0x04, 0x80]).any().is_err(), "indefinite");
        assert!(
            Reader::new(&[0x04, 0x81, 0x05, 0, 0, 0, 0, 0])
                .any()
                .is_err(),
            "non-minimal"
        );
        assert!(
            Reader::new(&[0x04, 0x82, 0x00, 0x90]).any().is_err(),
            "leading zero"
        );
        assert!(Reader::new(&[0x04, 0x05, 1, 2]).any().is_err(), "truncated");
        assert!(
            single(&[0x04, 0x01, 1, 2], OCTET_STRING, "t").is_err(),
            "trailing"
        );
    }

    #[test]
    fn oids() {
        for dotted in [
            "1.2.840.10045.4.3.3",
            "2.16.840.1.101.3.4.3.19",
            "2.23.133.5.4.4",
            "2.5.29.19",
            "1.3.132.0.34",
        ] {
            let encoded = oid(dotted);
            assert_eq!(oid_to_string(&encoded[2..]), dotted);
        }
        // id-ml-dsa-87, as RFC 9881 encodes it.
        assert_eq!(
            hex(&oid("2.16.840.1.101.3.4.3.19")),
            "0609608648016503040313"
        );
    }

    #[test]
    fn integers() {
        assert_eq!(integer(&[0]), [0x02, 0x01, 0x00]);
        assert_eq!(integer(&[0, 0, 0x7f]), [0x02, 0x01, 0x7f]);
        assert_eq!(integer(&[0x80]), [0x02, 0x02, 0x00, 0x80]);
        assert_eq!(integer_u64(256), [0x02, 0x02, 0x01, 0x00]);
        let enc = integer(&[0x80]);
        let t = single(&enc, INTEGER, "t").unwrap();
        assert_eq!(unsigned_integer(&t, "t").unwrap(), [0x80]);
    }

    #[test]
    fn key_usage_bits() {
        // keyCertSign (5) and cRLSign (6): 0000 0110, one unused bit.
        assert_eq!(named_bits(&[5, 6]), [0x03, 0x02, 0x01, 0x06]);
        // digitalSignature (0): 1000 0000, seven unused bits.
        assert_eq!(named_bits(&[0]), [0x03, 0x02, 0x07, 0x80]);
    }

    #[test]
    fn times() {
        let t = Time::parse("2023-01-01T00:00:00Z").unwrap();
        assert_eq!(t.to_der(), tlv(UTC_TIME, b"230101000000Z"));
        let forever = Time::parse("99991231235959").unwrap();
        assert_eq!(forever.to_der(), tlv(GENERALIZED_TIME, b"99991231235959Z"));
        for time in [t, forever] {
            let der = time.to_der();
            let parsed = Time::from_der(&Reader::new(&der).any().unwrap()).unwrap();
            assert_eq!(parsed, time);
        }
        assert!(Time::parse("2023-13-01 00:00:00").is_err());
        assert!(Time::parse("yesterday").is_err());
    }
}
