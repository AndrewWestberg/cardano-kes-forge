//! Allocation-free, bounded deterministic CBOR with borrowed value views.
use core::fmt;

pub const MAX_ENCODED_BYTES: usize = 8192;
pub const MAX_NESTING_DEPTH: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Oversize,
    Incomplete,
    NonCanonical,
    DuplicateOrUnsortedKey,
    Nesting,
    InvalidType,
    InvalidUtf8,
    TrailingBytes,
    MissingField,
    BufferTooSmall,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Oversize => "CBOR exceeds its size bound",
            Self::Incomplete => "incomplete CBOR",
            Self::NonCanonical => "noncanonical CBOR",
            Self::DuplicateOrUnsortedKey => "duplicate or unsorted CBOR map key",
            Self::Nesting => "CBOR exceeds its nesting bound",
            Self::InvalidType => "invalid CBOR type",
            Self::InvalidUtf8 => "invalid CBOR UTF-8",
            Self::TrailingBytes => "trailing CBOR bytes",
            Self::MissingField => "missing CBOR field",
            Self::BufferTooSmall => "CBOR output buffer is too small",
        })
    }
}
impl core::error::Error for Error {}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Value<'a> {
    raw: &'a [u8],
}
impl<'a> Value<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self, Error> {
        if raw.len() > MAX_ENCODED_BYTES {
            return Err(Error::Oversize);
        }
        let mut p = Parser { input: raw, pos: 0 };
        p.item(0)?;
        if p.pos != raw.len() {
            return Err(Error::TrailingBytes);
        }
        Ok(Self { raw })
    }
    pub const fn encoded(self) -> &'a [u8] {
        self.raw
    }
    pub fn uint(self) -> Result<u64, Error> {
        let (m, n, _) = header(self.raw)?;
        if m == 0 {
            Ok(n)
        } else {
            Err(Error::InvalidType)
        }
    }
    pub fn bytes(self) -> Result<&'a [u8], Error> {
        let (m, _, h) = header(self.raw)?;
        if m == 2 {
            Ok(&self.raw[h..])
        } else {
            Err(Error::InvalidType)
        }
    }
    pub fn text(self) -> Result<&'a str, Error> {
        let (m, _, h) = header(self.raw)?;
        if m != 3 {
            return Err(Error::InvalidType);
        }
        core::str::from_utf8(&self.raw[h..]).map_err(|_| Error::InvalidUtf8)
    }
    pub fn boolean(self) -> Result<bool, Error> {
        match self.raw {
            [0xf4] => Ok(false),
            [0xf5] => Ok(true),
            _ => Err(Error::InvalidType),
        }
    }
    pub fn is_null(self) -> bool {
        self.raw == [0xf6]
    }
    pub fn map(self) -> Result<Map<'a>, Error> {
        let (m, n, h) = header(self.raw)?;
        if m != 5 {
            return Err(Error::InvalidType);
        }
        Ok(Map {
            raw: self.raw,
            pos: h,
            remaining: n as usize,
        })
    }
    pub fn array(self) -> Result<Array<'a>, Error> {
        let (m, n, h) = header(self.raw)?;
        if m != 4 {
            return Err(Error::InvalidType);
        }
        Ok(Array {
            raw: self.raw,
            pos: h,
            remaining: n as usize,
        })
    }
}
fn header(raw: &[u8]) -> Result<(u8, u64, usize), Error> {
    let b = *raw.first().ok_or(Error::Incomplete)?;
    let a = b & 31;
    let m = b >> 5;
    let count = match a {
        0..=23 => return Ok((m, u64::from(a), 1)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        _ => return Err(Error::NonCanonical),
    };
    let bytes = raw.get(1..1 + count).ok_or(Error::Incomplete)?;
    let mut n = 0u64;
    for b in bytes {
        n = (n << 8) | u64::from(*b);
    }
    let min = match count {
        1 => 24,
        2 => 256,
        4 => 65536,
        _ => 4294967296,
    };
    if n < min {
        return Err(Error::NonCanonical);
    }
    Ok((m, n, 1 + count))
}
struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
}
impl Parser<'_> {
    fn item(&mut self, depth: usize) -> Result<(), Error> {
        let start = self.pos;
        let (m, n, h) = header(self.input.get(start..).ok_or(Error::Incomplete)?)?;
        self.pos += h;
        match m {
            0 => {}
            2 | 3 => {
                let len = usize::try_from(n).map_err(|_| Error::Oversize)?;
                let end = self.pos.checked_add(len).ok_or(Error::Oversize)?;
                let bytes = self.input.get(self.pos..end).ok_or(Error::Incomplete)?;
                if m == 3 {
                    core::str::from_utf8(bytes).map_err(|_| Error::InvalidUtf8)?;
                }
                self.pos = end;
            }
            4 | 5 => {
                if depth >= MAX_NESTING_DEPTH {
                    return Err(Error::Nesting);
                }
                if n > MAX_ENCODED_BYTES as u64 {
                    return Err(Error::Oversize);
                }
                let mut previous: Option<&[u8]> = None;
                for _ in 0..n {
                    if m == 5 {
                        let key = self.pos;
                        self.item(depth + 1)?;
                        let encoded = &self.input[key..self.pos];
                        Value { raw: encoded }.text()?;
                        if let Some(prev) = previous
                            && prev >= encoded
                        {
                            return Err(Error::DuplicateOrUnsortedKey);
                        }
                        previous = Some(encoded);
                    }
                    self.item(depth + 1)?;
                }
            }
            7 if matches!(self.input[start], 0xf4..=0xf6) => {}
            _ => return Err(Error::InvalidType),
        }
        Ok(())
    }
}
#[derive(Clone, Copy)]
pub struct Map<'a> {
    raw: &'a [u8],
    pos: usize,
    remaining: usize,
}
impl<'a> Map<'a> {
    pub fn len(self) -> usize {
        self.remaining
    }
    pub fn is_empty(self) -> bool {
        self.remaining == 0
    }
    pub fn get(self, key: &str) -> Result<Option<Value<'a>>, Error> {
        for field in self {
            let (k, v) = field?;
            if k == key {
                return Ok(Some(v));
            }
        }
        Ok(None)
    }
    pub fn required(self, key: &str) -> Result<Value<'a>, Error> {
        self.get(key)?.ok_or(Error::MissingField)
    }
    pub fn encoded(self) -> &'a [u8] {
        self.raw
    }
}
impl<'a> Iterator for Map<'a> {
    type Item = Result<(&'a str, Value<'a>), Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        self.remaining -= 1;
        let result = (|| {
            let mut p = Parser {
                input: self.raw,
                pos: self.pos,
            };
            let k = p.pos;
            p.item(0)?;
            let key = Value {
                raw: &self.raw[k..p.pos],
            }
            .text()?;
            let v = p.pos;
            p.item(0)?;
            self.pos = p.pos;
            Ok((
                key,
                Value {
                    raw: &self.raw[v..p.pos],
                },
            ))
        })();
        Some(result)
    }
}
#[derive(Clone, Copy)]
pub struct Array<'a> {
    raw: &'a [u8],
    pos: usize,
    remaining: usize,
}
impl<'a> Iterator for Array<'a> {
    type Item = Value<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let start = self.pos;
        let mut p = Parser {
            input: self.raw,
            pos: start,
        };
        p.item(0).ok()?;
        self.pos = p.pos;
        self.remaining -= 1;
        Some(Value {
            raw: &self.raw[start..p.pos],
        })
    }
}
/// Emit a canonical map with one field omitted, without copying signed bodies.
/// Feed each borrowed chunk directly into the caller's MAC/signature context.
pub fn visit_without(map: Map<'_>, omit: &str, mut sink: impl FnMut(&[u8])) -> Result<(), Error> {
    map.required(omit)?;
    let n = map.len() - 1;
    let mut h = [0u8; 9];
    let len = encode_head(5, n as u64, &mut h);
    sink(&h[..len]);
    for field in map {
        let (key, value) = field?;
        if key == omit {
            continue;
        }
        let len = encode_head(3, key.len() as u64, &mut h);
        sink(&h[..len]);
        sink(key.as_bytes());
        sink(value.encoded());
    }
    Ok(())
}
pub fn encode_head(major: u8, n: u64, out: &mut [u8; 9]) -> usize {
    if n < 24 {
        out[0] = (major << 5) | n as u8;
        1
    } else {
        let width = if n <= 255 {
            1
        } else if n <= 65535 {
            2
        } else if n <= u32::MAX as u64 {
            4
        } else {
            8
        };
        out[0] = (major << 5)
            | match width {
                1 => 24,
                2 => 25,
                4 => 26,
                _ => 27,
            };
        let b = n.to_be_bytes();
        out[1..1 + width].copy_from_slice(&b[8 - width..]);
        1 + width
    }
}

/// Bounded caller-buffer CBOR writer. `finish` checks ordering, arity and depth.
/// Map keys must be supplied in their encoded bytewise order.
pub struct Encoder<'a> {
    out: &'a mut [u8],
    pos: usize,
}
impl<'a> Encoder<'a> {
    pub fn new(out: &'a mut [u8]) -> Self {
        Self { out, pos: 0 }
    }
    fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
        let end = self.pos.checked_add(bytes.len()).ok_or(Error::Oversize)?;
        if end > MAX_ENCODED_BYTES {
            return Err(Error::Oversize);
        }
        let dst = self
            .out
            .get_mut(self.pos..end)
            .ok_or(Error::BufferTooSmall)?;
        dst.copy_from_slice(bytes);
        self.pos = end;
        Ok(())
    }
    fn head(&mut self, major: u8, n: u64) -> Result<(), Error> {
        let mut h = [0; 9];
        let len = encode_head(major, n, &mut h);
        self.append(&h[..len])
    }
    pub fn uint(&mut self, n: u64) -> Result<(), Error> {
        self.head(0, n)
    }
    pub fn bytes(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.head(2, bytes.len() as u64)?;
        self.append(bytes)
    }
    pub fn text(&mut self, text: &str) -> Result<(), Error> {
        self.head(3, text.len() as u64)?;
        self.append(text.as_bytes())
    }
    pub fn boolean(&mut self, b: bool) -> Result<(), Error> {
        self.append(&[if b { 0xf5 } else { 0xf4 }])
    }
    pub fn null(&mut self) -> Result<(), Error> {
        self.append(&[0xf6])
    }
    pub fn map(&mut self, fields: usize) -> Result<(), Error> {
        self.head(5, fields as u64)
    }
    pub fn array(&mut self, items: usize) -> Result<(), Error> {
        self.head(4, items as u64)
    }
    pub fn value(&mut self, value: Value<'_>) -> Result<(), Error> {
        self.append(value.encoded())
    }
    pub fn finish(self) -> Result<Value<'a>, Error> {
        Value::parse(&self.out[..self.pos])
    }
}
