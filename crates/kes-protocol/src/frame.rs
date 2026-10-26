//! Allocation-free length-prefixed streaming over canonical CBOR.
use crate::{FRAME_TIMEOUT_MS, MAX_FRAME_BYTES, error::Error};
use kes_core::cbor::Value;

/// Framing metadata separated from its caller-owned receive buffer.
///
/// This form lets firmware own one fixed USB buffer without a self-referential
/// borrow. The original first-byte deadline never slides.
pub struct ReceiverState {
    prefix: [u8; 4],
    prefix_len: usize,
    len: usize,
    expected: usize,
    has_expected: bool,
    started: u64,
    has_started: bool,
    last: u64,
    has_last: bool,
    failed: bool,
}

impl ReceiverState {
    pub const fn new() -> Self {
        Self {
            prefix: [0; 4],
            prefix_len: 0,
            len: 0,
            expected: 0,
            has_expected: false,
            started: 0,
            has_started: false,
            last: 0,
            has_last: false,
            failed: false,
        }
    }

    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn check_timeout(&mut self, now_ms: u64) -> Result<(), Error> {
        if self.failed {
            return Err(Error::InvalidValue);
        }
        if self.has_last && now_ms < self.last {
            self.failed = true;
            return Err(Error::ClockRegressed);
        }
        self.last = now_ms;
        self.has_last = true;
        if !(self.has_expected && self.expected == self.len)
            && self.has_started
            && now_ms - self.started >= u64::from(FRAME_TIMEOUT_MS)
        {
            self.failed = true;
            return Err(Error::Timeout);
        }
        Ok(())
    }

    /// Consumes at most one frame. Stop on completion; reset explicitly after use.
    pub fn push(
        &mut self,
        buffer: &mut [u8; MAX_FRAME_BYTES],
        input: &[u8],
        now_ms: u64,
    ) -> Result<usize, Error> {
        self.check_timeout(now_ms)?;
        if self.complete(buffer).is_some() || input.is_empty() {
            return Ok(0);
        }
        if !self.has_started {
            self.started = now_ms;
            self.has_started = true;
        }
        let mut used = 0;
        while self.prefix_len < 4 && used < input.len() {
            self.prefix[self.prefix_len] = input[used];
            self.prefix_len += 1;
            used += 1;
        }
        if self.prefix_len < 4 {
            return Ok(used);
        }
        if !self.has_expected {
            let n = u32::from_be_bytes(self.prefix) as usize;
            if n > MAX_FRAME_BYTES {
                self.failed = true;
                return Err(Error::Oversize);
            }
            if n == 0 {
                self.failed = true;
                return Err(Error::InvalidLength);
            }
            self.expected = n;
            self.has_expected = true;
        }
        let remaining = self.expected - self.len;
        let count = core::cmp::min(remaining, input.len() - used);
        buffer[self.len..self.len + count].copy_from_slice(&input[used..used + count]);
        self.len += count;
        Ok(used + count)
    }

    pub fn complete<'a>(&self, buffer: &'a [u8; MAX_FRAME_BYTES]) -> Option<&'a [u8]> {
        (self.has_expected && self.expected == self.len).then_some(&buffer[..self.len])
    }
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience receiver for callers that can retain a buffer borrow.
pub struct Receiver<'a> {
    buffer: &'a mut [u8; MAX_FRAME_BYTES],
    state: ReceiverState,
}

impl<'a> Receiver<'a> {
    pub fn new(buffer: &'a mut [u8; MAX_FRAME_BYTES]) -> Self {
        Self {
            buffer,
            state: ReceiverState::new(),
        }
    }

    pub fn reset(&mut self) {
        self.state.reset();
    }

    pub fn check_timeout(&mut self, now_ms: u64) -> Result<(), Error> {
        self.state.check_timeout(now_ms)
    }

    pub fn push(&mut self, input: &[u8], now_ms: u64) -> Result<usize, Error> {
        self.state.push(self.buffer, input, now_ms)
    }

    pub fn complete(&self) -> Option<&[u8]> {
        self.state.complete(self.buffer)
    }
}

const _: () = assert!(core::mem::size_of::<ReceiverState>() <= 128);
/// Encode an already canonical map into a caller buffer, including its prefix.
pub fn encode_frame(map: Value<'_>, out: &mut [u8]) -> Result<usize, Error> {
    map.map()?;
    let n = map.encoded().len();
    if out.len() < n + 4 {
        return Err(Error::BufferTooSmall);
    }
    out[..4].copy_from_slice(&(n as u32).to_be_bytes());
    out[4..n + 4].copy_from_slice(map.encoded());
    Ok(n + 4)
}
pub fn decode_frame(bytes: &[u8]) -> Result<Value<'_>, Error> {
    let p: [u8; 4] = bytes
        .get(..4)
        .ok_or(Error::Incomplete)?
        .try_into()
        .map_err(|_| Error::Incomplete)?;
    let n = u32::from_be_bytes(p) as usize;
    if n > MAX_FRAME_BYTES {
        return Err(Error::Oversize);
    }
    if bytes.len() < n + 4 {
        return Err(Error::Incomplete);
    }
    if bytes.len() != n + 4 {
        return Err(Error::TrailingBytes);
    }
    let v = Value::parse(&bytes[4..])?;
    v.map()?;
    Ok(v)
}
