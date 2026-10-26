use kes_core::journal::{Flash, FlashRules};

const PAGE_BYTES: usize = 256;
const SECTOR_BYTES: usize = 4096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    PowerLoss,
    Bounds,
    ProgramRule,
}

// All copied storage here is public object data or encrypted journal bytes, never
// a decoded state, key, plaintext workspace, or entropy source.
pub(super) struct NorFlash {
    cells: Vec<u8>,
    cached: Vec<u8>,
    cache_valid: Vec<bool>,
    // Remember the entire attempted page, including the as-yet unwritten suffix
    // of a torn program, to qualify only an identical CLEAN retry.
    programmed: Vec<Option<[u8; PAGE_BYTES]>>,
    completed: Vec<bool>,
    rules: FlashRules,
    cut_after: Option<usize>,
    steps: usize,
    power_lost: bool,
}

impl NorFlash {
    pub(super) fn new(capacity: usize) -> Self {
        assert!(
            u32::try_from(capacity).is_ok(),
            "NOR capacity exceeds address space"
        );
        Self {
            cells: vec![0xff; capacity],
            cached: vec![0xff; capacity],
            cache_valid: vec![false; capacity],
            programmed: vec![None; capacity.div_ceil(PAGE_BYTES)],
            completed: vec![false; capacity.div_ceil(PAGE_BYTES)],
            rules: FlashRules::OnceOnlyClean,
            cut_after: None,
            steps: 0,
            power_lost: false,
        }
    }

    pub(super) fn copy_world(&self) -> Self {
        Self {
            cells: self.cells.clone(),
            cached: self.cached.clone(),
            cache_valid: self.cache_valid.clone(),
            programmed: self.programmed.clone(),
            completed: self.completed.clone(),
            rules: self.rules,
            cut_after: None,
            steps: 0,
            power_lost: false,
        }
    }

    pub(super) fn arm_cut_after_bits(&mut self, bits: usize) {
        self.cut_after = Some(bits);
        self.steps = 0;
        self.power_lost = false;
    }

    pub(super) fn disarm(&mut self) {
        self.cut_after = None;
        self.power_lost = false;
    }

    pub(super) fn steps(&self) -> usize {
        self.steps
    }

    pub(super) fn raw(&self) -> &[u8] {
        &self.cells
    }

    /// Physical page-program completion witness for fault-phase assertions.
    /// It is not an authentication decision and may outlive a later torn erase.
    pub(super) fn completed_page(&self, offset: u32) -> bool {
        let offset = offset as usize;
        offset.is_multiple_of(PAGE_BYTES)
            && self
                .completed
                .get(offset / PAGE_BYTES)
                .copied()
                .unwrap_or(false)
    }

    pub(super) fn corrupt(&mut self, offset: usize, xor: u8) -> Result<(), Error> {
        self.check_power()?;
        let cell = self.cells.get_mut(offset).ok_or(Error::Bounds)?;
        *cell ^= xor;
        Ok(())
    }

    pub(super) fn replace_range(&mut self, offset: usize, bytes: &[u8]) -> Result<(), Error> {
        self.check_power()?;
        let range = self.range(offset, bytes.len())?;
        self.cells[range.clone()].copy_from_slice(bytes);
        // History injection is deliberately outside physical programming. It
        // must not make an injected programmed page available for a fresh write.
        if !range.is_empty() {
            for page_index in range.start / PAGE_BYTES..=(range.end - 1) / PAGE_BYTES {
                let start = page_index * PAGE_BYTES;
                let end = (start + PAGE_BYTES).min(self.cells.len());
                if self.programmed[page_index].is_some()
                    || self.cells[start..end].iter().any(|&byte| byte != 0xff)
                {
                    let mut page = [0xff; PAGE_BYTES];
                    page[..end - start].copy_from_slice(&self.cells[start..end]);
                    self.programmed[page_index] = Some(page);
                }
            }
        }
        Ok(())
    }

    pub(super) fn install_public_object(&mut self, offset: u32, bytes: &[u8]) -> Result<(), Error> {
        self.check_power()?;
        if !(offset as usize).is_multiple_of(PAGE_BYTES) || bytes.is_empty() {
            return Err(Error::ProgramRule);
        }
        let pages = bytes.len().div_ceil(PAGE_BYTES);
        let padded_length = pages.checked_mul(PAGE_BYTES).ok_or(Error::Bounds)?;
        self.range(offset as usize, padded_length)?;
        for (index, chunk) in bytes.chunks(PAGE_BYTES).enumerate() {
            let mut page = [0xff; PAGE_BYTES];
            page[..chunk.len()].copy_from_slice(chunk);
            let page_offset = (offset as usize + index * PAGE_BYTES) as u32;
            self.program_page(page_offset, &page)?;
            self.invalidate_cache()?;
            let mut readback = [0; PAGE_BYTES];
            self.read(page_offset, &mut readback)?;
            if readback != page {
                return Err(Error::ProgramRule);
            }
        }
        Ok(())
    }

    pub(super) fn set_rules(&mut self, rules: FlashRules) {
        self.rules = rules;
    }

    fn check_power(&self) -> Result<(), Error> {
        if self.power_lost {
            Err(Error::PowerLoss)
        } else {
            Ok(())
        }
    }

    fn range(&self, offset: usize, length: usize) -> Result<std::ops::Range<usize>, Error> {
        let end = offset.checked_add(length).ok_or(Error::Bounds)?;
        if end > self.cells.len() {
            return Err(Error::Bounds);
        }
        Ok(offset..end)
    }

    fn begin_bit_operation(&mut self, total: usize) -> Result<usize, Error> {
        self.check_power()?;
        let available = self
            .cut_after
            .map_or(total, |limit| limit.saturating_sub(self.steps).min(total));
        self.steps += available;
        if available < total {
            self.power_lost = true;
        }
        Ok(available)
    }
}

impl Flash for NorFlash {
    type Error = Error;

    fn capacity(&self) -> u32 {
        self.cells.len() as u32
    }

    fn rules(&self) -> FlashRules {
        self.rules
    }

    fn read(&mut self, offset: u32, out: &mut [u8]) -> Result<(), Self::Error> {
        self.check_power()?;
        let range = self.range(offset as usize, out.len())?;
        for (index, destination) in range.zip(out.iter_mut()) {
            if !self.cache_valid[index] {
                self.cached[index] = self.cells[index];
                self.cache_valid[index] = true;
            }
            *destination = self.cached[index];
        }
        Ok(())
    }

    fn program_page(&mut self, offset: u32, page: &[u8; PAGE_BYTES]) -> Result<(), Self::Error> {
        self.check_power()?;
        let start = offset as usize;
        if !start.is_multiple_of(PAGE_BYTES) {
            return Err(Error::ProgramRule);
        }
        let range = self.range(start, PAGE_BYTES)?;
        let page_index = start / PAGE_BYTES;
        if let Some(previous) = &self.programmed[page_index] {
            let identical_clean_retry =
                matches!(self.rules, FlashRules::QualifiedIdenticalCleanRetry)
                    && page[..8] == *b"KESMKR01"
                    && page[8] == 1
                    && page[9] == 2
                    && previous == page;
            if !identical_clean_retry {
                return Err(Error::ProgramRule);
            }
        }
        if self.cells[range]
            .iter()
            .zip(page)
            .any(|(&old, &new)| old & new != new)
        {
            return Err(Error::ProgramRule);
        }
        // Even a zero-bit cut consumes the program opportunity conservatively.
        self.programmed[page_index] = Some(*page);
        let total = PAGE_BYTES * 8;
        let available = self.begin_bit_operation(total)?;
        let whole_bytes = available / 8;
        for (cell, &byte) in self.cells[start..start + whole_bytes].iter_mut().zip(page) {
            *cell &= byte;
        }
        let partial_bits = available % 8;
        if partial_bits != 0 {
            let byte = page[whole_bytes];
            for bit in 0..partial_bits {
                self.cells[start + whole_bytes] &= byte | !(1u8 << bit);
            }
        }
        if available != total {
            return Err(Error::PowerLoss);
        }
        self.completed[page_index] = true;
        Ok(())
    }

    fn erase_sector(&mut self, offset: u32) -> Result<(), Self::Error> {
        self.check_power()?;
        let start = offset as usize;
        if !start.is_multiple_of(SECTOR_BYTES) {
            return Err(Error::ProgramRule);
        }
        self.range(start, SECTOR_BYTES)?;
        let total = SECTOR_BYTES * 8;
        let available = self.begin_bit_operation(total)?;
        let whole_bytes = available / 8;
        self.cells[start..start + whole_bytes].fill(0xff);
        let partial_bits = available % 8;
        if partial_bits != 0 {
            for bit in 0..partial_bits {
                self.cells[start + whole_bytes] |= 1u8 << bit;
            }
        }
        if available != total {
            return Err(Error::PowerLoss);
        }
        for page in &mut self.programmed[start / PAGE_BYTES..(start + SECTOR_BYTES) / PAGE_BYTES] {
            *page = None;
        }
        self.completed[start / PAGE_BYTES..(start + SECTOR_BYTES) / PAGE_BYTES].fill(false);
        Ok(())
    }

    fn invalidate_cache(&mut self) -> Result<(), Self::Error> {
        self.check_power()?;
        self.cache_valid.fill(false);
        self.cached.fill(0xff);
        Ok(())
    }
}
