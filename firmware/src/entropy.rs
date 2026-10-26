//! Bounded RP2350 entropy acquisition with every hardware health test enabled.

use core::fmt;

use embassy_rp::{Peri, peripherals::TRNG};
use hkdf::Hkdf;
use rand_chacha::{
    ChaCha20Rng,
    rand_core::{SeedableRng, TryCryptoRng, TryRngCore},
};
use rp_pac as pac;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

pub const SAMPLE_COUNT: u32 = 200;
pub const INVERTER_CHAIN_LENGTH: u8 = 1;
pub const ENTROPY_BITS_PER_BLOCK: usize = 192;
pub const MAX_STATUS_POLLS_PER_BLOCK: u32 = 2_000_000;

const BLOCK_BYTES: usize = ENTROPY_BITS_PER_BLOCK / 8;
const DRBG_SALT: &[u8] = b"cardano-kes-forge/chacha20-seed/v1";
const GENERATION_LABEL: &[u8] = b"generation";
const SESSION_LABEL: &[u8] = b"session";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EntropyError {
    Latched,
    Timeout,
    Configuration,
    Autocorrelation,
    ContinuousTest,
    VonNeumann,
    Derivation,
}

impl fmt::Display for EntropyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Latched => "entropy source is latched failed",
            Self::Timeout => "entropy acquisition exceeded its bounded poll window",
            Self::Configuration => "TRNG configuration readback failed",
            Self::Autocorrelation => "TRNG autocorrelation health test failed",
            Self::ContinuousTest => "TRNG continuous random-number health test failed",
            Self::VonNeumann => "TRNG Von Neumann health test failed",
            Self::Derivation => "ChaCha20 seed derivation failed",
        })
    }
}

impl core::error::Error for EntropyError {}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct EntropyCounters {
    pub successful_blocks: u32,
    pub failures: u32,
}

/// Owns the secure TRNG peripheral. A health error or timeout is sticky until
/// reboot; callers cannot clear it and retry into a successful operation.
pub struct HealthCheckedEntropy<'d> {
    _peripheral: Peri<'d, TRNG>,
    failed: bool,
    counters: EntropyCounters,
}

impl<'d> HealthCheckedEntropy<'d> {
    pub fn new(peripheral: Peri<'d, TRNG>) -> Result<Self, EntropyError> {
        let mut entropy = Self {
            _peripheral: peripheral,
            failed: false,
            counters: EntropyCounters::default(),
        };
        entropy.configure()?;
        Ok(entropy)
    }

    pub const fn counters(&self) -> EntropyCounters {
        self.counters
    }

    /// Fresh 256-bit ChaCha20 seed for one KES generation operation.
    pub fn generation_rng(&mut self) -> Result<ChaCha20Rng, EntropyError> {
        self.fresh_chacha(GENERATION_LABEL)
    }

    /// Fresh 256-bit ChaCha20 seed for one transport-session establishment.
    pub fn session_rng(&mut self) -> Result<ChaCha20Rng, EntropyError> {
        self.fresh_chacha(SESSION_LABEL)
    }

    pub fn root_bytes(&mut self) -> Result<Zeroizing<[u8; 32]>, EntropyError> {
        let mut root = Zeroizing::new([0u8; 32]);
        self.try_fill_bytes(&mut *root)?;
        Ok(root)
    }

    fn configure(&mut self) -> Result<(), EntropyError> {
        let regs = pac::TRNG;
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        regs.rst_bits_counter()
            .write(|w| w.set_rst_bits_counter(true));
        regs.trng_sw_reset().write(|w| w.set_trng_sw_reset(true));
        let _ = regs.trng_sw_reset().read();
        regs.rng_imr().write(|w| {
            w.set_ehr_valid_int_mask(true);
            w.set_autocorr_err_int_mask(true);
            w.set_crngt_err_int_mask(true);
            w.set_vn_err_int_mask(true);
        });
        regs.trng_config()
            .write(|w| w.set_rnd_src_sel(INVERTER_CHAIN_LENGTH));
        regs.sample_cnt1().write_value(SAMPLE_COUNT);
        regs.trng_debug_control().write(|w| {
            w.set_auto_correlate_bypass(false);
            w.set_trng_crngt_bypass(false);
            w.set_vnc_bypass(false);
        });
        regs.rng_debug_en_input()
            .write(|w| w.set_rng_debug_en(false));
        regs.rng_icr().write(|w| {
            w.set_ehr_valid(true);
            w.set_crngt_err(true);
            w.set_vn_err(true);
        });

        let masks = regs.rng_imr().read();
        let debug = regs.trng_debug_control().read();
        let configured = regs.trng_config().read().rnd_src_sel() == INVERTER_CHAIN_LENGTH
            && regs.sample_cnt1().read() == SAMPLE_COUNT
            && masks.ehr_valid_int_mask()
            && masks.autocorr_err_int_mask()
            && masks.crngt_err_int_mask()
            && masks.vn_err_int_mask()
            && !debug.auto_correlate_bypass()
            && !debug.trng_crngt_bypass()
            && !debug.vnc_bypass()
            && !regs.rng_debug_en_input().read().rng_debug_en();
        if !configured {
            self.failed = true;
            self.counters.failures = 1;
            return Err(EntropyError::Configuration);
        }
        Ok(())
    }

    fn fresh_chacha(&mut self, label: &[u8]) -> Result<ChaCha20Rng, EntropyError> {
        let raw = self.root_bytes()?;
        let mut seed = Zeroizing::new([0u8; 32]);
        Hkdf::<Sha256>::new(Some(DRBG_SALT), &*raw)
            .expand(label, &mut *seed)
            .map_err(|_| EntropyError::Derivation)?;
        Ok(ChaCha20Rng::from_seed(*seed))
    }

    fn block(&mut self) -> Result<Zeroizing<[u8; BLOCK_BYTES]>, EntropyError> {
        if self.failed {
            return Err(EntropyError::Latched);
        }
        let regs = pac::TRNG;
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(true));
        for _ in 0..MAX_STATUS_POLLS_PER_BLOCK {
            let status = regs.rng_isr().read();
            if status.autocorr_err() {
                return self.fail(EntropyError::Autocorrelation);
            }
            if status.crngt_err() {
                return self.fail(EntropyError::ContinuousTest);
            }
            if status.vn_err() {
                return self.fail(EntropyError::VonNeumann);
            }
            if regs.trng_valid().read().ehr_valid() {
                let words = Zeroizing::new([
                    regs.ehr_data0().read(),
                    regs.ehr_data1().read(),
                    regs.ehr_data2().read(),
                    regs.ehr_data3().read(),
                    regs.ehr_data4().read(),
                    // Reading EHR_DATA5 releases the complete result block.
                    regs.ehr_data5().read(),
                ]);
                self.stop_source();
                let mut block = Zeroizing::new([0u8; BLOCK_BYTES]);
                for (index, word) in words.iter().copied().enumerate() {
                    block[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
                }
                self.counters.successful_blocks = self.counters.successful_blocks.saturating_add(1);
                return Ok(block);
            }
            core::hint::spin_loop();
        }
        self.fail(EntropyError::Timeout)
    }

    fn stop_source(&self) {
        let regs = pac::TRNG;
        regs.rnd_source_enable().write(|w| w.set_rnd_src_en(false));
        regs.rst_bits_counter()
            .write(|w| w.set_rst_bits_counter(true));
    }

    fn fail<T>(&mut self, error: EntropyError) -> Result<T, EntropyError> {
        self.stop_source();
        self.failed = true;
        self.counters.failures = self.counters.failures.saturating_add(1);
        Err(error)
    }
}

impl TryRngCore for HealthCheckedEntropy<'_> {
    type Error = EntropyError;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), Self::Error> {
        for chunk in destination.chunks_mut(BLOCK_BYTES) {
            let mut block = self.block()?;
            chunk.copy_from_slice(&block[..chunk.len()]);
            block.zeroize();
        }
        Ok(())
    }
}

impl TryCryptoRng for HealthCheckedEntropy<'_> {}
