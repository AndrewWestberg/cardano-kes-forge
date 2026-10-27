//! Read-only RP2350 CS0 identification, not an alias-based size probe.
//!
//! Protocol reference: Pico SDK `hardware_flash/flash.c:flash_do_cmd_cs`.
//! RAM/boot2 reference: Embassy RP 0.10 `flash.rs` RAM helpers and `in_ram`.
//! The Winbond W25Q32RV Rev E datasheet maps 9Fh to EF/40/16 (4 MiB):
//! https://www.mouser.com/catalog/specsheets/Winbond%20Electronics%20Corporation_02-12-2026_W25Q32RV_SPI_QPI%20RevE%2011132025%20Plus.pdf
//! JEDEC alone also matches JV. We therefore require the RV SFDP header and
//! 32-Mbit density, as published with the RV driver submission:
//! https://lkml.iu.edu/2609.0/05132.html
//! This narrowly approved revision is deliberately fail-closed; a different
//! SFDP revision needs review, not a generic-capacity fallback. These public
//! identifiers are not authentication or proof of endurance/physical marking.
//!
//! Safety boundary: the caller owns FLASH and runs on core0. Embassy's core1
//! pause handshake precedes the critical section; interrupts remain masked
//! until XIP is restored. Any active DMA or XIP stream is rejected (no wait
//! that could deadlock the initializer). CS1 devices and writable external
//! memory are unsupported, so no external-RAM cache clean is needed. The
//! copied ROM boot2 restores the boot-selected flash protocol. Both QMI
//! windows, direct-mode configuration and all six QSPI pads are preserved.
//! Only the non-inlined RAM function runs with XIP unavailable: its arguments,
//! byte buffer, boot2 copy and function pointers are SRAM; its only callees
//! are resolved ROM functions and the SRAM boot2. Its loops use raw pointers
//! (no indexing panic paths, logging, allocation or flash-resident constants).
//! No status-register, flash-data, OTP, or protection write is issued.

use core::{
    ptr,
    sync::atomic::{Ordering, compiler_fence},
};

use embassy_rp::{flash::BOOTRAM_BASE, multicore, rom_data};
use embassy_sync::blocking_mutex::raw::{CriticalSectionRawMutex, RawMutex};
use rp_pac as pac;

pub(crate) const APPROVED_JEDEC: [u8; 3] = [0xef, 0x40, 0x16];
const APPROVED_SFDP_HEADER: [u8; 16] = [
    0x53, 0x46, 0x44, 0x50, 0x0a, 0x01, 0x00, 0xff, 0x00, 0x08, 0x01, 0x17, 0x80, 0x00, 0x00, 0xff,
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IdentificationError {
    Busy,
    UnsupportedBus,
    MissingRomData,
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Identity {
    pub jedec_id: [u8; 3],
    pub sfdp_header: [u8; 16],
    pub density_bits_minus_one: u32,
}

impl Identity {
    pub fn approved(self) -> bool {
        self.jedec_id == APPROVED_JEDEC
            && self.sfdp_header == APPROVED_SFDP_HEADER
            && self.density_bits_minus_one == 0x01ff_ffff
    }
}

type RomFn = unsafe extern "C" fn();

struct Functions {
    connect: RomFn,
    exit_xip: RomFn,
    flush: RomFn,
    boot2: RomFn,
}

pub(crate) fn identify() -> Result<Identity, IdentificationError> {
    // The FD ROM entry points to a pointer to the ROM's effective 16-bit
    // devinfo, not raw OTP. Only use it to exclude CS1, never to infer CS0 size.
    let entry = rom_data::rom_data_lookup(*b"FD", 0x0040);
    if entry == 0 {
        return Err(IdentificationError::MissingRomData);
    }
    // SAFETY: FD is the SDK-defined ROM pointer-to-pointer data entry.
    let devinfo = unsafe { ptr::read_volatile(entry as *const *const u16) };
    if devinfo.is_null() {
        return Err(IdentificationError::MissingRomData);
    }
    // SAFETY: non-null ROM-provided effective flash-devinfo pointer.
    if unsafe { ptr::read_volatile(devinfo) } & 0xf000 != 0
        || pac::XIP_CTRL.ctrl().read().writable_m1()
        || pac::XIP_CTRL.ctrl().read().writable_m0()
    {
        return Err(IdentificationError::UnsupportedBus);
    }

    multicore::pause_core1();
    let result = CriticalSectionRawMutex::new().lock(|| {
        // Reject even SRAM-only DMA: read/write chains could later touch XIP.
        if (0..16) // RP2350 has 16 DMA channels; Embassy's count is private.
            .any(|n| pac::DMA.ch(n).ctrl_trig().read().busy())
            || pac::XIP_CTRL.stream_ctr().read().0 != 0
            || pac::QMI.direct_csr().read().en()
        {
            return Err(IdentificationError::Busy);
        }
        let mut boot2 = [0u32; 64];
        // SAFETY: same 256-byte ROM boot2 copy used by Embassy RP2350 flash
        // helpers. The u32 array is aligned and remains live through all calls.
        unsafe { ptr::copy_nonoverlapping(BOOTRAM_BASE, boot2.as_mut_ptr(), 64) };
        let functions = Functions {
            connect: rom_data::connect_internal_flash::ptr(),
            exit_xip: rom_data::flash_exit_xip::ptr(),
            flush: rom_data::flash_flush_cache::ptr(),
            // SAFETY: a Thumb function at the aligned SRAM boot2 copy plus 1,
            // exactly as in Embassy's flash_function_pointers_with_boot2.
            boot2: unsafe { core::mem::transmute::<usize, RomFn>(boot2.as_ptr() as usize | 1) },
        };
        let mut jedec = [0x9f, 0, 0, 0];
        command(&functions, &mut jedec)?;
        let mut repeat = [0x9f, 0, 0, 0];
        command(&functions, &mut repeat)?;
        if jedec != repeat {
            return Err(IdentificationError::Busy);
        }
        let jedec_id = [jedec[1], jedec[2], jedec[3]];
        if jedec_id != APPROVED_JEDEC {
            // Do not send any further vendor-dependent command to an unknown
            // device. Zero SFDP fields mean it was deliberately not queried.
            return Ok(Identity {
                jedec_id,
                sfdp_header: [0; 16],
                density_bits_minus_one: 0,
            });
        }
        let mut sfdp = [0u8; 149];
        // 5Ah, 24-bit zero address, eight dummy clocks, then 144 SFDP bytes.
        // This includes BFPT DWORD2 at 0x84 without trusting a device pointer.
        sfdp[0] = 0x5a;
        command(&functions, &mut sfdp)?;
        let mut header = [0u8; 16];
        header.copy_from_slice(&sfdp[5..21]);
        Ok(Identity {
            jedec_id,
            sfdp_header: header,
            density_bits_minus_one: u32::from_le_bytes([
                sfdp[137], sfdp[138], sfdp[139], sfdp[140],
            ]),
        })
    });
    multicore::resume_core1();
    result
}

fn command(functions: &Functions, bytes: &mut [u8]) -> Result<(), IdentificationError> {
    // Save state while XIP is still available. We reject CS1 ROM support above,
    // so the SDK's CS1 restore case is simply restoring its original registers.
    let qmi = pac::QMI;
    let direct = qmi.direct_csr().read();
    let windows = [
        (
            qmi.mem(0).timing().read(),
            qmi.mem(0).rfmt().read(),
            qmi.mem(0).rcmd().read(),
            qmi.mem(0).wfmt().read(),
            qmi.mem(0).wcmd().read(),
        ),
        (
            qmi.mem(1).timing().read(),
            qmi.mem(1).rfmt().read(),
            qmi.mem(1).rcmd().read(),
            qmi.mem(1).wfmt().read(),
            qmi.mem(1).wcmd().read(),
        ),
    ];
    let mut pads = [0u32; 6];
    for (n, pad) in pads.iter_mut().enumerate() {
        // SAFETY: RP2350 PADS_QSPI has six consecutive pad registers at +4.
        *pad = unsafe { ptr::read_volatile((0x4004_0004 + n * 4) as *const u32) };
    }
    compiler_fence(Ordering::SeqCst);
    // SAFETY: identify holds the critical section with core1 paused and DMA /
    // streaming idle. All arguments and boot2 live on the SRAM stack. This RAM
    // routine restores XIP on success AND timeout before returning to this code.
    let ok = unsafe { command_ram(functions, bytes.as_mut_ptr(), bytes.len()) };
    for (n, state) in windows.into_iter().enumerate() {
        qmi.mem(n).timing().write_value(state.0);
        qmi.mem(n).rfmt().write_value(state.1);
        qmi.mem(n).rcmd().write_value(state.2);
        qmi.mem(n).wfmt().write_value(state.3);
        qmi.mem(n).wcmd().write_value(state.4);
    }
    qmi.direct_csr().write_value(direct);
    for (n, pad) in pads.into_iter().enumerate() {
        // SAFETY: restoring the same six QSPI pad registers saved above.
        unsafe { ptr::write_volatile((0x4004_0004 + n * 4) as *mut u32, pad) };
    }
    compiler_fence(Ordering::SeqCst);
    if ok {
        Ok(())
    } else {
        Err(IdentificationError::Timeout)
    }
}

#[inline(never)]
#[unsafe(link_section = ".data.ram_func")]
unsafe fn command_ram(functions: &Functions, bytes: *mut u8, count: usize) -> bool {
    // SAFETY: this whole function is the narrow XIP-off boundary described in
    // the module contract. Raw MMIO addresses/masks are RP2350 QMI registers.
    // No slice indexing, fallible arithmetic, or helper calls occur here.
    unsafe {
        (functions.connect)();
        (functions.exit_xip)();
        let csr = 0x400d_0000 as *mut u32;
        let tx = 0x400d_0004 as *mut u32;
        let rx = 0x400d_0008 as *const u32;
        // Divide system clock by 12 (12.5 MHz at stock 150 MHz). Manual CS0,
        // single-bit 8-bit TX records, matching the vendor 9Fh/5Ah protocols.
        let config = 12 << 22;
        ptr::write_volatile(csr, config | 1);
        let mut budget = 2_000_000u32;
        while ptr::read_volatile(csr) & 2 != 0 && budget != 0 {
            budget = budget.wrapping_sub(1);
        }
        let mut complete = budget != 0;
        if complete {
            ptr::write_volatile(csr, config | 5);
            let mut offset = 0usize;
            while offset < count && budget != 0 {
                while ptr::read_volatile(csr) & (1 << 10) != 0 && budget != 0 {
                    budget = budget.wrapping_sub(1);
                }
                if budget == 0 {
                    break;
                }
                ptr::write_volatile(tx, ptr::read(bytes.wrapping_add(offset)) as u32);
                while ptr::read_volatile(csr) & (1 << 16) != 0 && budget != 0 {
                    budget = budget.wrapping_sub(1);
                }
                if budget == 0 {
                    break;
                }
                ptr::write(bytes.wrapping_add(offset), ptr::read_volatile(rx) as u8);
                offset = offset.wrapping_add(1);
            }
            complete = offset == count;
        }
        // No queued multi-byte burst: each byte has been drained before the
        // next is submitted. Bound the final busy check on every exit path.
        while ptr::read_volatile(csr) & 2 != 0 && budget != 0 {
            budget = budget.wrapping_sub(1);
        }
        complete = complete && budget != 0;
        // Always leave direct mode and deassert CS, including timeout. ROM
        // cache flush and the copied boot2 re-establish executable XIP before
        // returning an error; no early return may skip these calls.
        ptr::write_volatile(csr, config);
        (functions.flush)();
        (functions.boot2)();
        complete
    }
}
