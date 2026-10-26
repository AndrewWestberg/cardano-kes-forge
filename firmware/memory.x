/* RP2350/Pico 2 fitted memory map.
 *
 * Firmware is linked for signed slot A. The updater owns relocation/selection
 * of slot B; application code must never write either slot through the journal
 * adapter. Offsets below match firmware/src/storage.rs exactly.
 */
MEMORY
{
  FLASH : ORIGIN = 0x10010000, LENGTH = 1024K
  RAM   : ORIGIN = 0x20000000, LENGTH = 520K
}

SECTIONS
{
  /* The RP2350 ROM and picotool require IMAGE_DEF in the first 4 KiB. */
  .start_block : ALIGN(4)
  {
    __start_block_addr = .;
    KEEP(*(.start_block));
    KEEP(*(.boot_info));
  } > FLASH
} INSERT AFTER .vector_table;

/* Keep executable code after IMAGE_DEF instead of orphaning it at image end. */
_stext = ALIGN(ADDR(.start_block) + SIZEOF(.start_block), ALIGNOF(.text));

SECTIONS
{
  .bi_entries : ALIGN(4)
  {
    __bi_entries_start = .;
    KEEP(*(.bi_entries));
    . = ALIGN(4);
    __bi_entries_end = .;
  } > FLASH
} INSERT AFTER .text;

SECTIONS
{
  .end_block : ALIGN(4)
  {
    __end_block_addr = .;
    KEEP(*(.end_block));
  } > FLASH
} INSERT AFTER .uninit;

PROVIDE(start_to_end = __end_block_addr - __start_block_addr);
PROVIDE(end_to_start = __start_block_addr - __end_block_addr);

__kes_flash_start = 0x10000000;
__kes_boot_partition_start = 0x10000000;
__kes_boot_partition_end = 0x10010000;
__kes_firmware_a_start = 0x10010000;
__kes_firmware_a_end = 0x10110000;
__kes_firmware_b_start = 0x10110000;
__kes_firmware_b_end = 0x10210000;
__kes_directory_start = 0x10210000;
__kes_directory_end = 0x10214000;
__kes_pools_start = 0x10214000;
__kes_pools_end = 0x10314000;
__kes_storage_end = 0x10314000;
__kes_flash_end = 0x10400000;

ASSERT(ORIGIN(FLASH) == __kes_firmware_a_start,
       "firmware link origin must equal slot A start");
ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) == __kes_firmware_a_end,
       "firmware image must remain within its 1 MiB slot");
ASSERT(__kes_directory_end - __kes_directory_start == 16K,
       "directory partition must remain 16 KiB");
ASSERT(__kes_pools_end - __kes_pools_start == 1024K,
       "32 pool regions must remain 1 MiB total");
ASSERT(__kes_storage_end - __kes_flash_start == 3152K,
       "declared storage reservation must remain 3152 KiB");
ASSERT(__kes_flash_end - __kes_storage_end == 944K,
       "fitted 4 MiB flash must retain 944 KiB spare");
ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x20082000,
       "RP2350 SRAM map must remain 520 KiB");
