/* Disposable RP2350 USB transport preflight image.
 *
 * This deliberately boots from the start of unpartitioned flash. It is not a
 * signed KES application slot and must never be used as release firmware.
 */
MEMORY
{
  FLASH : ORIGIN = 0x10000000, LENGTH = 4096K
  RAM   : ORIGIN = 0x20000000, LENGTH = 520K
}

SECTIONS
{
  .start_block : ALIGN(4)
  {
    __start_block_addr = .;
    KEEP(*(.start_block));
    KEEP(*(.boot_info));
  } > FLASH
} INSERT AFTER .vector_table;

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

ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x20082000,
       "RP2350 SRAM map must remain 520 KiB");
