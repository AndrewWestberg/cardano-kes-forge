/* Disposable A2 image occupies only the boot and firmware area. The directory,
 * pool journals, and development identity sector must not be linked into it. */
MEMORY
{
  FLASH : ORIGIN = 0x10000000, LENGTH = 2112K
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

ASSERT(ORIGIN(FLASH) + LENGTH(FLASH) == 0x10210000,
       "A2 image must not overlap directory, pool, or identity storage");
ASSERT(ORIGIN(RAM) + LENGTH(RAM) == 0x20082000,
       "RP2350 SRAM map must remain 520 KiB");
