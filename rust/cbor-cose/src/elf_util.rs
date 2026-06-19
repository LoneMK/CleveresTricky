use core::slice;
use goblin::elf::Elf;
use std::panic::{self, AssertUnwindSafe};

/// # Safety
/// The `elf_buffer` and `symbol_name` pointers must be valid for reads of `elf_size` and `sym_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn rust_find_elf_symbol(
    elf_buffer: *const u8,
    elf_size: usize,
    symbol_name: *const u8,
    sym_len: usize,
) -> u64 {
    let result = panic::catch_unwind(AssertUnwindSafe(|| {
        if elf_buffer.is_null() || symbol_name.is_null() || elf_size == 0 || sym_len == 0 {
            return 0;
        }

        let elf_bytes = slice::from_raw_parts(elf_buffer, elf_size);
        let sym_bytes = slice::from_raw_parts(symbol_name, sym_len);

        let sym_str = match std::str::from_utf8(sym_bytes) {
            Ok(s) => s,
            Err(_) => return 0,
        };

        if let Ok(elf) = Elf::parse(elf_bytes) {
            for sym in elf.dynsyms.iter() {
                if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
                    if name == sym_str {
                        return sym.st_value;
                    }
                }
            }
            for sym in elf.syms.iter() {
                if let Some(name) = elf.strtab.get_at(sym.st_name) {
                    if name == sym_str {
                        return sym.st_value;
                    }
                }
            }
        }
        0
    }));

    result.unwrap_or(0)
}
