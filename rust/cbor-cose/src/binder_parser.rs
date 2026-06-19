use crate::ffi::validate_slice_args;
use std::mem;

#[repr(C)]
pub struct RustOffsetCacheView {
    pub target_ptr_offset: usize,
    pub cookie_offset: usize,
    pub code_offset: usize,
    pub flags_offset: usize,
    pub sender_pid_offset: usize,
    pub sender_euid_offset: usize,
    pub data_size_offset: usize,
    pub data_ptr_offset: usize,
    pub transaction_data_size: usize,
    pub transaction_data_secctx_size: usize,
    pub valid: bool,
}

#[repr(C)]
pub struct RustParsedTransaction {
    pub target_ptr: usize,
    pub cookie: usize,
    pub code: u32,
    pub flags: u32,
    pub sender_pid: i32,
    pub sender_euid: u32,
    pub data_size: u64,
    pub data_buffer: usize,
    pub cmd: u32,
    pub raw_ptr: usize,
    pub raw_size: usize,
    pub valid: bool,
}

fn safe_read<T: Copy>(buf: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(mem::size_of::<T>())?;
    if end > buf.len() {
        return None;
    }
    let mut tmp = mem::MaybeUninit::<T>::uninit();
    unsafe {
        std::ptr::copy_nonoverlapping(
            buf.as_ptr().add(offset),
            tmp.as_mut_ptr() as *mut u8,
            mem::size_of::<T>(),
        );
        Some(tmp.assume_init())
    }
}

#[inline]
fn _ioc_size(cmd: u32) -> usize {
    // Matches _IOC_SIZE from linux/ioctl.h: bits 16..30
    ((cmd >> 16) & 0x3FFF) as usize
}

// Replicate Linux ioctl encoding to compute binder BR_* constants locally.
const IOC_NRBITS: u32 = 8;
const IOC_TYPEBITS: u32 = 8;
const IOC_SIZEBITS: u32 = 14;
const IOC_DIRBITS: u32 = 2;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u32 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u32 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_READ: u32 = 2;

const fn _ioc_dir(cmd: u32) -> u32 {
    (cmd >> IOC_DIRSHIFT) & ((1 << IOC_DIRBITS) - 1)
}

const fn _ioc_type(cmd: u32) -> u32 {
    (cmd >> IOC_TYPESHIFT) & ((1 << IOC_TYPEBITS) - 1)
}

const fn _ioc_nr(cmd: u32) -> u32 {
    (cmd >> IOC_NRSHIFT) & ((1 << IOC_NRBITS) - 1)
}

// Char literal 'r' == 0x72
const BINDER_TYPE: u32 = b'r' as u32;
const TRANSACTION_NR: u32 = 2;

#[no_mangle]
/// Parse a binder ioctl stream and extract transactions into the provided output slice.
///
/// # Safety
/// - `buffer_ptr` must point to `buffer_size` readable bytes and remain valid for the call.
/// - `consumed` must not exceed `buffer_size`.
/// - `cache_ptr` must be non-null, point to a valid [`RustOffsetCacheView`] populated from
///   trusted C++ offsets, and remain valid for the duration of the call.
/// - `out_txns` must either be null (to skip writes) or point to a slice of length
///   `max_txns` with properly aligned [`RustParsedTransaction`] storage.
/// - `out_txn_count` must be non-null and writable.
/// - All pointers must satisfy Rust's aliasing rules for the duration of this call.
pub unsafe extern "C" fn rust_parse_binder_stream(
    buffer_ptr: *const u8,
    consumed: usize,
    buffer_size: usize,
    cache_ptr: *const RustOffsetCacheView,
    out_txns: *mut RustParsedTransaction,
    max_txns: usize,
    out_txn_count: *mut usize,
) -> bool {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if out_txn_count.is_null() {
            return false;
        }
        *out_txn_count = 0;

        let cache = match cache_ptr.as_ref() {
            Some(c) if c.valid => c,
            _ => return false,
        };

        if buffer_ptr.is_null() || consumed == 0 || buffer_size == 0 {
            return false;
        }

        let buffer = match validate_slice_args(buffer_ptr, buffer_size) {
            Some(s) => s,
            None => return false,
        };

        if consumed > buffer.len() {
            return false;
        }

        let mut pos: usize = 0;
        let mut remaining: usize = consumed;

        while remaining >= mem::size_of::<u32>() {
            let cmd = match safe_read::<u32>(buffer, pos) {
                Some(c) => c,
                None => return false,
            };
            pos += mem::size_of::<u32>();
            remaining -= mem::size_of::<u32>();

            let payload_sz = _ioc_size(cmd);
            if payload_sz > remaining {
                return *out_txn_count > 0;
            }

            if _ioc_dir(cmd) == IOC_READ
                && _ioc_type(cmd) == BINDER_TYPE
                && _ioc_nr(cmd) == TRANSACTION_NR
            {
                if *out_txn_count >= max_txns || out_txns.is_null() {
                    pos += payload_sz;
                    remaining -= payload_sz;
                    continue;
                }

                let txn_slice = &buffer[pos..pos + payload_sz];
                let mut txn = RustParsedTransaction {
                    target_ptr: 0,
                    cookie: 0,
                    code: 0,
                    flags: 0,
                    sender_pid: 0,
                    sender_euid: 0,
                    data_size: 0,
                    data_buffer: 0,
                    cmd,
                    raw_ptr: buffer_ptr as usize + pos,
                    raw_size: payload_sz,
                    valid: true,
                };

                if let Some(v) = safe_read::<usize>(txn_slice, cache.target_ptr_offset) {
                    txn.target_ptr = v;
                }
                if let Some(v) = safe_read::<usize>(txn_slice, cache.cookie_offset) {
                    txn.cookie = v;
                }
                if let Some(v) = safe_read::<u32>(txn_slice, cache.code_offset) {
                    txn.code = v;
                }
                if let Some(v) = safe_read::<u32>(txn_slice, cache.flags_offset) {
                    txn.flags = v;
                }
                if let Some(v) = safe_read::<i32>(txn_slice, cache.sender_pid_offset) {
                    txn.sender_pid = v;
                }
                if let Some(v) = safe_read::<u32>(txn_slice, cache.sender_euid_offset) {
                    txn.sender_euid = v;
                }
                if let Some(v) = safe_read::<u64>(txn_slice, cache.data_size_offset) {
                    txn.data_size = v;
                }
                if let Some(v) = safe_read::<usize>(txn_slice, cache.data_ptr_offset) {
                    txn.data_buffer = v;
                }

                std::ptr::write(out_txns.add(*out_txn_count), txn);
                *out_txn_count += 1;
            }

            pos += payload_sz;
            remaining -= payload_sz;
        }

        *out_txn_count > 0
    })).unwrap_or(false)
}

#[no_mangle]
pub unsafe extern "C" fn rust_parse_binder_parcel(
    data: *const u8,
    size: usize,
    target: *const u8,
    target_len: usize,
) -> bool {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        if data.is_null() || target.is_null() || size == 0 || target_len == 0 {
            return false;
        }

        let parcel_bytes = std::slice::from_raw_parts(data, size);
        let target_bytes = std::slice::from_raw_parts(target, target_len);

        let target_str = match std::str::from_utf8(target_bytes) {
            Ok(s) => s,
            Err(_) => return false,
        };

        let mut u16_bytes = Vec::new();
        for c in target_str.encode_utf16() {
            u16_bytes.extend_from_slice(&c.to_ne_bytes());
        }
        
        if u16_bytes.is_empty() || u16_bytes.len() > parcel_bytes.len() {
            return false;
        }

        parcel_bytes.windows(u16_bytes.len()).any(|window| window == u16_bytes.as_slice())
    }));

    result.unwrap_or(false)
}
