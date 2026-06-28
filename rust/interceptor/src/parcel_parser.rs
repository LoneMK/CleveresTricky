use log::debug;

/// Zero-copy parcel parser to dynamically find InterfaceToken.
/// Instead of hardcoding `txn->code == 17`, we parse the ioctl buffer
/// and locate the UTF-16LE string `android.hardware.drm@1.4::ICrypto`
/// or similar tokens for Keystore.
pub fn parse_parcel_for_token(data: &[u8], target_token: &str) -> bool {
    let target_len = target_token.len() * 2;
    if data.len() < target_len {
        return false;
    }

    // Allocate on the stack instead of heap to avoid Vec overhead
    // Max typical binder token is ~60 characters (120 bytes)
    // We use a reasonably small upper bound that fits standard Android tokens
    let mut token_bytes = [0u8; 128];
    let mut byte_len = 0;

    for c in target_token.encode_utf16() {
        if byte_len + 2 > token_bytes.len() {
            // Token is too large for stack buffer, fallback to allocation-free but slower search
            let target_len_computed = target_token.encode_utf16().count() * 2;
            let found = data.windows(target_len_computed).any(|window| {
                let mut target_iter = target_token.encode_utf16();
                let mut match_found = true;
                for i in (0..target_len_computed).step_by(2) {
                    if let Some(cp) = target_iter.next() {
                        let b = cp.to_le_bytes();
                        if window[i] != b[0] || window[i + 1] != b[1] {
                            match_found = false;
                            break;
                        }
                    }
                }
                match_found
            });

            if found {
                debug!("Found interface token match for: {}", target_token);
                return true;
            }
            return false;
        }
        let b = c.to_le_bytes();
        token_bytes[byte_len] = b[0];
        token_bytes[byte_len + 1] = b[1];
        byte_len += 2;
    }

    let actual_token_bytes = &token_bytes[..byte_len];

    // A fast zero-copy search through the raw bytes using slice equality
    if let Some(_pos) = data
        .windows(actual_token_bytes.len())
        .position(|window| window == actual_token_bytes)
    {
        debug!("Found interface token match for: {}", target_token);
        return true;
    }

    false
}

/// Safe wrapper around Android Parcel byte streams
pub struct SafeParcel<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> SafeParcel<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }

    /// Read a 32-bit integer safely
    pub fn read_i32(&mut self) -> Option<i32> {
        if self.offset + 4 > self.data.len() {
            return None;
        }
        let bytes: [u8; 4] = self.data[self.offset..self.offset + 4].try_into().unwrap();
        self.offset += 4;
        Some(i32::from_ne_bytes(bytes))
    }

    /// Read a 64-bit integer safely
    pub fn read_i64(&mut self) -> Option<i64> {
        if self.offset + 8 > self.data.len() {
            return None;
        }
        let bytes: [u8; 8] = self.data[self.offset..self.offset + 8].try_into().unwrap();
        self.offset += 8;
        Some(i64::from_ne_bytes(bytes))
    }

    /// Read an Android UTF-16 string safely
    pub fn read_string16(&mut self) -> Option<String> {
        let length = self.read_i32()?;
        if length < 0 {
            return None; // Null string
        }
        let byte_len = (length as usize) * 2;
        if self.offset + byte_len > self.data.len() {
            return None;
        }

        let mut u16_chars = Vec::with_capacity(length as usize);
        for i in 0..(length as usize) {
            let start = self.offset + i * 2;
            let bytes: [u8; 2] = self.data[start..start + 2].try_into().unwrap();
            u16_chars.push(u16::from_le_bytes(bytes));
        }

        // Android pads strings to 4-byte boundaries
        let pad_len = (byte_len + 3) & !3;
        self.offset += pad_len;

        String::from_utf16(&u16_chars).ok()
    }
}
