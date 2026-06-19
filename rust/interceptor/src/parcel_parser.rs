use log::debug;

/// Zero-copy parcel parser to dynamically find InterfaceToken.
/// Instead of hardcoding `txn->code == 17`, we parse the ioctl buffer
/// and locate the UTF-16LE string `android.hardware.drm@1.4::ICrypto` 
/// or similar tokens for Keystore.
pub fn parse_parcel_for_token(data: &[u8], target_token: &str) -> bool {
    if data.len() < target_token.len() * 2 {
        return false;
    }

    let token_utf16: Vec<u16> = target_token.encode_utf16().collect();
    // Convert to bytes (UTF-16LE is standard for Android Parcel)
    let mut token_bytes = Vec::with_capacity(token_utf16.len() * 2);
    for c in token_utf16 {
        token_bytes.extend_from_slice(&c.to_le_bytes());
    }

    // A fast zero-copy search through the raw bytes
    // In a production Binder hook, the InterfaceToken is always preceded by STRICT_MODE_POLICY (u32)
    // and the string length (u32), so we could parse it exactly to avoid false positives.
    // For performance, a simple byte-window search is often sufficient if the token is unique enough.
    
    // We use a window iterator to find the sequence
    if let Some(_pos) = data.windows(token_bytes.len()).position(|window| window == token_bytes.as_slice()) {
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
