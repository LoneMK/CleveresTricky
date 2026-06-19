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
