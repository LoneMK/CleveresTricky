use log::debug;
use shared::hardware_sim::TeeLatencySimulator;

pub const KM_ERROR_OK: i32 = 0;
pub const KM_ERROR_UNSUPPORTED_PURPOSE: i32 = -2;
pub const KM_ERROR_INVALID_TAG: i32 = -76;
pub const KM_ERROR_INVALID_ARGUMENT: i32 = -38;
pub const KM_ERROR_UNIMPLEMENTED: i32 = -100;
pub const KM_ERROR_VERIFICATION_FAILED: i32 = -30;
pub const KM_ERROR_INVALID_KEY_BLOB: i32 = -33;

#[derive(Debug, Clone, Copy)]
pub enum KeyMintError {
    InvalidTag,
    InvalidArgument,
    UnsupportedPurpose,
    VerificationFailed,
    InvalidKeyBlob,
    Unknown,
}

impl KeyMintError {
    pub fn to_hal_code(self) -> i32 {
        match self {
            KeyMintError::InvalidTag => KM_ERROR_INVALID_TAG,
            KeyMintError::InvalidArgument => KM_ERROR_INVALID_ARGUMENT,
            KeyMintError::UnsupportedPurpose => KM_ERROR_UNSUPPORTED_PURPOSE,
            KeyMintError::VerificationFailed => KM_ERROR_VERIFICATION_FAILED,
            KeyMintError::InvalidKeyBlob => KM_ERROR_INVALID_KEY_BLOB,
            KeyMintError::Unknown => KM_ERROR_UNIMPLEMENTED,
        }
    }
}

/// Helper to execute a crypto closure, emulate latency, and mask errors into KeyMint HAL codes
pub fn execute_crypto_operation<F, T>(op: F) -> Result<T, i32>
where
    F: FnOnce() -> Result<T, KeyMintError>,
{
    // Emulate hardware latency first
    let sim = TeeLatencySimulator::new();
    sim.emulate_crypto_latency();

    // Execute and mask errors
    match op() {
        Ok(result) => Ok(result),
        Err(e) => {
            let hal_code = e.to_hal_code();
            debug!("Masking software crypto error {:?} to HAL code {}", e, hal_code);
            Err(hal_code)
        }
    }
}
