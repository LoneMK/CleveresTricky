use jni::JNIEnv;
use jni::objects::JClass;
use jni::sys::jbyteArray;
use log::{info, error};
use shared::logging::init_logger;

pub mod binder_hook;
pub mod parcel_parser;

#[no_mangle]
pub extern "system" fn JNI_OnLoad(_vm: jni::JavaVM, _reserved: *mut std::ffi::c_void) -> jni::sys::jint {
    init_logger("CleveresTrickyInterceptor");
    info!("CleveresTricky Rust Interceptor loaded!");
    binder_hook::init_frida_hooks();
    jni::sys::JNI_VERSION_1_6
}

// ----------------------------------------------------------------------------
// RKP Interceptor Native Callbacks
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_cleveres_tricky_cleverestech_RkpInterceptor_createProtectedDataNatively<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    info!("Executing RKP Spoofing entirely in Native Rust!");

    // Fake ECC coordinates (32 bytes) and HMAC key
    let x = vec![0x01; 32];
    let y = vec![0x02; 32];
    let hmac_key = vec![0xAA; 32];

    // Generate COSE_Mac0 structure using our memory-safe Rust library
    let maced_key = match cleverestricky_cbor_cose::cose::generate_maced_public_key(&x, &y, &hmac_key) {
        Ok(k) => k,
        Err(e) => {
            error!("Failed to generate MACed public key: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Build the attestation DeviceInfo
    let device_info = cleverestricky_cbor_cose::cose::create_device_info_cbor(
        Some(std::borrow::Cow::Borrowed("google")),
        Some(std::borrow::Cow::Borrowed("Google")),
        Some(std::borrow::Cow::Borrowed("husky")),
        Some(std::borrow::Cow::Borrowed("Pixel 8 Pro")),
        Some(std::borrow::Cow::Borrowed("husky")),
    );

    // Mock challenge
    let challenge = b"cleveres_tricky_rkp_bypass";

    // Create the final certificate request response
    let cbor_payload = cleverestricky_cbor_cose::cose::create_certificate_request_response(
        &[maced_key],
        challenge,
        &device_info,
    );
    
    match env.byte_array_from_slice(&cbor_payload) {
        Ok(arr) => **arr,
        Err(e) => {
            error!("Failed to create JNI byte array: {:?}", e);
            std::ptr::null_mut()
        }
    }
}
