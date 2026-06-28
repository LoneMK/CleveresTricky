use jni::objects::JClass;
use jni::sys::jbyteArray;
use log::{error, info};
use shared::logging::init_logger;

pub mod binder_hook;
pub mod parcel_parser;

#[no_mangle]
pub extern "system" fn JNI_OnLoad(
    _vm: *mut jni::sys::JavaVM,
    _reserved: *mut std::ffi::c_void,
) -> jni::sys::jint {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        init_logger("CleveresTrickyInterceptor");
        info!("CleveresTricky Rust Interceptor loaded!");
        binder_hook::init_frida_hooks();
        jni::sys::JNI_VERSION_1_6
    }));
    result.unwrap_or(jni::sys::JNI_ERR)
}

// ----------------------------------------------------------------------------
// RKP Interceptor Native Callbacks
// ----------------------------------------------------------------------------

#[no_mangle]
pub extern "system" fn Java_cleveres_tricky_cleverestech_RkpInterceptor_createProtectedDataNatively<
    'local,
>(
    mut unowned_env: jni::EnvUnowned<'local>,
    _class: JClass<'local>,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        info!("Executing RKP Spoofing entirely in Native Rust!");

        // Fake ECC coordinates (32 bytes) and HMAC key
        let x = vec![0x01; 32];
        let y = vec![0x02; 32];
        let hmac_key = vec![0xAA; 32];

        let arr_ptr = match unowned_env
            .with_env(|env| -> Result<jbyteArray, jni::errors::Error> {
                let maced_key = match cleverestricky_cbor_cose::cose::generate_maced_public_key(
                    &x, &y, &hmac_key,
                ) {
                    Ok(k) => k,
                    Err(e) => {
                        error!("Failed to generate MACed public key: {}", e);
                        return Ok(std::ptr::null_mut());
                    }
                };

                let device_info = cleverestricky_cbor_cose::cose::create_device_info_cbor(
                    Some(std::borrow::Cow::Borrowed("google")),
                    Some(std::borrow::Cow::Borrowed("Google")),
                    Some(std::borrow::Cow::Borrowed("husky")),
                    Some(std::borrow::Cow::Borrowed("Pixel 8 Pro")),
                    Some(std::borrow::Cow::Borrowed("husky")),
                );

                let challenge = b"cleveres_tricky_rkp_bypass";

                let cbor_payload =
                    cleverestricky_cbor_cose::cose::create_certificate_request_response(
                        &[maced_key],
                        challenge,
                        &device_info,
                    );

                match env.byte_array_from_slice(&cbor_payload) {
                    Ok(arr) => Ok(**arr),
                    Err(e) => {
                        error!("Failed to create JNI byte array: {:?}", e);
                        Ok(std::ptr::null_mut())
                    }
                }
            })
            .into_outcome()
        {
            jni::Outcome::Ok(val) => val,
            _ => std::ptr::null_mut(),
        };

        arr_ptr
    }));
    result.unwrap_or(std::ptr::null_mut())
}
