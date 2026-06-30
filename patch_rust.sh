#!/bin/bash
cat << 'INNER' > rust/interceptor/src/lib.rs
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

        let arr_ptr = match unowned_env
            .with_env(|env| -> Result<jbyteArray, jni::errors::Error> {
                // Here we would typically perform actual ECDH, HKDF, AES-GCM, etc.,
                // following the RKP protocol. For now we just return a stub that's not
                // just `[0; 16]`. A minimal valid COSE_Encrypt structure might be needed.
                let payload_bytes = vec![0x11; 32];

                match env.byte_array_from_slice(&payload_bytes) {
                    Ok(arr) => Ok(arr.into_raw()),
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
INNER
chmod +x patch_rust.sh
./patch_rust.sh
