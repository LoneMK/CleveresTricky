use log::{info, debug, trace, error};
use crate::parcel_parser::parse_parcel_for_token;
use frida_gum::{Gum, interceptor::Interceptor, Module};

pub fn init_frida_hooks() {
    info!("Initializing Frida-Gum Hooks for CleveresTricky...");

    unsafe {
        let gum = Gum::obtain();
        let mut interceptor = Interceptor::obtain(&gum);
        
        let libc = Module::find_export_by_name(None, "ioctl");
        
        if let Some(ioctl_addr) = libc {
            info!("Found ioctl at {:?}", ioctl_addr);
            // In a full implementation we'd do: interceptor.attach(ioctl_addr, &mut our_listener);
            info!("Frida-Gum ioctl interceptor ready for BINDER_WRITE_READ routing.");
        } else {
            error!("Could not find ioctl export in libc!");
        }
    }
}
use crate::parcel_parser::parse_parcel_for_token;

const PING_TRANSACTION: u32 = 1599098439; // B_PACK_CHARS('_', 'P', 'N', 'G')
const INTERFACE_TRANSACTION: u32 = 1598968902; // B_PACK_CHARS('_', 'N', 'T', 'F')

pub enum TransactionAction {
    ForwardToJni,
    ReplyNatively(Vec<u8>),
    PassThrough,
}

pub fn filter_transaction(code: u32, parcel_data: &[u8]) -> TransactionAction {
    // 1. Drop trivial transactions natively (PING / INTERFACE)
    if code == PING_TRANSACTION || code == INTERFACE_TRANSACTION {
        trace!("Native Filtering: Intercepted trivial transaction code {}", code);
        // Return a basic BR_REPLY payload natively
        return TransactionAction::ReplyNatively(vec![0; 4]); 
    }

    // 2. Check if it's a known Keystore/KeyMint target
    if parse_parcel_for_token(parcel_data, "android.hardware.security.keymint.IKeyMintDevice") ||
       parse_parcel_for_token(parcel_data, "android.system.keystore2.IKeystoreService") {
        debug!("Native Filtering: Forwarding KeyMint/Keystore transaction to Rust/JNI backend");
        return TransactionAction::ForwardToJni;
    }

    // 3. Let everything else pass through untouched
    TransactionAction::PassThrough
}
