use log::{info, debug, trace};
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
