use alloc::vec::Vec;
use crate::code_hashes::CODE_HASH_RSA;
use ckb_std::dynamic_loading::{CKBDLContext, Symbol};

/// function signature of validate_signature
type ValidateSignature = unsafe extern "C" fn(
    prefilled_data: *const u8,
    signature_buffer: *const u8,
    signature_size: u64,
    message_buffer: *const u8,
    message_size: u64,
    output: *mut u8,
    output_len: *mut u64,
) -> i32;

/// Symbol name
const VALIDATE_SIGNATURE: &[u8; 18] = b"validate_signature";

pub struct LibRSA {
    validate_signature: Symbol<ValidateSignature>,
}

impl LibRSA {
    pub fn load<T>(context: &mut CKBDLContext<T>) -> Self {
        // load library
        let lib = context.load(&CODE_HASH_RSA).expect("load rsa");

        // find symbols
        let validate_signature: Symbol<ValidateSignature> =
            unsafe { lib.get(VALIDATE_SIGNATURE).expect("load function") };
        LibRSA {
            validate_signature,
        }
    }


    pub fn validate_signature(
        &self,
        signature: &[u8],
        message: &[u8],
    ) -> Result<(), i32> {
        let mut output = [0u8; 1024];
        let mut output_len: u64 = 1024;

        let f = &self.validate_signature;
        let error_code = unsafe {
            f(
                Vec::new().as_ptr(),
                signature.as_ptr(),
                signature.len() as u64,
                message.as_ptr(),
                message.len() as u64,
                output.as_mut_ptr(),
                &mut output_len as *mut u64,
            )
        };

        if error_code != 0 {
            return Err(error_code);
        }
        Ok(())
    }
}
