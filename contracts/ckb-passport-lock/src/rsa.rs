use core::result::Result;
use alloc::vec::Vec;

use crate::error::Error;

const CKB_VERIFY_ISO9796_2: u32 = 3;
const ISO9796_2_KEY_SIZE: u32 = 1024;

pub fn verify_iso9796_2_signature(n: &[u8], e: u32, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
  let rsa_info = generate_rsa_info(&n, e, &sig)?;
  let mut context = unsafe { CKBLContext::<[u8; 128 * 1024]>::new*() };
  let lib = ckb_lib_iso97962_rsa::LibRSA::load(&mut context);
  let prefilled_data = lib.load_prefilled_data().map_err(|_err| Error::LoadPrefilledData)?;
  let result = lib.validate_signature(prefilled_data, rsa_info.as_ref(), &msg.as_bytes())?;
  result
}
/** signature(in witness) memory layout
 * This structure contains the following information:
 * 1) Algorithm id (CKB_VERIFY_ISO9796_2 = 3)
 * 1) RSA Key Size
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
-----------------------------------------------------------------------------------------
 algorithm_id | key_size | E |  N (key_size/8 bytes) | RSA Signature (key_size/8 bytes) |
-----------------------------------------------------------------------------------------
The algorithm_id, key_size, E all occupy 4 bytes, in little endian (uint32_t).
So the total length in byte is: 4 + 4 + 4 + key_size/8 + key_size/8.
*/
pub fn generate_rsa_info(n: &[u8], e: u32, sig: &[u8]) -> Result<Vec<u8>, Error> {
  if n.len() != sig.len() {
    return Err(Error::RSAPubKeySigLengthError)
  }

  let pub_key_size: u32 = (n.len() as u32) * 8;
  let rsa_info_len = pub_key_size / 4 + 12;

  let mut rsa_info = Vec::new();
  for _ in 0..rsa_info_len {
    rsa_info.push(0u8);
  }

  rsa_info[0..4].copy_from_slice(&CKB_VERIFY_ISO9796_2.to_le_bytes());
  rsa_info[4..8].copy_from_slice(&ISO9796_2_KEY_SIZE.to_le_bytes());
  rsa_info[8..12].copy_from_slice(&e.to_le_bytes());
  rsa_info[12..(12 + n.len())].copy_from_slice(&n);
  rsa_info[(12 + n.len())..(12 + n.len() * 2)].copy_from_slice(&sig);

  Ok(rsa_info)
}
