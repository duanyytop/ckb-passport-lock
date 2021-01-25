use core::result::Result;
use alloc::vec::Vec;
use ckb_lib_rsa::LibRSA;
use crate::error::Error;

pub fn verify_iso9796_2_signature(lib: &LibRSA, n: &[u8], e: u32, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
  let rsa_info = generate_rsa_info(&n, e, &sig)?;
  match lib.validate_signature(rsa_info.as_ref(), &msg) {
    Ok(_) => Ok(()),
    Err(err) => match err {
      52 => Err(Error::ISO97962MismatchHash),
      53 => Err(Error::ISO97962InvalidArg1),
      54 => Err(Error::ISO97962InvalidArg2),
      55 => Err(Error::ISO97962InvalidArg3),
      56 => Err(Error::ISO97962InvalidArg4),
      57 => Err(Error::ISO97962InvalidArg5),
      58 => Err(Error::ISO97962InvalidArg6),
      59 => Err(Error::ISO97962InvalidArg7),
      60 => Err(Error::ISO97962InvalidArg8),
      61 => Err(Error::ISO97962InvalidArg9),
      _ => Err(Error::ISO97962RSAVerifyError)
    }
  }
}

/** signature (in witness, or passed as arguments) memory layout
 * This structure contains the following information:
 * 1) Common header, 4 bytes, see RsaInfo
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
-----------------------------------------------------------------------------
|common header| E |  N (KeySize/8 bytes) | RSA Signature (KeySize/8 bytes)|
-----------------------------------------------------------------------------
The common header includes algorithm_id, key_size, padding, md_type whose data type are uint8_t.
The common header, E both occupy 4 bytes. E is in little endian(uint32_t).
The N must be little endian with [u8; 128]
So the total length in byte is: 4 + 4 + KeySize/8 + KeySize/8.
*/
fn generate_rsa_info(n: &[u8], e: u32, sig: &[u8]) -> Result<Vec<u8>, Error> {
  if n.len() != sig.len() {
    return Err(Error::RSAPubKeySigLengthError)
  }

  let pub_key_size: u32 = (n.len() as u32) * 8;
  let rsa_info_len = pub_key_size / 4 + 8;

  let mut rsa_info = Vec::new();
  for _ in 0..rsa_info_len {
    rsa_info.push(0u8);
  }

  rsa_info[0..4].copy_from_slice(&get_common_header());
  rsa_info[4..8].copy_from_slice(&e.to_le_bytes());
  rsa_info[8..(8 + n.len())].copy_from_slice(&n);
  rsa_info[(8 + n.len())..(8 + n.len() * 2)].copy_from_slice(&sig);

  Ok(rsa_info)
}

const ISO9796_2_ALGORITHM_ID: u8 = 2;
const ISO9796_2_KEY_SIZE: u8 = 1;
const ISO9796_2_PADDING: u8 = 0;
const ISO9796_2_MD_SHA1: u8 = 4;
pub fn get_common_header() -> [u8; 4] {
  [ISO9796_2_ALGORITHM_ID, ISO9796_2_KEY_SIZE, ISO9796_2_PADDING, ISO9796_2_MD_SHA1]
}
