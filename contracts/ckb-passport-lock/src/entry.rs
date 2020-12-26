// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;
use alloc::vec::Vec;

use ckb_std::{
    ckb_constants::Source,
    syscalls::load_witness,
    error::SysError,
    dynamic_loading::CKBDLContext,
    ckb_types::{bytes::Bytes, prelude::*},
    high_level::{load_script, load_witness_args, load_transaction, load_tx_hash},
};
use crate::error::Error;

mod rsa;
mod hash;

const MESSAGE_SINGLE_SIZE: usize = 8;
const SIGNATURE_LEN: usize = 512;  // in byte
const SUB_SIGNATURE_LEN: usize = 128;
const ALGORITHM_ID_AND_KEY_SIZE: usize = 8; 
const PUBLIC_KEY_E_LEN: usize = 4; 
const PUBLIC_KEY_N_LEN: usize = 128;
const SIGNATURE_TOTAL_LEN: usize = 652; 

const MAX_WITNESS_SIZE: usize = 32768;

pub fn main() -> Result<(), Error> {
    let script = load_script()?;
    let args: Bytes = script.args().unpack();
    if args.len() != 20 {
        return Err(Error::InvalidArgument);
    }

    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let witness: Bytes = witness_args
          .lock()
          .to_opt()
          .ok_or(Error::Encoding)?
          .unpack();

    let mut signature = [0u8; SIGNATURE_LEN];
    let mut pub_key_e = [0u8; PUBLIC_KEY_E_LEN];
    let mut pub_key_n = [0u8; PUBLIC_KEY_N_LEN];
    let pub_key_index = SIGNATURE_LEN + ALGORITHM_ID_AND_KEY_SIZE;
    signature.copy_from_slice(&witness[0..SIGNATURE_LEN]);
    pub_key_e.copy_from_slice(&witness[pub_key_index..(pub_key_index + PUBLIC_KEY_E_LEN)]);
    pub_key_n.copy_from_slice(&witness[(pub_key_index + PUBLIC_KEY_E_LEN)..]);

    let pub_key_e = u32::from_le_bytes(pub_key_e);

    let pub_key_hash = compute_pub_key_hash(&pub_key_n, pub_key_e)?;

    if args[..] != pub_key_hash {
        return Err(Error::WrongPubKey);
    }
    
    let message = generate_message()?;

    let mut context = unsafe { CKBDLContext::<[u8; 1024 * 128]>::new() };
    let lib = ckb_lib_rsa::LibRSA::load(&mut context);

    for index in 0..4 {
        let sub_message = &message[MESSAGE_SINGLE_SIZE * index..MESSAGE_SINGLE_SIZE * (index + 1)];
        let sub_signature = &signature[SUB_SIGNATURE_LEN * index..SUB_SIGNATURE_LEN * (index + 1)];
        match rsa::verify_iso9796_2_signature(&lib, &pub_key_n, pub_key_e, sub_message, sub_signature) {
            Ok(_) => continue,
            Err(err) => return Err(err)
        }
    }

    Ok(())
}

fn generate_message() -> Result<[u8; 32], Error> {
    let witness_args = load_witness_args(0, Source::GroupInput)?;
    let tx_hash = load_tx_hash()?;
    let mut blake2b = hash::new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash);
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGNATURE_TOTAL_LEN, 0);
        buf.into()
    };
    let witness_for_digest = witness_args
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());

    // Digest same group witnesses
    let mut i = 1;
    let mut witness_buf = [0u8; MAX_WITNESS_SIZE];
    loop {
        match load_witness(&mut witness_buf, 0, i, Source::GroupInput) {
            Ok(_witness) => {
                let witness_len = witness_buf.len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_buf);
                i += 1;
            },
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        }
    }

    // Digest witnesses that not covered by inputs
    let mut i = load_transaction()?.raw().inputs().len();
    loop {
        match load_witness(&mut witness_buf, 0, i, Source::Input) {
            Ok(_witness) => {
                let witness_len = witness_buf.len() as u64;
                blake2b.update(&witness_len.to_le_bytes());
                blake2b.update(&witness_buf);
                i += 1;
            },
            Err(SysError::IndexOutOfBound) => break,
            Err(err) => return Err(err.into()),
        }
    }
    blake2b.finalize(&mut message);

    Ok(message)
}

fn compute_pub_key_hash(pub_key_n: &[u8], pub_key_e: u32) -> Result<[u8; 20], Error> {
    let pub_key_vec_len = ALGORITHM_ID_AND_KEY_SIZE + PUBLIC_KEY_N_LEN + PUBLIC_KEY_E_LEN; // algorithm_id + key_size + n.len + e.len
    let mut pub_key_vec = Vec::new();
    for _ in 0..pub_key_vec_len {
        pub_key_vec.push(0u8);
    }

    pub_key_vec[0..4].copy_from_slice(&rsa::ALGORITHM_ID_ISO9796_2.to_le_bytes());
    pub_key_vec[4..8].copy_from_slice(&rsa::ISO9796_2_KEY_SIZE.to_le_bytes());
    pub_key_vec[8..12].copy_from_slice(&pub_key_e.to_le_bytes());
    pub_key_vec[12..].copy_from_slice(&pub_key_n);

    Ok(hash::blake2b_160(pub_key_vec))
}