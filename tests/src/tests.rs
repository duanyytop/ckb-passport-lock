use super::*;

use ckb_testtool::context::Context;
use ckb_tool::ckb_hash::{new_blake2b, blake2b_256};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder, TransactionView},
    packed::{self, *},
    prelude::*,
};
use ckb_tool::ckb_error::assert_error_eq;
use ckb_tool::ckb_script::ScriptError;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use std::fs;

const MAX_CYCLES: u64 = 70_000_000;

const ERROR_ISO97962_INVALID_ARG9: i8 = 17;
const WRONG_PUB_KEY: i8 = 6;

const MESSAGE_SINGLE_SIZE: usize = 8;
const SUB_SIGNATURE_SIZE: usize = 128;
const TX_SIGNATURE_SIZE: usize = 512;
const SIGN_INFO_SIZE: usize = 648;  // 512 + 136

const ISO9796_2_ALGORITHM_ID: u8 = 2;
const ISO9796_2_KEY_SIZE: u8 = 1;  // 1024
const ISO9796_2_PADDING: u8 = 0;
const ISO9796_2_MD_SHA1: u8 = 4;

fn blake160(data: &[u8]) -> [u8; 20] {
    let mut buf = [0u8; 20];
    let hash = blake2b_256(data);
    buf.clone_from_slice(&hash[..20]);
    buf
}

fn sign_tx(
    tx: TransactionView,
    private_key: &PKey<Private>,
    public_key: &PKey<Public>,
    is_pub_key_hash_error: bool
) -> TransactionView {
    let witnesses_len = tx.witnesses().len();
    let tx_hash = tx.hash();

    let mut signed_witnesses: Vec<packed::Bytes> = Vec::new();
    let mut blake2b = new_blake2b();
    let mut message = [0u8; 32];
    blake2b.update(&tx_hash.raw_data());

    // digest the first witness
    let witness = WitnessArgs::default();
    let zero_lock: Bytes = {
        let mut buf = Vec::new();
        buf.resize(SIGN_INFO_SIZE, 0);
        buf.into()
    };
    let witness_for_digest = witness
        .clone()
        .as_builder()
        .lock(Some(zero_lock).pack())
        .build();
    let witness_len = witness_for_digest.as_bytes().len() as u64;
    blake2b.update(&witness_len.to_le_bytes());
    blake2b.update(&witness_for_digest.as_bytes());
    (1..witnesses_len).for_each(|n| {
        let witness = tx.witnesses().get(n).unwrap();
        let witness_len = witness.raw_data().len() as u64;
        blake2b.update(&witness_len.to_le_bytes());
        blake2b.update(&witness.raw_data());
    });
    blake2b.finalize(&mut message);

    // openssl
    let mut rsa_signature = [0u8; TX_SIGNATURE_SIZE];
    for index in 0..4 {
        let mut signer = Signer::new(MessageDigest::sha1(), &private_key).unwrap();
        signer.update(&message[MESSAGE_SINGLE_SIZE * index..MESSAGE_SINGLE_SIZE * (index + 1)]).unwrap();
        rsa_signature[SUB_SIGNATURE_SIZE * index..SUB_SIGNATURE_SIZE * (index + 1)].copy_from_slice(&signer.sign_to_vec().unwrap());
    }

    let mut signed_signature = rsa_signature.clone().to_vec();
    let (mut rsa_info, _) = compute_pub_key_hash(public_key, is_pub_key_hash_error);
    signed_signature.append(&mut rsa_info);

    // verify it locally
    for index in 0..4 {
        let mut verifier = Verifier::new(MessageDigest::sha1(), &public_key).unwrap();
        verifier.update(&message[MESSAGE_SINGLE_SIZE * index..MESSAGE_SINGLE_SIZE * (index + 1)]).unwrap();
        assert!(verifier.verify(&rsa_signature[SUB_SIGNATURE_SIZE * index..SUB_SIGNATURE_SIZE * (index + 1)]).unwrap());
    }

    signed_witnesses.push(
        witness
            .as_builder()
            .lock(Some(Bytes::from(signed_signature)).pack())
            .build()
            .as_bytes()
            .pack(),
    );
    for i in 1..witnesses_len {
        signed_witnesses.push(tx.witnesses().get(i).unwrap());
    }
    tx.as_advanced_builder()
        .set_witnesses(signed_witnesses)
        .build()
}

fn compute_pub_key_hash(public_key: &PKey<Public>, is_pub_key_hash_error: bool) -> (Vec<u8>, Vec<u8>) {
    let mut result: Vec<u8> = vec![];
    result.extend_from_slice(&[ISO9796_2_ALGORITHM_ID, ISO9796_2_KEY_SIZE, ISO9796_2_PADDING, ISO9796_2_MD_SHA1]);

    let rsa_public_key = public_key.rsa().unwrap();

    let mut e = if is_pub_key_hash_error {
        let mut vec = rsa_public_key.e().to_vec();
        vec.insert(0, 1);
        vec
    } else {
        rsa_public_key.e().to_vec()
    };
    let mut n = rsa_public_key.n().to_vec();
    e.reverse();
    n.reverse();

    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < 128 {
        n.push(0);
    }

    result.append(&mut e);
    result.append(&mut n);

    let h = blake160(&result).into();
    (result, h)
}

fn generate_random_key() -> (PKey<Private>, PKey<Public>) {
    let rsa = Rsa::generate(1024).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let public_key_pem: Vec<u8> = private_key.public_key_to_pem().unwrap();
    let public_key = PKey::public_key_from_pem(&public_key_pem).unwrap();
    (private_key, public_key)
}

#[test]
fn test_wrong_signature() {
    let (private_key, public_key) = generate_random_key();

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-passport-lock");
    let out_point = context.deploy_cell(contract_bin);

    let rsa_bin: Bytes = fs::read("../ckb-production-scripts/build/validate_signature_rsa")
        .expect("load rsa")
        .into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    let (_, public_key_hash) = compute_pub_key_hash(&public_key, false);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, public_key_hash.into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point1 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input_out_point2 = context.create_cell(
        CellOutput::new_builder()
            .capacity(300u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(input_out_point1)
            .build(),
        CellInput::new_builder()
            .previous_output(input_out_point2)
            .build(),
    ];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(800u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];
    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
    }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(rsa_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);

    // sign
    let tx = sign_tx(tx, &private_key, &public_key, false);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(ERROR_ISO97962_INVALID_ARG9).input_lock_script(script_cell_index)
    );
}


#[test]
fn test_wrong_pub_key() {
    let (private_key, public_key) = generate_random_key();

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-passport-lock");
    let out_point = context.deploy_cell(contract_bin);

    let rsa_bin: Bytes = fs::read("../ckb-production-scripts/build/validate_signature_rsa")
        .expect("load rsa")
        .into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    let (_, public_key_hash) = compute_pub_key_hash(&public_key, false);

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, public_key_hash.into())
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point1 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input_out_point2 = context.create_cell(
        CellOutput::new_builder()
            .capacity(300u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(input_out_point1)
            .build(),
        CellInput::new_builder()
            .previous_output(input_out_point2)
            .build(),
    ];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(800u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];
    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
    }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .cell_dep(rsa_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);

    // sign
    let tx = sign_tx(tx, &private_key, &public_key, true);

    // run
    let err = context.verify_tx(&tx, MAX_CYCLES).unwrap_err();
    let script_cell_index = 0;
    assert_error_eq!(
        err,
        ScriptError::ValidationFailure(WRONG_PUB_KEY).input_lock_script(script_cell_index)
    );
}