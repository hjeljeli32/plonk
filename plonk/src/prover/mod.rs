pub mod part1;
pub mod part2;
pub mod part3;
pub mod part4;
pub mod part5;

use std::time::Instant;

use ark_bls12_381::Fr;

use crate::{
    common::{proof::{Proof, ProofJson}, utils::construct_Omega},
    setup_global_params::SetupGlobalParamsOutput,
    setup_proving_key::SetupProvingKeyOutput,
    setup_verification_key::SetupVerificationKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    proving_key: &SetupProvingKeyOutput,
    verification_key: &SetupVerificationKeyOutput,
) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();

    let pub_inputs = vec![Fr::from(5), Fr::from(6)];
    let output = Fr::from(77);

    // Define Omega as subgroup of size d
    let d = setup.d;
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

    let (T, com_T) = part1::run(&setup, &Omega);
    println!("✅ Part1 took: {:?}", start.elapsed());

    let start = Instant::now();

    let proof_T_minus_v_zero = part2::run(&setup, &pub_inputs, &Omega, &T, com_T);
    println!("✅ Part2 took: {:?}", start.elapsed());

    let start = Instant::now();

    let proof_T_S_zero = part3::run(&setup, &proving_key, &verification_key, &Omega, &T, com_T);
    println!("✅ Part3 took: {:?}", start.elapsed());

    let start = Instant::now();

    let proof_T_W_prescribed_permutation =
        part4::run(&setup, &proving_key, &verification_key, &Omega, &T, com_T);
    println!("✅ Part4 took: {:?}", start.elapsed());

    let start = Instant::now();

    let proof_last_gate_KZG = part5::run(&setup, &Omega, &T, output);
    println!("✅ Part5 took: {:?}", start.elapsed());

    let proof = Proof {
        pub_inputs,
        output,
        com_T,
        proof_T_minus_v_zero,
        proof_T_S_zero,
        proof_T_W_prescribed_permutation,
        proof_last_gate_KZG,
    };

    // Write Proof to a file
    let proof_json = ProofJson::from(&proof);
    let json_str = serde_json::to_string_pretty(&proof_json)?;
    std::fs::write("data/proof.json", json_str)?;
    println!("✅ Proof written to data/proof.json");

    Ok(())
}
