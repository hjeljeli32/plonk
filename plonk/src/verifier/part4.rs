use ark_bls12_381::Fr;

use crate::{
    common::{kzg::kzg_verify, proof::Proof},
    setup_global_params::SetupGlobalParamsOutput,
};

pub fn run(setup: &SetupGlobalParamsOutput, proof: &Proof, Omega: &Vec<Fr>) -> () {
    println!("Executing part 4: verifying the output of the last gate");

    // Extract global parameters
    let gp = &setup.gp;

    // Extract number of gates
    let number_gates = setup.number_gates;

    let com_T = proof.com_T;

    // Verify Prescribed Permutation Check
    assert!(
        kzg_verify(
            &gp,
            com_T,
            Omega[3 * number_gates - 1],
            proof.output,
            proof.proof_last_gate_KZG,
        ),
        "Verify must return true because the output of last gate should match"
    );
    println!("✅ Verified KZG proof of the output of the last gate");
}
