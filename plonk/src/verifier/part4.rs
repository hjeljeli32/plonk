use crate::{
    common::{kzg::kzg_verify, proof::Proof, utils::construct_Omega},
    setup_global_params::SetupGlobalParamsOutput,
};

pub fn run(setup: &SetupGlobalParamsOutput, proof: &Proof) -> () {
    println!("Executing part 4: verifying the output of the last gate");

    let d = setup.d;

    // Extract global parameters
    let gp = &setup.gp;

    // Extract number of gates
    let number_gates = setup.number_gates;

    let com_T = proof.com_T;

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

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
