use crate::{
    common::{
        proof::Proof,
        protocols::verify_T_S_zero_test,
        utils::{construct_Omega, derive_challenge_from_commitments},
    },
    setup_global_params::SetupGlobalParamsOutput,
    setup_verification_key::SetupVerificationKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    verification_key: &SetupVerificationKeyOutput,
    proof: &Proof,
) -> () {
    println!("Executing part 2...");

    let d = setup.d;

    let number_gates = setup.number_gates;
    let gp = &setup.gp;

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

    // Define Omega_gates
    let mut Omega_gates = vec![];
    (0..number_gates).for_each(|l| Omega_gates.push(Omega[3 * l]));

    let com_T = proof.com_T;
    let com_S = verification_key.com_S;

    // Derive challenge r from the commitments of T,S
    let r = derive_challenge_from_commitments(&[com_T, com_S]);

    // Verify T_S zero test
    assert!(
        verify_T_S_zero_test(
            &gp,
            Omega[1],
            &Omega_gates,
            com_T,
            com_S,
            r,
            &proof.proof_T_S_zero
        ),
        "Verification of T_S Zero Test of T and S must return true"
    );
    println!("✅ Verified T_S Zero Test of T and S on Omega_gates");
}
