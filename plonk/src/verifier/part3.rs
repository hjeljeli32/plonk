use crate::{
    common::{
        proof::Proof,
        protocols::verify_prescribed_permutation_check,
        utils::{construct_Omega, derive_multiple_challenges_from_commitments},
    },
    setup_global_params::SetupGlobalParamsOutput,
    setup_verification_key::SetupVerificationKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    verification_key: &SetupVerificationKeyOutput,
    proof: &Proof,
) -> () {
    println!("Executing part 3: verifying that the wiring is implemented correctly");

    let d = setup.d;

    // Extract global parameters
    let gp = &setup.gp;

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

    let com_T = proof.com_T;
    let com_W = verification_key.com_W;

    // Derive challenges (r, s, rp) from the commitments of T,W
    let challenges = derive_multiple_challenges_from_commitments(&[com_T, com_W], 3);
    let (r, s, rp) = (challenges[0], challenges[1], challenges[2]);

    // Verify Prescribed Permutation Check
    assert!(
        verify_prescribed_permutation_check(
            &gp,
            Omega[1],
            d,
            com_T,
            com_T,
            com_W,
            r,
            s,
            rp,
            &proof.proof_T_W_prescribed_permutation,
        ),
        "Verify must return true because W is prescribed permutation of T over Omega"
    );
    println!("✅ Verified T_W Prescribed Permutation Check on Omega");
}
