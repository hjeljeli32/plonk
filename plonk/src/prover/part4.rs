use ark_bls12_381::{Fr, G1Projective as G1};
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::{
    common::{
        protocols::{
            compute_q_zero_test, compute_t_and_t1_prescribed_permutation_check,
            prove_prescribed_permutation_check, PrescribedPermutationCheckProof,
        },
        utils::{construct_vanishing_polynomial, derive_multiple_challenges_from_commitments},
    },
    setup_global_params::SetupGlobalParamsOutput,
    setup_proving_key::SetupProvingKeyOutput,
    setup_verification_key::SetupVerificationKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    proving_key: &SetupProvingKeyOutput,
    verification_key: &SetupVerificationKeyOutput,
    Omega: &Vec<Fr>,
    T: &DensePolynomial<Fr>,
    com_T: G1,
) -> PrescribedPermutationCheckProof {
    println!("Executing part 4...");

    let d = setup.d;

    // Extract global parameters
    let gp = &setup.gp;

    // Extract polynomial W and its commitment
    let W = &proving_key.W;
    let com_W = verification_key.com_W;

    for y in Omega {
        assert_eq!(
            T.evaluate(&y),
            T.evaluate(&W.evaluate(&y)),
            "T_W should be equal to T on Omega"
        );
    }

    // construct Z_Omega (vanishing polynomial) of subset Omega
    let Z_Omega = construct_vanishing_polynomial(d);

    // Derive challenges (r, s, rp) from the commitments of T,W
    let challenges = derive_multiple_challenges_from_commitments(&[com_T, com_W], 3);

    // Construct the polynomials t and t1 based on polynomials W,T and subset Omega
    let (r, s) = (challenges[0], challenges[1]);
    let (t, t1) = compute_t_and_t1_prescribed_permutation_check(Omega, T, T, W, r, s);

    // Compute quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(d, &t1);

    // check that t1 is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, t1, "t1 must be divisible by Z_Omega");

    // Prove Prescribed Permutation Check
    let rp = challenges[2];
    let proof_T_W_prescribed_permutation =
        prove_prescribed_permutation_check(gp, Omega[1], d, &t, &q, T, T, W, rp);

    proof_T_W_prescribed_permutation
}
