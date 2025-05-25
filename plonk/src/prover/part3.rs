use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ff::{AdditiveGroup, Field};
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::{
    common::{
        polynomials::compose_polynomials,
        protocols::{
            compute_q_zero_test_from_roots, prove_T_S_zero_test,
            TSZeroTestProof,
        },
        utils::derive_challenge_from_commitments,
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
) -> TSZeroTestProof {
    println!("Executing part 3...");

    let number_gates = setup.number_gates;

    let gp = &setup.gp;

    // Define Omega_gates
    let mut Omega_gates = vec![];
    (0..number_gates).for_each(|l| Omega_gates.push(Omega[3 * l]));

    let S = &proving_key.S;
    let com_S = verification_key.com_S;

    let w = Omega[1];

    // T(w*y)
    let T_w_y = compose_polynomials(
        &T,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, w],
        },
    );
    // T(w^2*y)
    let T_w2_y = compose_polynomials(
        &T,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, w * w],
        },
    );
    // 1 - S(y)
    let one_minus_S = DensePolynomial {
        coeffs: vec![Fr::ONE],
    } - S;
    let S_T = S * &(T + &T_w_y) + &one_minus_S * &(T * &T_w_y) - &T_w2_y;

    for y in &Omega_gates {
        assert_eq!(S_T.evaluate(&y), Fr::ZERO, "S_T should cancel on y");
    }

    // Compute quotient polynomial of S_T by the vanishing polynomial defined by Omega_gates as roots
    let q = compute_q_zero_test_from_roots(&Omega_gates, &S_T);

    // Derive challenge r from the commitments of T,S
    let r = derive_challenge_from_commitments(&[com_T, com_S]);

    // Prove T_S zero test on Omega_gates
    let proof_T_S_zero = prove_T_S_zero_test(gp, w, &q, &T, &S, r);

    proof_T_S_zero
}
