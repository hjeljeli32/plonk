use ark_bls12_381::{Fr, G1Projective as G1};
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::{
    common::{
        kzg::kzg_commit,
        polynomials::interpolate_polynomial,
        protocols::{compute_q_zero_test_from_roots, prove_zero_test, ZeroTestProof},
        utils::derive_challenge_from_commitments,
    },
    setup_global_params::SetupGlobalParamsOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    pub_inputs: &Vec<Fr>,
    Omega: &Vec<Fr>,
    T: &DensePolynomial<Fr>,
    com_T: G1,
) -> ZeroTestProof {
    println!("Executing part 2: proving that T encodes the correct inputs");

    let number_public_inputs = setup.number_public_inputs;
    let d = setup.d;
    let gp = &setup.gp;

    // Define Omega_inputs
    let mut Omega_inputs = vec![];
    (0..number_public_inputs).for_each(|i| Omega_inputs.push(Omega[d - 1 - i]));
    assert_eq!(
        Omega_inputs,
        vec![Omega[Omega.len() - 1], Omega[Omega.len() - 2]],
        "Omega_inputs should be equal to [w^-1, w^-2]"
    );

    // v encodes all inputs: T(w^-j) = input#j
    // Interpolate the polynomial v
    let v = interpolate_polynomial(&Omega_inputs, pub_inputs);
    assert_eq!(
        v.degree(),
        number_public_inputs - 1,
        "v must be of degree 1"
    );
    let T_minus_v = T - &v;
    assert_eq!(T_minus_v.degree(), 11, "T_minus_v must be of degree 11");

    // Compute commitment of v and derive commitment of T-v
    let com_v = kzg_commit(gp, &v).unwrap();
    let com_T_minus_v = com_T - com_v;

    // Compute quotient polynomial of T-v by the vanishing polynomial defined by Omega_inputs as roots
    let q = compute_q_zero_test_from_roots(&Omega_inputs, &T_minus_v);

    // Derive challenge r from the commitment of T-v
    let r = derive_challenge_from_commitments(&[com_T_minus_v]);

    // Prove Zero Test of T-v on Omega_inputs
    let proof_T_minus_v_zero = prove_zero_test(gp, &T_minus_v, &q, r);

    proof_T_minus_v_zero
}
