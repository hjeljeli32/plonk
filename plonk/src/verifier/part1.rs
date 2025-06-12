use crate::{common::proof::Proof, setup_global_params::SetupGlobalParamsOutput};

use ark_bls12_381::Fr;
use ark_poly::Polynomial;

use crate::common::{
    kzg::kzg_commit,
    polynomials::interpolate_polynomial,
    protocols::verify_zero_on_roots_test,
    utils::derive_challenge_from_commitments,
};

pub fn run(setup: &SetupGlobalParamsOutput, proof: &Proof, Omega: &Vec<Fr>) -> () {
    println!("Executing part 1: verifying that T encodes the correct inputs");

    // Extract number of public inputs
    let number_public_inputs = setup.number_public_inputs;

    // Extract global parameters
    let gp = &setup.gp;

    let d = setup.d;

    // Define Omega_inputs
    let mut Omega_inputs = vec![];
    (0..number_public_inputs).for_each(|i| Omega_inputs.push(Omega[d - 1 - i]));
    assert_eq!(
        Omega_inputs,
        vec![Omega[Omega.len() - 1], Omega[Omega.len() - 2]],
        "Omega_inputs should be equal to [w^-1, w^-2]"
    );

    // v encodes all inputs: T(w^-j) = input#j
    let mut pub_inputs = vec![];
    (0..number_public_inputs).for_each(|i| pub_inputs.push(proof.pub_inputs[i]));

    // Interpolate the polynomial v
    let v = interpolate_polynomial(&Omega_inputs, &pub_inputs);
    assert_eq!(
        v.degree(),
        number_public_inputs - 1,
        "v must be of degree 1"
    );

    // Compute commitment of v and derive commitment of T-v
    let com_v = kzg_commit(gp, &v).unwrap();
    let com_T_minus_v = proof.com_T - com_v;

    // Derive challenge r from the commitment of T-v
    let r = derive_challenge_from_commitments(&[com_T_minus_v]);

    // Verify Zero Test of T-v on Omega_inputs
    assert!(
        verify_zero_on_roots_test(
            &setup.gp,
            &Omega_inputs,
            com_T_minus_v,
            r,
            &proof.proof_T_minus_v_zero,
        ),
        "Verification of Zero Test of T-v must return true"
    );
    println!("✅ Verified Zero Test of T-v on Omega_inputs");
}
