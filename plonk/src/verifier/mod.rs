use std::time::Instant;

use ark_poly::Polynomial;

use crate::{common::{kzg::kzg_commit, polynomials::interpolate_polynomial, proof::Proof, protocols::verify_zero_on_roots_test, utils::{construct_Omega, derive_challenge_from_commitment}}, setup::SetupOutput};

pub fn run(setup: &SetupOutput, proof: &Proof) -> () {
    println!("Executing verifier...");
    let start = Instant::now();

    let number_public_inputs = setup.number_public_inputs;
    let d = setup.d;

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

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
    let com_v = kzg_commit(&setup.gp, &v).unwrap();
    let com_T_minus_v = proof.com_T - com_v;

    // Derive challenge r from the commitment of T-v 
    let r = derive_challenge_from_commitment(&com_T_minus_v);

    // Verify Zero Test of T-v on Omega_inputs
    assert!(
        verify_zero_on_roots_test(
            &setup.gp,
            &Omega_inputs,
            com_T_minus_v,
            proof.com_q,
            r,
            proof.T_minus_v_r,
            proof.proof_T_minus_v,
            proof.q_r,
            proof.proof_q
        ),
        "Verification of Zero Test must return true"
    );
    println!("✅ Verified Zero Test of T-v on Omega_inputs");

    println!("✅ Verifier took: {:?}", start.elapsed());

    ()
}
