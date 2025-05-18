use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ff::Field;
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::{
    setup_global_params::SetupGlobalParamsOutput, setup_proving_key::SetupProvingKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    proving_key: &SetupProvingKeyOutput,
    Omega: &Vec<Fr>,
    T: &DensePolynomial<Fr>,
    // com_T: G1,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing part 3...");

    // let number_public_inputs = setup.number_public_inputs;
    // let d = setup.d;

    let number_gates = setup.number_gates;

    // Define Omega_gates
    let mut Omega_gates = vec![];
    (0..number_gates).for_each(|l| Omega_gates.push(Omega[3 * l]));

    let S = proving_key.S.clone();

    let w = Omega[1];
    for y in Omega_gates {
        let S_y = S.evaluate(&y);
        let T_y = T.evaluate(&y);
        let T_w_y = T.evaluate(&(&y * &w));
        let T_w2_y = T.evaluate(&(&y * &w * &w));
        let left = S_y * (T_y + T_w_y) + (Fr::ONE - S_y) * T_y * T_w_y;
        let right = T_w2_y;
        assert_eq!(left, right, "left must be equal to right");
    }

    // Define Omega_inputs
    // let mut Omega_inputs = vec![];
    // (0..number_public_inputs).for_each(|i| Omega_inputs.push(Omega[d - 1 - i]));
    // assert_eq!(
    //     Omega_inputs,
    //     vec![Omega[Omega.len() - 1], Omega[Omega.len() - 2]],
    //     "Omega_inputs should be equal to [w^-1, w^-2]"
    // );

    // // v encodes all inputs: T(w^-j) = input#j
    // let mut pub_inputs = vec![];
    // // v(w^-1) = 5
    // pub_inputs.push(Fr::from(5));
    // // v(w^-2) = 6
    // pub_inputs.push(Fr::from(6));

    // // Interpolate the polynomial v
    // let v = interpolate_polynomial(&Omega_inputs, &pub_inputs);
    // assert_eq!(
    //     v.degree(),
    //     number_public_inputs - 1,
    //     "v must be of degree 1"
    // );
    // let T_minus_v = T - &v;
    // assert_eq!(T_minus_v.degree(), 11, "T_minus_v must be of degree 11");

    // // Compute commitment of v and derive commitment of T-v
    // let com_v = kzg_commit(&setup.gp, &v).unwrap();
    // let com_T_minus_v = com_T - com_v;

    // // Compute quotient polynomial of T-v by the vanishing polynomial defined by Omega_inputs as roots
    // let q = compute_q_zero_test_from_roots(&Omega_inputs, &T_minus_v);
    // let com_q = kzg_commit(&setup.gp, &q).unwrap();

    // // Derive challenge r from the commitment of T-v
    // let r = derive_challenge_from_commitment(&com_T_minus_v);

    // // Prove Zero Test of T-v on Omega_inputs
    // let (T_minus_v_r, proof_T_minus_v, q_r, proof_q) =
    //     prove_zero_test(&setup.gp, &T_minus_v, &q, r);

    // let proof = Proof {
    //     pub_inputs,
    //     com_T,
    //     com_q,
    //     T_minus_v_r,
    //     proof_T_minus_v,
    //     q_r,
    //     proof_q,
    // };

    // // Write Proof to a file
    // let proof_json = ProofJson::from(&proof);
    // let json_str = serde_json::to_string_pretty(&proof_json)?;
    // std::fs::write("data/proof.json", json_str)?;
    // println!("✅ Proof written to data/proof.json");

    Ok(())
}
