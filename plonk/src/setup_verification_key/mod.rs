pub mod json;

use std::time::Instant;

use crate::common::kzg::kzg_commit;
use crate::common::utils::construct_Omega;
use crate::{
    common::polynomials::interpolate_polynomial, setup_global_params::SetupGlobalParamsOutput,
};

use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ff::{AdditiveGroup, Field};
use ark_poly::Polynomial;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use json::SetupVerificationKeyOutputJson;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetupVerificationKeyOutput {
    pub com_S: G1,
    pub com_W: G1,
}

pub fn convert_to_json_friendly_verification_key(
    output: &SetupVerificationKeyOutput,
) -> SetupVerificationKeyOutputJson {
    let mut buf_s = Vec::new();
    output.com_S.serialize_compressed(&mut buf_s).unwrap();
    let com_S = hex::encode(buf_s);

    let mut buf_w = Vec::new();
    output.com_W.serialize_compressed(&mut buf_w).unwrap();
    let com_W = hex::encode(buf_w);

    SetupVerificationKeyOutputJson { com_S, com_W }
}

pub fn run(setup: &SetupGlobalParamsOutput) -> SetupVerificationKeyOutput {
    let start = Instant::now();

    let d = setup.d;
    let number_gates = setup.number_gates;

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");
    // Define Omega_gates
    let mut Omega_gates = vec![];
    (0..number_gates).for_each(|l| Omega_gates.push(Omega[3 * l]));
    assert_eq!(
        Omega_gates.len(),
        number_gates,
        "Omega_gates must be of length number_gates"
    );

    let mut gates = vec![];

    // S encodes gates: S(w^3*l) = gate#l
    // S(w^0) = 1 -- addition gate
    gates.push(Fr::ONE);
    // S(w^3) = 1 -- addition gate
    gates.push(Fr::ONE);
    // S(w^6) = 0 -- multiplication gate
    gates.push(Fr::ZERO);

    // Interpolate the polynomial S
    let S = interpolate_polynomial(&Omega_gates, &gates);
    assert_eq!(
        S.degree(),
        number_gates - 1,
        "S must be of degree (number_gates - 1)"
    );

    // Compute commitment of S
    let com_S = kzg_commit(&setup.gp, &S).unwrap();

    // W encodes wirings
    let (mut W_x_vals, mut W_y_vals) = (vec![], vec![]);

    // W(w^-2, w^1, w^3) = (w^1, w^3, w^-2)
    W_x_vals.extend(vec![Omega[d - 2], Omega[1], Omega[3]]);
    W_y_vals.extend(vec![Omega[1], Omega[3], Omega[d - 2]]);

    // W(w^-1, w^0) = (w^0, w^-1)
    W_x_vals.extend(vec![Omega[d - 1], Omega[0]]);
    W_y_vals.extend(vec![Omega[0], Omega[d - 1]]);

    // W(w^2, w^6) = (w^6, w^2)
    W_x_vals.extend(vec![Omega[2], Omega[6]]);
    W_y_vals.extend(vec![Omega[6], Omega[2]]);

    // W(w^-3, w^4) = (w^4, w^-3)
    W_x_vals.extend(vec![Omega[d - 3], Omega[4]]);
    W_y_vals.extend(vec![Omega[4], Omega[d - 3]]);

    // W(w^5, w^7) = (w^7, w^5)
    W_x_vals.extend(vec![Omega[5], Omega[7]]);
    W_y_vals.extend(vec![Omega[7], Omega[5]]);

    // W(w^8) = w^8
    W_x_vals.push(Omega[8]);
    W_y_vals.push(Omega[8]);

    // Interpolate the polynomial W
    let W = interpolate_polynomial(&W_x_vals, &W_y_vals);
    assert_eq!(W.degree(), d - 1, "W must be of degree d-1");

    // Compute commitment of W
    let com_W = kzg_commit(&setup.gp, &W).unwrap();

    println!("✅ Generating verification key took: {:?}", start.elapsed());

    SetupVerificationKeyOutput { com_S, com_W }
}
