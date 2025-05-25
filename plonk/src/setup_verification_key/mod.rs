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
}

pub fn convert_to_json_friendly_verification_key(
    output: &SetupVerificationKeyOutput,
) -> SetupVerificationKeyOutputJson {
    let mut buf = Vec::new();
    output.com_S.serialize_compressed(&mut buf).unwrap();
    let com_S = hex::encode(buf);

    SetupVerificationKeyOutputJson { com_S }
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

    let com_S = kzg_commit(&setup.gp, &S).unwrap();

    println!("✅ Generating verification key took: {:?}", start.elapsed());

    SetupVerificationKeyOutput { com_S }
}
