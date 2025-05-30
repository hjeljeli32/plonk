pub mod json;

use crate::common::kzg::{kzg_setup, GlobalParameters};
use crate::setup_global_params::json::{GlobalParametersJson, SetupGlobalParamsOutputJson};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use std::time::Instant;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct SetupGlobalParamsOutput {
    pub number_gates: usize,
    pub number_public_inputs: usize,
    pub number_witnesses: usize,
    pub d: usize,
    pub gp: GlobalParameters,
}

pub fn convert_to_json_friendly_global_params(
    output: &SetupGlobalParamsOutput,
) -> SetupGlobalParamsOutputJson {
    let tau_powers_g1 = output
        .gp
        .tau_powers_g1
        .iter()
        .map(|g1| {
            let mut bytes = Vec::new();
            g1.serialize_compressed(&mut bytes).unwrap();
            hex::encode(bytes)
        })
        .collect();

    let mut g2_bytes = Vec::new();
    output
        .gp
        .tau_g2
        .serialize_compressed(&mut g2_bytes)
        .unwrap();

    SetupGlobalParamsOutputJson {
        number_gates: output.number_gates,
        number_public_inputs: output.number_public_inputs,
        number_witnesses: output.number_witnesses,
        d: output.d,
        gp: GlobalParametersJson {
            tau_powers_g1,
            tau_g2: hex::encode(g2_bytes),
        },
    }
}

pub fn run() -> SetupGlobalParamsOutput {
    println!("Executing setup...");
    let start = Instant::now();

    let number_gates = 3; // Circuit has 2 addition gates and 1 multiplication gate
    let number_public_inputs = 2; // Circuit has 2 public inputs (x1, x2)
    let number_witnesses = 1; // Circuit has 1 witness w
    let d = 3 * number_gates + number_public_inputs + number_witnesses;
    assert_eq!(d, 12, "d must be equal to 12");

    // generate global parameters, the largest polynmial to be committed is of degree 21
    let gp = kzg_setup(21);

    println!("✅ Setup took: {:?}", start.elapsed());

    SetupGlobalParamsOutput {
        number_gates,
        number_public_inputs,
        number_witnesses,
        d,
        gp,
    }
}
