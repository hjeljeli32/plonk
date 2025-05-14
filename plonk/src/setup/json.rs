use crate::setup::{GlobalParameters, SetupOutput};
use ark_bls12_381::{G1Projective as G1, G2Projective as G2};
use ark_serialize::CanonicalDeserialize;
use serde::Deserialize;
use serde::Serialize;

#[derive(Serialize, Deserialize)]
pub struct GlobalParametersJson {
    pub tau_powers_g1: Vec<String>,
    pub tau_g2: String,
}

#[derive(Serialize, Deserialize)]
pub struct SetupOutputJson {
    pub number_gates: usize,
    pub number_public_inputs: usize,
    pub number_witnesses: usize,
    pub d: usize,
    pub gp: GlobalParametersJson,
}

impl SetupOutputJson {
    pub fn into_setup_output(self) -> SetupOutput {
        let tau_powers_g1 = self
            .gp
            .tau_powers_g1
            .iter()
            .map(|hex_str| {
                let bytes = hex::decode(hex_str).expect("Invalid hex in tau_powers_g1");
                G1::deserialize_compressed(&*bytes).expect("Failed to deserialize G1")
            })
            .collect();

        let tau_g2_bytes = hex::decode(&self.gp.tau_g2).expect("Invalid hex in tau_g2");
        let tau_g2 = G2::deserialize_compressed(&*tau_g2_bytes).expect("Failed to deserialize G2");

        SetupOutput {
            number_gates: self.number_gates,
            number_public_inputs: self.number_public_inputs,
            number_witnesses: self.number_witnesses,
            d: self.d,
            gp: GlobalParameters {
                tau_powers_g1,
                tau_g2,
            },
        }
    }
}
