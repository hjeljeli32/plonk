use ark_bls12_381::G1Projective as G1;
use ark_serialize::CanonicalDeserialize;
use serde::{Deserialize, Serialize};

use crate::setup_verification_key::SetupVerificationKeyOutput;

#[derive(Serialize, Deserialize)]
pub struct SetupVerificationKeyOutputJson {
    pub com_S: String,
    pub com_W: String,
}

impl SetupVerificationKeyOutputJson {
    pub fn into_setup_output(self) -> SetupVerificationKeyOutput {
        let com_S_bytes = hex::decode(&self.com_S).expect("Invalid hex in com_S");
        let com_S = G1::deserialize_compressed(&*com_S_bytes).expect("Failed to deserialize com_S");

        let com_W_bytes = hex::decode(&self.com_W).expect("Invalid hex in com_W");
        let com_W = G1::deserialize_compressed(&*com_W_bytes).expect("Failed to deserialize com_W");

        SetupVerificationKeyOutput { com_S, com_W }
    }
}
