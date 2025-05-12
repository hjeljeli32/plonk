use ark_bls12_381::G1Projective as G1;
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use serde::{Serialize, Deserialize};

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    pub com_T: G1,
}

#[derive(Serialize, Deserialize)]
pub struct ProofJson {
    pub com_T: String, // hex-encoded compressed G1
}

impl From<&Proof> for ProofJson {
    fn from(proof: &Proof) -> Self {
        let mut bytes = Vec::new();
        proof.com_T
            .serialize_compressed(&mut bytes)
            .expect("serialization should not fail");
        ProofJson {
            com_T: hex::encode(bytes),
        }
    }
}

impl From<&ProofJson> for Proof {
    fn from(json: &ProofJson) -> Self {
        let bytes = hex::decode(&json.com_T).expect("Invalid hex in com_t");
        let com_T = G1::deserialize_compressed(&*bytes).expect("Failed to deserialize G1");
        Proof { com_T }
    }
}
