use ark_bls12_381::{Fr, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::common::protocols::ZeroTestProof;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    pub pub_inputs: Vec<Fr>,
    pub com_T: G1,
    pub proof_T_minus_v_zero: ZeroTestProof,
}

#[derive(Serialize, Deserialize)]
pub struct ProofJson {
    pub pub_inputs: Vec<String>,
    pub com_T: String,
    pub proof_T_minus_v_zero: (String, String, String, String, String),
}

impl From<&Proof> for ProofJson {
    fn from(proof: &Proof) -> Self {
        let mut buf = Vec::new();

        let pub_inputs = proof.pub_inputs.iter().map(|fr| fr.to_string()).collect();

        proof.com_T.serialize_compressed(&mut buf).unwrap();
        let com_T = hex::encode(&buf);
        buf.clear();

        proof.proof_T_minus_v_zero.com_q.serialize_compressed(&mut buf).unwrap();
        let proof_T_minus_v_zero_com_q = hex::encode(&buf);
        buf.clear();

        proof.proof_T_minus_v_zero.proof_f.serialize_compressed(&mut buf).unwrap();
        let proof_T_minus_v_zero_proof_f = hex::encode(&buf);
        buf.clear();

        proof.proof_T_minus_v_zero.proof_q.serialize_compressed(&mut buf).unwrap();
        let proof_T_minus_v_zero_proof_q = hex::encode(&buf);
        buf.clear();

        ProofJson {
            pub_inputs,
            com_T,
            proof_T_minus_v_zero: (
                proof_T_minus_v_zero_com_q,
                proof.proof_T_minus_v_zero.f_r.to_string(),
                proof_T_minus_v_zero_proof_f,
                proof.proof_T_minus_v_zero.q_r.to_string(),
                proof_T_minus_v_zero_proof_q,
            ),
        }
    }
}

impl From<&ProofJson> for Proof {
    fn from(json: &ProofJson) -> Self {
        let com_T_bytes = hex::decode(&json.com_T).expect("Invalid hex in com_T");

        let proof_T_minus_v_zero_com_q_bytes = hex::decode(&json.proof_T_minus_v_zero.0).expect("Invalid hex in proof_T_minus_v_zero.0");
        let proof_T_minus_v_zero_f_r = Fr::from_str(&json.proof_T_minus_v_zero.1).expect("Invalid proof_T_minus_v_zero_f_r");
        let proof_T_minus_v_zero_proof_f_bytes = hex::decode(&json.proof_T_minus_v_zero.2).expect("Invalid hex in proof_T_minus_v_zero.2");
        let proof_T_minus_v_zero_q_r = Fr::from_str(&json.proof_T_minus_v_zero.3).expect("Invalid proof_T_minus_v_zero_q_r");
        let proof_T_minus_v_zero_proof_q_bytes = hex::decode(&json.proof_T_minus_v_zero.4).expect("Invalid hex in proof_T_minus_v_zero.4");

        let com_T = G1::deserialize_compressed(&*com_T_bytes).expect("Failed to deserialize com_T");
        let proof_T_minus_v_zero_com_q = G1::deserialize_compressed(&*proof_T_minus_v_zero_com_q_bytes).expect("Failed to deserialize proof_T_minus_v_zero_com_q");
        let proof_T_minus_v_zero_proof_f = G1::deserialize_compressed(&*proof_T_minus_v_zero_proof_f_bytes).expect("Failed to deserialize proof_T_minus_v_zero_proof_f");
        let proof_T_minus_v_zero_proof_q = G1::deserialize_compressed(&*proof_T_minus_v_zero_proof_q_bytes).expect("Failed to deserialize proof_T_minus_v_zero_proof_q");

        let pub_inputs = json
            .pub_inputs
            .iter()
            .map(|s| Fr::from_str(s).expect("Invalid Fr in pub_inputs"))
            .collect();

        Proof {
            pub_inputs,
            com_T,
            proof_T_minus_v_zero: ZeroTestProof {
                com_q: proof_T_minus_v_zero_com_q,
                f_r: proof_T_minus_v_zero_f_r,
                proof_f: proof_T_minus_v_zero_proof_f,
                q_r: proof_T_minus_v_zero_q_r,
                proof_q: proof_T_minus_v_zero_proof_q,
            },
        }
    }
}
