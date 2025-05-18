use ark_bls12_381::{Fr, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use crate::common::protocols::ZeroTestProof;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    pub pub_inputs: Vec<Fr>,
    pub com_T: G1,
    pub com_q: G1,
    pub proof_T_minus_v_zero: ZeroTestProof,
}

#[derive(Serialize, Deserialize)]
pub struct ProofJson {
    pub pub_inputs: Vec<String>,
    pub com_T: String,
    pub com_q: String,
    pub proof_T_minus_v_zero: (String, String, String, String),
}

impl From<&Proof> for ProofJson {
    fn from(proof: &Proof) -> Self {
        let mut buf = Vec::new();

        let pub_inputs = proof.pub_inputs.iter().map(|fr| fr.to_string()).collect();

        proof.com_T.serialize_compressed(&mut buf).unwrap();
        let com_T = hex::encode(&buf);
        buf.clear();

        proof.com_q.serialize_compressed(&mut buf).unwrap();
        let com_q = hex::encode(&buf);
        buf.clear();

        proof.proof_T_minus_v_zero.proof_f.serialize_compressed(&mut buf).unwrap();
        let proof_T_minus_v_zero_proof_f = hex::encode(&buf);
        buf.clear();

        proof.proof_T_minus_v_zero.proof_q.serialize_compressed(&mut buf).unwrap();
        let proof_T_minus_v_zero_proof_q = hex::encode(&buf);

        ProofJson {
            pub_inputs,
            com_T,
            com_q,
            proof_T_minus_v_zero: (
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
        let com_q_bytes = hex::decode(&json.com_q).expect("Invalid hex in com_q");
        let com_T_bytes = hex::decode(&json.com_T).expect("Invalid hex in com_T");
        let proof_T_minus_v_zero_proof_f_bytes = hex::decode(&json.proof_T_minus_v_zero.1).expect("Invalid hex in proof_T_minus_v_zero.1");
        let proof_T_minus_v_zero_proof_q_bytes = hex::decode(&json.proof_T_minus_v_zero.3).expect("Invalid hex in proof_T_minus_v_zero.3");

        let com_q = G1::deserialize_compressed(&*com_q_bytes).expect("Failed to deserialize com_q");
        let com_T = G1::deserialize_compressed(&*com_T_bytes).expect("Failed to deserialize com_T");
        let proof_T_minus_v_zero_proof_f = G1::deserialize_compressed(&*proof_T_minus_v_zero_proof_f_bytes).expect("Failed to deserialize proof_T_minus_v_zero_proof_f");
        let proof_T_minus_v_zero_proof_q = G1::deserialize_compressed(&*proof_T_minus_v_zero_proof_q_bytes).expect("Failed to deserialize proof_T_minus_v_zero_proof_q");

        let pub_inputs = json
            .pub_inputs
            .iter()
            .map(|s| Fr::from_str(s).expect("Invalid Fr in pub_inputs"))
            .collect();
        let proof_T_minus_v_zero_f_r = Fr::from_str(&json.proof_T_minus_v_zero.0).expect("Invalid proof_T_minus_v_zero_f_r");
        let proof_T_minus_v_zero_q_r = Fr::from_str(&json.proof_T_minus_v_zero.2).expect("Invalid proof_T_minus_v_zero_q_r");

        Proof {
            pub_inputs,
            com_T,
            com_q,
            proof_T_minus_v_zero: ZeroTestProof {
                f_r: proof_T_minus_v_zero_f_r,
                proof_f: proof_T_minus_v_zero_proof_f,
                q_r: proof_T_minus_v_zero_q_r,
                proof_q: proof_T_minus_v_zero_proof_q,
            },
        }
    }
}
