use crate::common::protocols::{TSZeroTestProof, ZeroTestProof};
use ark_bls12_381::{Fr, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    pub pub_inputs: Vec<Fr>,
    pub com_T: G1,
    pub proof_T_minus_v_zero: ZeroTestProof,
    pub proof_T_S_zero: TSZeroTestProof,
}

#[derive(Serialize, Deserialize)]
pub struct ProofJson {
    pub pub_inputs: Vec<String>,
    pub com_T: String,
    pub proof_T_minus_v_zero: (String, String, String, String, String),
    pub proof_T_S_zero: (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        String,
    ),
}

impl From<&Proof> for ProofJson {
    fn from(proof: &Proof) -> Self {
        let mut buf = Vec::new();

        let pub_inputs = proof.pub_inputs.iter().map(|fr| fr.to_string()).collect();

        proof.com_T.serialize_compressed(&mut buf).unwrap();
        let com_T = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_minus_v_zero
            .com_q
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_minus_v_zero_com_q = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_minus_v_zero
            .proof_f_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_minus_v_zero_proof_f = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_minus_v_zero
            .proof_q_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_minus_v_zero_proof_q = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_S_zero
            .com_q
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_S_zero_com_q = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_S_zero
            .proof_T_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_S_zero_proof_T_r = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_S_zero
            .proof_T_w_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_S_zero_proof_T_w_r = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_S_zero
            .proof_T_w2_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_S_zero_proof_T_w2_r = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_S_zero
            .proof_S_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_S_zero_proof_S_r = hex::encode(&buf);
        buf.clear();

        proof
            .proof_T_S_zero
            .proof_q_r
            .serialize_compressed(&mut buf)
            .unwrap();
        let proof_T_S_zero_proof_q_r = hex::encode(&buf);
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
            proof_T_S_zero: (
                proof_T_S_zero_com_q,
                proof.proof_T_S_zero.T_r.to_string(),
                proof_T_S_zero_proof_T_r,
                proof.proof_T_S_zero.T_w_r.to_string(),
                proof_T_S_zero_proof_T_w_r,
                proof.proof_T_S_zero.T_w2_r.to_string(),
                proof_T_S_zero_proof_T_w2_r,
                proof.proof_T_S_zero.S_r.to_string(),
                proof_T_S_zero_proof_S_r,
                proof.proof_T_S_zero.q_r.to_string(),
                proof_T_S_zero_proof_q_r,
            ),
        }
    }
}

impl From<&ProofJson> for Proof {
    fn from(json: &ProofJson) -> Self {
        let com_T_bytes = hex::decode(&json.com_T).expect("Invalid hex in com_T");

        let proof_T_minus_v_zero_com_q_bytes = hex::decode(&json.proof_T_minus_v_zero.0)
            .expect("Invalid hex in proof_T_minus_v_zero.0");
        let proof_T_minus_v_zero_f_r =
            Fr::from_str(&json.proof_T_minus_v_zero.1).expect("Invalid proof_T_minus_v_zero_f_r");
        let proof_T_minus_v_zero_proof_f_bytes = hex::decode(&json.proof_T_minus_v_zero.2)
            .expect("Invalid hex in proof_T_minus_v_zero.2");
        let proof_T_minus_v_zero_q_r =
            Fr::from_str(&json.proof_T_minus_v_zero.3).expect("Invalid proof_T_minus_v_zero_q_r");
        let proof_T_minus_v_zero_proof_q_bytes = hex::decode(&json.proof_T_minus_v_zero.4)
            .expect("Invalid hex in proof_T_minus_v_zero.4");

        let proof_T_S_zero_com_q_bytes = hex::decode(&json.proof_T_S_zero.0).expect("Invalid hex");
        let proof_T_S_zero_T_r = Fr::from_str(&json.proof_T_S_zero.1).expect("Invalid Fr");
        let proof_T_S_zero_proof_T_r_bytes =
            hex::decode(&json.proof_T_S_zero.2).expect("Invalid hex");
        let proof_T_S_zero_T_w_r = Fr::from_str(&json.proof_T_S_zero.3).expect("Invalid Fr");
        let proof_T_S_zero_proof_T_w_r_bytes =
            hex::decode(&json.proof_T_S_zero.4).expect("Invalid hex");
        let proof_T_S_zero_T_w2_r = Fr::from_str(&json.proof_T_S_zero.5).expect("Invalid Fr");
        let proof_T_S_zero_proof_T_w2_r_bytes =
            hex::decode(&json.proof_T_S_zero.6).expect("Invalid hex");
        let proof_T_S_zero_S_r = Fr::from_str(&json.proof_T_S_zero.7).expect("Invalid Fr");
        let proof_T_S_zero_proof_S_r_bytes =
            hex::decode(&json.proof_T_S_zero.8).expect("Invalid hex");
        let proof_T_S_zero_q_r = Fr::from_str(&json.proof_T_S_zero.9).expect("Invalid Fr");
        let proof_T_S_zero_proof_q_r_bytes =
            hex::decode(&json.proof_T_S_zero.10).expect("Invalid hex");

        let com_T = G1::deserialize_compressed(&*com_T_bytes).expect("Failed to deserialize com_T");
        let proof_T_minus_v_zero_com_q =
            G1::deserialize_compressed(&*proof_T_minus_v_zero_com_q_bytes)
                .expect("Failed to deserialize proof_T_minus_v_zero_com_q");
        let proof_T_minus_v_zero_proof_f =
            G1::deserialize_compressed(&*proof_T_minus_v_zero_proof_f_bytes)
                .expect("Failed to deserialize proof_T_minus_v_zero_proof_f");
        let proof_T_minus_v_zero_proof_q =
            G1::deserialize_compressed(&*proof_T_minus_v_zero_proof_q_bytes)
                .expect("Failed to deserialize proof_T_minus_v_zero_proof_q");

        let proof_T_S_zero = TSZeroTestProof {
            com_q: G1::deserialize_compressed(&*proof_T_S_zero_com_q_bytes).unwrap(),
            T_r: proof_T_S_zero_T_r,
            proof_T_r: G1::deserialize_compressed(&*proof_T_S_zero_proof_T_r_bytes).unwrap(),
            T_w_r: proof_T_S_zero_T_w_r,
            proof_T_w_r: G1::deserialize_compressed(&*proof_T_S_zero_proof_T_w_r_bytes).unwrap(),
            T_w2_r: proof_T_S_zero_T_w2_r,
            proof_T_w2_r: G1::deserialize_compressed(&*proof_T_S_zero_proof_T_w2_r_bytes).unwrap(),
            S_r: proof_T_S_zero_S_r,
            proof_S_r: G1::deserialize_compressed(&*proof_T_S_zero_proof_S_r_bytes).unwrap(),
            q_r: proof_T_S_zero_q_r,
            proof_q_r: G1::deserialize_compressed(&*proof_T_S_zero_proof_q_r_bytes).unwrap(),
        };

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
                proof_f_r: proof_T_minus_v_zero_proof_f,
                q_r: proof_T_minus_v_zero_q_r,
                proof_q_r: proof_T_minus_v_zero_proof_q,
            },
            proof_T_S_zero,
        }
    }
}
