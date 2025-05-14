use ark_bls12_381::{Fr, G1Projective as G1};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Clone, CanonicalSerialize, CanonicalDeserialize)]
pub struct Proof {
    pub pub_inputs: Vec<Fr>,
    pub com_T: G1,
    pub com_q: G1,
    pub T_minus_v_r: Fr,
    pub proof_T_minus_v: G1,
    pub q_r: Fr,
    pub proof_q: G1,
}

#[derive(Serialize, Deserialize)]
pub struct ProofJson {
    pub pub_inputs: Vec<String>,
    pub com_T: String,
    pub com_q: String,
    pub T_minus_v_r: String,
    pub proof_T_minus_v: String,
    pub q_r: String,
    pub proof_q: String,
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

        proof.proof_T_minus_v.serialize_compressed(&mut buf).unwrap();
        let proof_T_minus_v = hex::encode(&buf);
        buf.clear();

        proof.proof_q.serialize_compressed(&mut buf).unwrap();
        let proof_q = hex::encode(&buf);

        ProofJson {
            pub_inputs,
            com_T,
            com_q,
            T_minus_v_r: proof.T_minus_v_r.to_string(),
            proof_T_minus_v,
            q_r: proof.q_r.to_string(),
            proof_q,
        }
    }
}

impl From<&ProofJson> for Proof {
    fn from(json: &ProofJson) -> Self {
        let com_q_bytes = hex::decode(&json.com_q).expect("Invalid hex in com_q");
        let com_T_bytes = hex::decode(&json.com_T).expect("Invalid hex in com_T");
        let proof_T_minus_v_bytes = hex::decode(&json.proof_T_minus_v).expect("Invalid hex in proof_T_minus_v");
        let proof_q_bytes = hex::decode(&json.proof_q).expect("Invalid hex in proof_q");

        let com_q = G1::deserialize_compressed(&*com_q_bytes).expect("Failed to deserialize com_q");
        let com_T = G1::deserialize_compressed(&*com_T_bytes).expect("Failed to deserialize com_T");
        let proof_T_minus_v = G1::deserialize_compressed(&*proof_T_minus_v_bytes).expect("Failed to deserialize proof_T_minus_v");
        let proof_q = G1::deserialize_compressed(&*proof_q_bytes).expect("Failed to deserialize proof_q");

        let pub_inputs = json.pub_inputs.iter().map(|s| Fr::from_str(s).expect("Invalid Fr in pub_inputs")).collect();
        let T_minus_v_r = Fr::from_str(&json.T_minus_v_r).expect("Invalid T_minus_v_r");
        let q_r = Fr::from_str(&json.q_r).expect("Invalid q_r");

        Proof {
            pub_inputs,
            com_T,
            com_q,
            T_minus_v_r,
            proof_T_minus_v,
            q_r,
            proof_q,
        }
    }
}