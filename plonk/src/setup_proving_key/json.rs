use ark_bls12_381::Fr;
use ark_poly::DenseUVPolynomial;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

use crate::setup_proving_key::SetupProvingKeyOutput;
use ark_poly::univariate::DensePolynomial;

#[derive(Serialize, Deserialize)]
pub struct SetupProvingKeyOutputJson {
    pub S: Vec<String>,
    pub W: Vec<String>,
}

impl SetupProvingKeyOutputJson {
    pub fn into_setup_output(self) -> SetupProvingKeyOutput {
        let coeffs_S = self
            .S
            .iter()
            .map(|s| Fr::from_str(s).expect("Invalid Fr in selector S"))
            .collect();
        let coeffs_W = self
            .W
            .iter()
            .map(|w| Fr::from_str(w).expect("Invalid Fr in wiring polynomial W"))
            .collect();
        SetupProvingKeyOutput {
            S: DensePolynomial::from_coefficients_vec(coeffs_S),
            W: DensePolynomial::from_coefficients_vec(coeffs_W),
        }
    }
}
