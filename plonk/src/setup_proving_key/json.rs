use ark_bls12_381::Fr;
use ark_poly::DenseUVPolynomial;
use serde::Deserialize;
use serde::Serialize;
use std::str::FromStr;

use ark_poly::univariate::DensePolynomial;
use crate::setup_proving_key::SetupProvingKeyOutput;

#[derive(Serialize, Deserialize)]
pub struct SetupProvingKeyOutputJson {
    pub S: Vec<String>,
}

impl SetupProvingKeyOutputJson {
    pub fn into_setup_output(self) -> SetupProvingKeyOutput {
        let coeffs = self.S.iter()
            .map(|s| Fr::from_str(s).expect("Invalid Fr in selector S"))
            .collect();
        SetupProvingKeyOutput {
            S: DensePolynomial::from_coefficients_vec(coeffs),
        }
    }
}