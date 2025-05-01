use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, UniformRand};
use ark_poly::{
    Polynomial,
    multivariate::{SparsePolynomial, SparseTerm},
};
use thiserror::Error;

use crate::common::pairing_utils::pairing_product;

use super::{
    bivariate_polynomials::{
        BivariateMonomialList, divide_by_linear_in_x, divide_by_linear_in_y,
        subtract_value_from_poly_monomials,
    },
    pairing_utils::pairing_value,
};

#[derive(Debug, Error)]
pub enum CommitError {
    #[error("Length of tau_powers_g1 must be at least equal to (d+1)*(d+2)/2")]
    CommitFailed,
}

#[derive(Clone)]
pub struct GlobalParameters {
    pub tau_powers_g1: Vec<G1>, // Vector of tau1^i * tau2^j * g1 for all pairs i,j in [0..degree] such that i+j <= degree
    pub tau_powers_g1_prime: Vec<G1>, // Vector of tau1^i * tau2^j * g1 for all pairs i,j in [0..degree-1] such that i+j <= degree-1
    pub tau_g2: Vec<G2>,              // Vector [tau1 * G2, tau2 * G2]
}

// Generate global parameters of KZG polynomial commitment scheme for birvariate polynomials
pub fn bivariate_kzg_setup(degree: usize) -> GlobalParameters {
    let mut rng = ark_std::test_rng();

    // Sample uniformly randoms tau1 and tau2
    let tau1 = Fr::rand(&mut rng);
    let tau2 = Fr::rand(&mut rng);
    let mut tau_powers_g1 = vec![];
    let mut tau_powers_g1_prime = vec![];

    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree] such that i+j <= degree
    for i in 0..(degree + 1) {
        for j in 0..(degree + 1) {
            if i + j <= degree {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1.push(G1::generator() * exponent);
            }
        }
    }

    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree-1] such that i+j <= degree-1
    for i in 0..degree {
        for j in 0..degree {
            if i + j <= (degree - 1) {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1_prime.push(G1::generator() * exponent);
            }
        }
    }

    // Compute [tau1 * G2, tau2 * G2]
    let tau_g2 = vec![G2::generator() * tau1, G2::generator() * tau2];

    GlobalParameters {
        tau_powers_g1,
        tau_powers_g1_prime,
        tau_g2,
    }
}

// Commit a polynomial f with respect to given global parameters
pub fn bivariate_kzg_commit(
    gp: &GlobalParameters,
    f: &SparsePolynomial<Fr, SparseTerm>,
    f_monomials: &BivariateMonomialList,
) -> Result<G1, CommitError> {
    if gp.tau_powers_g1.len() < (f.degree() + 1) * (f.degree() + 2) / 2 {
        Err(CommitError::CommitFailed)
    } else {
        // compute g1*f(tau)
        Ok(f_monomials
            .iter()
            .map(|(_, _, coeff)| coeff)
            .enumerate()
            .map(|(i, f_i)| gp.tau_powers_g1[i] * f_i)
            .reduce(|com_f, f_i_tau_i_g1| com_f + f_i_tau_i_g1)
            .unwrap())
    }
}

// Evaluate polynomial f on a given point (u1, u2) and generates proof
pub fn bivariate_kzg_evaluate(
    gp: &GlobalParameters,
    f: &SparsePolynomial<Fr, SparseTerm>,
    f_monomials: &BivariateMonomialList,
    u1: Fr,
    u2: Fr,
) -> (Fr, G1, G1) {
    // compute v as evaluation of f on (u1, u2)
    let v = f.evaluate(&vec![u1, u2]);

    // compute g = f-v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, v);

    // compute q1 and q2 such that (f-v) = q1*(x-u1) + q2*(y-u2)
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);
    let q2_monomials = divide_by_linear_in_y(&r_monomials, u2);

    // compute proof1 as g1*q1(tau)
    let proof1 = q1_monomials
        .iter()
        .map(|(_, _, coeff)| coeff)
        .enumerate()
        .map(|(i, q1_i)| gp.tau_powers_g1_prime[i] * q1_i)
        .reduce(|com_q1, q1_i_tau_i_g1| com_q1 + q1_i_tau_i_g1)
        .unwrap();

    // compute proof2 as g1*q1(tau)
    let proof2 = q2_monomials
        .iter()
        .map(|(_, _, coeff)| coeff)
        .enumerate()
        .map(|(i, q2_i)| gp.tau_powers_g1_prime[i] * q2_i)
        .reduce(|com_q2, q2_i_tau_i_g1| com_q2 + q2_i_tau_i_g1)
        .unwrap();

    (v, proof1, proof2)
}

// Verify the proof that commited polynomial f evaluates to v on point (u1, u2)
pub fn bivariate_kzg_verify(
    gp: &GlobalParameters,
    com_f: G1,
    u1: Fr,
    u2: Fr,
    v: Fr,
    proof1: G1,
    proof2: G1,
) -> bool {
    // compute left-hand side of pairing equality
    let e1 = Bls12_381::pairing(com_f - G1::generator() * v, G2::generator());

    // compute right-hand side of pairing equality
    let e21 = Bls12_381::pairing(proof1, gp.tau_g2[0] + G2::generator() * (-u1));
    let e22 = Bls12_381::pairing(proof2, gp.tau_g2[1] + G2::generator() * (-u2));
    let e2 = pairing_product(&e21, &e22);

    *pairing_value(&e1) == e2
}
