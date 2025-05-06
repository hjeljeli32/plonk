use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, UniformRand};
use ark_poly::{
    Polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CommitError {
    #[error("Length of tau_powers_g1 must be at least equal to degree of polynomial + 1")]
    CommitFailed,
}

#[derive(Clone)]
pub struct GlobalParameters {
    pub tau_powers_g1: Vec<G1>, // Vector of tau^i * G1
    pub tau_g2: G2,             // Element tau * G2
}

// Generate global parameters for KZG polynomial commitment scheme
pub fn kzg_setup(degree: usize) -> GlobalParameters {
    let mut rng = ark_std::test_rng();

    // Sample uniformly a random tau
    let tau = Fr::rand(&mut rng);
    let mut accumulator = G1::generator();
    let mut tau_powers_g1 = vec![accumulator];

    // Compute tau^i * g1 for all i in the range [1..degree]
    for _ in 1..(degree + 1) {
        accumulator = accumulator * tau; // Update accumulator with tau^i
        tau_powers_g1.push(accumulator); // Push tau^i into tau_powers_g1
    }

    // Compute tau * g2
    let tau_g2 = G2::generator() * tau;

    GlobalParameters {
        tau_powers_g1,
        tau_g2,
    }
}

// Commit a polynomial f with respect to given global parameters
pub fn kzg_commit(gp: &GlobalParameters, f: &DensePolynomial<Fr>) -> Result<G1, CommitError> {
    if gp.tau_powers_g1.len() < f.degree() + 1 {
        Err(CommitError::CommitFailed)
    } else {
        // compute g1*f(tau)
        Ok(f.coeffs
            .iter()
            .enumerate()
            .map(|(i, f_i)| gp.tau_powers_g1[i] * f_i)
            .reduce(|com_f, f_i_tau_i_g1| com_f + f_i_tau_i_g1)
            .unwrap())
    }
}

// Evaluate polynomial f on a given point u and generate proof
pub fn kzg_evaluate(gp: &GlobalParameters, f: &DensePolynomial<Fr>, u: Fr) -> (Fr, G1) {
    // compute v as evaluation of f on u
    let v = f.evaluate(&u);

    // compute f-v and x-u
    let f_minus_v = f - &DensePolynomial { coeffs: vec![v] };
    let x_minus_u = DensePolynomial {
        coeffs: vec![-u, Fr::ONE],
    };

    // compute q as (f-v)/(x-u)
    let (q, _) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&f_minus_v).into(), &(&x_minus_u).into())
            .unwrap();

    // compute proof as g1*q(tau)
    let proof = q
        .coeffs
        .iter()
        .enumerate()
        .map(|(i, q_i)| gp.tau_powers_g1[i] * q_i)
        .reduce(|proof, q_i_tau_i_g1| proof + q_i_tau_i_g1)
        .unwrap();

    (v, proof)
}

// Verify the proof that committed polynomial f evaluates to v on point u
pub fn kzg_verify(gp: &GlobalParameters, com_f: G1, u: Fr, v: Fr, proof: G1) -> bool {
    // compute left-hand side of pairing equality
    let e1 = Bls12_381::pairing(com_f - G1::generator() * v, G2::generator());
    // compute right-hand side of pairing equality
    let e2 = Bls12_381::pairing(proof, gp.tau_g2 + G2::generator() * (-u));

    e1 == e2
}
