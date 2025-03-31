use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ff::{AdditiveGroup, Field};
use ark_poly::univariate::{DenseOrSparsePolynomial, DensePolynomial};

use super::kzg::{GlobalParameters, kzg_evaluate, kzg_verify};

// Generates a proof that two previously committed polynomials f,g are equal
pub fn prove_equality(
    gp: &GlobalParameters,
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
    r: Fr,
) -> (Fr, G1, Fr, G1) {
    // compute f(r) and its proof
    let (y_f, proof_f) = kzg_evaluate(gp, f, r);
    // compute g(r) and its proof
    let (y_g, proof_g) = kzg_evaluate(gp, g, r);

    (y_f, proof_f, y_g, proof_g)
}

// Verify the proof that two previously committed polynomials f,g are equal
pub fn verify_equality(
    gp: &GlobalParameters,
    com_f: G1,
    com_g: G1,
    r: Fr,
    y_f: Fr,
    proof_f: G1,
    y_g: Fr,
    proof_g: G1,
) -> bool {
    (y_f == y_g) && kzg_verify(gp, com_f, r, y_f, proof_f) && kzg_verify(gp, com_g, r, y_g, proof_g)
}

// Computes the quotient polynomial q of f by the vanishing polynomial Z_Omega
pub fn compute_q_zero_test(k: usize, f: &DensePolynomial<Fr>) -> DensePolynomial<Fr> {
    // construct Z_Omega (vanishing polynomial)
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^k

    // compute q as quotient of f by Z_Omega
    let (q, _) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(f).into(), &(&Z_Omega).into()).unwrap();

    q
}

// Generates a proof that a polynomial (previously committed) is zero on subset Omega
pub fn prove_zero_test(
    gp: &GlobalParameters,
    f: &DensePolynomial<Fr>,
    q: &DensePolynomial<Fr>,
    r: Fr,
) -> (Fr, G1, Fr, G1) {
    // compute f(r) and its proof
    let (f_r, proof_f) = kzg_evaluate(gp, f, r);
    // compute q(r) and its proof
    let (q_r, proof_q) = kzg_evaluate(gp, q, r);

    (f_r, proof_f, q_r, proof_q)
}

// Verifies the proof that a polynomial (previously committed) is zero on subset Omega
pub fn verify_zero_test(
    gp: &GlobalParameters,
    k: usize,
    com_f: G1,
    com_q: G1,
    r: Fr,
    f_r: Fr,
    proof_f: G1,
    q_r: Fr,
    proof_q: G1
) -> bool {
    (f_r == q_r * (r.pow([k as u64]) - Fr::ONE))
        && kzg_verify(gp, com_q, r, q_r, proof_q)
        && kzg_verify(gp, com_f, r, f_r, proof_f)
}
