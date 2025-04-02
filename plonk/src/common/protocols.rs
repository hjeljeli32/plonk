use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_poly::{
    Polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
};

use crate::common::univariate_polynomials::{compose_polynomials, interpolate_polynomial};

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
    proof_q: G1,
) -> bool {
    (f_r == q_r * (r.pow([k as u64]) - Fr::ONE))
        && kzg_verify(gp, com_q, r, q_r, proof_q)
        && kzg_verify(gp, com_f, r, f_r, proof_f)
}

// Constructs the polynomials t and t1 based on polynomial f and subset Omega
pub fn compute_t_and_t1_product_check(
    Omega: &Vec<Fr>,
    f: &DensePolynomial<Fr>,
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let mut rng = ark_std::test_rng();

    // compute evaluations of t over Omega as product of evaluations of f
    let k = Omega.len();
    let mut t_y_vals: Vec<Fr> = (0..k)
        .map(|i| {
            (0..i + 1)
                .map(|j| f.evaluate(&Omega[j]))
                .reduce(|t_eval, f_eval| t_eval * f_eval)
                .unwrap()
        })
        .collect();
    t_y_vals.extend((0..(f.degree() + 1 - k)).map(|_| Fr::rand(&mut rng)));
    let mut t_x_vals = Omega.clone();
    t_x_vals.extend((0..(f.degree() + 1 - k)).map(|_| Fr::rand(&mut rng)));
    // interpolate polynomial t
    let t = interpolate_polynomial(&t_x_vals, &t_y_vals);

    // t(w*x)
    let t_w_x = compose_polynomials(
        &t,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // f(w*x)
    let f_w_x = compose_polynomials(
        &f,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // t1(x) = t(w*x) - t(x)f(w*x)
    let t1 = &t_w_x - &t * &f_w_x;

    (t, t1)
}

// Generates the proof of product check on subset Omega
pub fn prove_product_check(
    gp: &GlobalParameters,
    w: Fr,
    k: usize,
    t: &DensePolynomial<Fr>,
    q: &DensePolynomial<Fr>,
    f: &DensePolynomial<Fr>,
    r: Fr,
) -> (Fr, G1, Fr, G1, Fr, G1, Fr, G1, Fr, G1) {
    // compute t(w^(k-1)) and its proof
    let (t_w_k_minus_1, proof_t_w_k_minus_1) = kzg_evaluate(gp, t, w.pow([k as u64 - 1]));
    // compute t(r) and its proof
    let (t_r, proof_t_r) = kzg_evaluate(gp, t, r);
    // compute t(w*r) and its proof
    let (t_w_r, proof_t_w_r) = kzg_evaluate(gp, t, r * w);
    // compute q(r) and its proof
    let (q_r, proof_q_r) = kzg_evaluate(gp, q, r);
    // compute f(w*r) and its proof
    let (f_w_r, proof_f_w_r) = kzg_evaluate(gp, f, r * w);

    (
        t_w_k_minus_1,
        proof_t_w_k_minus_1,
        t_r,
        proof_t_r,
        t_w_r,
        proof_t_w_r,
        q_r,
        proof_q_r,
        f_w_r,
        proof_f_w_r,
    )
}

// Verifies the proof of product check on subset Omega
pub fn verify_product_check(
    gp: &GlobalParameters,
    w: Fr,
    k: usize,
    com_f: G1,
    com_q: G1,
    com_t: G1,
    r: Fr,
    t_w_k_minus_1: Fr,
    proof_t_w_k_minus_1: G1,
    t_r: Fr,
    proof_t_r: G1,
    t_w_r: Fr,
    proof_t_w_r: G1,
    q_r: Fr,
    proof_q_r: G1,
    f_w_r: Fr,
    proof_f_w_r: G1,
) -> bool {
    (t_w_k_minus_1 == Fr::ONE)
        && (t_w_r - t_r * f_w_r == q_r * (r.pow([k as u64]) - Fr::ONE))
        && kzg_verify(
            gp,
            com_t,
            w.pow([k as u64 - 1]),
            t_w_k_minus_1,
            proof_t_w_k_minus_1,
        )
        && kzg_verify(gp, com_t, r, t_r, proof_t_r)
        && kzg_verify(gp, com_t, r * w, t_w_r, proof_t_w_r)
        && kzg_verify(gp, com_q, r, q_r, proof_q_r)
        && kzg_verify(gp, com_f, r * w, f_w_r, proof_f_w_r)
}

// Constructs the polynomials t and t1 based on polynomials f,g and subset Omega
pub fn compute_t_and_t1_product_check_rational_functions(
    Omega: &Vec<Fr>,
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let mut rng = ark_std::test_rng();

    // compute evaluations of t over Omega as product of evaluations of f divided by evaluations of g
    let k = Omega.len();
    let mut t_y_vals: Vec<Fr> = (0..k)
        .map(|i| {
            (0..i + 1)
                .map(|j| (f.evaluate(&Omega[j]), g.evaluate(&Omega[j])))
                .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
                .reduce(|t_eval, eval| t_eval * eval)
                .unwrap()
        })
        .collect();
    t_y_vals.extend((0..(f.degree() + 1 - k)).map(|_| Fr::rand(&mut rng)));
    let mut t_x_vals = Omega.clone();
    t_x_vals.extend((0..(f.degree() + 1 - k)).map(|_| Fr::rand(&mut rng)));
    // interpolate polynomial t
    let t = interpolate_polynomial(&t_x_vals, &t_y_vals);

    // t(w*x)
    let t_w_x = compose_polynomials(
        &t,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // g(w*x)
    let g_w_x = compose_polynomials(
        &g,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // f(w*x)
    let f_w_x = compose_polynomials(
        &f,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // t1(x) = t(w*x)g(w*x) - t(x)f(w*x)
    let t1 = &t_w_x * &g_w_x - &t * &f_w_x;

    (t, t1)
}

// Generates the proof of product check of rational functions on subset Omega
pub fn prove_product_check_rational_functions(
    gp: &GlobalParameters,
    w: Fr,
    k: usize,
    t: &DensePolynomial<Fr>,
    q: &DensePolynomial<Fr>,
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
    r: Fr,
) -> (Fr, G1, Fr, G1, Fr, G1, Fr, G1, Fr, G1, Fr, G1) {
    // compute t(w^(k-1)) and its proof
    let (t_w_k_minus_1, proof_t_w_k_minus_1) = kzg_evaluate(gp, t, w.pow([k as u64 - 1]));
    // compute t(r) and its proof
    let (t_r, proof_t_r) = kzg_evaluate(gp, t, r);
    // compute t(w*r) and its proof
    let (t_w_r, proof_t_w_r) = kzg_evaluate(gp, t, r * w);
    // compute q(r) and its proof
    let (q_r, proof_q_r) = kzg_evaluate(gp, q, r);
    // compute f(w*r) and its proof
    let (f_w_r, proof_f_w_r) = kzg_evaluate(gp, f, r * w);
    // compute g(w*r) and its proof
    let (g_w_r, proof_g_w_r) = kzg_evaluate(gp, g, r * w);

    (
        t_w_k_minus_1,
        proof_t_w_k_minus_1,
        t_r,
        proof_t_r,
        t_w_r,
        proof_t_w_r,
        q_r,
        proof_q_r,
        f_w_r,
        proof_f_w_r,
        g_w_r,
        proof_g_w_r,
    )
}

// Verifies the proof of product check of rational functions on subset Omega
pub fn verify_product_check_rational_functions(
    gp: &GlobalParameters,
    w: Fr,
    k: usize,
    com_f: G1,
    com_g: G1,
    com_q: G1,
    com_t: G1,
    r: Fr,
    t_w_k_minus_1: Fr,
    proof_t_w_k_minus_1: G1,
    t_r: Fr,
    proof_t_r: G1,
    t_w_r: Fr,
    proof_t_w_r: G1,
    q_r: Fr,
    proof_q_r: G1,
    f_w_r: Fr,
    proof_f_w_r: G1,
    g_w_r: Fr,
    proof_g_w_r: G1,
) -> bool {
    (t_w_k_minus_1 == Fr::ONE)
        && (t_w_r * g_w_r - t_r * f_w_r == q_r * (r.pow([k as u64]) - Fr::ONE))
        && kzg_verify(
            gp,
            com_t,
            w.pow([k as u64 - 1]),
            t_w_k_minus_1,
            proof_t_w_k_minus_1,
        )
        && kzg_verify(gp, com_t, r, t_r, proof_t_r)
        && kzg_verify(gp, com_t, r * w, t_w_r, proof_t_w_r)
        && kzg_verify(gp, com_q, r, q_r, proof_q_r)
        && kzg_verify(gp, com_f, r * w, f_w_r, proof_f_w_r)
        && kzg_verify(gp, com_g, r * w, g_w_r, proof_g_w_r)
}
