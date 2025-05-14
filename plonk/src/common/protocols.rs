use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    Polynomial,
};

use crate::common::polynomials::{compose_polynomials, interpolate_polynomial};

use super::{
    kzg::{kzg_evaluate, kzg_verify, GlobalParameters},
    utils::{construct_vanishing_polynomial, construct_vanishing_polynomial_from_roots},
};

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
    let Z_Omega = construct_vanishing_polynomial(k);

    // compute q as quotient of f by Z_Omega
    let (q, _) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(f).into(), &(&Z_Omega).into()).unwrap();

    q
}

// Computes the quotient polynomial q of f by the vanishing polynomial Z_Omega defined by its roots
pub fn compute_q_zero_test_from_roots(
    roots: &Vec<Fr>,
    f: &DensePolynomial<Fr>,
) -> DensePolynomial<Fr> {
    // construct Z_Omega (vanishing polynomial) defined by its roots
    let Z_Omega = construct_vanishing_polynomial_from_roots(roots);

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

// Verifies the proof that a polynomial (previously committed) is zero on given roots
pub fn verify_zero_on_roots_test(
    gp: &GlobalParameters,
    roots: &Vec<Fr>,
    com_f: G1,
    com_q: G1,
    r: Fr,
    f_r: Fr,
    proof_f: G1,
    q_r: Fr,
    proof_q: G1,
) -> bool {
    let Z_Omega = construct_vanishing_polynomial_from_roots(roots);

    (f_r == q_r * Z_Omega.evaluate(&r))
        && kzg_verify(gp, com_q, r, q_r, proof_q)
        && kzg_verify(gp, com_f, r, f_r, proof_f)
}

// Constructs the polynomials t and t1 based on polynomial f and subset Omega for product check
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

// Constructs the polynomials t and t1 based on polynomials f,g and subset Omega for product check over rational functions
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

// Constructs the polynomials t and t1 based on polynomial f and subset Omega for sum check
pub fn compute_t_and_t1_sum_check(
    Omega: &Vec<Fr>,
    f: &DensePolynomial<Fr>,
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let mut rng = ark_std::test_rng();

    // compute evaluations of t over Omega as sum of evaluations of f
    let k = Omega.len();
    let mut t_y_vals: Vec<Fr> = (0..k)
        .map(|i| {
            (0..i + 1)
                .map(|j| f.evaluate(&Omega[j]))
                .reduce(|t_eval, f_eval| t_eval + f_eval)
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
    // t1(x) = t(w*x) - (t(x) + f(w*x))
    let t1 = &t_w_x - (&t + &f_w_x);

    (t, t1)
}

// Generates the proof of sum check on subset Omega
pub fn prove_sum_check(
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

// Verifies the proof of sum check on subset Omega
pub fn verify_sum_check(
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
    (t_w_k_minus_1 == Fr::ZERO)
        && (t_w_r - (t_r + f_w_r) == q_r * (r.pow([k as u64]) - Fr::ONE))
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

// Constructs the polynomials t and t1 based on polynomials f,g and subset Omega for prescribed permutation check
pub fn compute_t_and_t1_prescribed_permutation_check(
    Omega: &Vec<Fr>,
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
    W: &DensePolynomial<Fr>,
    r: Fr,
    s: Fr,
) -> (DensePolynomial<Fr>, DensePolynomial<Fr>) {
    let mut rng = ark_std::test_rng();

    // compute evaluations of t over Omega as product of evaluations r-sW(w^i)-f(w^i) divided by r-sw^i-g(w^i)
    let k = Omega.len();
    let mut t_y_vals: Vec<Fr> = (0..k)
        .map(|i| {
            (0..i + 1)
                .map(|j| {
                    (
                        Omega[j],
                        f.evaluate(&Omega[j]),
                        g.evaluate(&Omega[j]),
                        W.evaluate(&Omega[j]),
                    )
                })
                .map(|(w_j, f_eval, g_eval, W_eval)| {
                    (r - s * W_eval - f_eval) * (r - s * w_j - g_eval).inverse().unwrap()
                })
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
    // r-s*w*x
    let r_s_w_x = DensePolynomial {
        coeffs: vec![r, -s * Omega[1]],
    };
    // g(w*x)
    let g_w_x = compose_polynomials(
        &g,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // W(w*x)
    let W_w_x = compose_polynomials(
        &W,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // r-s*W(w*x)
    let r_s_W_w_x = compose_polynomials(
        &DensePolynomial {
            coeffs: vec![r, -s],
        },
        &W_w_x,
    );
    // f(w*x)
    let f_w_x = compose_polynomials(
        &f,
        &DensePolynomial {
            coeffs: vec![Fr::ZERO, Omega[1]],
        },
    );
    // t1(x) = t(w*x)(r - s*w*x - g(w*x)) - t(x)(r - s*W(w*x) - f(w*x))
    let t1 = &t_w_x * (&r_s_w_x - &g_w_x) - &t * (r_s_W_w_x - &f_w_x);

    (t, t1)
}

// Generates the proof of prescribed permutation check on subset Omega
pub fn prove_prescribed_permutation_check(
    gp: &GlobalParameters,
    w: Fr,
    k: usize,
    t: &DensePolynomial<Fr>,
    q: &DensePolynomial<Fr>,
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
    W: &DensePolynomial<Fr>,
    rp: Fr,
) -> (Fr, G1, Fr, G1, Fr, G1, Fr, G1, Fr, G1, Fr, G1, Fr, G1) {
    // compute t(w^(k-1)) and its proof
    let (t_w_k_minus_1, proof_t_w_k_minus_1) = kzg_evaluate(gp, t, w.pow([k as u64 - 1]));
    // compute t(rp) and its proof
    let (t_rp, proof_t_rp) = kzg_evaluate(gp, t, rp);
    // compute t(w*rp) and its proof
    let (t_w_rp, proof_t_w_rp) = kzg_evaluate(gp, t, rp * w);
    // compute q(rp) and its proof
    let (q_rp, proof_q_rp) = kzg_evaluate(gp, q, rp);
    // compute f(w*rp) and its proof
    let (f_w_rp, proof_f_w_rp) = kzg_evaluate(gp, f, rp * w);
    // compute g(w*rp) and its proof
    let (g_w_rp, proof_g_w_rp) = kzg_evaluate(gp, g, rp * w);
    // compute W(w*rp) and its proof
    let (W_w_rp, proof_W_w_rp) = kzg_evaluate(gp, W, rp * w);

    (
        t_w_k_minus_1,
        proof_t_w_k_minus_1,
        t_rp,
        proof_t_rp,
        t_w_rp,
        proof_t_w_rp,
        q_rp,
        proof_q_rp,
        f_w_rp,
        proof_f_w_rp,
        g_w_rp,
        proof_g_w_rp,
        W_w_rp,
        proof_W_w_rp,
    )
}

// Verifies the proof of prescribed permutation check on subset Omega
pub fn verify_prescribed_permutation_check(
    gp: &GlobalParameters,
    w: Fr,
    k: usize,
    com_f: G1,
    com_g: G1,
    com_W: G1,
    com_q: G1,
    com_t: G1,
    r: Fr,
    s: Fr,
    rp: Fr,
    t_w_k_minus_1: Fr,
    proof_t_w_k_minus_1: G1,
    t_rp: Fr,
    proof_t_rp: G1,
    t_w_rp: Fr,
    proof_t_w_rp: G1,
    q_rp: Fr,
    proof_q_rp: G1,
    f_w_rp: Fr,
    proof_f_w_rp: G1,
    g_w_rp: Fr,
    proof_g_w_rp: G1,
    W_w_rp: Fr,
    proof_W_w_rp: G1,
) -> bool {
    (t_w_k_minus_1 == Fr::ONE)
        && (t_w_rp * (r - s * w * rp - g_w_rp) - t_rp * (r - s * W_w_rp - f_w_rp)
            == q_rp * (rp.pow([k as u64]) - Fr::ONE))
        && kzg_verify(
            gp,
            com_t,
            w.pow([k as u64 - 1]),
            t_w_k_minus_1,
            proof_t_w_k_minus_1,
        )
        && kzg_verify(gp, com_t, rp, t_rp, proof_t_rp)
        && kzg_verify(gp, com_t, rp * w, t_w_rp, proof_t_w_rp)
        && kzg_verify(gp, com_q, rp, q_rp, proof_q_rp)
        && kzg_verify(gp, com_f, rp * w, f_w_rp, proof_f_w_rp)
        && kzg_verify(gp, com_g, rp * w, g_w_rp, proof_g_w_rp)
        && kzg_verify(gp, com_W, rp * w, W_w_rp, proof_W_w_rp)
}
