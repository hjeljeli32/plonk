use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, BigInteger256, FftField, Field, PrimeField, UniformRand};
use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_std::rand::seq::SliceRandom;
use plonk::common::{
    kzg::{kzg_commit, kzg_setup},
    protocols::{
        compute_q_zero_test, compute_t_and_t1_prescribed_permutation_check,
        compute_t_and_t1_product_check, compute_t_and_t1_product_check_rational_functions,
        compute_t_and_t1_sum_check, prove_equality, prove_prescribed_permutation_check,
        prove_product_check, prove_product_check_rational_functions, prove_sum_check,
        prove_zero_test, verify_equality, verify_prescribed_permutation_check,
        verify_product_check, verify_product_check_rational_functions, verify_sum_check,
        verify_zero_test,
    },
    polynomials::{interpolate_polynomial, random_polynomial},
};

fn construct_Omega(k: usize) -> Vec<Fr> {
    assert!(k.is_power_of_two(), "k must be a power of 2");
    let mut modulus_minus_1 = Fr::MODULUS;
    modulus_minus_1.sub_with_borrow(&BigInteger256::from(1_u64));
    let exponent = modulus_minus_1 >> k.ilog2(); // divide by k
    assert_eq!(
        exponent.mul(&BigInteger256::from(k as u64)).0,
        modulus_minus_1,
        "exponent must be divisible by k"
    );
    let omega = Fr::GENERATOR.pow(exponent.0.to_vec());

    (0..k).map(|i| omega.pow([i as u64])).collect()
}

fn construct_vanishing_polynomial(k: usize) -> DensePolynomial<Fr> {
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    DensePolynomial {
        coeffs: coefficients,
    }
}

#[test]
fn test_equality_success() {
    let mut rng = ark_std::test_rng();
    let degree = 10;

    // generate global parameters
    let gp = kzg_setup(degree);

    // Prover generates randomly a polynomial f
    let f = random_polynomial(&mut rng, degree);
    let g = f.clone();

    // Prover computes commitments of f and g
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves equality
    let (y_f, proof_f, y_g, proof_g) = prove_equality(&gp, &f, &g, r);

    // Verifier verifies equlity
    assert!(
        verify_equality(&gp, com_f, com_g, r, y_f, proof_f, y_g, proof_g),
        "Verify must return true because polynomials are equal"
    );
}

#[test]
fn test_equality_fail() {
    let mut rng = ark_std::test_rng();
    let degree = 10;

    // generate global parameters
    let gp = kzg_setup(degree);

    // Prover generates randomly a polynomial f and a polynomial g
    let f = random_polynomial(&mut rng, degree);
    let g = random_polynomial(&mut rng, degree);

    // Prover computes commitments of f and g
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves equality
    let (y_f, proof_f, y_g, proof_g) = prove_equality(&gp, &f, &g, r);

    // Verifier verifies equality
    assert!(
        verify_equality(&gp, com_f, com_g, r, y_f, proof_f, y_g, proof_g) == false,
        "Verify must return false because polynomials are not equal"
    );
}

#[test]
fn test_zero_test_success() {
    let mut rng = ark_std::test_rng();
    let degree = 10;

    // generate global parameters
    let k = 8;
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // compute x_vals and y_vals and interpolate f
    let mut x_vals = Omega.clone();
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let mut y_vals: Vec<Fr> = (0..8).map(|_| Fr::ZERO).collect();
    y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let f = interpolate_polynomial(&x_vals, &y_vals);

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover computes quotient polynomial of f by Z_Omega
    let q = compute_q_zero_test(k, &f);

    // check that f is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, f, "f must be divisible by Z_Omega");

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Zero Test
    let (f_r, proof_f, q_r, proof_q) = prove_zero_test(&gp, &f, &q, r);

    // Verifier verifies Zero Test
    assert!(
        verify_zero_test(&gp, k, com_f, com_q, r, f_r, proof_f, q_r, proof_q),
        "Verify must return true because polynomial is Zero on Omega"
    );
}

#[test]
fn test_zero_test_fail() {
    let mut rng = ark_std::test_rng();
    let degree = 10;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // generate f randomly so it won't be zero on Omega
    let f = random_polynomial(&mut rng, 10);

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover computes quotient polynomial of f by Z_Omega
    let q = compute_q_zero_test(k, &f);

    // check that f is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, f, "f must be not divisible by Z_Omega");

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Zero Test
    let (f_r, proof_f, q_r, proof_q) = prove_zero_test(&gp, &f, &q, r);

    // Verifier verifies Zero Test
    assert!(
        verify_zero_test(&gp, k, com_f, com_q, r, f_r, proof_f, q_r, proof_q) == false,
        "Verify must return false because polynomial is not Zero on Omega"
    );
}

#[test]
fn test_product_check_success() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // compute x_vals and y_vals and interpolate f
    let mut x_vals = Omega.clone();
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let mut y_vals: Vec<Fr> = (0..7).map(|_| Fr::rand(&mut rng)).collect();
    // product of f(omega_i) for i in [0,7]
    let product = y_vals
        .iter()
        .copied()
        .reduce(|prod, y_val| prod * y_val)
        .unwrap();
    y_vals.push(product.inverse().unwrap());
    y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let f = interpolate_polynomial(&x_vals, &y_vals);

    assert_eq!(
        Omega
            .iter()
            .map(|omega| f.evaluate(&omega))
            .reduce(|prod, f_omega| prod * f_omega)
            .unwrap(),
        Fr::ONE,
        "product of f over Omega must be equal to 1"
    );

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomial f and subset Omega
    let (t, t1) = compute_t_and_t1_product_check(&Omega, &f);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, t1, "t1 must be divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check
    let (
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
    ) = prove_product_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Product Check
    assert!(
        verify_product_check(
            &gp,
            Omega[1],
            k,
            com_f,
            com_q,
            com_t,
            r,
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
        ),
        "Verify must return true because polynomial's product over Omega is 1"
    );
}

#[test]
fn test_product_check_fail() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // generate f randomly so its product over Omega is not equal to 1
    let f = random_polynomial(&mut rng, 10);

    assert_ne!(
        Omega
            .iter()
            .map(|omega| f.evaluate(&omega))
            .reduce(|prod, f_omega| prod * f_omega)
            .unwrap(),
        Fr::ONE,
        "product of f over Omega must be not equal to 1"
    );

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomial f and subset Omega
    let (t, t1) = compute_t_and_t1_product_check(&Omega, &f);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, t1, "t1 must be not divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check
    let (
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
    ) = prove_product_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Product Check
    assert!(
        verify_product_check(
            &gp,
            Omega[1],
            k,
            com_f,
            com_q,
            com_t,
            r,
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
        ) == false,
        "Verify must return false because polynomial's product over Omega is not equal to 1"
    );
}

#[test]
fn test_sum_check_success() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup.
    let degree = 10;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // compute x_vals and y_vals and interpolate f
    let mut x_vals = Omega.clone();
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let mut y_vals: Vec<Fr> = (0..7).map(|_| Fr::rand(&mut rng)).collect();
    // sum of f(omega_i) for i in [0,7]
    let sum = y_vals
        .iter()
        .copied()
        .reduce(|sum, y_val| sum + y_val)
        .unwrap();
    y_vals.push(-sum);
    y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let f = interpolate_polynomial(&x_vals, &y_vals);

    assert_eq!(
        Omega
            .iter()
            .map(|omega| f.evaluate(&omega))
            .reduce(|sum, f_omega| sum + f_omega)
            .unwrap(),
        Fr::ZERO,
        "sum of f over Omega must be equal to 0"
    );

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomial f and subset Omega
    let (t, t1) = compute_t_and_t1_sum_check(&Omega, &f);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, t1, "t1 must be divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Sum Check
    let (
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
    ) = prove_sum_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Sum Check
    assert!(
        verify_sum_check(
            &gp,
            Omega[1],
            k,
            com_f,
            com_q,
            com_t,
            r,
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
        ),
        "Verify must return true because polynomial's sum over Omega is 1"
    );
}

#[test]
fn test_sum_check_fail() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup.
    let degree = 10;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // generate f randomly so its sum over Omega is not equal to 0
    let f = random_polynomial(&mut rng, 10);

    assert_ne!(
        Omega
            .iter()
            .map(|omega| f.evaluate(&omega))
            .reduce(|sum, f_omega| sum + f_omega)
            .unwrap(),
        Fr::ZERO,
        "sum of f over Omega must be not equal to 0"
    );

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomial f and subset Omega
    let (t, t1) = compute_t_and_t1_sum_check(&Omega, &f);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, t1, "t1 must be not divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Sum Check
    let (
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
    ) = prove_sum_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Sum Check
    assert!(
        verify_sum_check(
            &gp,
            Omega[1],
            k,
            com_f,
            com_q,
            com_t,
            r,
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
        ) == false,
        "Verify must return false because polynomial's sum over Omega is not equal to 1"
    );
}

#[test]
fn test_product_check_rational_functions_success() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // compute x_vals and f_y_vals,g_y_vals
    let mut x_vals = Omega.clone();
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let mut f_y_vals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    // product of f(omega_i) for i in [0,8]
    let f_y_vals_product = f_y_vals
        .iter()
        .copied()
        .reduce(|prod, eval| prod * eval)
        .unwrap();
    let mut g_y_vals: Vec<Fr> = (0..7).map(|_| Fr::rand(&mut rng)).collect();
    // product of g(omega_i) for i in [0,7]
    let g_y_vals_product = g_y_vals
        .iter()
        .copied()
        .reduce(|prod, eval| prod * eval)
        .unwrap();
    g_y_vals.push(g_y_vals_product * f_y_vals_product.inverse().unwrap());
    f_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    g_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    // interpolate f,g
    let f = interpolate_polynomial(&x_vals, &f_y_vals);
    let g = interpolate_polynomial(&x_vals, &f_y_vals);

    assert_eq!(
        Omega
            .iter()
            .map(|omega| (f.evaluate(&omega), g.evaluate(&omega)))
            .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
            .reduce(|prod, eval| prod * eval)
            .unwrap(),
        Fr::ONE,
        "product of f/g over Omega must be equal to 1"
    );

    // check that f,g are of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");
    assert_eq!(g.degree(), 10, "g must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitments of f,g
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomials f,g and subset Omega
    let (t, t1) = compute_t_and_t1_product_check_rational_functions(&Omega, &f, &g);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, t1, "t1 must be divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check of rational functions
    let (
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
    ) = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Product Check of rational functions
    assert!(
        verify_product_check_rational_functions(
            &gp,
            Omega[1],
            k,
            com_f,
            com_g,
            com_q,
            com_t,
            r,
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
        ),
        "Verify must return true because rational function's product over Omega is 1"
    );
}

#[test]
fn test_product_check_rational_functions_fail() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // generate f,g randomly so the product of their rational function over Omega is not equal to 1
    let f = random_polynomial(&mut rng, 10);
    let g = random_polynomial(&mut rng, 10);

    assert_ne!(
        Omega
            .iter()
            .map(|omega| (f.evaluate(&omega), g.evaluate(&omega)))
            .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
            .reduce(|prod, eval| prod * eval)
            .unwrap(),
        Fr::ONE,
        "product of f/g over Omega must be not equal to 1"
    );

    // check that f,g are of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");
    assert_eq!(g.degree(), 10, "g must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitments of f,g
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomials f,g and subset Omega
    let (t, t1) = compute_t_and_t1_product_check_rational_functions(&Omega, &f, &g);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, t1, "t1 must be not divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check of rational functions
    let (
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
    ) = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Product Check of rational functions
    assert!(
        verify_product_check_rational_functions(
            &gp,
            Omega[1],
            k,
            com_f,
            com_g,
            com_q,
            com_t,
            r,
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
        ) == false,
        "Verify must return false because rational function's product over Omega is not equal to 1"
    );
}

#[test]
fn test_permutation_check_success() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // compute x_vals and f_y_vals,g_y_vals
    let mut x_vals = Omega.clone();
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let mut f_y_vals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    // set g(w^0)..g(w^k-1) as a permutation of f(w^0)..f(w^k-1)
    let mut g_y_vals = f_y_vals.clone();
    g_y_vals.shuffle(&mut rng);
    f_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    g_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    // interpolate f,g
    let f = interpolate_polynomial(&x_vals, &f_y_vals);
    let g = interpolate_polynomial(&x_vals, &f_y_vals);

    assert_eq!(
        Omega
            .iter()
            .map(|omega| (f.evaluate(&omega), g.evaluate(&omega)))
            .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
            .reduce(|prod, eval| prod * eval)
            .unwrap(),
        Fr::ONE,
        "product of f/g over Omega must be equal to 1"
    );

    // check that f,g are of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");
    assert_eq!(g.degree(), 10, "g must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitments of f,g
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomials f,g and subset Omega
    let (t, t1) = compute_t_and_t1_product_check_rational_functions(&Omega, &f, &g);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, t1, "t1 must be divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Permutation Check
    let (
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
    ) = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Permutation Check
    assert!(
        verify_product_check_rational_functions(
            &gp,
            Omega[1],
            k,
            com_f,
            com_g,
            com_q,
            com_t,
            r,
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
        ),
        "Verify must return true because g is permutation of f over Omega"
    );
}

#[test]
fn test_permutation_check_fail() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // generate f,g randomly so the product of their rational function over Omega is not equal to 1
    let f = random_polynomial(&mut rng, 10);
    let g = random_polynomial(&mut rng, 10);

    assert_ne!(
        Omega
            .iter()
            .map(|omega| (f.evaluate(&omega), g.evaluate(&omega)))
            .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
            .reduce(|prod, eval| prod * eval)
            .unwrap(),
        Fr::ONE,
        "product of f/g over Omega must be not equal to 1"
    );

    // check that f,g are of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");
    assert_eq!(g.degree(), 10, "g must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitments of f,g
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Prover constructs the polynomials t and t1 based on polynomials f,g and subset Omega
    let (t, t1) = compute_t_and_t1_product_check_rational_functions(&Omega, &f, &g);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, t1, "t1 must be not divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Permutation Check
    let (
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
    ) = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Permutation Check
    assert!(
        verify_product_check_rational_functions(
            &gp,
            Omega[1],
            k,
            com_f,
            com_g,
            com_q,
            com_t,
            r,
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
        ) == false,
        "Verify must return false because g is not permutation of f over Omega"
    );
}

#[test]
fn test_prescribed_permutation_check_success() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // compute x_vals, W_y_vals, f_y_vals and g_y_vals
    let mut x_vals = Omega.clone();
    let mut W_y_vals = x_vals.clone();
    W_y_vals.shuffle(&mut rng);
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));

    let mut f_y_vals: Vec<Fr> = (0..8).map(|_| Fr::rand(&mut rng)).collect();
    // set g(W(w^0))..g(W(w^k-1)) equal to f(w^0)..f(w^k-1) for defined permutation W
    let mut g_y_vals = f_y_vals.clone();

    W_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    f_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    g_y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    // interpolate W,f,g
    let W = interpolate_polynomial(&x_vals, &W_y_vals);
    let f = interpolate_polynomial(&x_vals, &f_y_vals);
    let g = interpolate_polynomial(&W_y_vals, &g_y_vals);

    for omega in &Omega {
        assert_eq!(
            f.evaluate(&omega),
            g.evaluate(&W.evaluate(&omega)),
            "f(w) must be equal to g(W(w))"
        );
    }

    assert_eq!(
        Omega
            .iter()
            .map(|omega| (f.evaluate(&omega), g.evaluate(&omega)))
            .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
            .reduce(|prod, eval| prod * eval)
            .unwrap(),
        Fr::ONE,
        "product of f/g over Omega must be equal to 1"
    );

    // check that W,f,g are of degree 10
    assert_eq!(W.degree(), 10, "f must be of degree 10");
    assert_eq!(f.degree(), 10, "f must be of degree 10");
    assert_eq!(g.degree(), 10, "g must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitments of W,f,g
    let com_W = kzg_commit(&gp, &W).unwrap();
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Verifier generates randomly (r,s)
    let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    // Prover constructs the polynomials t and t1 based on polynomials W,f,g and subset Omega
    let (t, t1) = compute_t_and_t1_prescribed_permutation_check(&Omega, &f, &g, &W, r, s);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, t1, "t1 must be divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let rp = Fr::rand(&mut rng);

    // Prover proves Prescribed Permutation Check
    let (
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
    ) = prove_prescribed_permutation_check(&gp, Omega[1], k, &t, &q, &f, &g, &W, rp);

    // Verifier verifies Prescribed Permutation Check
    assert!(
        verify_prescribed_permutation_check(
            &gp,
            Omega[1],
            k,
            com_f,
            com_g,
            com_W,
            com_q,
            com_t,
            r,
            s,
            rp,
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
        ),
        "Verify must return true because g is prescribed permutation of f over Omega"
    );
}

#[test]
fn test_prescribed_permutation_check_fail() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;
    let k = 8;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    // generate f,g,W randomly
    let f = random_polynomial(&mut rng, 10);
    let g = random_polynomial(&mut rng, 10);
    let W = random_polynomial(&mut rng, 10);

    for omega in &Omega {
        assert_ne!(
            f.evaluate(&omega),
            g.evaluate(&W.evaluate(&omega)),
            "f(w) must be not equal to g(W(w))"
        );
    }

    assert_ne!(
        Omega
            .iter()
            .map(|omega| (f.evaluate(&omega), g.evaluate(&omega)))
            .map(|(f_eval, g_eval)| f_eval * g_eval.inverse().unwrap())
            .reduce(|prod, eval| prod * eval)
            .unwrap(),
        Fr::ONE,
        "product of f/g over Omega must be not equal to 1"
    );

    // check that W,f,g are of degree 10
    assert_eq!(W.degree(), 10, "f must be of degree 10");
    assert_eq!(f.degree(), 10, "f must be of degree 10");
    assert_eq!(g.degree(), 10, "g must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^8

    // Prover computes commitments of W,f,g
    let com_W = kzg_commit(&gp, &W).unwrap();
    let com_f = kzg_commit(&gp, &f).unwrap();
    let com_g = kzg_commit(&gp, &g).unwrap();

    // Verifier generates randomly (r,s)
    let (r, s) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    // Prover constructs the polynomials t and t1 based on polynomials W,f,g and subset Omega
    let (t, t1) = compute_t_and_t1_prescribed_permutation_check(&Omega, &f, &g, &W, r, s);

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test(k, &t1);

    // check that t1 is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, t1, "t1 must be not divisible by Z_Omega");

    // Prover computes commitment of t
    let com_t = kzg_commit(&gp, &t).unwrap();

    // Prover computes commitment of q
    let com_q = kzg_commit(&gp, &q).unwrap();

    // Verifier generates randomly r
    let rp = Fr::rand(&mut rng);

    // Prover proves Prescribed Permutation Check
    let (
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
    ) = prove_prescribed_permutation_check(&gp, Omega[1], k, &t, &q, &f, &g, &W, rp);

    // Verifier verifies Prescribed Permutation Check
    assert!(
        verify_prescribed_permutation_check(
            &gp,
            Omega[1],
            k,
            com_f,
            com_g,
            com_W,
            com_q,
            com_t,
            r,
            s,
            rp,
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
        ) == false,
        "Verify must return false because g is not prescribed permutation of f over Omega"
    );
}
