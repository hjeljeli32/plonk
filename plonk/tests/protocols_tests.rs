use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_poly::Polynomial;
use ark_std::rand::seq::SliceRandom;
use plonk::common::{
    kzg::{kzg_commit, kzg_setup},
    polynomials::{interpolate_polynomial, random_polynomial},
    protocols::{
        compute_q_zero_test, compute_q_zero_test_from_roots, compute_t1_T_S_zero_test,
        compute_t_and_t1_prescribed_permutation_check, compute_t_and_t1_product_check,
        compute_t_and_t1_product_check_rational_functions, compute_t_and_t1_sum_check,
        prove_T_S_zero_test, prove_equality, prove_prescribed_permutation_check,
        prove_product_check, prove_product_check_rational_functions, prove_sum_check,
        prove_zero_test, verify_T_S_zero_test, verify_equality,
        verify_prescribed_permutation_check, verify_product_check,
        verify_product_check_rational_functions, verify_sum_check, verify_zero_on_roots_test,
        verify_zero_test,
    },
    utils::{
        construct_Omega, construct_vanishing_polynomial, construct_vanishing_polynomial_from_roots,
    },
};

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
    let proof = prove_equality(&gp, &f, &g, r);

    // Verifier verifies equlity
    assert!(
        verify_equality(&gp, com_f, com_g, r, &proof),
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
    let proof = prove_equality(&gp, &f, &g, r);

    // Verifier verifies equality
    assert!(
        verify_equality(&gp, com_f, com_g, r, &proof) == false,
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Zero Test
    let proof = prove_zero_test(&gp, &f, &q, r);

    // Verifier verifies Zero Test
    assert!(
        verify_zero_test(&gp, k, com_f, r, &proof),
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

    // construct Z_Omega (vanishing polynomial) defined by its roots
    let Z_Omega = construct_vanishing_polynomial(k);

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover computes quotient polynomial of f by Z_Omega
    let q = compute_q_zero_test(k, &f);

    // check that f is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, f, "f must be not divisible by Z_Omega");

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Zero Test
    let proof = prove_zero_test(&gp, &f, &q, r);

    // Verifier verifies Zero Test
    assert!(
        verify_zero_test(&gp, k, com_f, r, &proof) == false,
        "Verify must return false because polynomial is not Zero on Omega"
    );
}

#[test]
fn test_zero_on_roots_test_success() {
    let mut rng = ark_std::test_rng();
    let degree = 10;

    // generate global parameters
    let Omega = vec![Fr::from(2), Fr::from(3)];
    let gp = kzg_setup(degree);

    // compute x_vals and y_vals and interpolate f
    let mut x_vals = Omega.clone();
    x_vals.extend((0..9).map(|_| Fr::rand(&mut rng)));
    let mut y_vals: Vec<Fr> = (0..2).map(|_| Fr::ZERO).collect();
    y_vals.extend((0..9).map(|_| Fr::rand(&mut rng)));
    let f = interpolate_polynomial(&x_vals, &y_vals);

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) defined by its roots
    let Z_Omega = construct_vanishing_polynomial_from_roots(&Omega);

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover computes quotient polynomial of f by Z_Omega
    let q = compute_q_zero_test_from_roots(&Omega, &f);

    // check that f is divisble by Z_Omega
    assert_eq!(&q * &Z_Omega, f, "f must be divisible by Z_Omega");

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Zero Test
    let proof = prove_zero_test(&gp, &f, &q, r);

    // Verifier verifies Zero Test
    assert!(
        verify_zero_on_roots_test(&gp, &Omega, com_f, r, &proof),
        "Verify must return true because polynomial is Zero on Omega"
    );
}

#[test]
fn test_zero_on_roots_test_fail() {
    let mut rng = ark_std::test_rng();
    let degree = 10;

    // generate global parameters
    let Omega = vec![Fr::from(2), Fr::from(3)];
    let gp = kzg_setup(degree);

    // generate f randomly so it won't be zero on Omega
    let f = random_polynomial(&mut rng, 10);

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) defined by its roots
    let Z_Omega = construct_vanishing_polynomial_from_roots(&Omega);

    // Prover computes commitment of f
    let com_f = kzg_commit(&gp, &f).unwrap();

    // Prover computes quotient polynomial of f by Z_Omega
    let q = compute_q_zero_test_from_roots(&Omega, &f);

    // check that f is not divisble by Z_Omega
    assert_ne!(&q * &Z_Omega, f, "f must be not divisible by Z_Omega");

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Zero Test
    let proof = prove_zero_test(&gp, &f, &q, r);

    // Verifier verifies Zero Test
    assert!(
        verify_zero_on_roots_test(&gp, &Omega, com_f, r, &proof) == false,
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check
    let proof = prove_product_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Product Check
    assert!(
        verify_product_check(&gp, Omega[1], k, com_f, r, &proof),
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check
    let proof = prove_product_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Product Check
    assert!(
        verify_product_check(&gp, Omega[1], k, com_f, r, &proof) == false,
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Sum Check
    let proof = prove_sum_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Sum Check
    assert!(
        verify_sum_check(&gp, Omega[1], k, com_f, r, &proof,),
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Sum Check
    let proof = prove_sum_check(&gp, Omega[1], k, &t, &q, &f, r);

    // Verifier verifies Sum Check
    assert!(
        verify_sum_check(&gp, Omega[1], k, com_f, r, &proof,) == false,
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check of rational functions
    let proof = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Product Check of rational functions
    assert!(
        verify_product_check_rational_functions(&gp, Omega[1], k, com_f, com_g, r, &proof,),
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Product Check of rational functions
    let proof = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Product Check of rational functions
    assert!(
        verify_product_check_rational_functions(&gp, Omega[1], k, com_f, com_g, r, &proof,)
            == false,
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
    let g = interpolate_polynomial(&x_vals, &g_y_vals);

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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Permutation Check
    let proof = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Permutation Check
    assert!(
        verify_product_check_rational_functions(&gp, Omega[1], k, com_f, com_g, r, &proof,),
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

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves Permutation Check
    let proof = prove_product_check_rational_functions(&gp, Omega[1], k, &t, &q, &f, &g, r);

    // Verifier verifies Permutation Check
    assert!(
        verify_product_check_rational_functions(&gp, Omega[1], k, com_f, com_g, r, &proof,)
            == false,
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

    // Verifier generates randomly r
    let rp = Fr::rand(&mut rng);

    // Prover proves Prescribed Permutation Check
    let proof = prove_prescribed_permutation_check(&gp, Omega[1], k, &t, &q, &f, &g, &W, rp);

    // Verifier verifies Prescribed Permutation Check
    assert!(
        verify_prescribed_permutation_check(
            &gp, Omega[1], k, com_f, com_g, com_W, r, s, rp, &proof,
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

    // Verifier generates randomly r
    let rp = Fr::rand(&mut rng);

    // Prover proves Prescribed Permutation Check
    let proof = prove_prescribed_permutation_check(&gp, Omega[1], k, &t, &q, &f, &g, &W, rp);

    // Verifier verifies Prescribed Permutation Check
    assert!(
        verify_prescribed_permutation_check(
            &gp, Omega[1], k, com_f, com_g, com_W, r, s, rp, &proof,
        ) == false,
        "Verify must return false because g is not prescribed permutation of f over Omega"
    );
}

#[test]
fn test_T_S_zero_test_success() {
    let mut rng = ark_std::test_rng();

    // this degree is used for kzg setup. We need to commit to polynomial q of degree 21.
    let degree = 21;
    let d = 12;
    let number_gates = 3;

    // generate global parameters
    let gp = kzg_setup(degree);

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

    let (mut x_vals, mut y_vals) = (vec![], vec![]);

    // T encodes all inputs: T(w^-j) = input#j
    // T(w^-1) = 5
    x_vals.push(Omega[d - 1]);
    y_vals.push(Fr::from(5));
    // T(w^-2) = 6
    x_vals.push(Omega[d - 2]);
    y_vals.push(Fr::from(6));
    // T(w^-3) = 1
    x_vals.push(Omega[d - 3]);
    y_vals.push(Fr::from(1));

    // T encodes all wires of the gates
    // Gate 0 (Addition)
    // T(w^0) = 5
    x_vals.push(Omega[0]);
    y_vals.push(Fr::from(5));
    // T(w^1) = 6
    x_vals.push(Omega[1]);
    y_vals.push(Fr::from(6));
    // T(w^2) = 11
    x_vals.push(Omega[2]);
    y_vals.push(Fr::from(11));

    // Gate 1 (Addition)
    // T(w^3) = 6
    x_vals.push(Omega[3]);
    y_vals.push(Fr::from(6));
    // T(w^4) = 1
    x_vals.push(Omega[4]);
    y_vals.push(Fr::from(1));
    // T(w^5) = 7
    x_vals.push(Omega[5]);
    y_vals.push(Fr::from(7));

    // Gate 2 (Multiplication)
    // T(w^6) = 11
    x_vals.push(Omega[6]);
    y_vals.push(Fr::from(11));
    // T(w^7) = 7
    x_vals.push(Omega[7]);
    y_vals.push(Fr::from(7));
    // T(w^8) = 77
    x_vals.push(Omega[8]);
    y_vals.push(Fr::from(77));

    // Interpolate the polynomial T that enodes the entire trace
    let T = interpolate_polynomial(&x_vals, &y_vals);
    assert_eq!(T.degree(), d - 1, "T must be of degree d-1");

    // Define Omega_gates
    let mut Omega_gates = vec![];
    (0..number_gates).for_each(|l| Omega_gates.push(Omega[3 * l]));

    let mut gates = vec![];

    // S encodes gates: S(w^3*l) = gate#l
    // S(w^0) = 1 -- addition gate
    gates.push(Fr::ONE);
    // S(w^3) = 1 -- addition gate
    gates.push(Fr::ONE);
    // T(w^6) = 0 -- multiplication gate
    gates.push(Fr::ZERO);

    // Interpolate the polynomial S
    let S = interpolate_polynomial(&Omega_gates, &gates);
    assert_eq!(
        S.degree(),
        number_gates - 1,
        "S must be of degree (number_gates - 1)"
    );

    let t1 = compute_t1_T_S_zero_test(Omega[1], &T, &S);

    // check that t1 is of degree 24
    assert_eq!(t1.degree(), 24, "t1 must be of degree 24");

    for y in &Omega_gates {
        assert_eq!(
            t1.evaluate(&y),
            Fr::ZERO,
            "t1 should be zero on Omega_gates"
        );
    }

    // construct Z_Omega_gates (vanishing polynomial) of subset Omega_gates
    let Z_Omega_gates = construct_vanishing_polynomial_from_roots(&Omega_gates);

    // Prover computes commitments of T,S
    let com_T = kzg_commit(&gp, &T).unwrap();
    let com_S = kzg_commit(&gp, &S).unwrap();

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test_from_roots(&Omega_gates, &t1);

    // check that q is of degree 21
    assert_eq!(q.degree(), 21, "q must be of degree 21");

    // check that t1 is divisble by Z_Omega_gates
    assert_eq!(
        &q * &Z_Omega_gates,
        t1,
        "t1 must be divisible by Z_Omega_gates"
    );

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves T_S zero test
    let proof = prove_T_S_zero_test(&gp, Omega[1], &q, &T, &S, r);

    // Verifier verifies T_S zero test
    assert!(
        verify_T_S_zero_test(&gp, Omega[1], &Omega_gates, com_T, com_S, r, &proof),
        "Verify must return true because T and S satisfy T_S zero test on Omega_gates"
    );
}

#[test]
fn test_T_S_zero_test_fail() {
    let mut rng = ark_std::test_rng();

    // this degree is used for kzg setup. We need to commit to polynomial q of degree 21.
    let degree = 21;
    let d = 12;
    let number_gates = 3;

    // generate global parameters
    let gp = kzg_setup(degree);

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

    // generate T,S randomly
    let T = random_polynomial(&mut rng, 11);
    let S = random_polynomial(&mut rng, 2);

    // Define Omega_gates
    let mut Omega_gates = vec![];
    (0..number_gates).for_each(|l| Omega_gates.push(Omega[3 * l]));

    let t1 = compute_t1_T_S_zero_test(Omega[1], &T, &S);

    // check that t1 is of degree 24
    assert_eq!(t1.degree(), 24, "t1 must be of degree 24");

    for y in &Omega_gates {
        assert_ne!(
            t1.evaluate(&y),
            Fr::ZERO,
            "t1 should be not zero on Omega_gates"
        );
    }

    // construct Z_Omega_gates (vanishing polynomial) of subset Omega_gates
    let Z_Omega_gates = construct_vanishing_polynomial_from_roots(&Omega_gates);

    // Prover computes commitments of T,S
    let com_T = kzg_commit(&gp, &T).unwrap();
    let com_S = kzg_commit(&gp, &S).unwrap();

    // Prover computes quotient polynomial of t1 by Z_Omega
    let q = compute_q_zero_test_from_roots(&Omega_gates, &t1);

    // check that q is of degree 21
    assert_eq!(q.degree(), 21, "q must be of degree 21");

    // check that t1 is divisble by Z_Omega_gates
    assert_ne!(
        &q * &Z_Omega_gates,
        t1,
        "t1 must be not divisible by Z_Omega_gates"
    );

    // Verifier generates randomly r
    let r = Fr::rand(&mut rng);

    // Prover proves T_S zero test
    let proof = prove_T_S_zero_test(&gp, Omega[1], &q, &T, &S, r);

    // Verifier verifies T_S zero test
    assert_eq!(
        verify_T_S_zero_test(&gp, Omega[1], &Omega_gates, com_T, com_S, r, &proof),
        false,
        "Verify must return false because T and S do not satisfy T_S zero test on Omega_gates"
    );
}
