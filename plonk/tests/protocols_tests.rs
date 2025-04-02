use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, BigInteger256, FftField, Field, PrimeField, UniformRand};
use ark_poly::{Polynomial, univariate::DensePolynomial};
use ark_std::rand::seq::SliceRandom;
use plonk::common::{
    kzg::{kzg_commit, kzg_setup},
    protocols::{
        compute_q_zero_test, compute_t_and_t1_product_check, compute_t_and_t1_product_check_rational_functions, prove_equality, prove_product_check, prove_product_check_rational_functions, prove_zero_test, verify_equality, verify_product_check, verify_product_check_rational_functions, verify_zero_test
    },
    univariate_polynomials::{interpolate_polynomial, random_polynomial},
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
    let gp = kzg_setup(degree);

    // define omega as element of order 8
    let mut exponent = Fr::MODULUS;
    exponent.sub_with_borrow(&BigInteger256::from(1_u64));
    exponent >>= 3; // divide exponent by 8
    let omega = Fr::GENERATOR.pow(exponent.0.to_vec());

    // compute x_vals and y_vals and interpolate f
    let mut x_vals: Vec<Fr> = (0..8).map(|i| omega.pow([i as u64])).collect();
    x_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let mut y_vals: Vec<Fr> = (0..8).map(|_| Fr::ZERO).collect();
    y_vals.extend((0..3).map(|_| Fr::rand(&mut rng)));
    let f = interpolate_polynomial(&x_vals, &y_vals);

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let k = 8;
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^8

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

    // generate global parameters
    let gp = kzg_setup(degree);

    // generate f randomly so it won't be zero on Omega
    let f = random_polynomial(&mut rng, 10);

    // check that f is of degree 10
    assert_eq!(f.degree(), 10, "f must be of degree 10");

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let k = 8;
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^8

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

    // generate global parameters
    let gp = kzg_setup(degree);

    // define omega as element of order 8
    let mut exponent = Fr::MODULUS;
    exponent.sub_with_borrow(&BigInteger256::from(1_u64));
    exponent >>= 3; // divide exponent by 8
    let omega = Fr::GENERATOR.pow(exponent.0.to_vec());
    let Omega: Vec<Fr> = (0..8).map(|i| omega.pow([i as u64])).collect();

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
    let k = 8;
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^8

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

    // generate global parameters
    let gp = kzg_setup(degree);

    // define omega as element of order 8
    let mut exponent = Fr::MODULUS;
    exponent.sub_with_borrow(&BigInteger256::from(1_u64));
    exponent >>= 3; // divide exponent by 8
    let omega = Fr::GENERATOR.pow(exponent.0.to_vec());
    let Omega: Vec<Fr> = (0..8).map(|i| omega.pow([i as u64])).collect();

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
    let k = 8;
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^8

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
fn test_product_check_rational_functions_success() {
    let mut rng = ark_std::test_rng();
    // this degree is used for kzg setup. We need to commit to polynomial q of degree 12.
    let degree = 12;

    // generate global parameters
    let gp = kzg_setup(degree);

    // define omega as element of order 8
    let mut exponent = Fr::MODULUS;
    exponent.sub_with_borrow(&BigInteger256::from(1_u64));
    exponent >>= 3; // divide exponent by 8
    let omega = Fr::GENERATOR.pow(exponent.0.to_vec());
    let Omega: Vec<Fr> = (0..8).map(|i| omega.pow([i as u64])).collect();

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
    let k = 8;
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^8

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

    // generate global parameters
    let gp = kzg_setup(degree);

    // define omega as element of order 8
    let mut exponent = Fr::MODULUS;
    exponent.sub_with_borrow(&BigInteger256::from(1_u64));
    exponent >>= 3; // divide exponent by 8
    let omega = Fr::GENERATOR.pow(exponent.0.to_vec());
    let Omega: Vec<Fr> = (0..8).map(|i| omega.pow([i as u64])).collect();

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
    let k = 8;
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    let Z_Omega = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^8

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
