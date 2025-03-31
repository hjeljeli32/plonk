use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, BigInteger256, FftField, Field, PrimeField, UniformRand};
use ark_poly::{univariate::DensePolynomial, Polynomial};
use plonk::common::{
    kzg::{kzg_commit, kzg_setup},
    protocols::{compute_q_zero_test, prove_equality, prove_zero_test, verify_equality, verify_zero_test},
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

    // check that f is divisble by Z_Omega
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