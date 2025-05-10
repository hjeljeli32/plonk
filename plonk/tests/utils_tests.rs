use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_poly::univariate::DensePolynomial;
use plonk::common::utils::{construct_Omega, construct_vanishing_polynomial};

#[test]
fn test_construct_Omega() {
    let k = 8;

    // define Omega as subset of size k
    let Omega = construct_Omega(k);

    for omega in &Omega {
        assert_eq!(omega.pow([k as u64]), Fr::ONE, "omega must be of order k");
    }
}

#[test]
fn test_construct_vanishing_polynomial() {
    let k = 4;

    // construct Z_Omega (vanishing polynomial) of subset Omega of size 8
    let Z_Omega = construct_vanishing_polynomial(k); // -1 + x^4

    assert_eq!(
        Z_Omega,
        DensePolynomial {
            coeffs: vec![Fr::from(-1), Fr::ZERO, Fr::ZERO, Fr::ZERO, Fr::from(1)],
        },
        "Z_Omega must be be equal to X^k -1"
    );
}
