use ark_bls12_381::Fr;
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::{AdditiveGroup, BigInteger, BigInteger256, FftField, Field, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use num_bigint::BigUint;

// Construct a subgroup Omega of order k by computing a k-th root of unity omega then raise it to powers 0..k-1
pub fn construct_Omega(k: usize) -> Vec<Fr> {
    assert!(k > 1, "k must be at least 2");

    let modulus_minus_1 = BigUint::from_bytes_le(&Fr::MODULUS.to_bytes_le()) - 1u64;
    let k_big = BigUint::from(k as u64);

    assert!(
        &modulus_minus_1 % &k_big == BigUint::zero(),
        "k must divide r - 1 (multiplicative group order)"
    );

    let exp_big = &modulus_minus_1 / &k_big;

    // Convert to [u64; 4] then to BigInteger256
    let mut limbs = [0u64; 4];
    let exp_bytes = exp_big.to_bytes_le();
    for (i, chunk) in exp_bytes.chunks(8).enumerate().take(4) {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        limbs[i] = u64::from_le_bytes(buf);
    }
    let exp = BigInteger256::new(limbs);

    let omega = Fr::GENERATOR.pow(&exp);

    // Build the subgroup
    (0..k).map(|i| omega.pow([i as u64])).collect()
}

// Construct Vanishing Polynomial as x^k - 1
pub fn construct_vanishing_polynomial(k: usize) -> DensePolynomial<Fr> {
    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; k - 1]);
    coefficients.push(Fr::ONE);
    DensePolynomial {
        coeffs: coefficients,
    }
}

/// Extract the inner field element from a pairing output.
pub fn pairing_value<P: Pairing>(output: &PairingOutput<P>) -> &P::TargetField {
    &output.0
}

/// Compute the product of two pairing outputs.
pub fn pairing_product<P: Pairing>(a: &PairingOutput<P>, b: &PairingOutput<P>) -> P::TargetField {
    a.0 * b.0
}
