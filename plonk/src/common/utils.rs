use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::pairing::{Pairing, PairingOutput};
use ark_ff::{AdditiveGroup, BigInteger, BigInteger256, FftField, Field, PrimeField, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;
use blake2::Blake2s256;
use digest::Digest;
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

// Construct Vanishing Polynomial defined by its roots
pub fn construct_vanishing_polynomial_from_roots(roots: &Vec<Fr>) -> DensePolynomial<Fr> {
    let mut vanishing_polynomial = DensePolynomial {
        coeffs: vec![Fr::ONE],
    };
    roots.iter().for_each(|root| {
        vanishing_polynomial = &vanishing_polynomial
            * &DensePolynomial {
                coeffs: vec![-*root, Fr::ONE],
            }
    });
    vanishing_polynomial
}

/// Derive a field element from a vector of commitments using Blake2s256
pub fn derive_challenge_from_commitments(commitments: &[G1]) -> Fr {
    let mut hasher = Blake2s256::new();

    for commitment in commitments {
        let mut bytes = Vec::new();
        commitment
            .serialize_compressed(&mut bytes)
            .expect("serialization should not fail");
        hasher.update(&bytes);
    }

    let hash = hasher.finalize();

    // Convert first 32 bytes of hash to a field element
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash[..32]);
    Fr::from_le_bytes_mod_order(&hash_bytes)
}

/// Derive multiple field elements from a vector of commitments using Blake2s256
pub fn derive_multiple_challenges_from_commitments(
    commitments: &[G1],
    num_challenges: usize,
) -> Vec<Fr> {
    let mut hasher = Blake2s256::new();

    // Hash all commitments
    for commitment in commitments {
        let mut bytes = Vec::new();
        commitment
            .serialize_compressed(&mut bytes)
            .expect("serialization should not fail");
        hasher.update(&bytes);
    }

    let base_hash = hasher.finalize();

    // Use domain separation to derive multiple challenges
    let mut challenges = Vec::with_capacity(num_challenges);
    for i in 0..num_challenges {
        let mut sub_hasher = Blake2s256::new();
        sub_hasher.update(&base_hash);
        sub_hasher.update(&[i as u8]); // domain separation
        let derived_hash = sub_hasher.finalize();

        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&derived_hash[..32]);
        let challenge = Fr::from_le_bytes_mod_order(&bytes);
        challenges.push(challenge);
    }

    challenges
}

/// Extract the inner field element from a pairing output.
pub fn pairing_value<P: Pairing>(output: &PairingOutput<P>) -> &P::TargetField {
    &output.0
}

/// Compute the product of two pairing outputs.
pub fn pairing_product<P: Pairing>(a: &PairingOutput<P>, b: &PairingOutput<P>) -> P::TargetField {
    a.0 * b.0
}
