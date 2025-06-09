use ark_bls12_381::{Fr, G1Projective as G1};
use ark_ec::PrimeGroup;
use ark_ff::{AdditiveGroup, Field, PrimeField};
use ark_poly::univariate::DensePolynomial;
use ark_serialize::CanonicalSerialize;
use digest::Digest;
use plonk::common::utils::{
    construct_Omega, construct_vanishing_polynomial, construct_vanishing_polynomial_from_roots,
    derive_challenge_from_commitments, derive_multiple_challenges_from_commitments,
};

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

#[test]
fn test_construct_vanishing_polynomial_from_roots() {
    // Z_Omega (vanishing polynomial) from roots 2, 3
    let Z_Omega = construct_vanishing_polynomial_from_roots(&vec![Fr::from(2), Fr::from(3)]); // (x-2) * (x-3)

    assert_eq!(
        Z_Omega,
        DensePolynomial {
            coeffs: vec![Fr::from(6), Fr::from(-5), Fr::from(1)],
        },
        "Z_Omega must be be equal to (X-2)(X-3)"
    );
}

#[test]
fn test_derive_challenge_from_single_commitment() {
    // Use generator as deterministic commitment
    let commitment = G1::generator();

    // Derive the challenge
    let challenge: Fr = derive_challenge_from_commitments(&[commitment]);

    // Re-derive expected value manually
    let mut bytes = Vec::new();
    commitment
        .serialize_compressed(&mut bytes)
        .expect("Serialization should not fail");
    let hash = blake2::Blake2s256::digest(&bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash[..32]);
    let expected = Fr::from_le_bytes_mod_order(&hash_bytes);

    // Now check
    assert_eq!(
        challenge, expected,
        "Derived challenge doesn't match expected value"
    );
}

#[test]
fn test_derive_challenge_from_two_commitments() {
    let commitment1 = G1::generator();
    let commitment2 = G1::generator().double(); // Distinct second commitment

    let challenge: Fr = derive_challenge_from_commitments(&[commitment1, commitment2]);

    // Derive expected value manually
    let mut bytes = Vec::new();
    commitment1.serialize_compressed(&mut bytes).unwrap();
    commitment2.serialize_compressed(&mut bytes).unwrap();
    let hash = blake2::Blake2s256::digest(&bytes);
    let mut hash_bytes = [0u8; 32];
    hash_bytes.copy_from_slice(&hash[..32]);
    let expected = Fr::from_le_bytes_mod_order(&hash_bytes);

    assert_eq!(
        challenge, expected,
        "Derived challenge from two commitments doesn't match expected value"
    );
}

#[test]
fn test_derive_three_challenges_from_two_commitments() {
    use plonk::common::utils::derive_multiple_challenges_from_commitments;

    let commitment1 = G1::generator();
    let commitment2 = G1::generator().double(); // A distinct second commitment

    let challenges = derive_multiple_challenges_from_commitments(&[commitment1, commitment2], 3);

    // Manually re-derive the expected challenges
    let mut bytes = Vec::new();
    commitment1.serialize_compressed(&mut bytes).unwrap();
    commitment2.serialize_compressed(&mut bytes).unwrap();
    let hash = blake2::Blake2s256::digest(&bytes);

    // Derive 3 field elements using successive chunks from the hash output
    let mut expected_challenges = Vec::new();
    let mut hasher_input = hash.to_vec();
    for i in 0..3 {
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(&hasher_input);
        hasher.update([i as u8]);
        let hash_i = hasher.finalize();
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&hash_i[..32]);
        let challenge_i = Fr::from_le_bytes_mod_order(&hash_bytes);
        expected_challenges.push(challenge_i);
    }

    assert_eq!(
        challenges, expected_challenges,
        "Derived challenges do not match expected values"
    );
}
