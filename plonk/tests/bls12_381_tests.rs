use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger256, Field, PrimeField};
use ark_std::UniformRand;

#[test]
fn test_field_modulus() {
    let modulus_minus_1 = Fr::from_bigint(BigInteger256::new([
        0xFFFFFFFF00000000,
        0x53BDA402FFFE5BFE,
        0x3339D80809A1D805,
        0x73EDA753299D7D48,
    ])).unwrap();
    
    let minus_1 = Fr::ZERO - Fr::from(1);

    assert_eq!(modulus_minus_1, minus_1, "modulus-1 should be -1");
}

#[test]
fn test_field_identity_elements() {
    let zero = Fr::ZERO;
    let one = Fr::ONE;

    assert_eq!(zero + one, one, "0 + 1 should be 1");
    assert_eq!(one * one, one, "1 * 1 should be 1");
}

#[test]
fn test_field_operations() {
    let a = Fr::from(7u64);
    let b = Fr::from(5u64);

    let sum = a + b;
    let product = a * b;
    let inverse_a = a.inverse().unwrap(); // Compute a⁻¹ mod p

    assert_eq!(sum, Fr::from(12u64), "Addition failed");
    assert_eq!(product, Fr::from(35u64), "Multiplication failed");
    assert_eq!(inverse_a * a, Fr::ONE, "Inverse computation failed");
}

#[test]
fn test_field_inversion() {
    let mut rng = ark_std::test_rng();
    for _ in 0..100 {
        let t = Fr::rand(&mut rng);
        let inverse_t = t.inverse().unwrap();

        assert_eq!(inverse_t * t, Fr::ONE, "Inverse computation failed");
    }
}

#[test]
fn test_field_division() {
    let mut rng = ark_std::test_rng();
    for _ in 0..100 {
        let t = Fr::rand(&mut rng);
        let inverse_t = Fr::ONE / t;

        assert_eq!(
            inverse_t,
            t.inverse().unwrap(),
            "Division and inverse are different"
        );
        assert_eq!(inverse_t * t, Fr::ONE, "Inverse computation failed");
    }
}
