use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::CurveGroup;
use ark_ec::{pairing::Pairing, AdditiveGroup, PrimeGroup};
use ark_ff::UniformRand;
use ark_std::Zero;
use plonk::common::utils::{pairing_product, pairing_value};

#[test]
fn test_closure() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random group elements
    let a = G1::rand(&mut rng);
    let b = G1::rand(&mut rng);

    assert!(
        (a + b).into_affine().is_on_curve(),
        "a+b is not on the curve"
    );
}

#[test]
fn test_associativity() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random group elements
    let a = G1::rand(&mut rng);
    let b = G1::rand(&mut rng);
    let c = G1::rand(&mut rng);

    assert_eq!(
        (a + b) + c,
        a + (b + c),
        "(a + b) + c is not equal to a + (b + c)"
    );
}

#[test]
fn test_identity() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly a random group element
    let a = G1::rand(&mut rng);
    let e = G1::zero();

    assert_eq!(a + e, e + a, "a + e is not equal to e + a");
    assert_eq!(a + e, a, "a + e is not equal to a");
}

#[test]
fn test_inverse() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly a random group element
    let a = G1::rand(&mut rng);
    let b = -a;

    assert_eq!(a + b, b + a, "a + (-a) is not equal to (-a) + a");
    assert_eq!(a + b, G1::zero(), "a + (-a) is not equal to e");
}

#[test]
fn test_double() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly a random group element
    let a = G1::rand(&mut rng);

    assert_eq!(a + a, a.double(), "a + a is not equal to 2*a");
}

#[test]
fn test_scalar_mul() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly a random scalar
    let x = Fr::rand(&mut rng);

    let a = G1::generator() * x;
    let b = G1::generator() * (-x);

    assert_eq!(a + b, G1::ZERO, "a + b is not equal to e");
}

#[test]
fn test_pairing() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random scalars
    let x = Fr::rand(&mut rng);
    let y = Fr::rand(&mut rng);

    let e1 = Bls12_381::pairing(G1::generator() * x, G2::generator() * y);
    let e2 = Bls12_381::pairing(G1::generator() * (x * y), G2::generator());

    assert_eq!(e1, e2, "e1 and e2 are not equal");
}

#[test]
fn test_product_pairing() {
    let mut rng = ark_std::test_rng();
    // Let's sample uniformly random scalars
    let x = Fr::rand(&mut rng);
    let y = Fr::rand(&mut rng);
    let z = x + y;

    let e_x = Bls12_381::pairing(G1::generator() * x, G2::generator());
    let e_y = Bls12_381::pairing(G1::generator() * y, G2::generator());
    let e_z = Bls12_381::pairing(G1::generator() * z, G2::generator());

    let product = pairing_product(&e_x, &e_y);
    assert_eq!(
        product,
        *pairing_value(&e_z),
        "e_x*e_y and e_z are not equal"
    );
}
