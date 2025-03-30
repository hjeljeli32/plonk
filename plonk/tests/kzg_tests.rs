use ark_bls12_381::{Bls12_381, Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::{PrimeGroup, pairing::Pairing};
use ark_ff::{Field, UniformRand};
use ark_poly::{
    Polynomial,
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
};
use ark_std::rand::Rng;
use plonk::common::{
    kzg::{GlobalParameters, commit, evaluate, setup, verify},
    univariate_polynomials::random_polynomial,
};

#[test]
fn test_setup() {
    let degree = 10;
    let gp = setup(degree);

    assert_eq!(
        gp.tau_powers_g1.len(),
        degree + 1,
        "tau_powers_g1 must be of degree d+1"
    );

    for i in 0..degree {
        assert_eq!(
            Bls12_381::pairing(gp.tau_powers_g1[i + 1], G2::generator()),
            Bls12_381::pairing(gp.tau_powers_g1[i], gp.tau_g2),
            "Pairing(g1*tau^{}, g2) must be equal to pairing(g1*tau^{}, g2*tau)",
            i + 1,
            i
        );
    }
}

#[test]
fn test_commit() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // I re-compute the setup instead of calling the setup function to know tau
    let tau = Fr::rand(&mut rng);
    let mut accumulator = G1::generator();
    let mut tau_powers_g1 = vec![accumulator];
    // Compute tau^i * g1 for all i in the range [1..degree]
    for _ in 1..(degree + 1) {
        accumulator = accumulator * tau; // Update accumulator with tau^i
        tau_powers_g1.push(accumulator); // Push tau^i into tau_powers_g1
    }
    // Compute tau * g2
    let tau_g2 = G2::generator() * tau;
    let gp = GlobalParameters {
        tau_powers_g1,
        tau_g2,
    };

    // generate randomly a polynomial f
    let f = random_polynomial(degree);

    // compute commitment of f
    let com_f = commit(&gp, &f);

    assert_eq!(
        com_f,
        G1::generator() * f.evaluate(&tau),
        "Commitment of f must be equal to g1*f(z)"
    );
}

#[test]
fn test_eval() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // I re-compute the setup instead of calling the setup function to know tau
    let tau = Fr::rand(&mut rng);
    let mut accumulator = G1::generator();
    let mut tau_powers_g1 = vec![accumulator];
    // Compute tau^i * g1 for all i in the range [1..degree]
    for _ in 1..(degree + 1) {
        accumulator = accumulator * tau; // Update accumulator with tau^i
        tau_powers_g1.push(accumulator); // Push tau^i into tau_powers_g1
    }
    // Compute tau * g2
    let tau_g2 = G2::generator() * tau;
    let gp = GlobalParameters {
        tau_powers_g1,
        tau_g2,
    };

    // generate randomly a polynomial f
    let f = random_polynomial(degree);

    // generate randomly u
    let u = Fr::rand(&mut rng);

    // compute f-v and x-u
    let f_minus_v = &f
        - &DensePolynomial {
            coeffs: vec![f.evaluate(&u)],
        };
    let x_minus_u = DensePolynomial {
        coeffs: vec![-u, Fr::ONE],
    };

    // compute q as (f-v)/(x-u)
    let (q, _) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&f_minus_v).into(), &(&x_minus_u).into())
            .unwrap();

    // call eval on gp, f, u
    let (v, proof) = evaluate(&gp, &f, u);

    assert_eq!(v, f.evaluate(&u), "v must be equal to f(u)");
    assert_eq!(
        proof,
        G1::generator() * q.evaluate(&tau),
        "Proof must be equal to g1*q(z)"
    );
}

#[test]
fn test_verify() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // I re-compute the setup instead of calling the setup function to know tau
    let tau = Fr::rand(&mut rng);
    let mut accumulator = G1::generator();
    let mut tau_powers_g1 = vec![accumulator];
    // Compute tau^i * g1 for all i in the range [1..degree]
    for _ in 1..(degree + 1) {
        accumulator = accumulator * tau; // Update accumulator with tau^i
        tau_powers_g1.push(accumulator); // Push tau^i into tau_powers_g1
    }
    // Compute tau * g2
    let tau_g2 = G2::generator() * tau;
    let gp = GlobalParameters {
        tau_powers_g1,
        tau_g2,
    };

    // generate randomly a polynomial f
    let f = random_polynomial(degree);

    // generate randomly u and compute v as f(u)
    let u = Fr::rand(&mut rng);
    let v = f.evaluate(&u);

    // compute f-v and x-u
    let f_minus_v = &f - &DensePolynomial { coeffs: vec![v] };
    let x_minus_u = DensePolynomial {
        coeffs: vec![-u, Fr::ONE],
    };

    // compute q as (f-v)/(x-u)
    let (q, _) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&f_minus_v).into(), &(&x_minus_u).into())
            .unwrap();

    // compute com_f as g1*f(tau) and proof as g1*q(tau)
    let com_f = G1::generator() * f.evaluate(&tau);
    let proof = G1::generator() * q.evaluate(&tau);

    // call verify on gp, com_f, u, v, proof
    assert!(verify(&gp, com_f, u, v, proof), "Verify must return true");
}

#[test]
fn test_full_protocol() {
    let mut rng = ark_std::test_rng();

    for _ in 0..10 {
        let degree = rng.gen_range(0..=100);

        // generate global parameters
        let gp = setup(degree);

        // generate randomly a polynomial f
        let f = random_polynomial(degree);

        // Prover computes commitment of f
        let com_f = commit(&gp, &f);

        // Verifier generates randomly u
        let u = Fr::rand(&mut rng);

        // Prover evaluates f on u
        let (v, proof) = evaluate(&gp, &f, u);

        // Verifier verifies (v, proof) sent by Prover
        assert!(verify(&gp, com_f, u, v, proof), "Verify must return true");
    }
}
