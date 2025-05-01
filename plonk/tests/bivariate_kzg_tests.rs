use ark_bls12_381::{Fr, G1Projective as G1, G2Projective as G2};
use ark_ec::PrimeGroup;
use ark_ff::{Field, UniformRand};
use ark_poly::Polynomial;
use ark_std::rand::Rng;
use plonk::common::{
    bivariate_kzg::{
        CommitError, GlobalParameters, bivariate_kzg_commit, bivariate_kzg_evaluate,
        bivariate_kzg_setup, bivariate_kzg_verify,
    },
    bivariate_polynomials::{
        divide_by_linear_in_x, divide_by_linear_in_y, monomial_list_to_sparsepoly,
        random_bivariate_polynomial, subtract_value_from_poly_monomials,
    },
};

#[test]
fn test_bivariate_kzg_setup() {
    let degree = 10;
    let gp = bivariate_kzg_setup(degree);

    assert_eq!(
        gp.tau_powers_g1.len(),
        (degree + 1) * (degree + 2) / 2,
        "Length of tau_powers_g1 must be (d+1)*(d+2)/2"
    );

    assert_eq!(
        gp.tau_powers_g1_prime.len(),
        degree * (degree + 1) / 2,
        "Length of tau_powers_g1_prime must be d*(d+1)/2"
    );

    assert_eq!(gp.tau_g2.len(), 2, "Length of tau_g2 must be 2");
}

#[test]
fn test_bivariate_kzg_commit_success() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // I re-compute the setup instead of calling the setup function to know tau
    let tau1 = Fr::rand(&mut rng);
    let tau2 = Fr::rand(&mut rng);
    let mut tau_powers_g1 = vec![];
    let mut tau_powers_g1_prime = vec![];
    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree] such that i+j <= degree
    for i in 0..(degree + 1) {
        for j in 0..(degree + 1) {
            if i + j <= degree {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1.push(G1::generator() * exponent);
            }
        }
    }
    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree-1] such that i+j <= degree-1
    for i in 0..degree {
        for j in 0..degree {
            if i + j <= (degree - 1) {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1_prime.push(G1::generator() * exponent);
            }
        }
    }
    // Compute [tau1 * G2, tau2 * G2]
    let tau_g2 = vec![G2::generator() * tau1, G2::generator() * tau2];
    let gp = GlobalParameters {
        tau_powers_g1,
        tau_powers_g1_prime,
        tau_g2,
    };

    // generate randomly a polynomial f
    let (f, f_monomials) = random_bivariate_polynomial(&mut rng, degree);

    // compute commitment of f
    let com_f = bivariate_kzg_commit(&gp, &f, &f_monomials).unwrap();

    assert_eq!(
        com_f,
        G1::generator() * f.evaluate(&vec![tau1, tau2]),
        "Commitment of f must be equal to g1*f(z)"
    );
}

#[test]
fn test_bivariate_kzg_commit_fail() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // generate global parameters
    let gp = bivariate_kzg_setup(degree);

    // generate randomly a polynomial f of degree + 1
    let (f, f_monomials) = random_bivariate_polynomial(&mut rng, degree + 1);

    // commit call should return an error
    let result = bivariate_kzg_commit(&gp, &f, &f_monomials);
    assert!(result.is_err(), "Expected an error but got Ok instead");
    if let Err(e) = result {
        assert!(
            matches!(e, CommitError::CommitFailed),
            "Unexpected error: {:?}",
            e
        );
    }
}

#[test]
fn test_bivariate_kzg_eval() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // I re-compute the setup instead of calling the setup function to know tau
    let tau1 = Fr::rand(&mut rng);
    let tau2 = Fr::rand(&mut rng);
    let mut tau_powers_g1 = vec![];
    let mut tau_powers_g1_prime = vec![];
    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree] such that i+j <= degree
    for i in 0..(degree + 1) {
        for j in 0..(degree + 1) {
            if i + j <= degree {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1.push(G1::generator() * exponent);
            }
        }
    }
    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree-1] such that i+j <= degree-1
    for i in 0..degree {
        for j in 0..degree {
            if i + j <= (degree - 1) {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1_prime.push(G1::generator() * exponent);
            }
        }
    }
    // Compute [tau1 * G2, tau2 * G2]
    let tau_g2 = vec![G2::generator() * tau1, G2::generator() * tau2];
    let gp = GlobalParameters {
        tau_powers_g1,
        tau_powers_g1_prime,
        tau_g2,
    };

    // generate randomly a polynomial f
    let (f, f_monomials) = random_bivariate_polynomial(&mut rng, degree);

    // generate randomly (u1, u2)
    let (u1, u2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

    // compute g = f-v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, f.evaluate(&vec![u1, u2]));

    // compute q1 and q2 such that (f-v) = q1*(x-u1) + q2*(y-u2)
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);
    let q2_monomials = divide_by_linear_in_y(&r_monomials, u2);
    let q1 = monomial_list_to_sparsepoly(&q1_monomials);
    let q2 = monomial_list_to_sparsepoly(&q2_monomials);

    // call eval on gp, f, u1, u2
    let (v, proof1, proof2) = bivariate_kzg_evaluate(&gp, &f, &f_monomials, u1, u2);

    assert_eq!(v, f.evaluate(&vec![u1, u2]), "v must be equal to f(u)");
    assert_eq!(
        proof1,
        G1::generator() * q1.evaluate(&vec![tau1, tau2]),
        "Proof1 must be equal to g1*q1(z)"
    );
    assert_eq!(
        proof2,
        G1::generator() * q2.evaluate(&vec![tau1, tau2]),
        "Proof2 must be equal to g1*q2(z)"
    );
}

#[test]
fn test_bivariate_kzg_verify() {
    let mut rng = ark_std::test_rng();

    let degree = 10;

    // I re-compute the setup instead of calling the setup function to know tau
    let tau1 = Fr::rand(&mut rng);
    let tau2 = Fr::rand(&mut rng);
    let mut tau_powers_g1 = vec![];
    let mut tau_powers_g1_prime = vec![];
    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree] such that i+j <= degree
    for i in 0..(degree + 1) {
        for j in 0..(degree + 1) {
            if i + j <= degree {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1.push(G1::generator() * exponent);
            }
        }
    }
    // Compute Monomials powers tau1^i * tau2^j * g1 for all pairs i,j in [0..degree-1] such that i+j <= degree-1
    for i in 0..degree {
        for j in 0..degree {
            if i + j <= (degree - 1) {
                let exponent = tau1.pow(&[i as u64]) * tau2.pow(&[j as u64]);
                tau_powers_g1_prime.push(G1::generator() * exponent);
            }
        }
    }
    // Compute [tau1 * G2, tau2 * G2]
    let tau_g2 = vec![G2::generator() * tau1, G2::generator() * tau2];
    let gp = GlobalParameters {
        tau_powers_g1,
        tau_powers_g1_prime,
        tau_g2,
    };

    // generate randomly a polynomial f
    let (f, f_monomials) = random_bivariate_polynomial(&mut rng, degree);

    // generate randomly (u1, u2) and compute v as f(u1, u2)
    let (u1, u2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));
    let v = f.evaluate(&vec![u1, u2]);

    // compute g = f-v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, f.evaluate(&vec![u1, u2]));

    // compute q1 and q2 such that (f-v) = q1*(x-u1) + q2*(y-u2)
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);
    let q2_monomials = divide_by_linear_in_y(&r_monomials, u2);
    let q1 = monomial_list_to_sparsepoly(&q1_monomials);
    let q2 = monomial_list_to_sparsepoly(&q2_monomials);

    // compute com_f as g1*f(tau) and (proof1, proof2) as (g1*q1(tau), g1*q2(tau))
    let com_f = G1::generator() * f.evaluate(&vec![tau1, tau2]);
    let proof1 = G1::generator() * q1.evaluate(&vec![tau1, tau2]);
    let proof2 = G1::generator() * q2.evaluate(&vec![tau1, tau2]);

    // call verify on gp, com_f, u, v, proof
    assert!(
        bivariate_kzg_verify(&gp, com_f, u1, u2, v, proof1, proof2),
        "Verify must return true"
    );
}

#[test]
fn test_full_bivariate_kzg_protocol() {
    let mut rng = ark_std::test_rng();

    for _ in 0..5 {
        let degree = rng.gen_range(0..=20);

        // generate global parameters
        let gp = bivariate_kzg_setup(degree);

        // Prover generates randomly a polynomial f
        let (f, f_monomials) = random_bivariate_polynomial(&mut rng, degree);

        // Prover computes commitment of f
        let com_f = bivariate_kzg_commit(&gp, &f, &f_monomials).unwrap();

        // Verifier generates randomly (u1, u2)
        let (u1, u2) = (Fr::rand(&mut rng), Fr::rand(&mut rng));

        // Prover evaluates f on (u1, u2)
        let (v, proof1, proof2) = bivariate_kzg_evaluate(&gp, &f, &f_monomials, u1, u2);

        // Verifier verifies (v, proof) sent by Prover
        assert!(
            bivariate_kzg_verify(&gp, com_f, u1, u2, v, proof1, proof2),
            "Verify must return true"
        );
    }
}
