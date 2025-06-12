use ark_bls12_381::{Fr, G1Projective as G1};
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::{
    common::{kzg::kzg_commit, polynomials::interpolate_polynomial},
    setup_global_params::SetupGlobalParamsOutput,
};

pub fn run(setup: &SetupGlobalParamsOutput, Omega: &Vec<Fr>) -> (DensePolynomial<Fr>, G1) {
    println!("Executing part 1: interpolating the computation trace T");

    let d = setup.d;

    let (mut x_vals, mut y_vals) = (vec![], vec![]);

    // T encodes all inputs: T(w^-j) = input#j
    // T(w^-1) = 5
    x_vals.push(Omega[d - 1]);
    y_vals.push(Fr::from(5));
    // T(w^-2) = 6
    x_vals.push(Omega[d - 2]);
    y_vals.push(Fr::from(6));
    // T(w^-3) = 1
    x_vals.push(Omega[d - 3]);
    y_vals.push(Fr::from(1));

    // T encodes all wires of the gates
    // Gate 0 (Addition)
    // T(w^0) = 5
    x_vals.push(Omega[0]);
    y_vals.push(Fr::from(5));
    // T(w^1) = 6
    x_vals.push(Omega[1]);
    y_vals.push(Fr::from(6));
    // T(w^2) = 11
    x_vals.push(Omega[2]);
    y_vals.push(Fr::from(11));

    // Gate 1 (Addition)
    // T(w^3) = 6
    x_vals.push(Omega[3]);
    y_vals.push(Fr::from(6));
    // T(w^4) = 1
    x_vals.push(Omega[4]);
    y_vals.push(Fr::from(1));
    // T(w^5) = 7
    x_vals.push(Omega[5]);
    y_vals.push(Fr::from(7));

    // Gate 2 (Multiplication)
    // T(w^6) = 11
    x_vals.push(Omega[6]);
    y_vals.push(Fr::from(11));
    // T(w^7) = 7
    x_vals.push(Omega[7]);
    y_vals.push(Fr::from(7));
    // T(w^8) = 77
    x_vals.push(Omega[8]);
    y_vals.push(Fr::from(77));

    // Interpolate the polynomial T that enodes the entire trace
    let T = interpolate_polynomial(&x_vals, &y_vals);
    assert_eq!(T.degree(), d - 1, "T must be of degree d-1");

    // Compute commitment of t
    let com_T = kzg_commit(&setup.gp, &T).unwrap();

    (T, com_T)
}
