use ark_bls12_381::Fr;
use ark_poly::{univariate::DensePolynomial, Polynomial};

use crate::common::polynomials::interpolate_polynomial;

pub fn run(number_public_inputs: usize, d: usize, Omega: &Vec<Fr>, T: &DensePolynomial<Fr>) -> () {
    println!("Executing part 2...");

    let mut Omega_inputs = vec![];
    (0..number_public_inputs).for_each(|i| Omega_inputs.push(Omega[d - 1 - i]));
    assert_eq!(
        Omega_inputs,
        vec![Omega[Omega.len() - 1], Omega[Omega.len() - 2]],
        "Omega_inputs should be equal to [w^-1, w^-2]"
    );

    let (mut x_vals, mut y_vals) = (vec![], vec![]);

    // v encodes all inputs: T(w^-j) = input#j
    // v(w^-1) = 5
    x_vals.push(Omega[d - 1]);
    y_vals.push(Fr::from(5));
    // v(w^-2) = 6
    x_vals.push(Omega[d - 2]);
    y_vals.push(Fr::from(6));

    // Interpolate the polynomial v
    let v = interpolate_polynomial(&x_vals, &y_vals);
    assert_eq!(
        v.degree(),
        number_public_inputs - 1,
        "v must be of degree 1"
    );
}
