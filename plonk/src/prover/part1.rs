use ark_bls12_381::Fr;
use ark_poly::Polynomial;

use crate::common::{polynomials::interpolate_polynomial, utils::construct_Omega};

pub fn run() -> () {
    println!("Executing part 1...");

    let number_gates = 3; // Circuit has 2 addition gates and 1 multiplication gate
    let number_inputs = 3; // Circuit has 2 public inputs (x1, x2) and 1 witness w
    let d = 3 * number_gates + number_inputs;
    assert_eq!(d, 12, "d must be equal to 12");

    // Define Omega as subgroup of size d
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

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
    assert_eq!(T.degree(), d-1, "T must be of degree d-1");

}
