use ark_bls12_381::Fr;
use ark_ff::Field;
use ark_poly::DenseUVPolynomial;
use ark_poly::polynomial::univariate::*;
use ark_std::{Zero, test_rng};
use rayon::prelude::*;

/// Generates a random polynomial of certain degree
pub fn random_polynomial(degree: usize) -> DensePolynomial<Fr> {
    let rng = &mut test_rng();
    DensePolynomial::<Fr>::rand(degree, rng)
}

/// Calculates lagrange polynomials corresponding to given points
fn calculate_lagrange_polynomials(x_points: &Vec<Fr>) -> Vec<DensePolynomial<Fr>> {
    let n = x_points.len();

    // Computes monomials and their product
    let monomials = x_points.par_iter().map(|x| DensePolynomial {
        coeffs: vec![-*x, Fr::from(1)],
    });
    let product = monomials.clone().into_par_iter().reduce(
        || DensePolynomial {
            coeffs: vec![Fr::ONE],
        },
        |product, monomial| product * monomial,
    );

    // Computes Lagrange polynomials
    let lagrange_polys = (0..n)
        .into_par_iter()
        .map(|i| {
            let numerator = &product
                / DensePolynomial {
                    coeffs: vec![-x_points[i], Fr::from(1)],
                };
            let denominator = (0..n)
                .filter(|&j| j != i)
                .collect::<Vec<_>>() // Collect into Vec to enable parallel iteration
                .into_par_iter()
                .map(|j| x_points[i] - x_points[j])
                .reduce(|| Fr::ONE, |val, denominator| denominator * val);
            &numerator * denominator.inverse().unwrap()
        })
        .collect();

    lagrange_polys
}

/// Interpolates a polynomial from given evaluations at points using Lagrange interpolation.
pub fn interpolate_polynomial(x_points: &Vec<Fr>, y_points: &Vec<Fr>) -> DensePolynomial<Fr> {
    let n = x_points.len();
    let lagrange_polys = calculate_lagrange_polynomials(&x_points);

    (0..n)
        .into_par_iter()
        .map(|i| &lagrange_polys[i] * y_points[i])
        .reduce(|| DensePolynomial::zero(), |result, value| result + &value)
}

/// Raises a polynomial to a power
pub fn pow(base: &DensePolynomial<Fr>, exp: u64) -> DensePolynomial<Fr> {
    let mut result = DensePolynomial::<Fr> {
        coeffs: vec![Fr::from(1)],
    };
    let mut base = base.clone();
    let mut exp = exp;

    while exp > 0 {
        if exp % 2 == 1 {
            result = &result * &base;
        }
        base = &base * &base;
        exp /= 2;
    }

    result
}

/// Computes the composition of two polynomials
pub fn compose_polynomials(
    f: &DensePolynomial<Fr>,
    g: &DensePolynomial<Fr>,
) -> DensePolynomial<Fr> {
    let f_coeffs = f.coeffs();
    let n = f_coeffs.len();
    let first_term = DensePolynomial::<Fr> {
        coeffs: vec![f_coeffs[0]],
    };

    // Precompute powers of g sequentially to avoid mutable conflicts in parallel execution
    let g_powers: Vec<DensePolynomial<Fr>> = (0..n)
        .scan(
            DensePolynomial {
                coeffs: vec![Fr::from(1)],
            },
            |g_power, _| {
                let current = g_power.clone();
                *g_power = g_power.clone() * g;
                Some(current)
            },
        )
        .collect();

    let terms: Vec<DensePolynomial<Fr>> = f_coeffs
        .par_iter()
        .enumerate()
        .skip(1)
        .map(|(i, coeff)| &g_powers[i] * *coeff)
        .collect();

    // Sum all terms - no need fo parallelization
    first_term + &terms.into_iter().reduce(|acc, e| &acc + e).unwrap()
}
