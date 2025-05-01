use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field};
use ark_poly::{
    DenseMVPolynomial, Polynomial,
    multivariate::{SparsePolynomial, SparseTerm, Term},
};
use plonk::common::bivariate_polynomials::*;

#[test]
fn test_monomial_list_to_sparsepoly() {
    let num_vars = 2;

    let poly_monomials = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::from(2)),
        (1, 0, Fr::from(1)),
        (1, 1, Fr::from(0)),
    ];

    let poly = monomial_list_to_sparsepoly(&poly_monomials);

    let terms = vec![
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 1), (1, 0)])), // x
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 0), (1, 1)])), // 2 * y
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 1
    ];
    let poly_expected = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    assert_eq!(poly, poly_expected);
}

#[test]
fn test_add_polys_monomials() {
    let f_monomials = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::from(2)),
        (0, 2, Fr::ZERO),
        (1, 0, Fr::from(1)),
        (1, 1, Fr::from(2)),
        (2, 0, Fr::ZERO),
    ]; // 1 + 2y + x + 2xy

    let g_monomials = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::ZERO),
        (0, 2, Fr::ZERO),
        (1, 0, Fr::ZERO),
        (1, 1, Fr::from(3)),
        (2, 0, Fr::from(1)),
    ]; // 1 + 3xy + x^2

    let result_monomials = add_polys_monomials(&f_monomials, &g_monomials);

    let result_monomials_expected = vec![
        (0, 0, Fr::from(2)),
        (0, 1, Fr::from(2)),
        (0, 2, Fr::ZERO),
        (1, 0, Fr::from(1)),
        (1, 1, Fr::from(5)),
        (2, 0, Fr::from(1)),
    ]; // 2 + 2y + x + 5xy + x^2

    assert_eq!(result_monomials, result_monomials_expected);
}

#[test]
fn test_subtract_polys_monomials() {
    let f_monomials = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::from(2)),
        (1, 0, Fr::from(1)),
    ]; // 1 + 2y + x

    let g_monomials = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::ZERO),
        (0, 2, Fr::ZERO),
        (1, 0, Fr::ZERO),
        (1, 1, Fr::from(3)),
        (2, 0, Fr::from(1)),
    ]; // 1 + 3xy + x^2

    let result_monomials = subtract_polys_monomials(&f_monomials, &g_monomials);

    let result_monomials_expected = vec![
        (0, 0, Fr::ZERO),
        (0, 1, Fr::from(2)),
        (0, 2, Fr::ZERO),
        (1, 0, Fr::from(1)),
        (1, 1, Fr::from(-3)),
        (2, 0, Fr::from(-1)),
    ]; // 2y + x - 3xy - x^2

    assert_eq!(result_monomials, result_monomials_expected);
}

#[test]
fn test_subtract_value_from_poly() {
    let f_monomials = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::from(2)),
        (1, 0, Fr::from(1)),
    ]; // 1 + 2y + x

    let result_monomials = subtract_value_from_poly_monomials(&f_monomials, Fr::from(-2));

    let result_monomials_expected = vec![
        (0, 0, Fr::from(3)),
        (0, 1, Fr::from(2)),
        (1, 0, Fr::from(1)),
    ]; // 3 + 2y + x

    assert_eq!(result_monomials, result_monomials_expected);
}

#[test]
fn test_multiply_polys_monomials() {
    let f_monomials = vec![(0, 0, Fr::from(1)), (0, 1, Fr::ZERO), (1, 0, Fr::from(1))]; // 1 + x

    let g_monomials = vec![(0, 0, Fr::from(1)), (0, 1, Fr::from(2)), (1, 0, Fr::ZERO)]; // 1 + 2y

    let result_monomials = multiply_bivariate_polys_monomials(&f_monomials, &g_monomials);

    let result_monomials_expected = vec![
        (0, 0, Fr::from(1)),
        (0, 1, Fr::from(2)),
        (0, 2, Fr::ZERO),
        (1, 0, Fr::from(1)),
        (1, 1, Fr::from(2)),
        (2, 0, Fr::ZERO),
    ]; // 1 + 2y + x + 2xy

    assert_eq!(result_monomials, result_monomials_expected);
}

#[test]
fn test_divide_by_linear_in_x_degree_2() {
    let u1 = Fr::from(2);
    let u2 = Fr::from(3);

    // Dynamically define f(x, y) = Σ c_{i,j} * x^i * y^j for i + j <= 2
    let mut coeff_counter = 1u64;
    let mut f_monomials: BivariateMonomialList = Vec::new();
    for i in 0..=2 {
        for j in 0..=2 {
            if i + j <= 2 {
                f_monomials.push((i, j, Fr::from(coeff_counter)));
                coeff_counter += 1;
            }
        }
    }
    let f = monomial_list_to_sparsepoly(&f_monomials);

    // Compute evaluation v = f(u1, u2)
    let v = f.evaluate(&vec![u1, u2]);

    // Compute g = f - v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, v);

    // Compute q1
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);

    let x_minus_u1 = vec![(0, 0, -u1), (0, 1, Fr::ZERO), (1, 0, Fr::ONE)];

    let left = multiply_bivariate_polys_monomials(&x_minus_u1, &q1_monomials);
    let reconstruction = add_polys_monomials(&left, &r_monomials);

    assert_eq!(
        reconstruction, g_monomials,
        "Reconstructed polynomial should match the original g(x,y)"
    );
}

#[test]
fn test_divide_by_linear_in_x_degree_10() {
    let u1 = Fr::from(5);
    let u2 = Fr::from(7);

    // Generate f(x, y) = Σ c_{i,j} * x^i * y^j for i + j <= 10
    let mut coeff_counter = 1u64;
    let mut f_monomials: BivariateMonomialList = Vec::new();
    for i in 0..=10 {
        for j in 0..=10 - i {
            f_monomials.push((i, j, Fr::from(coeff_counter)));
            coeff_counter += 1;
        }
    }
    let f = monomial_list_to_sparsepoly(&f_monomials);

    // Compute evaluation v = f(u1, u2)
    let v = f.evaluate(&vec![u1, u2]);

    // Compute g = f - v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, v);

    // Compute q1
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);

    // Reconstruct: q(x, y)*(x - u1) + r(x, y)
    let x_minus_u1 = vec![(0, 0, -u1), (0, 1, Fr::ZERO), (1, 0, Fr::ONE)];

    let left = multiply_bivariate_polys_monomials(&x_minus_u1, &q1_monomials);
    let reconstruction = add_polys_monomials(&left, &r_monomials);

    assert_eq!(
        reconstruction, g_monomials,
        "Reconstructed polynomial should match g(x,y)"
    );
}

#[test]
fn test_divide_by_linear_in_y_degree_2() {
    let u1 = Fr::from(2);
    let u2 = Fr::from(3);

    // Dynamically define f(x, y) = Σ c_{i,j} * x^i * y^j for i + j <= 2
    let mut coeff_counter = 1u64;
    let mut f_monomials: BivariateMonomialList = Vec::new();
    for i in 0..=2 {
        for j in 0..=2 {
            if i + j <= 2 {
                f_monomials.push((i, j, Fr::from(coeff_counter)));
                coeff_counter += 1;
            }
        }
    }
    let f = monomial_list_to_sparsepoly(&f_monomials);

    // Compute evaluation v = f(u1, u2)
    let v = f.evaluate(&vec![u1, u2]);

    // Compute g = f - v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, v);

    // Compute q1
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);
    // Compute q2
    let q2_monomials = divide_by_linear_in_y(&r_monomials, u2);

    let x_minus_u1 = vec![(0, 0, -u1), (0, 1, Fr::ZERO), (1, 0, Fr::ONE)];

    let y_minus_u2 = vec![(0, 0, -u2), (0, 1, Fr::ONE), (1, 0, Fr::ZERO)];

    let left = multiply_bivariate_polys_monomials(&x_minus_u1, &q1_monomials);
    let right = multiply_bivariate_polys_monomials(&y_minus_u2, &q2_monomials);
    let reconstruction = add_polys_monomials(&left, &right);

    assert_eq!(
        reconstruction, g_monomials,
        "Reconstructed polynomial should match the original g(x,y)"
    );
}

#[test]
fn test_divide_by_linear_in_y_degree_10() {
    let u1 = Fr::from(5);
    let u2 = Fr::from(7);

    // Generate f(x, y) = Σ c_{i,j} * x^i * y^j for i + j <= 10
    let mut coeff_counter = 1u64;
    let mut f_monomials: BivariateMonomialList = Vec::new();
    for i in 0..=10 {
        for j in 0..=10 - i {
            f_monomials.push((i, j, Fr::from(coeff_counter)));
            coeff_counter += 1;
        }
    }
    let f = monomial_list_to_sparsepoly(&f_monomials);

    // Compute evaluation v = f(u1, u2)
    let v = f.evaluate(&vec![u1, u2]);

    // Compute g = f - v
    let g_monomials = subtract_value_from_poly_monomials(&f_monomials, v);

    // Compute q1
    let (q1_monomials, r_monomials) = divide_by_linear_in_x(&g_monomials, u1);
    // Compute q2
    let q2_monomials = divide_by_linear_in_y(&r_monomials, u2);

    let x_minus_u1 = vec![(0, 0, -u1), (0, 1, Fr::ZERO), (1, 0, Fr::ONE)];

    let y_minus_u2 = vec![(0, 0, -u2), (0, 1, Fr::ONE), (1, 0, Fr::ZERO)];

    let left = multiply_bivariate_polys_monomials(&x_minus_u1, &q1_monomials);
    let right = multiply_bivariate_polys_monomials(&y_minus_u2, &q2_monomials);
    let reconstruction = add_polys_monomials(&left, &right);

    assert_eq!(
        reconstruction, g_monomials,
        "Reconstructed polynomial should match the original g(x,y)"
    );
}

#[test]
fn test_rand_bivariate_poly_degree() {
    let mut rng = ark_std::test_rng();
    for i in 0..100 {
        assert_eq!(
            random_bivariate_polynomial(&mut rng, i).0.degree(),
            i,
            "degree is wrong"
        );
    }
}

#[test]
fn test_add_polys() {
    let num_vars = 2;

    let terms = vec![
        (Fr::from(3), <SparseTerm as Term>::new(vec![(0, 2), (1, 1)])), // 3 * x^2 * y
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 1), (1, 2)])), // 2 * x * y^2
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 1)])), // y
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 1
    ];
    let poly1 = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    let terms = vec![
        (Fr::from(4), <SparseTerm as Term>::new(vec![(0, 2), (1, 1)])), // 4 * x^2 * y
        (Fr::from(5), <SparseTerm as Term>::new(vec![(0, 1), (1, 1)])), // 5 * x * y
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 1), (1, 0)])), // 2 * x
        (Fr::from(3), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 3
    ];
    let poly2 = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    let poly3 = &poly1 + &poly2;

    let terms = vec![
        (Fr::from(7), <SparseTerm as Term>::new(vec![(0, 2), (1, 1)])), // 7 * x^2 * y
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 1), (1, 2)])), // 2 * x * y^2
        (Fr::from(5), <SparseTerm as Term>::new(vec![(0, 1), (1, 1)])), // 5 * x * y
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 1)])), // y
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 1), (1, 0)])), // 2 * x
        (Fr::from(4), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 4
    ];
    let poly3_expected = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    assert_eq!(poly3, poly3_expected);
}

#[test]
fn test_mul_polys() {
    let num_vars = 2;

    let terms = vec![
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 1), (1, 1)])), // 2 * x * y
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 1), (1, 0)])), // x
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 1
    ];
    let poly1 = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    let terms = vec![
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 1), (1, 1)])), // x * y
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 1
    ];
    let poly2 = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    let poly3 = multiply_bivariate_polynomials(&poly1, &poly2);

    let terms = vec![
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 2), (1, 2)])), // 2 * x^2 * y^2
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 2), (1, 1)])), // 1 * x^2 * y
        (Fr::from(3), <SparseTerm as Term>::new(vec![(0, 1), (1, 1)])), // 3 * x * y
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 1), (1, 0)])), // x
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 1
    ];
    let poly3_expected = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    assert_eq!(poly3, poly3_expected);
}

#[test]
fn test_eval_poly() {
    let num_vars = 2;

    let terms = vec![
        (Fr::from(3), <SparseTerm as Term>::new(vec![(0, 0), (1, 1)])), // 3 * y
        (Fr::from(2), <SparseTerm as Term>::new(vec![(0, 1), (1, 0)])), // 2 * x
        (Fr::from(1), <SparseTerm as Term>::new(vec![(0, 0), (1, 0)])), // 1
    ];
    let poly1 = SparsePolynomial::from_coefficients_vec(num_vars, terms);

    assert_eq!(poly1.evaluate(&vec![Fr::from(1), Fr::from(2)]), Fr::from(9));
}
