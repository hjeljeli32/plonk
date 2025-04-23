use ark_bls12_381::Fr;
use ark_poly::{multivariate::{SparsePolynomial, SparseTerm, Term}, DenseMVPolynomial, Polynomial};
use plonk::common::bivariate_polynomials::*;

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

    let poly3 = multiply_sparse_polynomials(&poly1, &poly2);

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