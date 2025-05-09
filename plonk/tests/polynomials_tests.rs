use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, BigInteger, BigInteger256, FftField, Field, PrimeField};
use ark_poly::polynomial::univariate::*;
use ark_poly::{DenseUVPolynomial, Polynomial};
use ark_std::{UniformRand, rand::Rng, test_rng};
use plonk::common::polynomials::*;
use std::collections::HashSet;

#[test]
fn test_rand_poly_degree() {
    let mut rng = ark_std::test_rng();
    for i in 0..100 {
        assert_eq!(
            random_polynomial(&mut rng, i).degree(),
            i,
            "degree is wrong"
        );
    }
}

#[test]
fn test_add_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::from(2), Fr::from(3)],
    }; // 1 + 2*x + 3*x^2
    let poly2 = DensePolynomial {
        coeffs: vec![Fr::from(4), Fr::from(5), Fr::from(6)],
    }; // 4 + 5*x + 6*x^2
    let poly3 = &poly1 + &poly2;
    assert_eq!(poly3.coeffs, vec![Fr::from(5), Fr::from(7), Fr::from(9)]); // 5 + 7x + 9*x^2
}

#[test]
fn test_mul_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::ONE],
    }; // 1 + x
    let poly2 = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::ONE],
    }; // 1 + x
    let poly3 = &poly1 * &poly2;
    assert_eq!(poly3.coeffs, vec![Fr::ONE, Fr::from(2), Fr::ONE]); // 1 + 2x + x^2
}

#[test]
fn test_div_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![Fr::from(-1), Fr::ZERO, Fr::ONE],
    }; // -1 + x^2
    let poly2 = DensePolynomial {
        coeffs: vec![Fr::from(-1), Fr::ONE],
    }; // -1 + x
    let poly3 = &poly1 / &poly2;
    assert_eq!(poly3.coeffs, vec![Fr::ONE, Fr::ONE]); // 1 + x
}

#[test]
fn test_divide_with_q_r_polys() {
    let poly1 = DensePolynomial {
        coeffs: vec![
            Fr::from(4),
            Fr::from(-5),
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ZERO,
            Fr::ONE,
        ],
    }; // 4 - 5x + x^9
    let poly2 = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::ZERO, Fr::ONE],
    }; // 1 + x^2
    let (q, r) =
        DenseOrSparsePolynomial::divide_with_q_and_r(&(&poly1).into(), &(&poly2).into()).unwrap();
    assert_eq!(
        q.coeffs,
        vec![
            Fr::ZERO,
            Fr::from(-1),
            Fr::ZERO,
            Fr::ONE,
            Fr::ZERO,
            Fr::from(-1),
            Fr::ZERO,
            Fr::ONE
        ]
    ); // -x + x^3 - x^5 + x^7
    assert_eq!(r.coeffs, vec![Fr::from(4), Fr::from(-4)]); // 4 - 4x
}

#[test]
fn test_divide_with_q_r_rand_polys() {
    let rng = &mut test_rng();
    for _ in 0..20 {
        let degree_a = rng.gen_range(0..=50);
        let degree_b = rng.gen_range(0..=50);
        let a = DensePolynomial::<Fr>::rand(degree_a, rng);
        let b = DensePolynomial::<Fr>::rand(degree_b, rng);
        let (q, r) =
            DenseOrSparsePolynomial::divide_with_q_and_r(&(&a).into(), &(&b).into()).unwrap();
        let d = &r + &q * &b;
        let degree_r = r.degree();
        assert!(
            degree_r < degree_b || (degree_r == 0 && degree_b == 0),
            "Polynomial r must have a smaller degree than polynomial b (r: {}, b: {})",
            degree_r,
            degree_b
        );
        assert_eq!(
            d, a,
            "Polynomial d: {:?} must be equal to a: {:?}",
            d.coeffs, a.coeffs
        )
    }
}

#[test]
fn test_prod_polys() {
    // define g as element of order 1024
    let mut exponent = Fr::MODULUS;
    exponent.sub_with_borrow(&BigInteger256::from(1_u64));
    exponent >>= 10; // divide exponent by 1024
    let g = Fr::GENERATOR.pow(exponent.0.to_vec());

    let mut coefficients = vec![Fr::from(-1)];
    coefficients.extend(vec![Fr::ZERO; 1023]);
    coefficients.push(Fr::ONE);
    let expected_product = DensePolynomial {
        coeffs: coefficients,
    }; // -1 + x^1024

    let mut product = DensePolynomial {
        coeffs: vec![Fr::ONE],
    }; // start product with polynomial 1
    for i in 0..1024 {
        let gi = g.pow(&[i]); // g^i, exponentiation with a scalar field
        let term = DensePolynomial {
            coeffs: vec![-gi, Fr::ONE],
        }; // (X - g^i) as (1, -gi)
        product = product * term; // Multiply with the accumulated product
    }
    assert_eq!(
        product, expected_product,
        "Polynomial product: {:?} must be equal to expected_product: {:?}",
        product.coeffs, expected_product.coeffs
    )
}

#[test]
fn test_eval_poly() {
    let poly = DensePolynomial {
        coeffs: vec![Fr::ZERO, Fr::ONE, Fr::ONE],
    }; // x + x^2
    assert_eq!(poly.evaluate(&Fr::from(5)), Fr::from(30));
}

#[test]
fn test_poly_interpolation() {
    let x_vals = vec![Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)];
    let y_vals = vec![
        Fr::from(0u64), // f(0)
        Fr::from(1u64), // f(1)
        Fr::from(8u64), // f(2)
    ];
    let poly = interpolate_polynomial(&x_vals, &y_vals);
    let expected_poly = DensePolynomial {
        coeffs: vec![Fr::ZERO, Fr::from(-2), Fr::from(3)],
    }; // -2x + 3x^2
    assert_eq!(
        poly, expected_poly,
        "Interpolated poly: {:?} must be equal to expected_poly: {:?}",
        poly.coeffs, expected_poly.coeffs
    );
}

#[test]
fn test_rand_poly_interpolation() {
    let rng = &mut test_rng();
    for _ in 0..10 {
        let degree = rng.gen_range(0..=100);
        let poly = DensePolynomial::<Fr>::rand(degree, rng);
        let mut x_vals: HashSet<Fr> = HashSet::new();
        while x_vals.len() < degree + 1 {
            x_vals.insert(Fr::rand(rng));
        }
        let x_vals: Vec<Fr> = x_vals.into_iter().collect();
        let y_vals: Vec<Fr> = x_vals.iter().map(|x| poly.evaluate(x)).collect();
        let interpolated_poly = interpolate_polynomial(&x_vals, &y_vals);
        assert_eq!(
            interpolated_poly, poly,
            "Interpolated poly: {:?} must be equal to poly: {:?}",
            interpolated_poly.coeffs, poly.coeffs
        );
    }
}

#[test]
fn test_pow_poly() {
    let f = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::ONE],
    }; // 1 + x
    let f_pow_2 = pow(&f, 2);
    let f_pow_3 = pow(&f, 3);
    let f_pow_2_expected = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::from(2), Fr::ONE],
    }; // 1 + 2x + x^2
    let f_pow_3_expected = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::from(3), Fr::from(3), Fr::ONE],
    }; // 1 + 3x + 3x^2 + x^3
    assert_eq!(f_pow_2, f_pow_2_expected);
    assert_eq!(f_pow_3, f_pow_3_expected);
}

#[test]
fn test_compose_polys() {
    let f = DensePolynomial {
        coeffs: vec![Fr::ZERO, Fr::ONE, Fr::ONE],
    }; // x + x^2
    let g = DensePolynomial {
        coeffs: vec![Fr::ONE, Fr::ONE],
    }; // 1 + x
    let f_g = compose_polynomials(&f, &g);
    let f_g_expected = DensePolynomial {
        coeffs: vec![Fr::from(2), Fr::from(3), Fr::ONE],
    }; // 2 + 3x + x^2
    assert_eq!(
        f_g, f_g_expected,
        "Composed poly: {:?} must be equal to poly: {:?}",
        f_g.coeffs, f_g_expected.coeffs
    );
}
