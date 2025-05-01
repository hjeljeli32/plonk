use ark_bls12_381::Fr;
use ark_ff::{AdditiveGroup, Field, UniformRand};
use ark_poly::{
    DenseMVPolynomial,
    multivariate::{SparsePolynomial, SparseTerm, Term},
};
use ark_std::Zero;
use ark_std::rand::Rng;
use std::collections::HashMap;

/// A monomial term as (i, j) -> X^i * Y^j
pub type BivariateMonomial = (usize, usize);
/// A bivariate polynomial in sparse format
pub type BivariateMonomialList = Vec<(usize, usize, Fr)>;

/// Converts (i, j, coeff) to SparsePolynomial
pub fn monomial_list_to_sparsepoly(
    monomials: &BivariateMonomialList,
) -> SparsePolynomial<Fr, SparseTerm> {
    let terms: Vec<_> = monomials
        .iter()
        .map(|(i, j, c)| (*c, SparseTerm::new(vec![(0, *i), (1, *j)])))
        .collect();
    SparsePolynomial::from_coefficients_vec(2, terms)
}

/// Add poly2 to poly1, and return result sorted by x then y, including zero monomials in the full total degree support
pub fn add_polys_monomials(
    poly1: &BivariateMonomialList,
    poly2: &BivariateMonomialList,
) -> BivariateMonomialList {
    let mut map: HashMap<(usize, usize), Fr> = HashMap::new();
    let mut max_total_deg = 0;

    for &(i, j, c) in poly1.iter() {
        map.entry((i, j)).and_modify(|e| *e += c).or_insert(c);
        max_total_deg = max_total_deg.max(i + j);
    }
    for &(i, j, c) in poly2.iter() {
        map.entry((i, j)).and_modify(|e| *e += c).or_insert(c);
        max_total_deg = max_total_deg.max(i + j);
    }

    for i in 0..=max_total_deg {
        for j in 0..=max_total_deg {
            if i + j <= max_total_deg {
                map.entry((i, j)).or_insert(Fr::ZERO);
            }
        }
    }

    let mut result: BivariateMonomialList = map.into_iter().map(|((i, j), c)| (i, j, c)).collect();

    result.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1))); // sort by x then y
    result
}

/// Subtract poly2 from poly1, and return result sorted by x then y, including zero monomials in the full total degree support
pub fn subtract_polys_monomials(
    poly1: &BivariateMonomialList,
    poly2: &BivariateMonomialList,
) -> BivariateMonomialList {
    let mut map: HashMap<(usize, usize), Fr> = HashMap::new();
    let mut max_total_deg = 0;

    for &(i, j, c) in poly1.iter() {
        map.entry((i, j)).and_modify(|e| *e += c).or_insert(c);
        max_total_deg = max_total_deg.max(i + j);
    }
    for &(i, j, c) in poly2.iter() {
        map.entry((i, j)).and_modify(|e| *e -= c).or_insert(-c);
        max_total_deg = max_total_deg.max(i + j);
    }

    for i in 0..=max_total_deg {
        for j in 0..=max_total_deg {
            if i + j <= max_total_deg {
                map.entry((i, j)).or_insert(Fr::ZERO);
            }
        }
    }

    let mut result: BivariateMonomialList = map.into_iter().map(|((i, j), c)| (i, j, c)).collect();

    result.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1))); // sort by x then y
    result
}

/// Subtract a given value v from the constant term in f.
/// Return the new list of monomials for f - v
pub fn subtract_value_from_poly_monomials(
    f_monomials: &BivariateMonomialList,
    v: Fr,
) -> BivariateMonomialList {
    let mut new_monomials = f_monomials.clone();

    let found = new_monomials
        .iter_mut()
        .find(|(i, j, _)| *i == 0 && *j == 0);

    if let Some((_, _, coeff)) = found {
        *coeff -= v;
    } else {
        new_monomials.push((0, 0, -v));
    }

    new_monomials.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    new_monomials
}

/// Multiply two bivariate polynomials and return the result, padded and sorted by (i,j)
pub fn multiply_bivariate_polys_monomials(
    poly1: &BivariateMonomialList,
    poly2: &BivariateMonomialList,
) -> BivariateMonomialList {
    let mut result_map = HashMap::new();

    // Multiply every monomial of poly1 with every monomial of poly2
    for &(i1, j1, c1) in poly1 {
        for &(i2, j2, c2) in poly2 {
            let i = i1 + i2;
            let j = j1 + j2;
            let coeff = c1 * c2;
            result_map
                .entry((i, j))
                .and_modify(|e: &mut Fr| *e += coeff)
                .or_insert(coeff);
        }
    }

    // Find maximum total degree for padding
    let mut max_total_deg = 0;
    for &(i, j) in result_map.keys() {
        max_total_deg = max_total_deg.max(i + j);
    }

    // Ensure padding (i,j) up to max_total_deg
    for i in 0..=max_total_deg {
        for j in 0..=max_total_deg {
            if i + j <= max_total_deg {
                result_map.entry((i, j)).or_insert(Fr::ZERO);
            }
        }
    }

    // Convert map to sorted list
    let mut result: BivariateMonomialList = result_map
        .into_iter()
        .map(|((i, j), c)| (i, j, c))
        .collect();

    result.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    result
}

/// Evaluate a bivariate polynomial at (u1, u2)
pub fn evaluate_bivariate(poly: &BivariateMonomialList, u1: Fr, u2: Fr) -> Fr {
    let mut result = Fr::ZERO;
    for &(i, j, coeff) in poly {
        let term = coeff * u1.pow([i as u64]) * u2.pow([j as u64]);
        result += term;
    }
    result
}

/// Divide a bivariate polynomial `g(x, y)` by the linear factor `(x - u1)`.
pub fn divide_by_linear_in_x(
    g_monomials: &BivariateMonomialList,
    u1: Fr,
) -> (BivariateMonomialList, BivariateMonomialList) {
    use std::collections::HashMap;

    let mut dividend: HashMap<(usize, usize), Fr> = g_monomials
        .iter()
        .map(|&(i, j, coeff)| ((i, j), coeff))
        .collect();

    let mut q1 = HashMap::new();

    // Division loop
    while let Some((&(i, j), &coeff)) = dividend
        .iter()
        .filter(|((i, _), c)| *i > 0 && !c.is_zero())
        .max_by_key(|((i, j), _)| (*i, *j))
    {
        let new_key = (i - 1, j);
        q1.insert(new_key, coeff);

        dividend.remove(&(i, j));
        *dividend.entry((i - 1, j)).or_insert(Fr::ZERO) += coeff * u1;
    }

    let mut q1_monomials: BivariateMonomialList =
        q1.into_iter().map(|((i, j), c)| (i, j, c)).collect();

    // Build padded remainder
    let mut r_map: HashMap<(usize, usize), Fr> = dividend;

    // Compute total degree d = max(i + j) in original g
    let max_total_deg = g_monomials
        .iter()
        .map(|&(i, j, _)| i + j)
        .max()
        .unwrap_or(0);

    // Pad all (i, j) such that i + j <= d, even if i > 0
    for i in 0..=max_total_deg {
        for j in 0..=max_total_deg - i {
            r_map.entry((i, j)).or_insert(Fr::ZERO);
        }
    }

    let mut r_monomials: BivariateMonomialList =
        r_map.into_iter().map(|((i, j), c)| (i, j, c)).collect();

    // Sort output
    q1_monomials.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    r_monomials.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));

    (q1_monomials, r_monomials)
}

/// Divide a bivariate polynomial `g(x, y)` by the linear factor `(y - u2)`.
pub fn divide_by_linear_in_y(g_monomials: &BivariateMonomialList, u2: Fr) -> BivariateMonomialList {
    use std::collections::HashMap;

    let mut dividend: HashMap<(usize, usize), Fr> = g_monomials
        .iter()
        .map(|&(i, j, coeff)| ((i, j), coeff))
        .collect();

    let mut q2 = HashMap::new();

    while let Some((&(i, j), &coeff)) = dividend
        .iter()
        .filter(|((_, j), c)| *j > 0 && !c.is_zero())
        .max_by_key(|((i, j), _)| (*j, *i))
    // Highest degree in y first
    {
        let new_key = (i, j - 1);
        q2.insert(new_key, coeff);

        dividend.remove(&(i, j));
        *dividend.entry((i, j - 1)).or_insert(Fr::ZERO) += coeff * u2;
    }

    // Determine total degree of g(x, y)
    let max_total_deg = g_monomials
        .iter()
        .map(|&(i, j, _)| i + j)
        .max()
        .unwrap_or(0);

    // Pad q2 with all monomials (i, j) such that i + j <= max_total_deg - 1
    // because degree(q2) = degree(g) - 1
    for i in 0..=max_total_deg {
        for j in 0..=max_total_deg - i {
            if i + j <= max_total_deg - 1 {
                q2.entry((i, j)).or_insert(Fr::ZERO);
            }
        }
    }

    let mut q2_monomials: BivariateMonomialList =
        q2.into_iter().map(|((i, j), c)| (i, j, c)).collect();

    q2_monomials.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
    q2_monomials
}

/// Generate a random bivariate polynomial of certain degree
pub fn random_bivariate_polynomial(
    rng: &mut impl Rng,
    degree: usize,
) -> (SparsePolynomial<Fr, SparseTerm>, BivariateMonomialList) {
    let mut terms = Vec::new();
    let mut monomials = Vec::new();

    for i in 0..=degree {
        for j in 0..=degree {
            if i + j <= degree {
                let coeff = Fr::rand(rng);
                let term = SparseTerm::new(vec![(0, i), (1, j)]);
                terms.push((coeff, term));
                monomials.push((i, j, coeff));
            }
        }
    }

    let poly = SparsePolynomial::from_coefficients_vec(2, terms);
    (poly, monomials)
}

// Multiplies 2 bivariate polynomials
pub fn multiply_bivariate_polynomials(
    poly1: &SparsePolynomial<Fr, SparseTerm>,
    poly2: &SparsePolynomial<Fr, SparseTerm>,
) -> SparsePolynomial<Fr, SparseTerm> {
    let num_vars = poly1.num_vars;
    let mut term_map: HashMap<SparseTerm, Fr> = HashMap::new();

    for (coeff1, term1) in &poly1.terms {
        for (coeff2, term2) in &poly2.terms {
            let new_coeff = *coeff1 * *coeff2;
            let mut combined_exponents = term1.iter().cloned().collect::<HashMap<usize, usize>>();
            for (var, exp) in term2.iter() {
                *combined_exponents.entry(*var).or_insert(0) += *exp;
            }
            let new_term = SparseTerm::new(combined_exponents.into_iter().collect());
            term_map
                .entry(new_term)
                .and_modify(|c| *c += new_coeff)
                .or_insert(new_coeff);
        }
    }

    // Remove zero coefficients
    let terms = term_map
        .into_iter()
        .map(|(term, coeff)| (coeff, term))
        .collect();

    SparsePolynomial::from_coefficients_vec(num_vars, terms)
}
