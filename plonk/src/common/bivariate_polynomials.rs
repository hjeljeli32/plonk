use std::collections::HashMap;
use ark_bls12_381::Fr;
use ark_poly::{multivariate::{SparsePolynomial, SparseTerm, Term}, DenseMVPolynomial};

pub fn multiply_sparse_polynomials(
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