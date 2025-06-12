use ark_bls12_381::{Fr, G1Projective as G1};
use ark_poly::univariate::DensePolynomial;

use crate::{common::kzg::kzg_evaluate, setup_global_params::SetupGlobalParamsOutput};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    Omega: &Vec<Fr>,
    T: &DensePolynomial<Fr>,
    output: Fr,
) -> G1 {
    println!("Executing part 5: proving the output of the last gate");

    // Extract global parameters
    let gp = &setup.gp;

    // Extract number of gates
    let number_gates = setup.number_gates;

    // Call KZG eval on gp, T, Omega[3 * number_gates - 1]
    let (v, proof_last_gate_KZG) = kzg_evaluate(&gp, T, Omega[3 * number_gates - 1]);

    // Check that evaluation matches with output
    assert_eq!(v, output, "Evaluation does not matche with output");

    proof_last_gate_KZG
}
