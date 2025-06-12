pub mod part1;
pub mod part2;
pub mod part3;
pub mod part4;

use std::time::Instant;

use crate::{
    common::{proof::Proof, utils::construct_Omega}, setup_global_params::SetupGlobalParamsOutput,
    setup_verification_key::SetupVerificationKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    verification_key: &SetupVerificationKeyOutput,
    proof: &Proof,
) -> () {
    let start = Instant::now();

    // Define Omega as subgroup of size d
    let d = setup.d;
    let Omega = construct_Omega(d);
    assert_eq!(Omega.len(), d, "Omega must be of length d");

    part1::run(setup, proof, &Omega);
    println!("✅ Part1 took: {:?}", start.elapsed());

    let start = Instant::now();

    part2::run(setup, verification_key, proof, &Omega);
    println!("✅ Part2 took: {:?}", start.elapsed());

    let start = Instant::now();

    part3::run(setup, verification_key, proof, &Omega);
    println!("✅ Part3 took: {:?}", start.elapsed());

    let start = Instant::now();

    part4::run(setup, proof, &Omega);
    println!("✅ Part4 took: {:?}", start.elapsed());
}
