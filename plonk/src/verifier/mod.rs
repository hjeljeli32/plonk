pub mod part1;
pub mod part2;

use std::time::Instant;

use crate::{
    common::proof::Proof, setup_global_params::SetupGlobalParamsOutput,
    setup_verification_key::SetupVerificationKeyOutput,
};

pub fn run(
    setup: &SetupGlobalParamsOutput,
    verification_key: &SetupVerificationKeyOutput,
    proof: &Proof,
) -> () {
    let start = Instant::now();

    let _ = part1::run(setup, proof);
    println!("✅ Part1 took: {:?}", start.elapsed());

    let start = Instant::now();

    let _ = part2::run(setup, verification_key, proof);
    println!("✅ Part2 took: {:?}", start.elapsed());
}
