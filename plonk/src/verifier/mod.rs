pub mod part1;

use std::time::Instant;

use crate::{common::proof::Proof, setup_global_params::SetupGlobalParamsOutput};

pub fn run(setup: &SetupGlobalParamsOutput, proof: &Proof) -> () {
    let start = Instant::now();

    let _ = part1::run(&setup, &proof);
    println!("✅ Part1 took: {:?}", start.elapsed());

    // let start = Instant::now();

    // let _ = part2::run(&setup, &proof);
    // println!("✅ Part2 took: {:?}", start.elapsed());
}
