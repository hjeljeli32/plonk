pub mod part1;
pub mod part2;
pub mod part3;

use std::time::Instant;

use crate::{
    setup_global_params::SetupGlobalParamsOutput, setup_proving_key::SetupProvingKeyOutput,
};

pub fn run(setup: &SetupGlobalParamsOutput, proving_key: &SetupProvingKeyOutput) -> () {
    let start = Instant::now();

    let (Omega, T, com_T) = part1::run(&setup);
    println!("✅ Part1 took: {:?}", start.elapsed());

    let start = Instant::now();

    let _ = part2::run(&setup, &Omega, &T, com_T).unwrap();
    println!("✅ Part2 took: {:?}", start.elapsed());

    let start = Instant::now();

    let _ = part3::run(&setup, &proving_key, &Omega, &T).unwrap();
    println!("✅ Part3 took: {:?}", start.elapsed());
}
