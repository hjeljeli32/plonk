pub mod part1;
pub mod part2;

use std::time::Instant;

use crate::setup::SetupOutput;

pub fn run(setup: &SetupOutput) -> () {
    println!("Executing prover...");
    let start = Instant::now();

    let (Omega, T) = part1::run(&setup);
    println!("✅ Part1 took: {:?}", start.elapsed());
    let start = Instant::now();

    part2::run(&setup, &Omega, &T);
    println!("✅ Part2 took: {:?}", start.elapsed());
}
