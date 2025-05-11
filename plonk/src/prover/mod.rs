pub mod part1;
pub mod part2;

use std::time::Instant;

pub fn run() -> () {
    println!("Executing prover...");
    let start = Instant::now();

    let (number_public_inputs, d, Omega, T) = part1::run();
    println!("✅ Part1 took: {:?}", start.elapsed());
    let start = Instant::now();

    part2::run(number_public_inputs, d, &Omega, &T);
    println!("✅ Part2 took: {:?}", start.elapsed());
}
