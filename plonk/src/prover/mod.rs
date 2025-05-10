pub mod part1;

use std::time::Instant;

pub fn run() -> () {
    println!("Executing prover...");
    let start = Instant::now();

    part1::run();
    println!("✅ Part1 took: {:?}", start.elapsed());
}
