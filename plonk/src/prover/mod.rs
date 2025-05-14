pub mod part1;
pub mod part2;

use std::time::Instant;

use crate::setup::SetupOutput;

pub fn run(setup: &SetupOutput) -> () {
    let start = Instant::now();

    let (Omega, T, com_T) = part1::run(&setup);
    println!("✅ Part1 took: {:?}", start.elapsed());
    let start = Instant::now();

    let _ = part2::run(&setup, &Omega, &T, com_T).unwrap();
    println!("✅ Part2 took: {:?}", start.elapsed());
}
