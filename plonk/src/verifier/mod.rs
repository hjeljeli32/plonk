use std::time::Instant;

use crate::common::proof::Proof;

pub fn run(proof: &Proof) -> Result<(), Box<dyn std::error::Error>> {
    println!("Executing verifier...");
    let start = Instant::now();

    println!("✅ Verifier took: {:?}", start.elapsed());

    Ok(())
}
