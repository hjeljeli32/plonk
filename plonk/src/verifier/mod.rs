use std::time::Instant;

pub fn run() -> () {
    println!("Executing prover...");
    let start = Instant::now();

    println!("✅ Verifier took: {:?}", start.elapsed());
}
