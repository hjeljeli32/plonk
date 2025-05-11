use std::time::Instant;

pub fn run() -> () {
    println!("Executing verifier...");
    let start = Instant::now();

    println!("✅ Verifier took: {:?}", start.elapsed());
}
