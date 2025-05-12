use plonk::{common::proof::{Proof, ProofJson}, verifier};
use std::error::Error;


fn main() -> Result<(), Box<dyn Error>> {
    println!("Running verifier...");

    let json_str = std::fs::read_to_string("data/proof.json")?;
    let proof_json: ProofJson = serde_json::from_str(&json_str)?;
    let proof: Proof = Proof::from(&proof_json);
    println!("✅ Loaded proof from data/proof.json");

    let _ = verifier::run(&proof);

    Ok(())
}
