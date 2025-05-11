use plonk::prover;
use plonk::setup::json::SetupOutputJson;
use std::fs::File;
use std::io::BufReader;
use serde_json;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Running prover...");

    // Open and read srs.json
    let file = File::open("data/srs.json")?;
    let reader = BufReader::new(file);
    let setup_json: SetupOutputJson = serde_json::from_reader(reader)?;

    println!("✅ Loaded setup parameters from srs.json");
    println!("\tNumber of gates: {}", setup_json.number_gates);
    println!("\tNumber of public inputs: {}", setup_json.number_public_inputs);
    println!("\tNumber of witnesses: {}", setup_json.number_witnesses);
    println!("\td: {}", setup_json.d);    

    prover::run();

    Ok(())
}
