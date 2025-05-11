use plonk::prover;
use plonk::setup::SetupOutput;
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

    let setup = setup_json.into_setup_output();

    println!("✅ Loaded setup parameters from srs.json");
    println!("\tNumber of gates: {}", setup.number_gates);
    println!("\tNumber of public inputs: {}", setup.number_public_inputs);
    println!("\tNumber of witnesses: {}", setup.number_witnesses);
    println!("\td: {}", setup.d);    
    println!("\tLength of tau_powers_g1: {}", setup.gp.tau_powers_g1.len());

    prover::run(&setup);

    Ok(())
}
