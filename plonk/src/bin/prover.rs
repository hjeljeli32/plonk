use plonk::prover;
use plonk::setup_global_params::json::SetupGlobalParamsOutputJson;
use serde_json;
use std::error::Error;
use std::fs::File;
use std::io::BufReader;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Running prover...");

    // Open and read srs.json
    let file = File::open("data/srs.json")?;
    let reader = BufReader::new(file);
    let setup_json: SetupGlobalParamsOutputJson = serde_json::from_reader(reader)?;
    let setup = setup_json.into_setup_output();
    println!("✅ Loaded setup parameters from srs.json");
    println!("\t Number of gates: {}", setup.number_gates);
    println!("\t Number of public inputs: {}", setup.number_public_inputs);
    println!("\t Number of witnesses: {}", setup.number_witnesses);
    println!("\t d: {}", setup.d);
    println!(
        "\t Length of tau_powers_g1: {}",
        setup.gp.tau_powers_g1.len()
    );

    prover::run(&setup);

    Ok(())
}
