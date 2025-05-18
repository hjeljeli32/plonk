use plonk::prover;
use plonk::setup_global_params::json::SetupGlobalParamsOutputJson;
use plonk::setup_proving_key::json::SetupProvingKeyOutputJson;
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

    // Open and read proving_key.json
    let file = File::open("data/proving_key.json")?;
    let reader = BufReader::new(file);
    let proving_key_json: SetupProvingKeyOutputJson = serde_json::from_reader(reader)?;
    let proving_key = proving_key_json.into_setup_output();
    println!("✅ Loaded proving key from proving_key.json");

    prover::run(&setup, &proving_key);

    Ok(())
}
