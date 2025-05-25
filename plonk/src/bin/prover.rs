use plonk::prover;
use plonk::setup_global_params::json::SetupGlobalParamsOutputJson;
use plonk::setup_proving_key::json::SetupProvingKeyOutputJson;
use plonk::setup_verification_key::json::SetupVerificationKeyOutputJson;
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

    // Open and read verification_key.json
    let file = File::open("data/verification_key.json")?;
    let reader = BufReader::new(file);
    let verification_key_json: SetupVerificationKeyOutputJson = serde_json::from_reader(reader)?;
    let verification_key = verification_key_json.into_setup_output();
    println!("✅ Loaded verification key from verification_key.json");

    prover::run(&setup, &proving_key, &verification_key)?;
    println!("✅ Prover ran successfully");

    Ok(())
}
