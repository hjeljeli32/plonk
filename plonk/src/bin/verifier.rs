use plonk::{
    common::proof::{Proof, ProofJson},
    setup_global_params::json::SetupGlobalParamsOutputJson,
    setup_verification_key::json::SetupVerificationKeyOutputJson,
    verifier,
};
use std::{error::Error, fs::File, io::BufReader};

fn main() -> Result<(), Box<dyn Error>> {
    println!("Running verifier...");

    // Open and read srs.json
    let file = File::open("data/srs.json")?;
    let reader = BufReader::new(file);
    let setup_json: SetupGlobalParamsOutputJson = serde_json::from_reader(reader)?;
    let setup = setup_json.into_setup_output();
    println!("✅ Loaded setup parameters from srs.json");

    // Open and read verification_key.json
    let file = File::open("data/verification_key.json")?;
    let reader = BufReader::new(file);
    let verification_key_json: SetupVerificationKeyOutputJson = serde_json::from_reader(reader)?;
    let verification_key = verification_key_json.into_setup_output();
    println!("✅ Loaded verification key from verification_key.json");

    // Open and read proof.json
    let json_str = std::fs::read_to_string("data/proof.json")?;
    let proof_json: ProofJson = serde_json::from_str(&json_str)?;
    let proof: Proof = Proof::from(&proof_json);
    println!("✅ Loaded proof from data/proof.json");

    let _ = verifier::run(&setup, &verification_key, &proof);

    Ok(())
}
