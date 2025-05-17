use plonk::{
    common::proof::{Proof, ProofJson},
    setup_global_params::json::SetupGlobalParamsOutputJson,
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
    println!("\t Number of gates: {}", setup.number_gates);
    println!("\t Number of public inputs: {}", setup.number_public_inputs);
    println!("\t Number of witnesses: {}", setup.number_witnesses);
    println!("\t d: {}", setup.d);
    println!(
        "\t Length of tau_powers_g1: {}",
        setup.gp.tau_powers_g1.len()
    );

    // Open and read proof.json
    let json_str = std::fs::read_to_string("data/proof.json")?;
    let proof_json: ProofJson = serde_json::from_str(&json_str)?;
    let proof: Proof = Proof::from(&proof_json);
    println!("✅ Loaded proof from data/proof.json");

    let _ = verifier::run(&setup, &proof);

    Ok(())
}
