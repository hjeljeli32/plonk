use plonk::setup_global_params::json::SetupGlobalParamsOutputJson;
use plonk::setup_verification_key;
use plonk::setup_verification_key::convert_to_json_friendly_verification_key;
use std::error::Error;
use std::fs::{create_dir_all, File};
use std::io::{BufReader, Write};

fn main() -> Result<(), Box<dyn Error>> {
    println!("Running setup_verification_key...");

    // Open and read srs.json
    let file = File::open("data/srs.json")?;
    let reader = BufReader::new(file);
    let setup_json: SetupGlobalParamsOutputJson = serde_json::from_reader(reader)?;
    let setup = setup_json.into_setup_output();
    println!("✅ Loaded setup parameters from srs.json");

    let output = setup_verification_key::run(&setup);

    create_dir_all("data")?;
    {
        let json_output = convert_to_json_friendly_verification_key(&output);
        let json_str = serde_json::to_string_pretty(&json_output)?;
        let mut file = File::create("data/verification_key.json")?;
        file.write_all(json_str.as_bytes())?;
    }

    println!("✅ Verification key written to data/verification_key.json");
    Ok(())
}
