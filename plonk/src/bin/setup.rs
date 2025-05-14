use plonk::setup::{self, convert_to_json_friendly};
use std::error::Error;
use std::fs::{create_dir_all, File};
use std::io::Write;

fn main() -> Result<(), Box<dyn Error>> {
    println!("Running setup...");

    let output = setup::run();

    create_dir_all("data")?;
    {
        let json_output = convert_to_json_friendly(&output);
        let json_str = serde_json::to_string_pretty(&json_output)?;
        let mut file = File::create("data/srs.json")?;
        file.write_all(json_str.as_bytes())?;
    }

    println!("✅ SRS written to data/srs.json");
    Ok(())
}
