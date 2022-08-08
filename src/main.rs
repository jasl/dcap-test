use anyhow::Result;
use std::fs;

fn create_quote_vec(data: &[u8]) -> Result<Vec<u8>> {
    // TODO: DCAP-only for now, should determine which RA type via `/dev/attestation/attestation_type`
    fs::write("/dev/attestation/user_report_data", data)?;
    Ok(fs::read("/dev/attestation/quote")?)
}

fn main() {
    let quote = create_quote_vec("Hello, world!".as_bytes()).expect("Create quote error");
    fs::write("/data/storage_files/quote.dat", quote.clone()).expect("Write error");

    println!("0x{}", hex::encode(quote.clone()));
}
