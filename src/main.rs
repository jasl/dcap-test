mod quote_generator;
mod quote_verifier;
mod tcb_info;

fn main() {
    let quote_bag = quote_generator::create_quote_bag("Hello, world!".as_bytes());
    quote_generator::quote_verification(quote_bag.quote.clone(), quote_bag.quote_collateral);

    let current_time: u64 = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();
    quote_verifier::sgx_qv_verify_quote(&quote_bag.quote.clone(), &quote_bag.quote_collateral, current_time);

    println!("Done");
}
