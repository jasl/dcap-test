extern crate alloc;
extern crate core;

use crate::quote::Quote;

mod quote_generator;
mod quote_verifier;
mod tcb;
mod quote;

fn get_qe_certification_data_size(quote: &[u8]) -> usize {
    0
}

fn extract_chain_from_quote(quote: &[u8]) {

}

fn main() {
    let quote_bag = quote_generator::create_quote_bag("Hello, world!".as_bytes());
    quote_generator::quote_verification(quote_bag.quote.clone(), quote_bag.quote_collateral);

    println!("= Test parsing TCB info from collateral =");
    let tcb_info_json_str = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_bag.quote_collateral.tcb_info as *const u8,
            (quote_bag.quote_collateral.tcb_info_size - 1) as usize // Trim '\0'
        );

        core::str::from_utf8(slice).expect("Collateral TCB info should an UTF-8 string")
    };
    let _ = tcb::TCBInfo::from_json_str(tcb_info_json_str);
    println!("==========================================");

    println!("= Test parsing quote =");
    let _ = Quote::parse(&quote_bag.quote);
    println!("======================");


    let current_time: u64 = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();
    quote_verifier::sgx_qv_verify_quote(&quote_bag.quote.clone(), &quote_bag.quote_collateral, current_time);

    println!("Done");
}
