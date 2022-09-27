extern crate alloc;
extern crate core;

use crate::quote::Quote;
use crate::quote_collateral::QuoteCollateral;

mod quote_verifier;
mod tcb;
mod quote;
mod qe_identity;
mod quote_collateral;

fn main() {
    let quote = include_bytes!("../sample/quote").to_vec();
    let quote_collateral = QuoteCollateral {
        major_version: 3,
        minor_version: 0,
        tee_type: 0,
        pck_crl_issuer_chain: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/pck_crl_issuer_chain")).to_string(),
        root_ca_crl: include_bytes!("../sample/quote_collateral/root_ca_crl").to_vec(),
        pck_crl: include_bytes!("../sample/quote_collateral/pck_crl").to_vec(),
        tcb_info_issuer_chain: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/tcb_info_issuer_chain")).to_string(),
        tcb_info: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/tcb_info")).to_string(),
        qe_identity_issuer_chain: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/qe_identity_issuer_chain")).to_string(),
        qe_identity: String::from_utf8_lossy(include_bytes!("../sample/quote_collateral/qe_identity")).to_string(),
    };

    println!("= Test parsing TCB info from collateral =");
    let _ = tcb::TCBInfo::from_json_str(&quote_collateral.tcb_info);
    println!("==========================================");

    println!("= Test parsing quote =");
    let _ = Quote::parse(&quote);
    println!("======================");

    let current_time: u64 = std::time::SystemTime::now().duration_since(std::time::SystemTime::UNIX_EPOCH).unwrap().as_secs().try_into().unwrap();
    quote_verifier::sgx_qv_verify_quote(&quote, quote_collateral, current_time);

    println!("Done");
}
