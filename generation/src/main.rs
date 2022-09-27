use std::fs;

mod quote_generator;

fn main() {
    let quote_bag = quote_generator::create_quote_bag("Hello, world!".as_bytes());

    quote_generator::quote_verification(quote_bag.quote.clone(), quote_bag.quote_collateral);

    let quote = quote_bag.quote;
    let quote_collateral = quote_bag.quote_collateral;

    println!("Collateral Version:");
    let major_version = unsafe { quote_collateral.__bindgen_anon_1.__bindgen_anon_1.major_version };
    let minor_version = unsafe { quote_collateral.__bindgen_anon_1.__bindgen_anon_1.minor_version };
    println!("{}.{}", major_version, minor_version);

    println!("Collateral TEE type:");
    let tee_type = quote_collateral.tee_type;
    println!("{}", tee_type);

    println!("Collateral PCK CRL issuer chain size:");
    println!("{}", quote_collateral.pck_crl_issuer_chain_size);
    println!("Collateral PCK CRL issuer chain data:");
    let pck_crl_issuer_chain = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.pck_crl_issuer_chain as *const u8,
            (quote_collateral.pck_crl_issuer_chain_size - 1) as usize, // trim last '\0'
        );

        core::str::from_utf8(slice).expect("Collateral PCK CRL issuer chain should an UTF-8 string")
    };
    println!("{}", pck_crl_issuer_chain);

    println!("Collateral ROOT CA CRL size:");
    println!("{}", quote_collateral.root_ca_crl_size);
    println!("Collateral ROOT CA CRL data:");
    let root_ca_crl = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.root_ca_crl as *const u8,
            (quote_collateral.root_ca_crl_size - 1) as usize // trim last '\0'
        );

        slice.to_vec()
    };
    println!("0x{}", hex::encode_upper(root_ca_crl.clone()));

    println!("Collateral PCK CRL size:");
    println!("{}", quote_collateral.pck_crl_size);
    println!("Collateral PCK CRL data:");
    let pck_crl = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.pck_crl as *const u8,
            (quote_collateral.pck_crl_size - 1) as usize // trim last '\0'
        );

        slice.to_vec()
    };
    println!("0x{}", hex::encode_upper(pck_crl.clone()));

    println!("Collateral TCB info issuer chain size:");
    println!("{}", quote_collateral.tcb_info_issuer_chain_size);
    println!("Collateral TCB info issuer chain data:");
    let tcb_info_issuer_chain = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.tcb_info_issuer_chain as *const u8,
            (quote_collateral.tcb_info_issuer_chain_size - 1) as usize, // trim last '\0'
        );

        core::str::from_utf8(slice).expect("Collateral TCB info issuer chain should an UTF-8 string")
    };
    println!("{}", tcb_info_issuer_chain);

    println!("Collateral TCB info size:");
    println!("{}", quote_collateral.tcb_info_size);
    println!("Collateral TCB info data:");
    let tcb_info = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.tcb_info as *const u8,
            (quote_collateral.tcb_info_size - 1) as usize // trim last '\0'
        );

        core::str::from_utf8(slice).expect("Collateral TCB info should an UTF-8 string")
    };
    println!("{}", tcb_info);

    println!("Collateral QE identity issuer chain size:");
    println!("{}", quote_collateral.qe_identity_issuer_chain_size);
    println!("Collateral QE identity issuer chain data:");
    let qe_identity_issuer_chain = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.qe_identity_issuer_chain as *const u8,
            (quote_collateral.qe_identity_issuer_chain_size - 1) as usize // trim last '\0'
        );

        core::str::from_utf8(slice).expect("Collateral QE identity issuer chain should an UTF-8 string")
    };
    println!("{}", qe_identity_issuer_chain);

    println!("Collateral QE Identity size:");
    println!("{}", quote_collateral.qe_identity_size);
    println!("Collateral QE identity data:");
    let qe_identity = unsafe {
        let slice = core::slice::from_raw_parts(
            quote_collateral.qe_identity as *const u8,
            (quote_collateral.qe_identity_size - 1) as usize // trim last '\0'
        );

        core::str::from_utf8(slice).expect("Collateral QE Identity should an UTF-8 string")
    };
    println!("{}", qe_identity);

    fs::create_dir_all("/data/sample/quote_collateral").unwrap();

    fs::write(
        "/data/sample/quote",
        quote
    ).unwrap();

    // fs::write(
    //     "/data/sample/quote_collateral/major_version",
    //     major_version
    // ).unwrap();
    // fs::write(
    //     "/data/sample/quote_collateral/major_version",
    //     minor_version
    // ).unwrap();
    // fs::write(
    //     "/data/sample/quote_collateral/tee_type",
    //     tee_type
    // ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/pck_crl_issuer_chain",
        pck_crl_issuer_chain
    ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/root_ca_crl",
        root_ca_crl
    ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/pck_crl",
        pck_crl
    ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/tcb_info_issuer_chain",
        tcb_info_issuer_chain
    ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/tcb_info",
        tcb_info
    ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/qe_identity_issuer_chain",
        qe_identity_issuer_chain
    ).unwrap();
    fs::write(
        "/data/sample/quote_collateral/qe_identity",
        qe_identity
    ).unwrap();

    println!("Done");
}
