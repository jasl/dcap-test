mod quote_generator;
mod quote_verifier;

fn main() {
    let quote_bag = quote_generator::create_quote_bag("Hello, world!".as_bytes());
    quote_generator::quote_verification(quote_bag);

    println!("Done");
}
