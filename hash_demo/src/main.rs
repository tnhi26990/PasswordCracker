use std::env;
use pbkdf2::{pbkdf2_hmac, pbkdf2_hmac_array};
use sha2::Sha256;

fn print_hex(array: &[u8]) {
    for byte in array {
        print!("{:0>2x}", byte);
    }
    print!("\n");
}

fn main() {

let args: Vec<String> = env::args().collect();

if args.len() != 4 {
    println!("Usage: cargo run -- iterations salt password");
    return;
}

let iterations: u32 = match args[1].parse() {
    Ok(x) => x,
    _ => {println!("Enter valid u32 for argument 1"); return},
};
let salt = &args[2];
let password = &args[3];

//Confirm the program input
println!("Got password: '{password}', salt: '{salt}', and iterations: {iterations}");

//This function takes a reference to an array, and stores the result hash
// in that array. May be faster for doing many repeated hashes.
let mut hash1 = [0u8; 20];
pbkdf2_hmac::<Sha256>(password.as_bytes(), salt.as_bytes(), iterations, &mut hash1);

//Print output first with the debug formatter, then with our custom function
println!("hash1: {hash1:x?}");
print_hex(&hash1);

//This function returns the output as an array
let hash2 = pbkdf2_hmac_array::<Sha256, 20>(password.as_bytes(), salt.as_bytes(), iterations);
println!("hash2: {hash2:x?}");
print_hex(&hash2);

}

