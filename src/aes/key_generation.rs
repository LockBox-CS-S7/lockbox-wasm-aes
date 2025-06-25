use sha2::Sha256;
use pbkdf2::pbkdf2_hmac;
// use rand::Rng;
use getrandom::getrandom;


const ITERATIONS: u32 = 600_000;

pub fn derive_key_from_passphrase(pass: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key_buffer = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass, salt, ITERATIONS, &mut key_buffer);

    key_buffer
}

pub fn generate_salt() -> [u8; 16] {
    let mut buffer = [0u8; 16];
    getrandom(&mut buffer)
        .expect("Failed to generate random values for salt");
    
    buffer
}
