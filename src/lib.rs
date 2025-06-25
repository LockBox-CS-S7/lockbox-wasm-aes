mod aes;

use wasm_bindgen::prelude::*;
use aes::aes_encryption::{encrypt, decrypt, EncryptedData};

#[wasm_bindgen]
extern "C" {
    pub fn alert(s: &str);
}

#[wasm_bindgen]
pub fn greet(name: &str) {
    alert(&format!("Hello, {}!", name));
}

#[wasm_bindgen]
pub fn encrypt_bytes(bytes: Vec<u8>, password: &str) -> Vec<u8> {
    encrypt(&bytes, password).expect("Failed to encrypt the received data")
}

#[wasm_bindgen]
pub fn decrypt_bytes(bytes: Vec<u8>, password: &str) -> Vec<u8> {
    let data = EncryptedData::from_bytes(bytes);
    decrypt(data, password).expect("Failed to decrypt the ciphertext")
}