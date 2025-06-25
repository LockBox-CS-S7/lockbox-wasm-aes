mod aes;

use std::time::Instant;
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
pub fn encrypt_bytes(bytes: Vec<u8>, password: &str) -> EncryptionResult {
    let now = Instant::now();
    let ciphertext = encrypt(&bytes, password).expect("Failed to encrypt the received data");
    
    EncryptionResult {
        data: ciphertext,
        duration: now.elapsed().as_millis(),
    }
}

#[wasm_bindgen]
pub fn decrypt_bytes(bytes: Vec<u8>, password: &str) -> EncryptionResult {
    let now = Instant::now();
    
    let data = EncryptedData::from_bytes(bytes);
    let plaintext = decrypt(data, password).expect("Failed to decrypt the ciphertext");
    
    EncryptionResult { 
        data: plaintext, 
        duration: now.elapsed().as_millis() 
    }
}

#[wasm_bindgen]
pub struct EncryptionResult {
    data: Vec<u8>,
    duration: u128,
}

#[wasm_bindgen]
impl EncryptionResult {
    #[wasm_bindgen(constructor)]
    pub fn new(data: Vec<u8>, duration: u128) -> EncryptionResult {
        EncryptionResult { data, duration }
    }

    #[wasm_bindgen(getter)]
    pub fn data(&self) -> Vec<u8> {
        self.data.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn duration(&self) -> u128 {
        self.duration
    }
}