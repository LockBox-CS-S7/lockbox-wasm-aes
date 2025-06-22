use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce};
use super::key_generation;


pub fn encrypt(data: &[u8], passphrase: &str) -> Result<EncryptedData, aes_gcm::Error> {    
    let salt = key_generation::generate_salt();
    let key = key_generation::derive_key_from_passphrase(passphrase.as_bytes(), &salt);

    let cipher = Aes256Gcm::new(&key.into());

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, data)?;

    Ok(EncryptedData::new(&ciphertext, &nonce))
}

pub fn decrypt(data: EncryptedData, passphrase: &str) -> Result<Vec<u8>, aes_gcm::Error> {
    let salt = key_generation::generate_salt();
    let key = key_generation::derive_key_from_passphrase(passphrase.as_bytes(), &salt);
    
    let cipher = Aes256Gcm::new(&key.into());

    let nonce = Nonce::clone_from_slice(data.nonce.as_slice());
    let plain_text = cipher.decrypt(&nonce, data.data.as_slice())?;

    Ok(plain_text)
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedData {
    data: Vec<u8>,
    nonce: Vec<u8>,
}

impl EncryptedData {
    pub fn new(data: &[u8], nonce: &[u8]) -> Self {
        Self {
            data: data.to_vec(),
            nonce: nonce.to_vec(),
        }
    }

    pub fn data(&self) -> &Vec<u8> {
        &self.data
    }

    pub fn nonce(&self) -> &Vec<u8> {
        &self.nonce
    }
}
