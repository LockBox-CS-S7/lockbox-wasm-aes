use aes_gcm::{aead::{Aead, AeadCore, KeyInit, OsRng}, Aes256Gcm, Nonce};
use super::key_generation;

/// Encrypts a bytes slice using AES-GCM and PBKDF2.
/// 
/// ## Parameters:
/// * `data` - The data that should get encrypted.
/// * `passphrase` - The password that should be used for encryption.
/// 
/// ## Returns:
/// The encrypted data as a vector containing the following data in order:
/// 1. **nonce** - 12 bytes
/// 2. **salt** - 16 bytes
/// 3. **ciphertext** - remaining bytes
pub fn encrypt(data: &[u8], passphrase: &str) -> Result<Vec<u8>, aes_gcm::Error> {    
    let salt = key_generation::generate_salt();
    let key = key_generation::derive_key_from_passphrase(passphrase.as_bytes(), &salt);

    let cipher = Aes256Gcm::new(&key.into());

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    let ciphertext = cipher.encrypt(&nonce, data)?;

    let data = EncryptedData {
        nonce: nonce.to_vec(),
        salt,
        ciphertext,
    };
    
    Ok(data.as_bytes())
}

/// Decrypts encrypted data.
/// 
/// ## Parameters:
/// * `data` - The encrypted data that should be decrypted.
/// * `passphrase` - The password that was used for encryption.
/// 
/// ## Returns:
/// The decrypted data in the form of a `Vec<u8>` to allow for easy wasm binding.
pub fn decrypt(data: EncryptedData, passphrase: &str) -> Result<Vec<u8>, aes_gcm::Error> {
    let salt = key_generation::generate_salt();
    let key = key_generation::derive_key_from_passphrase(passphrase.as_bytes(), &salt);
    
    let cipher = Aes256Gcm::new(&key.into());

    let nonce = Nonce::clone_from_slice(data.nonce.as_slice());
    let plain_text = cipher.decrypt(&nonce, data.ciphertext.as_slice())?;

    Ok(plain_text)
}

#[derive(Debug, Clone, PartialEq)]
pub struct EncryptedData {
    pub nonce: Vec<u8>,
    pub salt: [u8; 16],
    pub ciphertext: Vec<u8>,
}

impl EncryptedData {
    pub fn as_bytes(mut self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        bytes.append(&mut self.nonce);
        for b in self.salt {
            bytes.push(b);
        }
        bytes.append(&mut self.ciphertext.clone());
        
        bytes
    }
    
    pub fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let mut nonce = Vec::new();
        for i in bytes.drain(0..12) {
            nonce.push(i);
        }
        
        let mut salt = [0u8; 16];
        let mut salt_counter: usize = 0;
        for i in bytes.drain(0..16) {
            salt[salt_counter] = i;
            salt_counter += 1;
        }
        
        Self {
            nonce,
            salt,
            ciphertext: bytes,  // The remaining bytes must be the ciphertext.
        }
    }
}
