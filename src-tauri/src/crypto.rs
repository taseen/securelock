use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use argon2::{Argon2, Algorithm, Version, Params};
use rand::RngCore;
use zeroize::Zeroize;

const SALT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const KEY_LEN: usize = 32;

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let params = Params::new(65536, 3, 1, Some(KEY_LEN))
        .map_err(|e| format!("Argon2 params error: {}", e))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("Key derivation error: {}", e))?;
    Ok(key)
}

pub fn encrypt(key: &[u8; KEY_LEN], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Cipher init error: {}", e))?;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| format!("Encryption error: {}", e))?;
    let mut result = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

pub fn decrypt(key: &[u8; KEY_LEN], data: &[u8]) -> Result<Vec<u8>, String> {
    if data.len() < NONCE_LEN {
        return Err("Data too short to contain nonce".into());
    }
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("Cipher init error: {}", e))?;
    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "Decryption failed — wrong password or corrupted data".into())
}

pub fn create_verify_token(key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    encrypt(key, b"SECURELOCK_VERIFY_TOKEN_V1")
}

pub fn verify_password(key: &[u8; KEY_LEN], encrypted_token: &[u8]) -> bool {
    match decrypt(key, encrypted_token) {
        Ok(plaintext) => plaintext == b"SECURELOCK_VERIFY_TOKEN_V1",
        Err(_) => false,
    }
}

pub fn wrap_key(master_key: &[u8; KEY_LEN], folder_key: &[u8; KEY_LEN]) -> Result<Vec<u8>, String> {
    encrypt(master_key, folder_key)
}

pub fn unwrap_key(master_key: &[u8; KEY_LEN], wrapped: &[u8]) -> Result<[u8; KEY_LEN], String> {
    let key_bytes = decrypt(master_key, wrapped)?;
    key_bytes.try_into().map_err(|_| "Invalid wrapped key length".to_string())
}

pub fn zeroize_key(key: &mut [u8; KEY_LEN]) {
    key.zeroize();
}
