use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2, Params,
};
use secrecy::{ExposeSecret, SecretString};
use zeroize::Zeroizing;
use anyhow::{anyhow, Context, Result};

pub const KEY_SIZE: usize = 32;
pub const NONCE_SIZE: usize = 12; 

pub fn derive_key(
    password: &SecretString,
    salt: &[u8],
    mem_limit: u32,
    iterations: u32,
) -> Result<Zeroizing<[u8; KEY_SIZE]>> {
    let mut derived_key = [0u8; KEY_SIZE];
    
    let params = Params::new(mem_limit, iterations, 1, Some(KEY_SIZE))
        .map_err(|e| anyhow!("Parameter error Argon2: {}", e))?;
    
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    argon2
        .hash_password_into(password.expose_secret().as_bytes(), salt, &mut derived_key)
        .map_err(|e| anyhow!("error KDF: {}", e))?;

    Ok(Zeroizing::new(derived_key))
}

pub struct Cipher;

impl Cipher {
    /// AES-256-GSM
    pub fn encrypt(
        plaintext: &[u8],
        key: &[u8; KEY_SIZE],
        nonce_bytes: &[u8; NONCE_SIZE],
        ad: &[u8],
    ) -> Result<Vec<u8>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce_bytes);
        
        let payload = Payload {
            msg: plaintext,
            aad: ad,
        };

        cipher
            .encrypt(nonce, payload)
            .map_err(|e| anyhow!("Encrypt error: {}", e))
    }

    pub fn decrypt(
        ciphertext: &[u8],
        key: &[u8; KEY_SIZE],
        nonce_bytes: &[u8; NONCE_SIZE],
        ad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        let cipher = Aes256Gcm::new(key.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let payload = Payload {
            msg: ciphertext,
            aad: ad,
        };
        let decrypted = cipher
            .decrypt(nonce, payload)
            .map_err(|e| anyhow!("Decrypt Error: {}", e))?;

        Ok(Zeroizing::new(decrypted))
    }
}
