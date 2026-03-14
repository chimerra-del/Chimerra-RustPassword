use binrw::{BinRead, BinWrite};
use binrw::binrw;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{Read, Write};
use anyhow::{Context, Result};
use crate::crypto::{self, KEY_SIZE, NONCE_SIZE};
use secrecy::ExposeSecret;

// Magic bytes
const MAGIC: [u8; 4] = *b"RVLT";
const CURRENT_VERSION: u32 = 1;

#[binrw]
#[br(little)]
#[bw(little)]
#[derive(Debug)]
pub struct VaultHeader {
    pub magic: [u8; 4],
    pub version: u32,
    pub salt: [u8; 16],
    pub argon_mem: u32,
    pub argon_iter: u32,
    pub nonce: [u8; NONCE_SIZE],
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VaultContent {
    pub entries: BTreeMap<String, String>,
}

pub struct Storage;

impl Storage {
    pub fn save(
        path: &str,
        header: &mut VaultHeader,
        content: &VaultContent,
        key: &[u8; KEY_SIZE],
    ) -> Result<()> {
        let raw_data = bincode::serialize(content)
            .context("Data serialization error")?;
            
        let encrypted_data = crypto::Cipher::encrypt(
            &raw_data,
            key,
            &header.nonce,
            &header.version.to_le_bytes(),
        )?;

        let tmp_path = format!("{}.tmp", path);

        {
            let mut file = File::create(&tmp_path)
                .context("Failed to create temporary vault file")?;          
            header.write(&mut file).map_err(|e| anyhow::anyhow!(e))?;
            file.write_all(&encrypted_data)
                .context("Failed to write encrypted data")?;
            file.sync_all().context("Failed to sync data to disk")?;
        }

        fs::rename(&tmp_path, path)
            .context("Failed to atomically replace the vault file")?;

        Ok(())
    }

    pub fn load(
        path: &str,
        password: &secrecy::SecretString,
    ) -> Result<(VaultHeader, VaultContent)> {
        let mut file = File::open(path).context("Storage not found")?;
        
        let header = VaultHeader::read(&mut file)
            .map_err(|e| anyhow::anyhow!("Failed to read Header: {}", e))?;

        if header.magic != MAGIC {
            return Err(anyhow::anyhow!("Incorrect file format: (Magic mismatch)"));
        }
        let key = crypto::derive_key(
            password,
            &header.salt,
            header.argon_mem,
            header.argon_iter,
        )?;

        let mut encrypted_data = Vec::new();
        file.read_to_end(&mut encrypted_data)?;

        let decrypted_data = crypto::Cipher::decrypt(
            &encrypted_data,
            &key,
            &header.nonce,
            &header.version.to_le_bytes(),
        )?;

        let content: VaultContent = bincode::deserialize(&decrypted_data)
            .context("Deserialization error (possibly corrupted data)")?;

        Ok((header, content))
    }
}
