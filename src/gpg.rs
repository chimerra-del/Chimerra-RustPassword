use anyhow::{anyhow, Context, Result};
use sequoia_openpgp as openpgp;
use openpgp::cert::Cert;
use openpgp::crypto::{KeyPair, SessionKey};
use openpgp::parse::{stream::*, Parse};
use openpgp::policy::StandardPolicy;
use openpgp::serialize::stream::{Encryptor2, LiteralWriter, Message}; 
use openpgp::types::SymmetricAlgorithm;
use std::io::{Read, Write};

pub fn encrypt_data(data: &[u8], recipient_cert_bytes: &[u8]) -> Result<Vec<u8>> {
    let policy = &StandardPolicy::new();
    let cert = Cert::from_bytes(recipient_cert_bytes)
        .context("Failed to parse public key (Cert)")?;
    let recipients = cert
        .keys()
        .with_policy(policy, None)
        .supported()
        .alive()
        .revoked(false)
        .for_transport_encryption();

    let mut ciphertext = Vec::new();

    {
        let message = Message::new(&mut ciphertext);
        let encryptor = Encryptor2::for_recipients(message, recipients)
            .build()
            .context("Failed to create Encryptor")?;

        let mut literal_writer = LiteralWriter::new(encryptor)
            .build()
            .context("Failed to create LiteralWriter")?;

        literal_writer.write_all(data).context("Error writing data to PGP stream")?;
        literal_writer.finalize().context("PGP stream finalization error")?;
    }

    Ok(ciphertext)
}

struct DecryptorHelper {
    keypair: KeyPair,
}

impl VerificationHelper for DecryptorHelper {
    fn get_certs(&mut self, _ids: &[openpgp::KeyHandle]) -> openpgp::Result<Vec<Cert>> {
        Ok(Vec::new()) 
    }

    fn check(&mut self, _structure: MessageStructure) -> openpgp::Result<()> {
        Ok(())
    }
}

impl DecryptionHelper for DecryptorHelper {
    fn decrypt<D>(
        &mut self,
        pkesks: &[openpgp::packet::PKESK],
        _skesks: &[openpgp::packet::SKESK],
        sym_algo: Option<SymmetricAlgorithm>,
        mut decrypt: D,
    ) -> openpgp::Result<Option<openpgp::Fingerprint>> 
        D: FnMut(SymmetricAlgorithm, &SessionKey) -> bool,
    {
        for pkesk in pkesks {
            if let Some((algo, session_key)) = pkesk.decrypt(&mut self.keypair, sym_algo) {
                if decrypt(algo, &session_key) {
                    return Ok(Some(self.keypair.public().fingerprint()));
                }
            }
        }
        Ok(None)
    }
}

pub fn decrypt_data(encrypted_data: &[u8], secret_key_bytes: &[u8], password: Option<&str>) -> Result<Vec<u8>> {
    let policy = &StandardPolicy::new();
    let cert = Cert::from_bytes(secret_key_bytes)
        .context("Failed to parse the secret key")?;

    let mut keypair = None;
    for key in cert.keys().with_policy(policy, None).secret().supported().alive().revoked(false).for_storage_encryption() {
        let mut pk = key.key().clone();
        
        if pk.secret().is_encrypted() {
            if let Some(pwd) = password {
                let algo = pk.pk_algo();
                pk.secret_mut()
                    .decrypt_in_place(algo, &pwd.into())
                    .context("Wrong password for PGP-key")?;
            } else {
                continue;
            }
        }
        
        keypair = Some(pk.into_keypair().context("Creating error KeyPair")?);
        break;
    }

    let keypair = keypair.ok_or_else(|| anyhow!("No valid private keys found in the certificate"))?;
    let helper = DecryptorHelper { keypair };
    let mut decryptor = DecryptorBuilder::from_bytes(encrypted_data)?
        .with_policy(policy, None, helper)
        .context("PGP decryptor initialization error")?;

    let mut plaintext = Vec::new();
    decryptor.read_to_end(&mut plaintext).context("Error reading decrypted data")?;

    Ok(plaintext)
          }
