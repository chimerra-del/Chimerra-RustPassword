use std::io::{self, Read, Write};
use std::fs;
mod sys_utils;
mod crypto;
mod storage;
mod gpg; 
mod vcs;
mod generator;

use clap::{Parser, Subcommand};
use secrecy::{SecretString, ExposeSecret};
use rand::RngCore;
use crate::storage::{VaultHeader, VaultContent, Storage};

// Simple Password-Store in Pass style

#[derive(Parser)]
#[command(name = "vault", about = "Chimerra-PasswordStore", version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {  // команды
    Init { path: String }, 
    Insert { path: String, key: String },
    Show { path: String, key: String },
    
    List { path: String },
    Delete { path: String, key: String },
    
    GpgEncrypt { input: String, output: String, pub_key: String },
    GpgDecrypt { input: String, output: String, priv_key: String },
    
    Mnemonic(generator::MnemonicArgs),
}

fn main() -> anyhow::Result<()> {
    sys_utils::harden_process()?;

    let cli = Cli::parse();

    match cli.command {
        Commands::Init { path } => {
            let password = read_password("Please, create the master key: ")?;
            
            let mut salt = [0u8; 16];
            let mut nonce = [0u8; 12];
            rand::thread_rng().fill_bytes(&mut salt);
            rand::thread_rng().fill_bytes(&mut nonce);

            let mut header = VaultHeader {
                magic: *b"RVLT",
                version: 1,
                salt,
                argon_mem: 65536,
                argon_iter: 3,
                nonce,
            };

            let key = crypto::derive_key(&password, &header.salt, header.argon_mem, header.argon_iter)?;
            let content = VaultContent::default();
            Storage::save(&path, &mut header, &content, &key)?;

            println!("Created: {}", path);
        }

        Commands::Insert { path, key } => {
            let password = read_password("Enter Master Key: ")?;
            let (mut header, mut content) = Storage::load(&path, &password)?;

            println!("Enter data for '{}' (Ctrl+D for exit):", key);
            let mut buffer = String::new();
            io::stdin().read_to_string(&mut buffer)?;

            content.entries.insert(key, buffer.trim().to_string());
            rand::thread_rng().fill_bytes(&mut header.nonce);
            
            let key_derived = crypto::derive_key(&password, &header.salt, header.argon_mem, header.argon_iter)?;
            Storage::save(&path, &mut header, &content, &key_derived)?;

            // просто пример
            let _ = vcs::commit_changes(&path, "Vault updated");

            println!("Data is Saved.");
        }

        Commands::Show { path, key } => {
            let password = read_password("Enter Master Key: ")?;
            let (_, content) = Storage::load(&path, &password)?;

            if let Some(value) = content.entries.get(&key) {
                println!("--- SECRET START ---");
                println!("{}", value);
                println!("--- SECRET END ---");
            } else {
                println!("key '{}' is not found.", key);
            }
        }
        Commands::GpgEncrypt { input, output, pub_key } => {
            let data = fs::read(&input)?;
            let key_bytes = fs::read(&pub_key)?;
            
            let encrypted = gpg::encrypt_data(&data, &key_bytes)?;
            fs::write(&output, encrypted)?;
            println!("File encrypted via PGP: {}", output);
        }

        Commands::List { path } => {
            let password = read_password("Enter Master Key: ")?;
            let (_, content) = Storage::load(&path, &password)?;

            if content.entries.is_empty() {
                println!("Vault is empty.");
            } else {
                println!("=== VAULT ENTRIES ===");
                for key in content.entries.keys() {
                    println!("- {}", key);
                }
                println!("=====================");
            }
        }

        Commands::Delete { path, key } => {
            let password = read_password("Enter Master Key: ")?;
            let (mut header, mut content) = Storage::load(&path, &password)?;

            if content.entries.remove(&key).is_some() {
                rand::thread_rng().fill_bytes(&mut header.nonce);
                
                let key_derived = crypto::derive_key(&password, &header.salt, header.argon_mem, header.argon_iter)?;
                Storage::save(&path, &mut header, &content, &key_derived)?;

                
                let commit_msg = format!("Removed key '{}'", key);
                let _ = vcs::commit_changes(&path, &commit_msg);

                println!("Key '{}' successfully deleted.", key);
            } else {
                println!("Key '{}' not found in the vault.", key);
            }
        }

        Commands::GpgDecrypt { input, output, priv_key } => {
            let data = fs::read(&input)?;
            let key_bytes = fs::read(&priv_key)?;
            
            let password = read_password("Enter PGP Key Password (leave empty if none): ")?;
            let pass_str = password.expose_secret();
            let opt_pass = if pass_str.is_empty() { None } else { Some(pass_str.as_str()) };

            let decrypted = gpg::decrypt_data(&data, &key_bytes, opt_pass)?;
            fs::write(&output, decrypted)?;
            println!("File decrypted via PGP: {}", output);
        } 
        
        Commands::Mnemonic(args) => {
             generator::run_generator(args)?;
        } 
    } 

    Ok(())
} 

fn read_password(prompt: &str) -> anyhow::Result<SecretString> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let pass = rpassword::read_password()?;
    Ok(SecretString::from(pass))
      }
