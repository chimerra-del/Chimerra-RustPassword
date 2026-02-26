use bip39::{Language, Mnemonic};
use clap::Args;
use rand::RngCore;
use rand::rngs::OsRng;
use unicode_width::UnicodeWidthStr;
use zeroize::Zeroizing;
use rpassword::prompt_password;
use anyhow::{anyhow, Result};

const DEFAULT_STRENGTH: usize = 128;

#[derive(Args, Debug)]
pub struct MnemonicArgs {
    #[arg(short = 'w', help = "Words (12 or 24)")]
    pub words: Option<usize>,

    #[arg(short = 'l', default_value = "english", help = "Lang. Of Phrase")]
    pub language: String,

    #[arg(short = 'e', help = "Show Entropy and etc.")]
    pub show_entropy: bool,

    #[arg(short = 'p', long = "passphrase", help = "Needed BIP39 passphrase")]
    pub passphrase: bool,

    #[arg(long = "list", help = "Lang. support list")]
    pub list_languages: bool,
}

pub fn run_generator(args: MnemonicArgs) -> Result<()> {
    if args.list_languages {
        print_supported_languages();
        return Ok(());
    }

    let lang = parse_language(&args.language)?;
    let bits = match args.words {
        Some(12) => 128,
        Some(24) => 256,
        None => DEFAULT_STRENGTH,
        _ => return Err(anyhow!("Supported only 12 or 24 words")),
    };

    let mut entropy = Zeroizing::new(vec![0u8; bits / 8]);
    OsRng.fill_bytes(&mut entropy[..]);

    let mnemonic = Mnemonic::from_entropy_in(lang, &entropy[..])
        .map_err(|e| anyhow!("Generation error: {}", e))?;

    if args.show_entropy {
        println!("Entropy (hex): {}", hex::encode(&*entropy));
    }

    println!("\n┌─ YOUR PHRASE ──────────────────────────────────┐");
    println!("│ {:<59} │", mnemonic.to_string());
    println!("└─────────────────────────────────────────────────────────────┘");

    if args.passphrase {
        let pass = prompt_password("Enter Code Phrase (BIP39 Passphrase): ")?;
        let seed = mnemonic.to_seed(pass);
        println!("Seed (hex): {}", hex::encode(seed));
    }

    Ok(())
}

fn parse_language(s: &str) -> Result<Language> {
    match s.to_lowercase().as_str() {
        "english" | "en" => Ok(Language::English),
        _ => Err(anyhow!("Lang. not supported, please use --list")),
    }
}

fn print_supported_languages() {
    println!("Supported Lang.: en, es, fr, it, ja, ko, и др.");
      }
