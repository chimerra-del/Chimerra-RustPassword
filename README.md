# ChimerraPass

⚠️ Experimental / Educational Project

ChimerraPass is a personal password store inspired by pass,
built to explore secure systems design in Rust.

## Goals
- Learn memory hardening techniques (mlock, prctl)
- Practice safe handling of secrets in Rust
- Design a binary encrypted storage format
- Combine KDF-based encryption with GPG tooling

## Non-Goals
- Production-ready password manager
- Security audit or formal verification
- Cross-platform support (Linux-first)

## Threat Model
- Attacker with filesystem access
- Cold RAM attacks (best-effort mitigation)
- No protection against compromised OS

## Architecture
- Single encrypted container
- Argon2id → AES-GCM
- Optional GPG wrapping

## Why this project exists

I started ChimerraPass as a portfolio project to practice Rust
beyond CRUD apps and web services.

Things I wanted to explore:
- safe handling of secrets in Rust
- memory hardening techniques on Linux
- basic cryptographic building blocks (KDFs, AEAD)
- designing a simple binary file format
- building a small but non-trivial CLI tool

## What this project is NOT

- ❌ Not a production-ready password manager
- ❌ Not meant to compete with `pass`, Bitwarden, KeePass, etc.
- ❌ No formal threat model or guarantees


## High-level design

- Single encrypted binary container (instead of many files)
- Master password → Argon2id → encryption key
- AEAD encryption (AES-GCM)
- Versioned file format
- Secrets are never passed via CLI arguments (stdin only)


## Security notes

ChimerraPass makes a best-effort attempt to avoid common mistakes,
but **should not be considered secure**.

Implemented or planned mitigations:
- memory locking (mlock / mlockall)
- disabling core dumps
- zeroization of sensitive buffers
- modern KDF (Argon2id)
- authenticated encryption (AEAD)

