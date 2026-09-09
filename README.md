# Enigma Stick Firmware

## Overview

The Enigma Stick is a work-in-progress open hardware/firmware/software ecosystem
for consumer hardware backed cryptographic keys and secure cryptographic operations.

The firmware is meant to be run on an ESP32 (tested on C3) with an SE051 secure
element connected via I2C. Hardware specifications and board designs are a
future project and will be linked here when ready. The firmware also includes
support for two status LEDs via GPIO which can be safely ignored if desired.

## Features

- **SE051-backed cryptography:** Customer private and symmetric keys are generated and stored inside the secure element. The ESP stores key metadata in NVS.
- **PIN authentication:** Token provisioning and PIN-based unlock using PBKDF2-HMAC-SHA-256 and an ESP-side PSA HMAC secret.
- **Authenticated sessions:** Encrypted ESP-to-SE communication after unlock, with automatic locking after inactivity and token/lock status reporting.
- **AES key generation and encryption:** Internal HKDF-based key derivation from an SE-held HMAC master, plus AES-GCM authenticated encryption and decryption. The master is established internally using ECDH during provisioning.
- **RSA key generation and signing:** Persistent RSA key pairs with RSA-PSS/SHA-256 signatures.
- **EC key generation and signing:** NIST P-256, P-384, and P-521 support with ECDSA and SHA-256, SHA-384, and SHA-512 respectively.
- **Public-key export:** RSA and EC public keys exported as DER-encoded SubjectPublicKeyInfo for use with tools such as OpenSSL.
- **Key metadata and usage policies:** Stable key IDs, labels, key types, sizes, and intended usages, with access policies enforced by the SE.
- **USB command interface:** Framed binary commands for provisioning, authentication, status, key generation, encryption, decryption, signing, and public-key export.
- **Serialized SE access:** A dedicated FreeRTOS worker owns secure-element operations and session state.

## Roadmap

- [x] RSA OAEP decryption
- [ ] ECDH + HKDF
- [ ] HMAC keys
- [ ] Dev cleanup script
- [ ] Key Management
  - [x] List provisioned keys
  - [x] Search by label/type/usage
  - [x] Fetch metadata by ID
  - [ ] Support key deletion
- [ ] Storage visibility
