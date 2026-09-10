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
- **RSA key generation, signing, and decryption:** Persistent RSA key pairs with RSA-PSS/SHA-256 signatures and RSA-OAEP/SHA-1 decryption.
- **EC key generation and signing:** NIST P-256, P-384, and P-521 support with ECDSA and SHA-256, SHA-384, and SHA-512 respectively.
- **ECDH key agreement:** Import a peer EC public key and derive a shared secret inside the SE, then use HKDF-SHA-256 to create a persistent AES-256 key. The response includes the public salt and context information needed for the peer to derive the same key.
- **HMAC keys and authentication:** Internal HKDF-based HMAC key generation, with HMAC-SHA-256 and HMAC-SHA-512 MAC creation and verification.
- **Public-key export:** RSA and EC public keys exported as DER-encoded SubjectPublicKeyInfo for use with tools such as OpenSSL.
- **Key management:** List keys, filter by label/type/usage, look up metadata by object ID, and delete customer keys and their metadata. Deleted object IDs may be reused.
- **Key metadata and usage policies:** Versioned NVS records store labels, key types, sizes, intended usages, and creation timestamps supplied by the host where supported. Access policies are enforced by the SE.
- **USB command interface:** Framed binary commands for provisioning, authentication, status, key management, encryption, decryption, signing, HMAC verification, ECDH derivation, and public-key export.
- **Serialized SE access:** A dedicated FreeRTOS worker owns secure-element operations and session state.

## Roadmap

- [x] RSA OAEP decryption
- [x] ECDH + HKDF
- [x] HMAC keys
- [x] Key Management
  - [x] List provisioned keys
  - [x] Search by label/type/usage
  - [x] Fetch metadata by ID
  - [x] Support key deletion
- [ ] Proper error code responses
- [ ] Storage visibility
