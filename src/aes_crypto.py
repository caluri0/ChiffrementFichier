"""
Symmetric encryption with AES-256-GCM.

Learning path:
  - AES (Advanced Encryption Standard): fast symmetric cipher; same key
    encrypts and decrypts. Used for bulk data (files, disks, TLS records).
  - GCM (Galois/Counter Mode): provides confidentiality AND integrity
    (an attacker cannot flip bits without detection). Prefer GCM over
    obsolete modes like ECB or unauthenticated CBC.
  - Password-based keys: humans supply passwords, not random 32-byte keys.
    PBKDF2 stretches the password with many iterations + a random salt so
    brute-force and rainbow tables become much harder.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from src.constants import AES_KEY_SIZE, GCM_NONCE_SIZE, PBKDF2_ITERATIONS, SALT_SIZE


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """
    Turn a user password into a 256-bit AES key using PBKDF2-HMAC-SHA256.

    The salt must be unique per file and stored alongside the ciphertext
    (it is not secret; it only separates key derivations).
    """
    if len(salt) != SALT_SIZE:
        raise ValueError(f"Salt must be {SALT_SIZE} bytes, got {len(salt)}")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def generate_data_key() -> bytes:
    """Random 256-bit key for hybrid mode (encrypt file directly with this)."""
    return os.urandom(AES_KEY_SIZE)


def encrypt_bytes(plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt with AES-GCM.

    Returns (nonce, ciphertext_including_tag).
    GCM appends a 16-byte authentication tag to the ciphertext internally.
    """
    if len(key) != AES_KEY_SIZE:
        raise ValueError(f"AES key must be {AES_KEY_SIZE} bytes")

    nonce = os.urandom(GCM_NONCE_SIZE)
    aesgcm = AESGCM(key)
    # Associated data is empty; file format header is outside the AEAD scope
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
    return nonce, ciphertext


def decrypt_bytes(nonce: bytes, ciphertext: bytes, key: bytes) -> bytes:
    """
    Decrypt and verify integrity. Wrong key or tampered data raises an exception.
    """
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)
