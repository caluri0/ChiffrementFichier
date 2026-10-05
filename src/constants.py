"""
Shared constants for the encrypted file container format.

Learning note — why a custom container?
  Raw ciphertext alone is hard to decrypt reliably: you need the nonce,
  salt, algorithm version, and (for hybrid mode) the RSA-wrapped key.
  A small header makes the tool self-describing and portfolio-friendly.
"""

# 4-byte magic so we can detect our files vs random binary
MAGIC = b"CFEF"

# Increment when the on-disk layout changes (never decrypt old files blindly)
FORMAT_VERSION = 1

# One byte in the header identifies the encryption mode
MODE_AES_PASSWORD = 0x01
MODE_RSA_HYBRID = 0x02

# AES-256 needs a 32-byte key; GCM standard nonce size is 12 bytes
AES_KEY_SIZE = 32
GCM_NONCE_SIZE = 12

# PBKDF2: slow down password guessing (offline attacks)
PBKDF2_ITERATIONS = 600_000
SALT_SIZE = 16

# RSA key size for hybrid mode (4096 is a common modern choice)
RSA_KEY_SIZE = 4096
