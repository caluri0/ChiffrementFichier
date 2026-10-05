"""
High-level file encryption / decryption and on-disk container format.

Container layout (all modes start with):
  MAGIC (4) | version (1) | mode (1) | payload...

MODE_AES_PASSWORD payload:
  salt (16) | nonce (12) | ciphertext+tag

MODE_RSA_HYBRID payload:
  wrapped_key_len (2, big-endian) | RSA-OAEP(wrapped AES key) | nonce (12) | ciphertext+tag
"""

from __future__ import annotations

import os
import struct
from pathlib import Path

from src import aes_crypto, rsa_crypto
from src.constants import (
    FORMAT_VERSION,
    GCM_NONCE_SIZE,
    MAGIC,
    MODE_AES_PASSWORD,
    MODE_RSA_HYBRID,
    SALT_SIZE,
)


class FileFormatError(ValueError):
    """Raised when the file is not a valid CFEF container."""


def _read_exact(data: bytes, offset: int, size: int) -> tuple[bytes, int]:
    end = offset + size
    if end > len(data):
        raise FileFormatError("Truncated encrypted file")
    return data[offset:end], end


def encrypt_file_aes_password(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    """
    Password-based encryption — good for personal backups on one machine.

    Workflow: random salt → derive AES key from password → encrypt file bytes.
    """
    plaintext = input_path.read_bytes()
    salt = os.urandom(SALT_SIZE)
    key = aes_crypto.derive_key_from_password(password, salt)
    nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, key)

    header = MAGIC + bytes([FORMAT_VERSION, MODE_AES_PASSWORD])
    body = salt + nonce + ciphertext
    output_path.write_bytes(header + body)


def decrypt_file_aes_password(
    input_path: Path,
    output_path: Path,
    password: str,
) -> None:
    data = input_path.read_bytes()
    parts = _parse_aes_password_payload(data)
    key = aes_crypto.derive_key_from_password(password, parts["salt"])
    try:
        decrypted = aes_crypto.decrypt_bytes(
            parts["nonce"], parts["ciphertext"], key
        )
    except Exception as exc:
        raise ValueError(
            "Decryption failed: wrong password or file was modified"
        ) from exc
    output_path.write_bytes(decrypted)


def _parse_aes_password_payload(data: bytes) -> dict[str, bytes]:
    offset = _parse_header(data, MODE_AES_PASSWORD)
    salt, offset = _read_exact(data, offset, SALT_SIZE)
    nonce, offset = _read_exact(data, offset, GCM_NONCE_SIZE)
    ciphertext = data[offset:]
    return {"salt": salt, "nonce": nonce, "ciphertext": ciphertext}


def encrypt_file_rsa_hybrid(
    input_path: Path,
    output_path: Path,
    public_key_path: Path,
) -> None:
    """
    Hybrid encryption — how production systems protect large files.

    1. Generate random AES data key (never derived from a password here).
    2. Encrypt file with AES-GCM.
    3. Encrypt the small AES key with RSA public key.
    """
    public_key = rsa_crypto.load_public_key_pem(public_key_path)
    plaintext = input_path.read_bytes()

    data_key = aes_crypto.generate_data_key()
    nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, data_key)
    wrapped_key = rsa_crypto.wrap_aes_key(data_key, public_key)

    if len(wrapped_key) > 65535:
        raise ValueError("Wrapped key too large for container format")

    header = MAGIC + bytes([FORMAT_VERSION, MODE_RSA_HYBRID])
    body = struct.pack(">H", len(wrapped_key)) + wrapped_key + nonce + ciphertext
    output_path.write_bytes(header + body)


def decrypt_file_rsa_hybrid(
    input_path: Path,
    output_path: Path,
    private_key_path: Path,
    pem_password: str | None,
) -> None:
    private_key = rsa_crypto.load_private_key_pem(private_key_path, pem_password)
    data = input_path.read_bytes()
    offset = _parse_header(data, MODE_RSA_HYBRID)

    wrapped_len = struct.unpack(">H", data[offset : offset + 2])[0]
    offset += 2
    wrapped_key, offset = _read_exact(data, offset, wrapped_len)
    nonce, offset = _read_exact(data, offset, GCM_NONCE_SIZE)
    ciphertext = data[offset:]

    try:
        data_key = rsa_crypto.unwrap_aes_key(wrapped_key, private_key)
        plaintext = aes_crypto.decrypt_bytes(nonce, ciphertext, data_key)
    except Exception as exc:
        raise ValueError(
            "Decryption failed: wrong key, corrupted file, or tampered data"
        ) from exc
    output_path.write_bytes(plaintext)


def _parse_header(data: bytes, expected_mode: int) -> int:
    if len(data) < 6:
        raise FileFormatError("File too short")
    if data[:4] != MAGIC:
        raise FileFormatError("Not a CFEF encrypted file (bad magic)")
    version = data[4]
    mode = data[5]
    if version != FORMAT_VERSION:
        raise FileFormatError(f"Unsupported format version: {version}")
    if mode != expected_mode:
        raise FileFormatError(f"Expected mode {expected_mode:#x}, got {mode:#x}")
    return 6
