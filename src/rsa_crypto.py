"""
Asymmetric encryption with RSA-OAEP (SHA-256).

Learning path:
  - RSA: key pair (public / private). Anyone can encrypt with the public key;
    only the private key holder can decrypt. Too slow for large files.
  - Typical pattern: RSA encrypts a small random AES key (hybrid encryption);
    AES encrypts the actual document — same idea as TLS and PGP.
  - OAEP (Optimal Asymmetric Encryption Padding): modern padding that avoids
    many classical RSA pitfalls; never use PKCS#1 v1.5 for new designs.
"""

from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

from src.constants import RSA_KEY_SIZE


def generate_rsa_keypair() -> tuple[RSAPrivateKey, RSAPublicKey]:
    """Create a new RSA key pair (default 4096-bit)."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )
    return private_key, private_key.public_key()


def save_private_key_pem(private_key: RSAPrivateKey, path: Path, password: str | None) -> None:
    """
    Serialize private key to PEM. Optional password encrypts the PEM file
    (protects key at rest — still not a substitute for OS-level security).
    """
    if password:
        encryption: serialization.KeySerializationEncryption = serialization.BestAvailableEncryption(password.encode("utf-8"))
    else:
        encryption = serialization.NoEncryption()

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )
    path.write_bytes(pem)


def save_public_key_pem(public_key: RSAPublicKey, path: Path) -> None:
    """Public keys can be shared; used by senders to encrypt."""
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path.write_bytes(pem)


def load_private_key_pem(path: Path, password: str | None) -> RSAPrivateKey:
    data = path.read_bytes()
    pwd = password.encode("utf-8") if password else None
    key = serialization.load_pem_private_key(data, password=pwd)
    if not isinstance(key, RSAPrivateKey):
        raise TypeError("PEM file does not contain an RSA private key")
    return key


def load_public_key_pem(path: Path) -> RSAPublicKey:
    data = path.read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, RSAPublicKey):
        raise TypeError("PEM file does not contain an RSA public key")
    return key


def _oaep_padding() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def wrap_aes_key(aes_key: bytes, public_key: RSAPublicKey) -> bytes:
    """Encrypt the symmetric data key with RSA public key (key encapsulation)."""
    return public_key.encrypt(aes_key, _oaep_padding())


def unwrap_aes_key(wrapped: bytes, private_key: RSAPrivateKey) -> bytes:
    """Recover the symmetric data key with RSA private key."""
    return private_key.decrypt(wrapped, _oaep_padding())
