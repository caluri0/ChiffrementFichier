"""Local file encryption toolkit for portfolio and learning."""

from src.aes_crypto import (
    decrypt_bytes,
    derive_key_from_password,
    encrypt_bytes,
    generate_data_key,
)
from src.constants import (
    AES_KEY_SIZE,
    FORMAT_VERSION,
    GCM_NONCE_SIZE,
    MAGIC,
    MODE_AES_PASSWORD,
    MODE_RSA_HYBRID,
    PBKDF2_ITERATIONS,
    RSA_KEY_SIZE,
    SALT_SIZE,
)
from src.file_encryptor import (
    FileFormatError,
    decrypt_file_aes_password,
    decrypt_file_rsa_hybrid,
    encrypt_file_aes_password,
    encrypt_file_rsa_hybrid,
)
from src.rsa_crypto import (
    generate_rsa_keypair,
    load_private_key_pem,
    load_public_key_pem,
    save_private_key_pem,
    save_public_key_pem,
    unwrap_aes_key,
    wrap_aes_key,
)

__all__ = [
    # aes_crypto
    "derive_key_from_password",
    "generate_data_key",
    "encrypt_bytes",
    "decrypt_bytes",
    # constants
    "MAGIC",
    "FORMAT_VERSION",
    "MODE_AES_PASSWORD",
    "MODE_RSA_HYBRID",
    "AES_KEY_SIZE",
    "GCM_NONCE_SIZE",
    "SALT_SIZE",
    "PBKDF2_ITERATIONS",
    "RSA_KEY_SIZE",
    # file_encryptor
    "encrypt_file_aes_password",
    "decrypt_file_aes_password",
    "encrypt_file_rsa_hybrid",
    "decrypt_file_rsa_hybrid",
    "FileFormatError",
    # rsa_crypto
    "generate_rsa_keypair",
    "save_private_key_pem",
    "save_public_key_pem",
    "load_private_key_pem",
    "load_public_key_pem",
    "wrap_aes_key",
    "unwrap_aes_key",
]
