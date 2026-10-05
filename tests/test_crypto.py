import os

import pytest

from src import aes_crypto, constants, file_encryptor, rsa_crypto


class TestAESCrypto:
    """Tests for AES-GCM + PBKDF2 primitives."""

    def test_derive_key_from_password_deterministic(self):
        """Same password + same salt = same key."""
        password = "test-password-123"
        salt = os.urandom(constants.SALT_SIZE)
        key1 = aes_crypto.derive_key_from_password(password, salt)
        key2 = aes_crypto.derive_key_from_password(password, salt)
        assert key1 == key2
        assert len(key1) == constants.AES_KEY_SIZE

    def test_derive_key_from_password_different_salt(self):
        """Different salt = different key."""
        password = "test-password-123"
        salt1 = os.urandom(constants.SALT_SIZE)
        salt2 = os.urandom(constants.SALT_SIZE)
        key1 = aes_crypto.derive_key_from_password(password, salt1)
        key2 = aes_crypto.derive_key_from_password(password, salt2)
        assert key1 != key2

    def test_derive_key_wrong_salt_size_raises(self):
        """Invalid salt size should raise ValueError."""
        with pytest.raises(ValueError, match="Salt must be 16 bytes"):
            aes_crypto.derive_key_from_password("pwd", b"short")

    def test_generate_data_key_random(self):
        """Each call should produce different random key."""
        key1 = aes_crypto.generate_data_key()
        key2 = aes_crypto.generate_data_key()
        assert key1 != key2
        assert len(key1) == constants.AES_KEY_SIZE

    def test_encrypt_decrypt_roundtrip(self):
        """Encrypt then decrypt should recover plaintext."""
        key = aes_crypto.generate_data_key()
        plaintext = b"Hello, World! This is a test message."
        nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, key)
        decrypted = aes_crypto.decrypt_bytes(nonce, ciphertext, key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_large_data(self):
        """Test with larger payload (1MB)."""
        key = aes_crypto.generate_data_key()
        plaintext = os.urandom(1024 * 1024)
        nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, key)
        decrypted = aes_crypto.decrypt_bytes(nonce, ciphertext, key)
        assert decrypted == plaintext

    def test_encrypt_decrypt_empty_data(self):
        """Test with empty payload."""
        key = aes_crypto.generate_data_key()
        plaintext = b""
        nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, key)
        decrypted = aes_crypto.decrypt_bytes(nonce, ciphertext, key)
        assert decrypted == plaintext

    def test_wrong_key_fails(self):
        """Decrypting with wrong key should raise."""
        key1 = aes_crypto.generate_data_key()
        key2 = aes_crypto.generate_data_key()
        plaintext = b"secret"
        nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, key1)
        with pytest.raises(Exception):  # GCM tag verification fails
            aes_crypto.decrypt_bytes(nonce, ciphertext, key2)

    def test_tampered_ciphertext_fails(self):
        """Modified ciphertext should fail decryption."""
        key = aes_crypto.generate_data_key()
        plaintext = b"secret message"
        nonce, ciphertext = aes_crypto.encrypt_bytes(plaintext, key)
        # Flip a bit in ciphertext
        tampered = bytearray(ciphertext)
        tampered[0] ^= 0xFF
        with pytest.raises(Exception):
            aes_crypto.decrypt_bytes(nonce, bytes(tampered), key)

    def test_nonce_uniqueness(self):
        """Each encryption should generate unique nonce."""
        key = aes_crypto.generate_data_key()
        plaintext = b"same plaintext"
        nonces = set()
        for _ in range(100):
            nonce, _ = aes_crypto.encrypt_bytes(plaintext, key)
            assert nonce not in nonces
            nonces.add(nonce)


class TestRSACrypto:
    """Tests for RSA-OAEP key wrapping."""

    @pytest.fixture
    def keypair(self):
        return rsa_crypto.generate_rsa_keypair()

    def test_generate_keypair(self, keypair):
        """Keypair generation should produce valid keys."""
        private_key, public_key = keypair
        assert private_key is not None
        assert public_key is not None
        assert private_key.key_size == constants.RSA_KEY_SIZE

    def test_wrap_unwrap_roundtrip(self, keypair):
        """Wrap then unwrap should recover AES key."""
        private_key, public_key = keypair
        aes_key = os.urandom(constants.AES_KEY_SIZE)
        wrapped = rsa_crypto.wrap_aes_key(aes_key, public_key)
        unwrapped = rsa_crypto.unwrap_aes_key(wrapped, private_key)
        assert unwrapped == aes_key

    def test_wrap_unwrap_different_keys(self, keypair):
        """Different AES keys produce different wrapped output."""
        private_key, public_key = keypair
        key1 = os.urandom(constants.AES_KEY_SIZE)
        key2 = os.urandom(constants.AES_KEY_SIZE)
        wrapped1 = rsa_crypto.wrap_aes_key(key1, public_key)
        wrapped2 = rsa_crypto.wrap_aes_key(key2, public_key)
        assert wrapped1 != wrapped2

    def test_unwrap_wrong_key_fails(self, keypair):
        """Unwrap with wrong private key should fail."""
        private_key, public_key = keypair
        other_private, _ = rsa_crypto.generate_rsa_keypair()
        aes_key = os.urandom(constants.AES_KEY_SIZE)
        wrapped = rsa_crypto.wrap_aes_key(aes_key, public_key)
        with pytest.raises(Exception):
            rsa_crypto.unwrap_aes_key(wrapped, other_private)

    def test_pem_serialization_roundtrip(self, keypair, tmp_path):
        """Save/load PEM should preserve keys."""
        private_key, public_key = keypair
        priv_path = tmp_path / "private.pem"
        pub_path = tmp_path / "public.pem"

        rsa_crypto.save_private_key_pem(private_key, priv_path, None)
        rsa_crypto.save_public_key_pem(public_key, pub_path)

        loaded_priv = rsa_crypto.load_private_key_pem(priv_path, None)
        loaded_pub = rsa_crypto.load_public_key_pem(pub_path)

        # Test they work the same
        aes_key = os.urandom(constants.AES_KEY_SIZE)
        wrapped = rsa_crypto.wrap_aes_key(aes_key, loaded_pub)
        unwrapped = rsa_crypto.unwrap_aes_key(wrapped, loaded_priv)
        assert unwrapped == aes_key

    def test_pem_with_password(self, keypair, tmp_path):
        """Password-protected PEM should require password to load."""
        private_key, public_key = keypair
        priv_path = tmp_path / "private_enc.pem"

        rsa_crypto.save_private_key_pem(private_key, priv_path, "mypassword")

        # Should load with correct password
        loaded = rsa_crypto.load_private_key_pem(priv_path, "mypassword")
        assert loaded is not None

        # Should fail with wrong password
        with pytest.raises(Exception):
            rsa_crypto.load_private_key_pem(priv_path, "wrongpassword")

        # Should fail with no password
        with pytest.raises(Exception):
            rsa_crypto.load_private_key_pem(priv_path, None)


class TestFileEncryptorAES:
    """Tests for AES password-based file encryption."""

    def test_encrypt_decrypt_file_aes(self, tmp_path):
        """Full file encrypt/decrypt roundtrip."""
        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        output_file = tmp_path / "test_decrypted.txt"

        plaintext = b"This is a test file content.\nWith multiple lines.\n"
        input_file.write_bytes(plaintext)

        password = "my-secret-password-123"
        file_encryptor.encrypt_file_aes_password(input_file, encrypted_file, password)
        file_encryptor.decrypt_file_aes_password(encrypted_file, output_file, password)

        assert output_file.read_bytes() == plaintext

    def test_encrypt_decrypt_large_file(self, tmp_path):
        """Test with 10MB file."""
        input_file = tmp_path / "large.bin"
        encrypted_file = tmp_path / "large.bin.enc"
        output_file = tmp_path / "large_decrypted.bin"

        plaintext = os.urandom(10 * 1024 * 1024)
        input_file.write_bytes(plaintext)

        password = "large-file-password"
        file_encryptor.encrypt_file_aes_password(input_file, encrypted_file, password)
        file_encryptor.decrypt_file_aes_password(encrypted_file, output_file, password)

        assert output_file.read_bytes() == plaintext

    def test_wrong_password_fails(self, tmp_path):
        """Decrypt with wrong password should raise ValueError."""
        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        output_file = tmp_path / "test_decrypted.txt"

        input_file.write_bytes(b"secret")
        file_encryptor.encrypt_file_aes_password(input_file, encrypted_file, "correct")
        with pytest.raises(ValueError, match="Decryption failed"):
            file_encryptor.decrypt_file_aes_password(encrypted_file, output_file, "wrong")

    def test_tampered_file_fails(self, tmp_path):
        """Modified encrypted file should fail."""
        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        output_file = tmp_path / "test_decrypted.txt"

        input_file.write_bytes(b"secret")
        file_encryptor.encrypt_file_aes_password(input_file, encrypted_file, "password")

        # Tamper with encrypted file
        data = bytearray(encrypted_file.read_bytes())
        data[-1] ^= 0xFF  # Flip last bit
        encrypted_file.write_bytes(data)

        with pytest.raises(ValueError, match="Decryption failed"):
            file_encryptor.decrypt_file_aes_password(encrypted_file, output_file, "password")

    def test_file_format_error_on_non_cfef(self, tmp_path):
        """Non-CFEF file should raise FileFormatError."""
        input_file = tmp_path / "fake.enc"
        output_file = tmp_path / "out.txt"
        input_file.write_bytes(b"not a cfef file")

        with pytest.raises(file_encryptor.FileFormatError, match="bad magic"):
            file_encryptor.decrypt_file_aes_password(input_file, output_file, "pwd")

    def test_different_passwords_produce_different_ciphertext(self, tmp_path):
        """Same plaintext, different passwords = different ciphertext."""
        input_file = tmp_path / "test.txt"
        enc1 = tmp_path / "test1.enc"
        enc2 = tmp_path / "test2.enc"

        input_file.write_bytes(b"same content")
        file_encryptor.encrypt_file_aes_password(input_file, enc1, "password1")
        file_encryptor.encrypt_file_aes_password(input_file, enc2, "password2")

        assert enc1.read_bytes() != enc2.read_bytes()

    def test_aes_container_format(self, tmp_path):
        """Verify CFEF container structure for AES mode."""
        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        input_file.write_bytes(b"test content")

        file_encryptor.encrypt_file_aes_password(input_file, encrypted_file, "pwd")
        data = encrypted_file.read_bytes()

        # Check header
        assert data[:4] == constants.MAGIC
        assert data[4] == constants.FORMAT_VERSION
        assert data[5] == constants.MODE_AES_PASSWORD

        # Payload: salt(16) + nonce(12) + ciphertext
        payload = data[6:]
        assert len(payload) >= constants.SALT_SIZE + constants.GCM_NONCE_SIZE


class TestFileEncryptorHybrid:
    """Tests for RSA hybrid file encryption."""

    @pytest.fixture
    def keypair_files(self, tmp_path):
        """Generate keypair and save to temp files."""
        private_key, public_key = rsa_crypto.generate_rsa_keypair()
        priv_path = tmp_path / "private.pem"
        pub_path = tmp_path / "public.pem"
        rsa_crypto.save_private_key_pem(private_key, priv_path, None)
        rsa_crypto.save_public_key_pem(public_key, pub_path)
        return priv_path, pub_path

    def test_encrypt_decrypt_file_hybrid(self, tmp_path, keypair_files):
        """Full hybrid encrypt/decrypt roundtrip."""
        priv_path, pub_path = keypair_files
        input_file = tmp_path / "secret.txt"
        encrypted_file = tmp_path / "secret.txt.enc"
        output_file = tmp_path / "secret_decrypted.txt"

        plaintext = b"Hybrid encryption test content."
        input_file.write_bytes(plaintext)

        file_encryptor.encrypt_file_rsa_hybrid(input_file, encrypted_file, pub_path)
        file_encryptor.decrypt_file_rsa_hybrid(encrypted_file, output_file, priv_path, None)

        assert output_file.read_bytes() == plaintext

    def test_encrypt_decrypt_large_file_hybrid(self, tmp_path, keypair_files):
        """Hybrid with 10MB file."""
        priv_path, pub_path = keypair_files
        input_file = tmp_path / "large.bin"
        encrypted_file = tmp_path / "large.bin.enc"
        output_file = tmp_path / "large_decrypted.bin"

        plaintext = os.urandom(10 * 1024 * 1024)
        input_file.write_bytes(plaintext)

        file_encryptor.encrypt_file_rsa_hybrid(input_file, encrypted_file, pub_path)
        file_encryptor.decrypt_file_rsa_hybrid(encrypted_file, output_file, priv_path, None)

        assert output_file.read_bytes() == plaintext

    def test_wrong_private_key_fails(self, tmp_path, keypair_files):
        """Decrypt with different private key should fail."""
        _, pub_path = keypair_files
        other_priv, _ = rsa_crypto.generate_rsa_keypair()
        other_priv_path = tmp_path / "other_private.pem"
        rsa_crypto.save_private_key_pem(other_priv, other_priv_path, None)

        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        output_file = tmp_path / "out.txt"

        input_file.write_bytes(b"secret")
        file_encryptor.encrypt_file_rsa_hybrid(input_file, encrypted_file, pub_path)

        with pytest.raises(ValueError, match="Decryption failed"):
            file_encryptor.decrypt_file_rsa_hybrid(encrypted_file, output_file, other_priv_path, None)

    def test_hybrid_container_format(self, tmp_path, keypair_files):
        """Verify CFEF container structure for hybrid mode."""
        _, pub_path = keypair_files
        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        input_file.write_bytes(b"test")

        file_encryptor.encrypt_file_rsa_hybrid(input_file, encrypted_file, pub_path)
        data = encrypted_file.read_bytes()

        # Check header
        assert data[:4] == constants.MAGIC
        assert data[4] == constants.FORMAT_VERSION
        assert data[5] == constants.MODE_RSA_HYBRID

        # Payload: wrapped_key_len(2) + wrapped_key + nonce(12) + ciphertext
        payload = data[6:]
        import struct
        wrapped_len = struct.unpack(">H", payload[:2])[0]
        assert wrapped_len > 0
        assert wrapped_len <= 65535

    def test_hybrid_with_password_protected_private_key(self, tmp_path, keypair_files):
        """Hybrid decrypt with password-protected private key."""
        priv_path, pub_path = keypair_files
        # Re-save private key with password
        private_key = rsa_crypto.load_private_key_pem(priv_path, None)
        enc_priv_path = tmp_path / "private_enc.pem"
        rsa_crypto.save_private_key_pem(private_key, enc_priv_path, "keypassword")

        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        output_file = tmp_path / "out.txt"

        input_file.write_bytes(b"protected key test")
        file_encryptor.encrypt_file_rsa_hybrid(input_file, encrypted_file, pub_path)
        file_encryptor.decrypt_file_rsa_hybrid(encrypted_file, output_file, enc_priv_path, "keypassword")

        assert output_file.read_bytes() == b"protected key test"

    def test_hybrid_wrong_pem_password_fails(self, tmp_path, keypair_files):
        """Wrong PEM password should fail."""
        priv_path, pub_path = keypair_files
        private_key = rsa_crypto.load_private_key_pem(priv_path, None)
        enc_priv_path = tmp_path / "private_enc.pem"
        rsa_crypto.save_private_key_pem(private_key, enc_priv_path, "keypassword")

        input_file = tmp_path / "test.txt"
        encrypted_file = tmp_path / "test.txt.enc"
        output_file = tmp_path / "out.txt"

        input_file.write_bytes(b"test")
        file_encryptor.encrypt_file_rsa_hybrid(input_file, encrypted_file, pub_path)

        with pytest.raises(Exception):
            file_encryptor.decrypt_file_rsa_hybrid(encrypted_file, output_file, enc_priv_path, "wrong")


class TestConstants:
    """Test constants values."""

    def test_magic_bytes(self):
        assert constants.MAGIC == b"CFEF"

    def test_format_version(self):
        assert constants.FORMAT_VERSION == 1

    def test_mode_values(self):
        assert constants.MODE_AES_PASSWORD == 0x01
        assert constants.MODE_RSA_HYBRID == 0x02

    def test_key_sizes(self):
        assert constants.AES_KEY_SIZE == 32
        assert constants.GCM_NONCE_SIZE == 12
        assert constants.SALT_SIZE == 16
        assert constants.RSA_KEY_SIZE == 4096

    def test_pbkdf2_iterations(self):
        assert constants.PBKDF2_ITERATIONS == 600_000


class TestCLI:
    """Basic CLI integration tests."""

    def test_main_help(self):
        """Main help should work."""
        import sys
        from io import StringIO

        from main import build_parser
        parser = build_parser()
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            parser.parse_args(["--help"])
        except SystemExit:
            pass
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        assert "encrypt" in output
        assert "decrypt" in output
        assert "keygen" in output

    def test_keygen_help(self):
        import sys
        from io import StringIO

        from main import build_parser
        parser = build_parser()
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            parser.parse_args(["keygen", "--help"])
        except SystemExit:
            pass
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        assert "private" in output

    def test_encrypt_help(self):
        import sys
        from io import StringIO

        from main import build_parser
        parser = build_parser()
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            parser.parse_args(["encrypt", "--help"])
        except SystemExit:
            pass
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        assert "mode" in output


# Run with: pytest tests/ -v
