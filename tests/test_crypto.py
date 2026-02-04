"""Tests for cryptoid.crypto module (v2 multi-user key-wrapping)."""

import json
import base64
import pytest

from cryptoid.crypto import (
    encrypt,
    decrypt,
    content_hash,
    rewrap_keys,
    validate_username,
    generate_salt,
    salt_to_hex,
    hex_to_salt,
    CryptoidError,
    _build_secret,
    _wrap_key,
    _unwrap_key,
    _derive_key,
    SALT_LENGTH,
    KEY_LENGTH,
    IV_LENGTH,
)


class TestBuildSecret:
    """Test secret string construction."""

    def test_with_username(self):
        assert _build_secret("pass", "alice") == "alice:pass"

    def test_without_username(self):
        assert _build_secret("pass") == "pass"

    def test_with_none_username(self):
        assert _build_secret("pass", None) == "pass"


class TestKeyWrapping:
    """Test low-level key wrap/unwrap."""

    def test_wrap_unwrap_roundtrip(self):
        """Wrapped key can be unwrapped with the same wrapping key."""
        salt = generate_salt()
        wrapping_key = _derive_key("alice:password", salt)
        cek = b"\x42" * KEY_LENGTH

        iv, ct = _wrap_key(cek, wrapping_key)
        result = _unwrap_key(iv, ct, wrapping_key)

        assert result == cek

    def test_unwrap_wrong_key_returns_none(self):
        """Wrong wrapping key returns None."""
        salt = generate_salt()
        right_key = _derive_key("alice:password", salt)
        wrong_key = _derive_key("bob:password", salt)
        cek = b"\x42" * KEY_LENGTH

        iv, ct = _wrap_key(cek, right_key)
        result = _unwrap_key(iv, ct, wrong_key)

        assert result is None

    def test_wrap_produces_different_iv_each_time(self):
        """Each wrap generates a unique IV."""
        salt = generate_salt()
        wrapping_key = _derive_key("alice:password", salt)
        cek = b"\x42" * KEY_LENGTH

        iv1, _ = _wrap_key(cek, wrapping_key)
        iv2, _ = _wrap_key(cek, wrapping_key)

        assert iv1 != iv2


class TestValidateUsername:
    """Test username validation."""

    def test_valid_username(self):
        validate_username("alice")  # Should not raise

    def test_empty_username_raises(self):
        with pytest.raises(CryptoidError, match="empty"):
            validate_username("")

    def test_colon_in_username_raises(self):
        with pytest.raises(CryptoidError, match=":"):
            validate_username("alice:bob")

    def test_unicode_username(self):
        validate_username("アリス")  # Should not raise


class TestEncryptDecrypt:
    """Test encrypt/decrypt round-trip with multi-user key wrapping."""

    def test_round_trip_single_user(self):
        """Single user encrypt/decrypt round-trip."""
        users = {"alice": "password123"}
        plaintext = "Hello, secret world!"

        ciphertext = encrypt(plaintext, users)
        decrypted = decrypt(ciphertext, "password123", "alice")

        assert decrypted == plaintext

    def test_round_trip_multi_user(self):
        """Multiple users can each decrypt the same content."""
        users = {"alice": "pass-a", "bob": "pass-b", "carol": "pass-c"}
        plaintext = "Team secret"

        ciphertext = encrypt(plaintext, users)

        for username, password in users.items():
            assert decrypt(ciphertext, password, username) == plaintext

    def test_wrong_user_fails(self):
        """User not in the encrypted set cannot decrypt."""
        users = {"alice": "pass-a"}
        ciphertext = encrypt("secret", users)

        with pytest.raises(CryptoidError, match="[Dd]ecryption failed"):
            decrypt(ciphertext, "pass-b", "bob")

    def test_wrong_password_fails(self):
        """Wrong password for a valid user fails."""
        users = {"alice": "correct-pass"}
        ciphertext = encrypt("secret", users)

        with pytest.raises(CryptoidError, match="[Dd]ecryption failed"):
            decrypt(ciphertext, "wrong-pass", "alice")

    def test_round_trip_unicode(self):
        """Unicode content survives encryption round-trip."""
        plaintext = "こんにちは世界 🔐 émojis and ümlauts"
        users = {"alice": "unicode-password-αβγ"}

        ciphertext = encrypt(plaintext, users)
        decrypted = decrypt(ciphertext, "unicode-password-αβγ", "alice")

        assert decrypted == plaintext

    def test_round_trip_large_content(self):
        """Large content encrypts correctly."""
        plaintext = "# Secret Blog Post\n\n" + ("Lorem ipsum dolor sit amet. " * 500)
        users = {"alice": "blog-password"}

        ciphertext = encrypt(plaintext, users)
        decrypted = decrypt(ciphertext, "blog-password", "alice")

        assert decrypted == plaintext

    def test_round_trip_empty_content(self):
        """Empty string can be encrypted and decrypted."""
        users = {"alice": "password"}

        ciphertext = encrypt("", users)
        decrypted = decrypt(ciphertext, "password", "alice")

        assert decrypted == ""

    def test_with_explicit_salt(self):
        """Encryption with explicit salt works."""
        salt = generate_salt()
        users = {"alice": "password"}

        ciphertext = encrypt("secret", users, salt=salt)
        decrypted = decrypt(ciphertext, "password", "alice")

        assert decrypted == "secret"

    def test_empty_users_raises(self):
        """Empty users dict raises error."""
        with pytest.raises(CryptoidError, match="at least one user"):
            encrypt("secret", {})

    def test_invalid_username_raises(self):
        """Username with ':' raises during encrypt."""
        with pytest.raises(CryptoidError, match=":"):
            encrypt("secret", {"alice:bob": "password"})

    def test_invalid_salt_length_raises(self):
        """Wrong salt length raises error."""
        with pytest.raises(CryptoidError, match="Salt must be"):
            encrypt("secret", {"alice": "password"}, salt=b"short")


class TestCiphertextFormat:
    """Test the v2 ciphertext output format."""

    def test_output_is_base64(self):
        """Ciphertext output is valid base64."""
        ciphertext = encrypt("test", {"alice": "password"})
        decoded = base64.b64decode(ciphertext)
        assert isinstance(decoded, bytes)

    def test_output_contains_v2_fields(self):
        """Ciphertext JSON contains all required v2 fields."""
        ciphertext = encrypt("test", {"alice": "password"})
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)

        assert data["v"] == 2
        assert data["alg"] == "aes-256-gcm"
        assert data["kdf"] == "pbkdf2-sha256"
        assert data["iter"] == 310000
        assert "salt" in data
        assert "iv" in data
        assert "ct" in data
        assert "keys" in data
        assert isinstance(data["keys"], list)

    def test_key_blob_count_matches_users(self):
        """Number of key blobs matches number of users."""
        users = {"alice": "a", "bob": "b", "carol": "c"}
        ciphertext = encrypt("test", users)
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)

        assert len(data["keys"]) == 3

    def test_key_blob_has_iv_and_ct(self):
        """Each key blob has iv and ct fields."""
        ciphertext = encrypt("test", {"alice": "password"})
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)

        for blob in data["keys"]:
            assert "iv" in blob
            assert "ct" in blob
            # IV and CT should be valid base64
            base64.b64decode(blob["iv"])
            base64.b64decode(blob["ct"])

    def test_salt_is_16_bytes(self):
        ciphertext = encrypt("test", {"alice": "password"})
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)
        salt = base64.b64decode(data["salt"])
        assert len(salt) == 16

    def test_iv_is_12_bytes(self):
        ciphertext = encrypt("test", {"alice": "password"})
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)
        iv = base64.b64decode(data["iv"])
        assert len(iv) == 12

    def test_output_is_html_safe(self):
        """Ciphertext is safe for HTML embedding."""
        dangerous = '</script></template><img onerror="alert(1)">'
        ciphertext = encrypt(dangerous, {"alice": "password"})

        import re
        assert re.fullmatch(r'[A-Za-z0-9+/=]+', ciphertext)
        assert "<" not in ciphertext
        assert ">" not in ciphertext

        assert decrypt(ciphertext, "password", "alice") == dangerous

    def test_different_encryptions_produce_different_output(self):
        """Same inputs produce different ciphertext each time."""
        users = {"alice": "password"}
        ct1 = encrypt("same", users)
        ct2 = encrypt("same", users)

        assert ct1 != ct2
        assert decrypt(ct1, "password", "alice") == "same"
        assert decrypt(ct2, "password", "alice") == "same"


class TestDecryptionErrors:
    """Test error handling during decryption."""

    def test_malformed_base64_raises(self):
        with pytest.raises(CryptoidError, match="[Ii]nvalid"):
            decrypt("not-valid-base64!!!", "password", "alice")

    def test_malformed_json_raises(self):
        bad = base64.b64encode(b"not json").decode()
        with pytest.raises(CryptoidError, match="[Ii]nvalid"):
            decrypt(bad, "password", "alice")

    def test_missing_fields_raises(self):
        incomplete = base64.b64encode(json.dumps({"v": 2}).encode()).decode()
        with pytest.raises(CryptoidError, match="[Mm]issing|[Ii]nvalid"):
            decrypt(incomplete, "password", "alice")

    def test_unsupported_version_raises(self):
        future_version = base64.b64encode(
            json.dumps({
                "v": 99,
                "alg": "aes-256-gcm",
                "kdf": "pbkdf2-sha256",
                "iter": 310000,
                "salt": base64.b64encode(b"x" * 16).decode(),
                "iv": base64.b64encode(b"x" * 12).decode(),
                "ct": base64.b64encode(b"x" * 32).decode(),
                "keys": [{"iv": "AA==", "ct": "AA=="}],
            }).encode()
        ).decode()

        with pytest.raises(CryptoidError, match="[Uu]nsupported|[Vv]ersion"):
            decrypt(future_version, "password", "alice")

    def test_empty_keys_array_raises(self):
        payload = base64.b64encode(
            json.dumps({
                "v": 2,
                "alg": "aes-256-gcm",
                "kdf": "pbkdf2-sha256",
                "iter": 310000,
                "salt": base64.b64encode(b"x" * 16).decode(),
                "iv": base64.b64encode(b"x" * 12).decode(),
                "ct": base64.b64encode(b"x" * 32).decode(),
                "keys": [],
            }).encode()
        ).decode()

        with pytest.raises(CryptoidError, match="[Ii]nvalid|empty"):
            decrypt(payload, "password", "alice")

    def test_tampered_ciphertext_raises(self):
        """Tampered content ciphertext is detected."""
        ciphertext = encrypt("secret", {"alice": "password"})
        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)

        ct_bytes = bytearray(base64.b64decode(data["ct"]))
        ct_bytes[0] ^= 0xFF
        data["ct"] = base64.b64encode(bytes(ct_bytes)).decode()

        tampered = base64.b64encode(json.dumps(data).encode()).decode()

        with pytest.raises(CryptoidError, match="[Dd]ecryption failed"):
            decrypt(tampered, "password", "alice")


class TestRewrapKeys:
    """Test key re-wrapping functionality."""

    def test_rewrap_add_user(self):
        """Rewrap to add a new user."""
        old_users = {"alice": "pass-a"}
        new_users = {"alice": "pass-a", "bob": "pass-b"}

        ciphertext = encrypt("secret", old_users)
        rewrapped = rewrap_keys(ciphertext, old_users, new_users)

        # Both users can decrypt
        assert decrypt(rewrapped, "pass-a", "alice") == "secret"
        assert decrypt(rewrapped, "pass-b", "bob") == "secret"

    def test_rewrap_remove_user(self):
        """Rewrap to remove a user."""
        old_users = {"alice": "pass-a", "bob": "pass-b"}
        new_users = {"alice": "pass-a"}

        ciphertext = encrypt("secret", old_users)
        rewrapped = rewrap_keys(ciphertext, old_users, new_users)

        # Alice can still decrypt
        assert decrypt(rewrapped, "pass-a", "alice") == "secret"

        # Bob can no longer decrypt
        with pytest.raises(CryptoidError):
            decrypt(rewrapped, "pass-b", "bob")

    def test_rewrap_change_password(self):
        """Rewrap after changing a user's password."""
        old_users = {"alice": "old-pass"}
        new_users = {"alice": "new-pass"}

        ciphertext = encrypt("secret", old_users)
        rewrapped = rewrap_keys(ciphertext, old_users, new_users)

        # New password works
        assert decrypt(rewrapped, "new-pass", "alice") == "secret"

        # Old password no longer works
        with pytest.raises(CryptoidError):
            decrypt(rewrapped, "old-pass", "alice")

    def test_rewrap_with_rekey(self):
        """Rekey generates new CEK and re-encrypts content."""
        old_users = {"alice": "pass-a"}
        new_users = {"alice": "pass-a", "bob": "pass-b"}

        ciphertext = encrypt("secret", old_users)
        rewrapped = rewrap_keys(ciphertext, old_users, new_users, rekey=True)

        # Content still decrypts correctly
        assert decrypt(rewrapped, "pass-a", "alice") == "secret"
        assert decrypt(rewrapped, "pass-b", "bob") == "secret"

        # Payloads should differ (new CEK + IV)
        old_data = json.loads(base64.b64decode(ciphertext))
        new_data = json.loads(base64.b64decode(rewrapped))
        assert old_data["ct"] != new_data["ct"]
        assert old_data["iv"] != new_data["iv"]

    def test_rewrap_no_old_users_raises(self):
        with pytest.raises(CryptoidError, match="old_users"):
            rewrap_keys("payload", {}, {"alice": "pass"})

    def test_rewrap_no_new_users_raises(self):
        with pytest.raises(CryptoidError, match="new_users"):
            rewrap_keys("payload", {"alice": "pass"}, {})

    def test_rewrap_wrong_credentials_raises(self):
        ciphertext = encrypt("secret", {"alice": "pass-a"})
        with pytest.raises(CryptoidError, match="Cannot recover CEK"):
            rewrap_keys(ciphertext, {"bob": "wrong"}, {"carol": "new"})


class TestSaltUtilities:
    """Test salt generation and conversion."""

    def test_generate_salt_length(self):
        salt = generate_salt()
        assert len(salt) == SALT_LENGTH

    def test_generate_salt_random(self):
        s1 = generate_salt()
        s2 = generate_salt()
        assert s1 != s2

    def test_salt_hex_roundtrip(self):
        salt = generate_salt()
        hex_str = salt_to_hex(salt)
        recovered = hex_to_salt(hex_str)
        assert recovered == salt

    def test_hex_to_salt_wrong_length_raises(self):
        with pytest.raises(CryptoidError, match="Salt must be"):
            hex_to_salt("aabb")

    def test_hex_to_salt_invalid_hex_raises(self):
        with pytest.raises(CryptoidError, match="[Ii]nvalid hex"):
            hex_to_salt("not-hex-string-of-right-length!")

    def test_salt_to_hex_format(self):
        salt = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff"
        assert salt_to_hex(salt) == "00112233445566778899aabbccddeeff"


class TestContentHash:
    """Test content_hash() function for integrity verification."""

    def test_hash_length(self):
        result = content_hash("test content")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_deterministic(self):
        content = "Hello, world!"
        assert content_hash(content) == content_hash(content)

    def test_hash_different_content(self):
        assert content_hash("content A") != content_hash("content B")

    def test_hash_empty_content(self):
        result = content_hash("")
        assert len(result) == 32
        assert result == "e3b0c44298fc1c149afbf4c8996fb924"

    def test_hash_unicode_content(self):
        result = content_hash("こんにちは世界 🔐")
        assert len(result) == 32
        assert all(c in "0123456789abcdef" for c in result)

    def test_hash_large_content(self):
        result = content_hash("x" * 100000)
        assert len(result) == 32

    def test_hash_whitespace_sensitive(self):
        h1 = content_hash("content")
        h2 = content_hash("content ")
        h3 = content_hash(" content")
        assert h1 != h2
        assert h1 != h3
        assert h2 != h3
