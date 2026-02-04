"""Core cryptographic functions for cryptoid.

Provides AES-256-GCM encryption with PBKDF2-SHA256 key derivation,
compatible with WebCrypto API for browser-side decryption.

v2 format uses key-wrapping: content encrypted with random CEK,
CEK wrapped per-user with PBKDF2-derived wrapping keys.
"""

import base64
import hashlib
import json
import os
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class CryptoidError(Exception):
    """Base exception for cryptoid errors."""

    pass


# Cryptographic parameters (must match browser-side implementation)
VERSION = 2
ALGORITHM = "aes-256-gcm"
KDF = "pbkdf2-sha256"
ITERATIONS = 310000
SALT_LENGTH = 16  # 128 bits
IV_LENGTH = 12  # 96 bits (standard for GCM)
KEY_LENGTH = 32  # 256 bits


def _derive_key(secret: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from secret using PBKDF2-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LENGTH,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(secret.encode("utf-8"))


def _build_secret(password: str, username: str | None = None) -> str:
    """Build the secret string for key derivation.

    If username is provided, secret is "username:password".
    Otherwise, secret is just the password.
    """
    if username:
        return f"{username}:{password}"
    return password


def _wrap_key(cek: bytes, wrapping_key: bytes) -> tuple[bytes, bytes]:
    """Wrap a CEK with a wrapping key using AES-256-GCM.

    Args:
        cek: Content Encryption Key to wrap.
        wrapping_key: Key derived from user's password.

    Returns:
        Tuple of (iv, ciphertext) for the wrapped key.
    """
    iv = os.urandom(IV_LENGTH)
    aesgcm = AESGCM(wrapping_key)
    ct = aesgcm.encrypt(iv, cek, None)
    return iv, ct


def _unwrap_key(iv: bytes, ct: bytes, wrapping_key: bytes) -> bytes | None:
    """Unwrap a CEK using a wrapping key.

    Args:
        iv: IV used for wrapping.
        ct: Ciphertext of the wrapped key.
        wrapping_key: Key derived from user's password.

    Returns:
        The unwrapped CEK, or None if the wrapping key is wrong.
    """
    aesgcm = AESGCM(wrapping_key)
    try:
        return aesgcm.decrypt(iv, ct, None)
    except (InvalidTag, Exception):
        return None


def validate_username(username: str) -> None:
    """Validate a username for use in key derivation.

    Raises:
        CryptoidError: If username is empty or contains ':'.
    """
    if not username:
        raise CryptoidError("Username cannot be empty")
    if ":" in username:
        raise CryptoidError(f"Username cannot contain ':': {username!r}")


def encrypt(
    plaintext: str,
    users: dict[str, str],
    salt: bytes | None = None,
    meta: dict | None = None,
) -> str:
    """Encrypt plaintext using v2 key-wrapping format.

    Content is encrypted with a random CEK, which is then wrapped
    for each user.

    Args:
        plaintext: The text to encrypt (can be empty).
        users: Dict of {username: password} for multi-user encryption.
        salt: Optional 16-byte salt. If None, generates random.
        meta: Optional metadata dict to encrypt alongside content.

    Returns:
        Base64-encoded JSON containing all parameters needed for decryption.
    """
    if not users:
        raise CryptoidError("Must provide at least one user")

    for username in users:
        validate_username(username)

    # Use provided salt or generate random
    if salt is None:
        salt = os.urandom(SALT_LENGTH)
    elif len(salt) != SALT_LENGTH:
        raise CryptoidError(f"Salt must be {SALT_LENGTH} bytes, got {len(salt)}")

    # Generate random CEK and content IV
    cek = os.urandom(KEY_LENGTH)
    content_iv = os.urandom(IV_LENGTH)

    # JSON-wrap plaintext with metadata
    inner = json.dumps({"c": plaintext, "m": meta})

    # Encrypt content with CEK
    aesgcm = AESGCM(cek)
    content_ct = aesgcm.encrypt(content_iv, inner.encode("utf-8"), None)

    # Build key blobs — one per user
    keys = []
    for username, password in users.items():
        secret = _build_secret(password, username)
        wrapping_key = _derive_key(secret, salt)
        wrap_iv, wrap_ct = _wrap_key(cek, wrapping_key)
        keys.append(
            {
                "iv": base64.b64encode(wrap_iv).decode("ascii"),
                "ct": base64.b64encode(wrap_ct).decode("ascii"),
            }
        )

    # Assemble v2 payload
    payload = {
        "v": VERSION,
        "alg": ALGORITHM,
        "kdf": KDF,
        "iter": ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(content_iv).decode("ascii"),
        "ct": base64.b64encode(content_ct).decode("ascii"),
        "keys": keys,
    }

    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def decrypt(ciphertext: str, password: str, username: str) -> str:
    """Decrypt v2 ciphertext with username and password.

    Tries all key blobs in the payload with a single PBKDF2 derivation.

    Args:
        ciphertext: Base64-encoded JSON from encrypt().
        password: The password used for encryption.
        username: The username for key derivation.

    Returns:
        The original plaintext.

    Raises:
        CryptoidError: If decryption fails.
    """
    # Decode base64
    try:
        decoded = base64.b64decode(ciphertext)
    except Exception as e:
        raise CryptoidError(f"Invalid base64 encoding: {e}") from e

    # Parse JSON
    try:
        data: dict[str, Any] = json.loads(decoded)
    except json.JSONDecodeError as e:
        raise CryptoidError(f"Invalid JSON format: {e}") from e

    # Validate version
    version = data.get("v")
    if version != VERSION:
        raise CryptoidError(f"Unsupported format version: {version}")

    # Extract required fields
    required_fields = ["salt", "iv", "ct", "keys"]
    for field_name in required_fields:
        if field_name not in data:
            raise CryptoidError(f"Missing required field: {field_name}")

    try:
        salt = base64.b64decode(data["salt"])
        content_iv = base64.b64decode(data["iv"])
        content_ct = base64.b64decode(data["ct"])
    except Exception as e:
        raise CryptoidError(f"Invalid base64 in payload fields: {e}") from e

    keys_list = data["keys"]
    if not isinstance(keys_list, list) or not keys_list:
        raise CryptoidError("Invalid or empty keys array")

    # Build secret and derive wrapping key (ONE PBKDF2 call)
    secret = _build_secret(password, username)
    wrapping_key = _derive_key(secret, salt)

    # Try each key blob
    cek = None
    for key_blob in keys_list:
        try:
            blob_iv = base64.b64decode(key_blob["iv"])
            blob_ct = base64.b64decode(key_blob["ct"])
        except Exception:
            continue
        result = _unwrap_key(blob_iv, blob_ct, wrapping_key)
        if result is not None:
            cek = result
            break

    if cek is None:
        raise CryptoidError(
            "Decryption failed: wrong password or tampered ciphertext"
        )

    # Decrypt content with recovered CEK
    aesgcm = AESGCM(cek)
    try:
        inner_bytes = aesgcm.decrypt(content_iv, content_ct, None)
    except InvalidTag:
        raise CryptoidError("Decryption failed: content decryption error")
    except Exception as e:
        raise CryptoidError(f"Decryption failed: {e}") from e

    # Parse inner JSON wrapper
    try:
        inner = json.loads(inner_bytes.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise CryptoidError(
            f"Decryption failed: invalid inner format: {e}"
        ) from e

    return inner["c"]


def rewrap_keys(
    encrypted_payload: str,
    old_users: dict[str, str],
    new_users: dict[str, str],
    rekey: bool = False,
) -> str:
    """Re-wrap keys for a new set of users without re-encrypting content.

    Recovers the CEK using any old credential, then wraps it for new users.
    If rekey=True, generates a new CEK and re-encrypts content.

    Args:
        encrypted_payload: Base64-encoded v2 payload.
        old_users: Dict of {username: password} — any one is used to recover CEK.
        new_users: New {username: password} dict for re-wrapping.
        rekey: If True, generate new CEK and re-encrypt content.

    Returns:
        New base64-encoded v2 payload with re-wrapped keys.
    """
    if not old_users:
        raise CryptoidError("Must provide old_users to recover CEK")
    if not new_users:
        raise CryptoidError("Must provide new_users for re-wrapping")

    for username in new_users:
        validate_username(username)

    # Decode payload
    try:
        decoded = base64.b64decode(encrypted_payload)
        data: dict[str, Any] = json.loads(decoded)
    except Exception as e:
        raise CryptoidError(f"Invalid payload: {e}") from e

    if data.get("v") != VERSION:
        raise CryptoidError(f"Unsupported format version: {data.get('v')}")

    salt = base64.b64decode(data["salt"])
    content_iv = base64.b64decode(data["iv"])
    content_ct = base64.b64decode(data["ct"])
    keys_list = data["keys"]

    # Recover CEK using old credentials
    cek = None
    for uname, upwd in old_users.items():
        secret = _build_secret(upwd, uname)
        wrapping_key = _derive_key(secret, salt)
        for key_blob in keys_list:
            blob_iv = base64.b64decode(key_blob["iv"])
            blob_ct = base64.b64decode(key_blob["ct"])
            result = _unwrap_key(blob_iv, blob_ct, wrapping_key)
            if result is not None:
                cek = result
                break
        if cek is not None:
            break

    if cek is None:
        raise CryptoidError("Cannot recover CEK: no valid old credentials")

    # If rekey, generate new CEK and re-encrypt content
    if rekey:
        aesgcm = AESGCM(cek)
        try:
            inner_bytes = aesgcm.decrypt(content_iv, content_ct, None)
        except Exception as e:
            raise CryptoidError(f"Cannot decrypt content for rekey: {e}") from e

        cek = os.urandom(KEY_LENGTH)
        content_iv = os.urandom(IV_LENGTH)
        aesgcm = AESGCM(cek)
        content_ct = aesgcm.encrypt(content_iv, inner_bytes, None)

    # Build new key blobs
    new_keys = []
    for uname, upwd in new_users.items():
        secret = _build_secret(upwd, uname)
        wrapping_key = _derive_key(secret, salt)
        wrap_iv, wrap_ct = _wrap_key(cek, wrapping_key)
        new_keys.append(
            {
                "iv": base64.b64encode(wrap_iv).decode("ascii"),
                "ct": base64.b64encode(wrap_ct).decode("ascii"),
            }
        )

    # Assemble new payload
    payload = {
        "v": VERSION,
        "alg": ALGORITHM,
        "kdf": KDF,
        "iter": ITERATIONS,
        "salt": base64.b64encode(salt).decode("ascii"),
        "iv": base64.b64encode(content_iv).decode("ascii"),
        "ct": base64.b64encode(content_ct).decode("ascii"),
        "keys": new_keys,
    }

    return base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")


def generate_salt() -> bytes:
    """Generate a random salt for consistent encryption.

    Returns:
        16-byte random salt.
    """
    return os.urandom(SALT_LENGTH)


def salt_to_hex(salt: bytes) -> str:
    """Convert salt bytes to hex string for config storage."""
    return salt.hex()


def hex_to_salt(hex_str: str) -> bytes:
    """Convert hex string back to salt bytes.

    Raises:
        CryptoidError: If hex string is invalid or wrong length.
    """
    try:
        salt = bytes.fromhex(hex_str)
    except ValueError as e:
        raise CryptoidError(f"Invalid hex string for salt: {e}") from e

    if len(salt) != SALT_LENGTH:
        raise CryptoidError(
            f"Salt must be {SALT_LENGTH} bytes ({SALT_LENGTH * 2} hex chars), "
            f"got {len(salt)} bytes"
        )
    return salt


# Content hash parameters
HASH_LENGTH = 16  # 128 bits (32 hex chars) - sufficient for integrity check


def content_hash(content: str) -> str:
    """Compute truncated SHA-256 hash of content for integrity verification.

    Args:
        content: The plaintext content to hash.

    Returns:
        Hex-encoded truncated hash (32 characters / 128 bits).
    """
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return digest[:HASH_LENGTH].hex()
