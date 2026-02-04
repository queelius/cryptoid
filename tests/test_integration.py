"""Integration tests for cryptoid (v2 multi-user).

Tests the full encrypt → decrypt workflow including cascade,
multi-user access, and edge cases.
"""

import base64
import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from cryptoid.cli import main, encrypt_file, decrypt_file
from cryptoid.crypto import encrypt, decrypt, content_hash
from cryptoid.frontmatter import is_already_encrypted


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def hugo_site(tmp_path):
    """Copy test Hugo site to temp directory."""
    fixture_path = Path(__file__).parent / "fixtures" / "hugo-site"
    site_path = tmp_path / "hugo-site"
    shutil.copytree(fixture_path, site_path)
    return site_path


class TestFullWorkflow:
    """Test complete encrypt/decrypt workflow."""

    def test_encrypt_decrypt_roundtrip(self, runner, hugo_site):
        """Full encrypt → decrypt cycle preserves content."""
        content_dir = hugo_site / "content"
        config_path = hugo_site / ".cryptoid.yaml"

        secret_file = content_dir / "secret-notes.md"
        original_content = secret_file.read_text()
        assert "Top Secret Information" in original_content
        assert not is_already_encrypted(original_content)

        # Encrypt
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Verify encrypted
        encrypted_content = secret_file.read_text()
        assert is_already_encrypted(encrypted_content)
        assert "Top Secret Information" not in encrypted_content
        assert "cryptoid-encrypted" in encrypted_content
        assert 'mode="user"' in encrypted_content

        # Decrypt
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Verify restored
        restored_content = secret_file.read_text()
        assert not is_already_encrypted(restored_content)
        assert "Top Secret Information" in restored_content

    def test_public_file_unchanged(self, runner, hugo_site):
        content_dir = hugo_site / "content"
        config_path = hugo_site / ".cryptoid.yaml"

        public_file = content_dir / "public-post.md"
        original = public_file.read_text()

        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0
        assert public_file.read_text() == original

    def test_cascade_workflow(self, runner, hugo_site):
        """Files inherit encryption from _index.md cascade."""
        content_dir = hugo_site / "content"
        config_path = hugo_site / ".cryptoid.yaml"

        auto_file = content_dir / "private" / "auto-encrypted.md"
        original = auto_file.read_text()
        assert "encrypted: true" not in original

        # Encrypt
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Should be encrypted with encrypted: true added
        encrypted = auto_file.read_text()
        assert is_already_encrypted(encrypted)
        assert "encrypted: true" in encrypted

        # Decrypt
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Should be decrypted
        decrypted = auto_file.read_text()
        assert not is_already_encrypted(decrypted)
        assert "automatically encrypted" in decrypted or "own front matter" in decrypted

    def test_idempotent_encryption(self, runner, hugo_site):
        """Running encrypt twice doesn't double-encrypt."""
        content_dir = hugo_site / "content"
        config_path = hugo_site / ".cryptoid.yaml"

        secret_file = content_dir / "secret-notes.md"

        # First encrypt
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0
        first_encryption = secret_file.read_text()

        # Second encrypt (should skip)
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0
        assert "skip" in result.output.lower() or "0 encrypted" in result.output.lower()

        # Content should be same
        assert secret_file.read_text() == first_encryption

    def test_rewrap_workflow(self, runner, hugo_site):
        """Full encrypt → rewrap → decrypt cycle."""
        content_dir = hugo_site / "content"
        config_path = hugo_site / ".cryptoid.yaml"

        # Encrypt
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Rewrap
        result = runner.invoke(main, [
            "rewrap",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Decrypt
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        secret_file = content_dir / "secret-notes.md"
        assert "Top Secret Information" in secret_file.read_text()


class TestCrossCompatibility:
    """Test Python encryption format for JavaScript WebCrypto."""

    def test_v2_ciphertext_format(self):
        """Verify v2 format is compatible with JS WebCrypto."""
        users = {"alice": "test-password"}
        ciphertext = encrypt("Hello, encrypted world!", users)

        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)

        # v2 format
        assert data["v"] == 2
        assert data["alg"] == "aes-256-gcm"
        assert data["kdf"] == "pbkdf2-sha256"
        assert data["iter"] == 310000

        # Salt: 16 bytes
        salt = base64.b64decode(data["salt"])
        assert len(salt) == 16

        # IV: 12 bytes
        iv = base64.b64decode(data["iv"])
        assert len(iv) == 12

        # Content ciphertext includes 16-byte auth tag
        ct = base64.b64decode(data["ct"])
        assert len(ct) >= 16

        # Keys array with iv and ct per user
        assert isinstance(data["keys"], list)
        assert len(data["keys"]) == 1
        for blob in data["keys"]:
            assert "iv" in blob
            assert "ct" in blob

    def test_encryption_non_deterministic(self):
        """Different encryptions produce different results (random CEK/IV)."""
        users = {"alice": "password"}
        ct1 = encrypt("Test", users)
        ct2 = encrypt("Test", users)
        assert ct1 != ct2

        assert decrypt(ct1, "password", "alice") == "Test"
        assert decrypt(ct2, "password", "alice") == "Test"

    def test_multi_user_key_blobs(self):
        """Multiple users produce separate key blobs."""
        users = {"alice": "a", "bob": "b", "carol": "c"}
        ciphertext = encrypt("Team secret", users)

        decoded = base64.b64decode(ciphertext)
        data = json.loads(decoded)
        assert len(data["keys"]) == 3

        # Each user can decrypt
        for username, password in users.items():
            assert decrypt(ciphertext, password, username) == "Team secret"


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_content_encryption(self, tmp_path):
        md_file = tmp_path / "empty.md"
        md_file.write_text("""---
title: "Empty"
encrypted: true
---

""")
        users = {"alice": "password"}
        encrypt_file(md_file, users)
        assert is_already_encrypted(md_file.read_text())

        decrypt_file(md_file, users)
        content = md_file.read_text()
        assert not is_already_encrypted(content)

    def test_unicode_content_preservation(self, tmp_path):
        unicode_body = """
# 日本語タイトル

こんにちは世界！

Émojis: 🔐 🎉 🚀

Greek: αβγδ

Math: ∑∏∫
"""

        md_file = tmp_path / "unicode.md"
        md_file.write_text(f"""---
title: "Unicode Test"
encrypted: true
---
{unicode_body}
""")
        users = {"アリス": "パスワード"}
        encrypt_file(md_file, users)
        decrypt_file(md_file, users)

        content = md_file.read_text()
        assert "日本語タイトル" in content
        assert "🔐" in content
        assert "αβγδ" in content

    def test_large_content_handling(self, tmp_path):
        large_body = "# Long Post\n\n" + ("Lorem ipsum dolor sit amet. " * 2000)

        md_file = tmp_path / "large.md"
        md_file.write_text(f"""---
title: "Large Post"
encrypted: true
---
{large_body}
""")
        users = {"alice": "password"}
        encrypt_file(md_file, users)
        assert is_already_encrypted(md_file.read_text())

        decrypt_file(md_file, users)
        content = md_file.read_text()
        assert "Lorem ipsum" in content
        assert content.count("Lorem ipsum") == 2000


class TestContentHashIntegrity:
    """Test content hash storage and verification."""

    def test_hash_stored_in_shortcode(self, tmp_path):
        body = "This is the secret content."
        expected_hash = content_hash(body)

        md_file = tmp_path / "test.md"
        md_file.write_text(f"""---
title: "Test"
encrypted: true
---
{body}
""")
        users = {"alice": "password"}
        encrypt_file(md_file, users)

        encrypted_content = md_file.read_text()
        assert f'hash="{expected_hash}"' in encrypted_content

    def test_hash_preserved_through_roundtrip(self, tmp_path):
        body = "Original content for hash test."
        original_hash = content_hash(body)

        md_file = tmp_path / "hash_test.md"
        md_file.write_text(f"""---
title: "Hash Test"
encrypted: true
---
{body}
""")
        users = {"alice": "test-password"}
        encrypt_file(md_file, users)

        encrypted_content = md_file.read_text()
        assert f'hash="{original_hash}"' in encrypted_content

        decrypt_file(md_file, users)

        decrypted_content = md_file.read_text()
        import frontmatter
        post = frontmatter.loads(decrypted_content)
        decrypted_hash = content_hash(post.content)
        assert decrypted_hash == original_hash

    def test_hash_with_unicode_content(self, tmp_path):
        body = "日本語コンテンツ 🔐 αβγδ"
        expected_hash = content_hash(body)

        md_file = tmp_path / "unicode.md"
        md_file.write_text(f"""---
title: "Unicode"
encrypted: true
---
{body}
""")
        users = {"alice": "パスワード"}
        encrypt_file(md_file, users)

        encrypted_content = md_file.read_text()
        assert f'hash="{expected_hash}"' in encrypted_content

    def test_hash_with_empty_body(self, tmp_path):
        body = ""
        expected_hash = content_hash(body)

        md_file = tmp_path / "empty.md"
        md_file.write_text(f"""---
title: "Empty"
encrypted: true
---
{body}
""")
        users = {"alice": "password"}
        encrypt_file(md_file, users)

        encrypted_content = md_file.read_text()
        assert f'hash="{expected_hash}"' in encrypted_content


class TestMultiUserAccess:
    """Test multi-user encryption and access control."""

    def test_file_encrypted_for_multiple_users(self, tmp_path):
        """Multiple users can each decrypt the same file."""
        md_file = tmp_path / "team.md"
        md_file.write_text("""---
title: "Team File"
encrypted: true
---

Team secret content.
""")
        users = {"alice": "pass-a", "bob": "pass-b", "carol": "pass-c"}
        encrypt_file(md_file, users)

        # Each user can decrypt individually
        for username, password in users.items():
            encrypted_content = md_file.read_text()
            from cryptoid.cli import _extract_shortcode_content
            extracted = _extract_shortcode_content(encrypted_content)
            result = decrypt(extracted["ciphertext"], password, username)
            assert "Team secret content" in result

    def test_non_authorized_user_cannot_decrypt(self, tmp_path):
        """User not in the encrypted set cannot decrypt."""
        md_file = tmp_path / "restricted.md"
        md_file.write_text("""---
title: "Restricted"
encrypted: true
---

Restricted content.
""")
        # Only encrypt for alice
        encrypt_file(md_file, {"alice": "pass-a"})

        from cryptoid.crypto import CryptoidError
        with pytest.raises(CryptoidError, match="no valid"):
            decrypt_file(md_file, {"bob": "pass-b"})

    def test_admin_group_gets_access(self, runner, tmp_path):
        """Admin group members always get key blobs."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "file.md").write_text("""---
title: "Members Only"
encrypted: true
groups: ["members"]
---

Members content.
""")

        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass-a"
  bob: "pass-b"
  carol: "pass-c"

groups:
  admin: [alice]
  members: [bob, carol]
""")

        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0

        # Alice (admin) should be able to decrypt even though
        # she's not in "members" group
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])
        assert result.exit_code == 0
        assert "Members content" in (content_dir / "file.md").read_text()
