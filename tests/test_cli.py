"""Tests for cryptoid.cli module (v2 multi-user)."""

import pytest
from click.testing import CliRunner

from cryptoid.cli import (
    main,
    load_config,
    encrypt_file,
    decrypt_file,
    resolve_encryption,
    resolve_users,
)
from cryptoid.crypto import CryptoidError
from cryptoid.frontmatter import is_already_encrypted


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def temp_config(tmp_path):
    """Create a v2 config file."""
    config_path = tmp_path / ".cryptoid.yaml"
    config_path.write_text("""users:
  alice: "test-password-123"
  bob: "bob-password-456"

groups:
  admin: [alice]
  team: [alice, bob]

salt: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
""")
    return config_path


@pytest.fixture
def temp_content_dir(tmp_path):
    """Create a content directory with test files and _index.md cascade."""
    content_dir = tmp_path / "content"
    content_dir.mkdir()

    # Public post (no encryption)
    (content_dir / "public.md").write_text("""---
title: "Public Post"
date: 2024-01-15
---

This is public content.
""")

    # Encrypted post (own front matter)
    (content_dir / "secret.md").write_text("""---
title: "Secret Post"
encrypted: true
groups: ["team"]
password_hint: "Test hint"
---

This is secret content that should be encrypted.
""")

    # Private directory with _index.md cascade
    private_dir = content_dir / "private"
    private_dir.mkdir()
    (private_dir / "_index.md").write_text("""---
title: "Private Section"
encrypted: true
groups: ["team"]
---
""")
    (private_dir / "inherited.md").write_text("""---
title: "Inherited Encryption"
---

This file inherits encryption from _index.md.
""")

    # Opt-out in encrypted directory
    (private_dir / "opt-out.md").write_text("""---
title: "Opt Out"
encrypted: false
---

This stays plain despite being in an encrypted directory.
""")

    return content_dir


# =============================================================================
# Config loading tests
# =============================================================================


class TestLoadConfig:
    """Test v2 configuration loading."""

    def test_load_valid_config(self, temp_config):
        config = load_config(temp_config)

        assert config["users"]["alice"] == "test-password-123"
        assert config["users"]["bob"] == "bob-password-456"
        assert config["groups"]["admin"] == ["alice"]
        assert config["groups"]["team"] == ["alice", "bob"]
        assert config["salt_bytes"] is not None

    def test_missing_config_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            load_config(tmp_path / "nonexistent.yaml")

    def test_missing_users_raises(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("groups:\n  team: [alice]\n")
        with pytest.raises(CryptoidError, match="users"):
            load_config(config_path)

    def test_invalid_username_raises(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text('users:\n  "alice:bob": "pass"\n')
        with pytest.raises(CryptoidError, match=":"):
            load_config(config_path)

    def test_empty_password_raises(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text('users:\n  alice: ""\n')
        with pytest.raises(CryptoidError, match="empty"):
            load_config(config_path)

    def test_group_member_not_in_users_raises(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
groups:
  team: [alice, bob]
""")
        with pytest.raises(CryptoidError, match="bob.*not found"):
            load_config(config_path)

    def test_invalid_salt_raises(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
salt: "tooshort"
""")
        with pytest.raises(CryptoidError, match="[Ss]alt"):
            load_config(config_path)

    def test_no_salt_is_ok(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text('users:\n  alice: "pass"\n')
        config = load_config(config_path)
        assert config["salt_bytes"] is None

    def test_no_groups_is_ok(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text('users:\n  alice: "pass"\n')
        config = load_config(config_path)
        assert config["groups"] == {}


# =============================================================================
# Cascade resolution tests
# =============================================================================


class TestResolveEncryption:
    """Test _index.md cascade resolution."""

    def test_own_encrypted_true(self, temp_content_dir):
        """File with own encrypted: true is resolved."""
        config = resolve_encryption(
            temp_content_dir / "secret.md", temp_content_dir
        )
        assert config is not None
        assert config.encrypted is True
        assert config.groups == ["team"]

    def test_inherited_from_index(self, temp_content_dir):
        """File inherits encryption from _index.md."""
        config = resolve_encryption(
            temp_content_dir / "private" / "inherited.md", temp_content_dir
        )
        assert config is not None
        assert config.encrypted is True
        assert config.groups == ["team"]

    def test_opt_out_overrides_cascade(self, temp_content_dir):
        """File with encrypted: false overrides _index.md cascade."""
        config = resolve_encryption(
            temp_content_dir / "private" / "opt-out.md", temp_content_dir
        )
        assert config is None

    def test_plain_file_no_cascade(self, temp_content_dir):
        """File without encryption and no _index.md cascade is not encrypted."""
        config = resolve_encryption(
            temp_content_dir / "public.md", temp_content_dir
        )
        assert config is None

    def test_index_md_never_encrypted(self, temp_content_dir):
        """_index.md files themselves are never encrypted."""
        config = resolve_encryption(
            temp_content_dir / "private" / "_index.md", temp_content_dir
        )
        assert config is None

    def test_nested_cascade(self, tmp_path):
        """Nested _index.md overrides parent."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()

        # Parent cascade
        (content_dir / "_index.md").write_text("""---
encrypted: true
groups: ["all"]
---
""")

        # Child override
        sub = content_dir / "sub"
        sub.mkdir()
        (sub / "_index.md").write_text("""---
encrypted: true
groups: ["team"]
---
""")

        (sub / "file.md").write_text("""---
title: "Test"
---
Content
""")

        config = resolve_encryption(sub / "file.md", content_dir)
        assert config is not None
        # Should get the nearest _index.md groups (team), not parent (all)
        assert config.groups == ["team"]


# =============================================================================
# Resolve users tests
# =============================================================================


class TestResolveUsers:
    """Test group → user resolution."""

    @pytest.fixture
    def config(self):
        return {
            "users": {
                "alice": "pass-a",
                "bob": "pass-b",
                "carol": "pass-c",
            },
            "groups": {
                "admin": ["alice"],
                "team": ["alice", "bob"],
                "members": ["bob", "carol"],
            },
        }

    def test_groups_none_returns_all(self, config):
        users = resolve_users(None, config)
        assert set(users.keys()) == {"alice", "bob", "carol"}

    def test_groups_all_returns_all(self, config):
        users = resolve_users(["all"], config)
        assert set(users.keys()) == {"alice", "bob", "carol"}

    def test_specific_group(self, config):
        users = resolve_users(["members"], config)
        # members = [bob, carol] + admin = [alice]
        assert set(users.keys()) == {"alice", "bob", "carol"}

    def test_admin_always_injected(self, config):
        users = resolve_users(["members"], config)
        assert "alice" in users  # alice is in admin

    def test_unknown_group_raises(self, config):
        with pytest.raises(CryptoidError, match="nonexistent"):
            resolve_users(["nonexistent"], config)

    def test_no_admin_group(self, config):
        """Works fine without an admin group."""
        del config["groups"]["admin"]
        users = resolve_users(["members"], config)
        assert set(users.keys()) == {"bob", "carol"}

    def test_multiple_groups_union(self, config):
        """Multiple groups produce union of members."""
        del config["groups"]["admin"]  # Remove admin to test pure union
        users = resolve_users(["team", "members"], config)
        assert set(users.keys()) == {"alice", "bob", "carol"}


# =============================================================================
# File encrypt/decrypt tests
# =============================================================================


class TestEncryptFile:
    """Test single file encryption."""

    def test_encrypt_file_basic(self, tmp_path):
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "Test"
encrypted: true
---

Secret content here.
""")
        users = {"alice": "password123"}
        result = encrypt_file(md_file, users)

        assert result is True
        content = md_file.read_text()
        assert is_already_encrypted(content)
        assert "Secret content here" not in content
        assert "{{< cryptoid-encrypted" in content
        assert 'mode="user"' in content

    def test_encrypt_preserves_frontmatter(self, tmp_path):
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "My Title"
date: 2024-01-15
encrypted: true
password_hint: "The hint"
remember: "session"
custom_field: "preserved"
---

Secret content.
""")
        encrypt_file(md_file, {"alice": "password"})
        content = md_file.read_text()

        assert 'title: "My Title"' in content or "title: My Title" in content
        assert "encrypted: true" in content
        assert 'hint="The hint"' in content
        assert 'remember="session"' in content

    def test_encrypt_skips_already_encrypted(self, tmp_path):
        md_file = tmp_path / "test.md"
        original_content = """---
title: "Test"
encrypted: true
---

{{< cryptoid-encrypted mode="user" hint="" remember="ask" hash="abc" >}}
eyJhbGciOiAiYWVzLTI1Ni1nY20ifQ==
{{< /cryptoid-encrypted >}}
"""
        md_file.write_text(original_content)
        result = encrypt_file(md_file, {"alice": "password"})

        assert result is False
        assert md_file.read_text() == original_content


class TestDecryptFile:
    """Test single file decryption."""

    def test_decrypt_file_basic(self, tmp_path):
        md_file = tmp_path / "test.md"
        original_body = "Secret content here.\n\nWith multiple paragraphs."

        md_file.write_text(f"""---
title: "Test"
encrypted: true
---

{original_body}
""")
        users = {"alice": "password123"}
        encrypt_file(md_file, users)

        assert is_already_encrypted(md_file.read_text())

        result = decrypt_file(md_file, users)
        assert result is True
        content = md_file.read_text()
        assert not is_already_encrypted(content)
        assert original_body in content

    def test_decrypt_wrong_password_raises(self, tmp_path):
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "Test"
encrypted: true
---

Secret content.
""")
        encrypt_file(md_file, {"alice": "correct-password"})

        with pytest.raises(CryptoidError, match="[Dd]ecryption failed|no valid"):
            decrypt_file(md_file, {"bob": "wrong-password"})

    def test_decrypt_tries_multiple_users(self, tmp_path):
        """Decryption succeeds if any user credential works."""
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "Test"
encrypted: true
---

Secret content.
""")
        encrypt_file(md_file, {"alice": "pass-a", "bob": "pass-b"})

        # Decrypt with a set containing the right user plus wrong ones
        result = decrypt_file(md_file, {"wrong": "wrong", "alice": "pass-a"})
        assert result is True

    def test_decrypt_skips_not_encrypted(self, tmp_path):
        md_file = tmp_path / "test.md"
        original = """---
title: "Test"
encrypted: true
---

Plain content (not encrypted yet).
"""
        md_file.write_text(original)
        result = decrypt_file(md_file, {"alice": "password"})

        assert result is False
        assert md_file.read_text() == original


# =============================================================================
# CLI command tests
# =============================================================================


class TestEncryptCommand:
    """Test the encrypt CLI command."""

    def test_encrypt_command_basic(self, runner, temp_content_dir, temp_config):
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0

        # Directly encrypted file
        secret_content = (temp_content_dir / "secret.md").read_text()
        assert is_already_encrypted(secret_content)

        # Cascade-inherited file
        inherited_content = (temp_content_dir / "private" / "inherited.md").read_text()
        assert is_already_encrypted(inherited_content)

        # Opt-out file stays plain
        optout_content = (temp_content_dir / "private" / "opt-out.md").read_text()
        assert not is_already_encrypted(optout_content)

        # Public file stays plain
        public_content = (temp_content_dir / "public.md").read_text()
        assert not is_already_encrypted(public_content)

    def test_encrypt_dry_run(self, runner, temp_content_dir, temp_config):
        original_content = (temp_content_dir / "secret.md").read_text()

        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
            "--dry-run",
        ])

        assert result.exit_code == 0
        assert "dry run" in result.output.lower() or "would encrypt" in result.output.lower()
        assert (temp_content_dir / "secret.md").read_text() == original_content

    def test_encrypt_unknown_group_error(self, runner, tmp_path):
        """Error when file references a non-existent group."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.md").write_text("""---
encrypted: true
groups: ["nonexistent"]
---
Content
""")
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text('users:\n  alice: "pass"\n')

        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        assert result.exit_code != 0
        assert "nonexistent" in result.output.lower()


class TestDecryptCommand:
    """Test the decrypt CLI command."""

    def test_decrypt_command_basic(self, runner, temp_content_dir, temp_config):
        # First encrypt
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0
        assert is_already_encrypted((temp_content_dir / "secret.md").read_text())

        # Now decrypt
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        secret_content = (temp_content_dir / "secret.md").read_text()
        assert not is_already_encrypted(secret_content)
        assert "secret content that should be encrypted" in secret_content.lower()


# =============================================================================
# Status command tests
# =============================================================================


class TestStatusCommand:
    """Test the status CLI command."""

    def test_status_shows_files(self, runner, temp_content_dir, temp_config):
        result = runner.invoke(main, [
            "status",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        assert "plain" in result.output.lower()
        assert "pending" in result.output.lower()
        assert "Total:" in result.output

    def test_status_verbose(self, runner, temp_content_dir, temp_config):
        result = runner.invoke(main, [
            "status",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
            "--verbose",
        ])

        assert result.exit_code == 0
        assert "Group usage:" in result.output
        assert "Per-user access:" in result.output

    def test_status_after_encrypt(self, runner, temp_content_dir, temp_config):
        # Encrypt first
        runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        result = runner.invoke(main, [
            "status",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        assert "ENCRYPTED" in result.output


# =============================================================================
# Rewrap command tests
# =============================================================================


class TestRewrapCommand:
    """Test the rewrap CLI command."""

    def test_rewrap_basic(self, runner, temp_content_dir, temp_config):
        # Encrypt first
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0

        # Rewrap
        result = runner.invoke(main, [
            "rewrap",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        assert "rewrapped" in result.output.lower()

        # Verify can still decrypt
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0

    def test_rewrap_with_rekey(self, runner, temp_content_dir, temp_config):
        # Encrypt first
        runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        # Rewrap with rekey
        result = runner.invoke(main, [
            "rewrap",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
            "--rekey",
        ])

        assert result.exit_code == 0
        assert "rekeyed" in result.output.lower()

        # Verify can still decrypt
        result = runner.invoke(main, [
            "decrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0


# =============================================================================
# Cascade encryption (replacing encrypt_dirs tests)
# =============================================================================


class TestCascadeEncryption:
    """Test _index.md cascade encryption."""

    def test_cascade_encrypts_inherited_files(self, runner, temp_content_dir, temp_config):
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0

        inherited = (temp_content_dir / "private" / "inherited.md").read_text()
        assert is_already_encrypted(inherited)
        assert "encrypted: true" in inherited

    def test_cascade_respects_opt_out(self, runner, temp_content_dir, temp_config):
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0

        optout = (temp_content_dir / "private" / "opt-out.md").read_text()
        assert not is_already_encrypted(optout)
        assert "This stays plain" in optout

    def test_index_md_not_encrypted(self, runner, temp_content_dir, temp_config):
        result = runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])
        assert result.exit_code == 0

        index = (temp_content_dir / "private" / "_index.md").read_text()
        assert not is_already_encrypted(index)


# =============================================================================
# Protect / Unprotect command tests
# =============================================================================


class TestProtectCommand:
    """Test the protect CLI command."""

    def test_protect_directory_creates_index(self, runner, tmp_path):
        """Protect creates _index.md with encryption settings."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        result = runner.invoke(main, [
            "protect", str(content_dir), "--groups", "team",
        ])

        assert result.exit_code == 0
        index_path = content_dir / "_index.md"
        assert index_path.exists()

        content = index_path.read_text()
        assert "encrypted: true" in content
        assert "team" in content

    def test_protect_directory_updates_existing_index(self, runner, tmp_path):
        """Protect updates existing _index.md without losing other fields."""
        content_dir = tmp_path / "content" / "blog"
        content_dir.mkdir(parents=True)
        index_path = content_dir / "_index.md"
        index_path.write_text("""---
title: "Blog Posts"
description: "All my blog posts"
---

Welcome to the blog.
""")

        result = runner.invoke(main, [
            "protect", str(content_dir), "--groups", "members",
        ])

        assert result.exit_code == 0
        content = index_path.read_text()
        assert "encrypted: true" in content
        assert "members" in content
        # Preserved existing fields
        assert "Blog Posts" in content
        assert "All my blog posts" in content
        assert "Welcome to the blog" in content

    def test_protect_directory_multiple_groups(self, runner, tmp_path):
        """Multiple --groups flags produce a list."""
        content_dir = tmp_path / "content" / "shared"
        content_dir.mkdir(parents=True)

        result = runner.invoke(main, [
            "protect", str(content_dir),
            "--groups", "team", "--groups", "members",
        ])

        assert result.exit_code == 0
        content = (content_dir / "_index.md").read_text()
        assert "encrypted: true" in content
        assert "team" in content
        assert "members" in content

    def test_protect_directory_with_hint_and_remember(self, runner, tmp_path):
        """Protect passes hint and remember options through."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        result = runner.invoke(main, [
            "protect", str(content_dir),
            "--groups", "team",
            "--hint", "Ask the team lead",
            "--remember", "session",
        ])

        assert result.exit_code == 0
        content = (content_dir / "_index.md").read_text()
        assert "encrypted: true" in content
        assert "Ask the team lead" in content
        assert "session" in content

    def test_protect_directory_no_groups_defaults_to_all(self, runner, tmp_path):
        """Protect without --groups means all users get access."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        result = runner.invoke(main, [
            "protect", str(content_dir),
        ])

        assert result.exit_code == 0
        assert "all" in result.output.lower()

    def test_protect_file(self, runner, tmp_path):
        """Protect updates a file's front matter."""
        md_file = tmp_path / "secret.md"
        md_file.write_text("""---
title: "Secret Post"
date: 2024-01-15
---

Secret content here.
""")

        result = runner.invoke(main, [
            "protect", str(md_file), "--groups", "admin",
        ])

        assert result.exit_code == 0
        content = md_file.read_text()
        assert "encrypted: true" in content
        assert "admin" in content
        # Preserved other fields
        assert "Secret Post" in content
        assert "Secret content here" in content

    def test_protect_file_with_all_options(self, runner, tmp_path):
        """Protect file with hint and remember options."""
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "Test"
---

Content.
""")

        result = runner.invoke(main, [
            "protect", str(md_file),
            "--groups", "team",
            "--hint", "The usual",
            "--remember", "local",
        ])

        assert result.exit_code == 0
        content = md_file.read_text()
        assert "encrypted: true" in content
        assert "team" in content
        assert "The usual" in content
        assert "local" in content

    def test_protect_idempotent(self, runner, tmp_path):
        """Running protect twice produces same result."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        runner.invoke(main, [
            "protect", str(content_dir), "--groups", "team",
        ])
        first = (content_dir / "_index.md").read_text()

        runner.invoke(main, [
            "protect", str(content_dir), "--groups", "team",
        ])
        second = (content_dir / "_index.md").read_text()

        assert first == second

    def test_protect_updates_groups(self, runner, tmp_path):
        """Running protect again with different groups updates them."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        runner.invoke(main, [
            "protect", str(content_dir), "--groups", "team",
        ])

        runner.invoke(main, [
            "protect", str(content_dir), "--groups", "members",
        ])

        content = (content_dir / "_index.md").read_text()
        assert "members" in content


class TestUnprotectCommand:
    """Test the unprotect CLI command."""

    def test_unprotect_directory(self, runner, tmp_path):
        """Unprotect removes encryption settings from _index.md."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        # First protect
        runner.invoke(main, [
            "protect", str(content_dir), "--groups", "team",
        ])
        assert (content_dir / "_index.md").exists()

        # Then unprotect
        result = runner.invoke(main, [
            "unprotect", str(content_dir),
        ])

        assert result.exit_code == 0
        assert "no longer inherit" in result.output.lower()

    def test_unprotect_directory_removes_empty_index(self, runner, tmp_path):
        """Unprotect removes _index.md if it has no remaining content."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        # Create index with only encryption settings
        runner.invoke(main, [
            "protect", str(content_dir), "--groups", "team",
        ])

        # Unprotect
        runner.invoke(main, ["unprotect", str(content_dir)])

        # _index.md should be removed since it only had title + encryption
        assert not (content_dir / "_index.md").exists()

    def test_unprotect_directory_preserves_other_content(self, runner, tmp_path):
        """Unprotect keeps _index.md if it has other meaningful content."""
        content_dir = tmp_path / "content" / "blog"
        content_dir.mkdir(parents=True)
        index_path = content_dir / "_index.md"
        index_path.write_text("""---
title: "Blog"
encrypted: true
groups: ["team"]
description: "My blog section"
---

This section contains blog posts.
""")

        result = runner.invoke(main, [
            "unprotect", str(content_dir),
        ])

        assert result.exit_code == 0
        assert index_path.exists()
        content = index_path.read_text()
        # Encryption fields removed
        assert "encrypted" not in content
        assert "groups" not in content
        # Other content preserved
        assert "Blog" in content
        assert "My blog section" in content
        assert "blog posts" in content

    def test_unprotect_directory_no_index(self, runner, tmp_path):
        """Unprotect on directory without _index.md is a no-op."""
        content_dir = tmp_path / "content" / "empty"
        content_dir.mkdir(parents=True)

        result = runner.invoke(main, [
            "unprotect", str(content_dir),
        ])

        assert result.exit_code == 0
        assert "nothing to unprotect" in result.output.lower()

    def test_unprotect_directory_no_encryption(self, runner, tmp_path):
        """Unprotect on directory with _index.md but no encryption is a no-op."""
        content_dir = tmp_path / "content" / "blog"
        content_dir.mkdir(parents=True)
        (content_dir / "_index.md").write_text("""---
title: "Blog"
---

Blog section.
""")

        result = runner.invoke(main, [
            "unprotect", str(content_dir),
        ])

        assert result.exit_code == 0
        assert "nothing to unprotect" in result.output.lower()

    def test_unprotect_file(self, runner, tmp_path):
        """Unprotect sets encrypted: false on a file."""
        md_file = tmp_path / "secret.md"
        md_file.write_text("""---
title: "Secret"
encrypted: true
groups: ["team"]
password_hint: "hint"
---

Content.
""")

        result = runner.invoke(main, [
            "unprotect", str(md_file),
        ])

        assert result.exit_code == 0
        content = md_file.read_text()
        assert "encrypted: false" in content
        # Encryption-related fields removed
        assert "groups" not in content
        assert "password_hint" not in content
        # Preserved other content
        assert "Secret" in content
        assert "Content." in content

    def test_unprotect_encrypted_file_warns(self, runner, tmp_path):
        """Unprotect on already-encrypted file warns to decrypt first."""
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "Test"
encrypted: true
---

Secret content.
""")
        encrypt_file(md_file, {"alice": "password"})

        result = runner.invoke(main, [
            "unprotect", str(md_file),
        ])

        assert result.exit_code != 0
        assert "decrypt" in result.output.lower()

    def test_protect_then_unprotect_file(self, runner, tmp_path):
        """Full protect → unprotect cycle on a file."""
        md_file = tmp_path / "test.md"
        md_file.write_text("""---
title: "Test"
---

Content.
""")

        runner.invoke(main, ["protect", str(md_file), "--groups", "team"])
        content = md_file.read_text()
        assert "encrypted: true" in content

        runner.invoke(main, ["unprotect", str(md_file)])
        content = md_file.read_text()
        assert "encrypted: false" in content

    def test_protect_unprotect_directory_roundtrip(self, runner, tmp_path):
        """Full protect → unprotect cycle on a directory."""
        content_dir = tmp_path / "content" / "private"
        content_dir.mkdir(parents=True)

        runner.invoke(main, ["protect", str(content_dir), "--groups", "team"])
        assert (content_dir / "_index.md").exists()
        assert "encrypted: true" in (content_dir / "_index.md").read_text()

        runner.invoke(main, ["unprotect", str(content_dir)])
        # Should be cleaned up since protect created a minimal _index.md
        assert not (content_dir / "_index.md").exists()


# =============================================================================
# Validate command tests
# =============================================================================


class TestValidateCommand:
    """Test the validate CLI command."""

    def test_validate_clean_config(self, runner, temp_content_dir, temp_config):
        """Validation passes for a well-formed setup."""
        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        assert "passed" in result.output.lower()

    def test_validate_after_encrypt(self, runner, temp_content_dir, temp_config):
        """Validation passes after encrypting files."""
        runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        assert "passed" in result.output.lower()
        assert "OK:" in result.output  # encrypted files verified

    def test_validate_missing_config(self, runner, tmp_path):
        """Validation fails if config file is missing."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(tmp_path / "nonexistent.yaml"),
        ])

        assert result.exit_code != 0
        assert "error" in result.output.lower()

    def test_validate_undefined_group_in_frontmatter(self, runner, tmp_path):
        """Validation reports error for undefined group reference."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.md").write_text("""---
title: "Test"
encrypted: true
groups: ["nonexistent_group"]
---

Content here.
""")
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
groups:
  team: [alice]
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        assert result.exit_code != 0
        assert "nonexistent_group" in result.output
        assert "FAILED" in result.output

    def test_validate_unused_group_warning(self, runner, tmp_path):
        """Validation warns about groups defined but not referenced."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.md").write_text("""---
title: "Test"
encrypted: true
groups: ["team"]
---

Content here.
""")
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
  bob: "pass-b"
groups:
  admin: [alice]
  team: [alice]
  unused_group: [bob]
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        # Should pass (warnings don't cause failure) but report the warning
        assert result.exit_code == 0
        assert "unused_group" in result.output
        assert "WARNING" in result.output

    def test_validate_user_without_group_warning(self, runner, tmp_path):
        """Validation warns about users not in any group."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "test.md").write_text("""---
title: "Test"
---

Plain content.
""")
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
  orphan_user: "pass-orphan"
groups:
  admin: [alice]
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        assert result.exit_code == 0
        assert "orphan_user" in result.output
        assert "WARNING" in result.output

    def test_validate_encrypted_file_not_decryptable(self, runner, tmp_path):
        """Validation reports error when encrypted file can't be decrypted."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()

        # Create and encrypt a file with one set of credentials
        md_file = content_dir / "test.md"
        md_file.write_text("""---
title: "Test"
encrypted: true
---

Secret content.
""")

        old_config_path = tmp_path / ".old-config.yaml"
        old_config_path.write_text("""users:
  alice: "old-password"
""")

        runner.invoke(main, [
            "encrypt",
            "--content-dir", str(content_dir),
            "--config", str(old_config_path),
        ])

        # Now validate with different credentials
        new_config_path = tmp_path / ".cryptoid.yaml"
        new_config_path.write_text("""users:
  bob: "different-password"
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(new_config_path),
        ])

        assert result.exit_code != 0
        assert "cannot be decrypted" in result.output.lower()
        assert "FAILED" in result.output

    def test_validate_cascade_resolution_error(self, runner, tmp_path):
        """Validation reports error when cascade resolves to invalid group."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()

        private_dir = content_dir / "private"
        private_dir.mkdir()
        (private_dir / "_index.md").write_text("""---
encrypted: true
groups: ["nonexistent"]
---
""")
        (private_dir / "file.md").write_text("""---
title: "Test"
---

Inherited content.
""")

        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
groups:
  admin: [alice]
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        assert result.exit_code != 0
        assert "nonexistent" in result.output.lower()

    def test_validate_no_encrypted_files(self, runner, tmp_path):
        """Validation works when no files are encrypted."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "plain.md").write_text("""---
title: "Plain"
---

Just a plain file.
""")
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass"
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        assert result.exit_code == 0
        assert "No encrypted files" in result.output

    def test_validate_hash_integrity(self, runner, temp_content_dir, temp_config):
        """Validation verifies content hash integrity on encrypted files."""
        # Encrypt
        runner.invoke(main, [
            "encrypt",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        # Validate should check hashes
        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(temp_content_dir),
            "--config", str(temp_config),
        ])

        assert result.exit_code == 0
        # All encrypted files should show OK
        assert "OK:" in result.output

    def test_validate_all_checks_pass(self, runner, tmp_path):
        """Full validation with all checks passing — no warnings, no errors."""
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "secret.md").write_text("""---
title: "Secret"
encrypted: true
groups: ["team"]
---

Top secret content.
""")
        (content_dir / "public.md").write_text("""---
title: "Public"
---

Public content.
""")

        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text("""users:
  alice: "pass-a"
  bob: "pass-b"
groups:
  admin: [alice]
  team: [alice, bob]
""")

        result = runner.invoke(main, [
            "validate",
            "--content-dir", str(content_dir),
            "--config", str(config_path),
        ])

        assert result.exit_code == 0
        assert "no errors or warnings" in result.output.lower()
