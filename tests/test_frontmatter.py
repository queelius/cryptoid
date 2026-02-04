"""Tests for cryptoid.frontmatter module."""

import pytest

from cryptoid.frontmatter import (
    parse_markdown,
    should_encrypt,
    is_already_encrypted,
    get_encryption_config,
    EncryptionConfig,
)


class TestParseMarkdown:
    """Test markdown front matter parsing."""

    def test_parse_simple_frontmatter(self):
        content = """---
title: "Test Post"
date: 2024-01-15
---

This is the body content.
"""
        fm, body = parse_markdown(content)

        assert fm["title"] == "Test Post"
        assert body.strip() == "This is the body content."

    def test_parse_no_frontmatter(self):
        content = "Just plain content without front matter."
        fm, body = parse_markdown(content)

        assert fm == {}
        assert body == content

    def test_parse_encrypted_fields(self):
        content = """---
title: "Secret Notes"
encrypted: true
groups: ["team", "admin"]
password_hint: "The usual one"
remember: "session"
---

Secret content here.
"""
        fm, body = parse_markdown(content)

        assert fm["encrypted"] is True
        assert fm["groups"] == ["team", "admin"]
        assert fm["password_hint"] == "The usual one"
        assert fm["remember"] == "session"


class TestShouldEncrypt:
    """Test encryption flag detection."""

    def test_encrypted_true(self):
        content = """---
title: "Secret"
encrypted: true
---
Content
"""
        assert should_encrypt(content) is True

    def test_encrypted_false(self):
        content = """---
title: "Public"
encrypted: false
---
Content
"""
        assert should_encrypt(content) is False

    def test_no_encrypted_field(self):
        content = """---
title: "Normal Post"
---
Content
"""
        assert should_encrypt(content) is False

    def test_no_frontmatter(self):
        content = "Just plain markdown content."
        assert should_encrypt(content) is False


class TestIsAlreadyEncrypted:
    """Test detection of already-encrypted content."""

    def test_detects_cryptoid_shortcode(self):
        content = """---
title: "Secret"
encrypted: true
---

{{< cryptoid-encrypted hint="The usual" remember="ask" >}}
eyJ2IjoxLCJhbGciOiJhZXMtMjU2LWdjbSIsIm...base64...
{{< /cryptoid-encrypted >}}
"""
        assert is_already_encrypted(content) is True

    def test_not_encrypted_without_shortcode(self):
        content = """---
title: "Secret"
encrypted: true
---

This is plaintext that should be encrypted.
"""
        assert is_already_encrypted(content) is False

    def test_detects_shortcode_variations(self):
        variations = [
            "{{<cryptoid-encrypted>}}",
            "{{< cryptoid-encrypted >}}",
            "{{<  cryptoid-encrypted  >}}",
            '{{< cryptoid-encrypted hint="test" >}}',
            '{{< cryptoid-encrypted mode="user" hint="test" >}}',
        ]
        for shortcode in variations:
            content = f"---\ntitle: test\n---\n{shortcode}\ndata\n{{{{< /cryptoid-encrypted >}}}}"
            assert is_already_encrypted(content) is True, f"Failed for: {shortcode}"


class TestGetEncryptionConfig:
    """Test extraction of encryption configuration."""

    def test_all_fields(self):
        content = """---
title: "Secret"
encrypted: true
groups: ["team", "admin"]
password_hint: "The usual"
remember: "local"
---
Content
"""
        config = get_encryption_config(content)

        assert config.encrypted is True
        assert config.groups == ["team", "admin"]
        assert config.password_hint == "The usual"
        assert config.remember == "local"

    def test_defaults(self):
        content = """---
title: "Secret"
encrypted: true
---
Content
"""
        config = get_encryption_config(content)

        assert config.encrypted is True
        assert config.groups is None
        assert config.password_hint is None
        assert config.remember == "ask"

    def test_not_encrypted(self):
        content = """---
title: "Public"
---
Content
"""
        config = get_encryption_config(content)
        assert config.encrypted is False

    def test_invalid_remember_value(self):
        content = """---
encrypted: true
remember: "invalid-value"
---
Content
"""
        with pytest.raises(ValueError, match="[Ii]nvalid.*remember"):
            get_encryption_config(content)

    def test_single_group_normalized_to_list(self):
        """A single group string is normalized to a list."""
        content = """---
encrypted: true
groups: "team"
---
Content
"""
        config = get_encryption_config(content)
        assert config.groups == ["team"]

    def test_groups_all(self):
        """groups: ['all'] is a valid value."""
        content = """---
encrypted: true
groups: ["all"]
---
Content
"""
        config = get_encryption_config(content)
        assert config.groups == ["all"]


class TestEncryptionConfig:
    """Test EncryptionConfig dataclass."""

    def test_valid_remember_values(self):
        for remember in ["none", "session", "local", "ask"]:
            config = EncryptionConfig(
                encrypted=True,
                remember=remember,
            )
            assert config.remember == remember

    def test_default_groups_is_none(self):
        config = EncryptionConfig(encrypted=True)
        assert config.groups is None

    def test_groups_list(self):
        config = EncryptionConfig(encrypted=True, groups=["team", "admin"])
        assert config.groups == ["team", "admin"]
