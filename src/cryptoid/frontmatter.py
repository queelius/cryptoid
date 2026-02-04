"""Front matter parsing for cryptoid.

Handles extraction and validation of encryption-related front matter
fields from markdown files.
"""

import re
from dataclasses import dataclass, field
from typing import Any

import frontmatter


# Valid values for the 'remember' field
VALID_REMEMBER_VALUES = frozenset({"none", "session", "local", "ask"})

# Pattern to detect cryptoid shortcode (already encrypted)
SHORTCODE_PATTERN = re.compile(r"\{\{<\s*cryptoid-encrypted\b")


@dataclass
class EncryptionConfig:
    """Configuration for encrypting a page.

    Attributes:
        encrypted: Whether the page should be encrypted.
        groups: List of group names whose members get access (None = all users).
        password_hint: Optional hint to display on the page.
        remember: Password storage behavior ("none", "session", "local", "ask").
    """

    encrypted: bool = False
    groups: list[str] | None = None
    password_hint: str | None = None
    remember: str = "ask"


def parse_markdown(content: str) -> tuple[dict[str, Any], str]:
    """Parse markdown content and extract front matter.

    Args:
        content: Raw markdown file content.

    Returns:
        Tuple of (front_matter_dict, body_content).
        If no front matter is present, returns ({}, original_content).
    """
    post = frontmatter.loads(content)
    return dict(post.metadata), post.content


def should_encrypt(content: str) -> bool:
    """Check if content should be encrypted based on front matter.

    Args:
        content: Raw markdown file content.

    Returns:
        True if front matter contains `encrypted: true`.
    """
    fm, _ = parse_markdown(content)
    return fm.get("encrypted", False) is True


def is_already_encrypted(content: str) -> bool:
    """Check if content is already encrypted (contains cryptoid shortcode).

    Args:
        content: Raw markdown file content.

    Returns:
        True if content contains the cryptoid-encrypted shortcode.
    """
    return bool(SHORTCODE_PATTERN.search(content))


def get_encryption_config(content: str) -> EncryptionConfig:
    """Extract encryption configuration from content.

    Args:
        content: Raw markdown file content.

    Returns:
        EncryptionConfig with values from front matter or defaults.

    Raises:
        ValueError: If remember field has invalid value.
    """
    fm, _ = parse_markdown(content)

    encrypted = fm.get("encrypted", False) is True
    groups = fm.get("groups")
    password_hint = fm.get("password_hint")
    remember = fm.get("remember", "ask")

    # Normalize groups to list or None
    if groups is not None and not isinstance(groups, list):
        groups = [groups]

    # Validate remember value
    if remember not in VALID_REMEMBER_VALUES:
        raise ValueError(
            f"Invalid 'remember' value: {remember!r}. "
            f"Must be one of: {', '.join(sorted(VALID_REMEMBER_VALUES))}"
        )

    return EncryptionConfig(
        encrypted=encrypted,
        groups=groups,
        password_hint=password_hint,
        remember=remember,
    )
