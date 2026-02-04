"""Command-line interface for cryptoid.

Provides encrypt/decrypt/status/rewrap commands for processing Hugo content
directories with multi-user key-wrapping encryption.
"""

import re
import sys
from pathlib import Path
from typing import Any

import click
import yaml
import frontmatter

from .crypto import (
    encrypt,
    decrypt,
    content_hash,
    rewrap_keys,
    hex_to_salt,
    validate_username,
    CryptoidError,
)
from .frontmatter import (
    parse_markdown,
    should_encrypt,
    is_already_encrypted,
    get_encryption_config,
    EncryptionConfig,
)


# =============================================================================
# Configuration loading and validation
# =============================================================================


def load_config(config_path: Path) -> dict[str, Any]:
    """Load cryptoid configuration from YAML file.

    Expected format:
        users:
          alice: "alice-password"
          bob: "bob-password"
        groups:
          admin: [alice]
          team: [alice, bob]
        salt: "hex-string-32-chars"

    Args:
        config_path: Path to .cryptoid.yaml

    Returns:
        Validated configuration dictionary with 'users', 'groups', 'salt'.

    Raises:
        FileNotFoundError: If config file doesn't exist.
        CryptoidError: If config is invalid.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
        config = yaml.safe_load(f) or {}

    # Validate users
    users = config.get("users")
    if not users or not isinstance(users, dict):
        raise CryptoidError("Config must have a non-empty 'users' dict")

    for username, password in users.items():
        validate_username(str(username))
        if not password:
            raise CryptoidError(f"Password for user '{username}' cannot be empty")
        # Ensure string types
        users[username] = str(password)

    config["users"] = {str(k): str(v) for k, v in users.items()}

    # Validate groups
    groups = config.get("groups", {})
    if not isinstance(groups, dict):
        raise CryptoidError("'groups' must be a dict")

    for group_name, members in groups.items():
        if not isinstance(members, list):
            raise CryptoidError(f"Group '{group_name}' members must be a list")
        for member in members:
            if str(member) not in config["users"]:
                raise CryptoidError(
                    f"Group '{group_name}' member '{member}' not found in users"
                )
        groups[group_name] = [str(m) for m in members]

    config["groups"] = groups

    # Validate salt
    salt_hex = config.get("salt")
    if salt_hex:
        config["salt_bytes"] = hex_to_salt(str(salt_hex))
    else:
        config["salt_bytes"] = None

    return config


# =============================================================================
# Cascade resolution
# =============================================================================


def resolve_encryption(file_path: Path, content_dir: Path) -> EncryptionConfig | None:
    """Resolve effective encryption config for a file using _index.md cascade.

    Algorithm:
        1. If file's own front matter has 'encrypted' field → use it
        2. Walk up parent dirs to content_dir, checking each _index.md
        3. First _index.md with 'encrypted' field → use it (nearest wins)
        4. Nothing found → None (not encrypted)

    _index.md files themselves are never encrypted.

    Args:
        file_path: Path to the markdown file.
        content_dir: Root content directory.

    Returns:
        EncryptionConfig if encryption applies, None if not.
    """
    # _index.md files are never encrypted
    if file_path.name == "_index.md":
        return None

    content = file_path.read_text(encoding="utf-8")
    fm, _ = parse_markdown(content)

    # Check file's own front matter
    if "encrypted" in fm:
        if fm["encrypted"] is False:
            return None
        if fm["encrypted"] is True:
            return get_encryption_config(content)

    # Walk up parent directories
    try:
        rel = file_path.parent.relative_to(content_dir)
    except ValueError:
        return None

    # Build list of directories from file's parent up to content_dir
    dirs_to_check = []
    current = file_path.parent
    while True:
        dirs_to_check.append(current)
        if current == content_dir:
            break
        parent = current.parent
        if parent == current:
            break
        current = parent

    for dir_path in dirs_to_check:
        index_file = dir_path / "_index.md"
        if index_file.exists():
            index_content = index_file.read_text(encoding="utf-8")
            index_fm, _ = parse_markdown(index_content)
            if "encrypted" in index_fm:
                if index_fm["encrypted"] is False:
                    return None
                if index_fm["encrypted"] is True:
                    return get_encryption_config(index_content)

    return None


def resolve_users(
    groups_list: list[str] | None,
    config: dict[str, Any],
) -> dict[str, str]:
    """Resolve group names to a set of {username: password} pairs.

    Args:
        groups_list: List of group names from front matter, or None for all users.
        config: Loaded configuration dict.

    Returns:
        Dict of {username: password} for all resolved users.

    Raises:
        CryptoidError: If a referenced group doesn't exist.
    """
    all_users = config["users"]
    groups = config["groups"]

    # None or contains "all" → every user
    if groups_list is None or "all" in groups_list:
        resolved = dict(all_users)
    else:
        resolved = {}
        for group_name in groups_list:
            if group_name not in groups:
                raise CryptoidError(f"Group '{group_name}' not found in config")
            for member in groups[group_name]:
                resolved[member] = all_users[member]

    # Always inject admin group if it exists
    if "admin" in groups:
        for member in groups["admin"]:
            resolved[member] = all_users[member]

    return resolved


# =============================================================================
# Shortcode extraction (flexible attribute parsing)
# =============================================================================


def _extract_shortcode_content(content: str) -> dict[str, str] | None:
    """Extract attributes and ciphertext from cryptoid shortcode.

    Returns dict with keys: mode, hint, remember, hash, ciphertext.
    Returns None if no shortcode found.
    """
    # Match the full shortcode with its content
    pattern = r'\{\{<\s*cryptoid-encrypted\s*(.*?)\s*>\}\}\s*(.*?)\s*\{\{<\s*/cryptoid-encrypted\s*>\}\}'
    match = re.search(pattern, content, re.DOTALL)
    if not match:
        return None

    attrs_str = match.group(1)
    ciphertext = match.group(2).strip()

    # Parse individual attributes
    attr_pattern = r'(\w+)="([^"]*)"'
    attrs = dict(re.findall(attr_pattern, attrs_str))

    return {
        "mode": attrs.get("mode", "user"),
        "hint": attrs.get("hint", ""),
        "remember": attrs.get("remember", "ask"),
        "hash": attrs.get("hash", ""),
        "ciphertext": ciphertext,
    }


# =============================================================================
# File encryption/decryption
# =============================================================================


def encrypt_file(
    file_path: Path,
    users: dict[str, str],
    salt: bytes | None = None,
) -> bool:
    """Encrypt a single markdown file in place.

    Args:
        file_path: Path to the markdown file.
        users: Dict of {username: password} for the effective user set.
        salt: Optional shared salt from config.

    Returns:
        True if file was encrypted, False if skipped (already encrypted).
    """
    content = file_path.read_text(encoding="utf-8")

    # Skip if already encrypted
    if is_already_encrypted(content):
        return False

    # Parse front matter and body
    post = frontmatter.loads(content)
    body = post.content

    # Get encryption config for hint/remember
    config = get_encryption_config(content)

    # Compute content hash before encryption
    hash_value = content_hash(body)

    # Encrypt the body with multi-user key wrapping
    ciphertext = encrypt(body, users, salt=salt)

    # Build shortcode with config
    mode_attr = 'mode="user"'
    hint_attr = f'hint="{config.password_hint or ""}"'
    remember_attr = f'remember="{config.remember}"'
    hash_attr = f'hash="{hash_value}"'
    shortcode = f"{{{{< cryptoid-encrypted {mode_attr} {hint_attr} {remember_attr} {hash_attr} >}}}}\n{ciphertext}\n{{{{< /cryptoid-encrypted >}}}}"

    # Rebuild the file with encrypted body
    post.content = shortcode

    # Ensure encrypted flag is set
    post.metadata["encrypted"] = True

    # Write back
    file_path.write_text(frontmatter.dumps(post), encoding="utf-8")
    return True


def decrypt_file(
    file_path: Path,
    users: dict[str, str],
) -> bool:
    """Decrypt a single markdown file in place.

    Tries each user credential until one succeeds.

    Args:
        file_path: Path to the encrypted markdown file.
        users: Dict of {username: password} to try.

    Returns:
        True if file was decrypted, False if skipped (not encrypted).

    Raises:
        CryptoidError: If decryption fails for all users.
    """
    content = file_path.read_text(encoding="utf-8")

    # Skip if not encrypted
    if not is_already_encrypted(content):
        return False

    # Extract ciphertext from shortcode
    extracted = _extract_shortcode_content(content)
    if not extracted:
        raise CryptoidError(f"Could not extract ciphertext from {file_path}")

    expected_hash = extracted["hash"]
    ciphertext = extracted["ciphertext"]

    # Try each user credential
    plaintext = None
    for username, password in users.items():
        try:
            plaintext = decrypt(ciphertext, password, username)
            break
        except CryptoidError:
            continue

    if plaintext is None:
        raise CryptoidError(
            f"Decryption failed for {file_path}: no valid credentials"
        )

    # Verify content hash if present
    if expected_hash:
        actual_hash = content_hash(plaintext)
        if actual_hash != expected_hash:
            raise CryptoidError(
                f"Content hash mismatch in {file_path}: decryption may be corrupted"
            )

    # Parse front matter (preserved in encrypted file)
    post = frontmatter.loads(content)

    # Replace shortcode with decrypted content
    post.content = plaintext

    # Write back
    file_path.write_text(frontmatter.dumps(post), encoding="utf-8")
    return True


# =============================================================================
# CLI commands
# =============================================================================


@click.group()
@click.version_option()
def main():
    """Cryptoid: Client-side encrypted content for Hugo."""
    pass


@main.command()
@click.option(
    "--content-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="content",
    help="Hugo content directory",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
@click.option(
    "--dry-run",
    is_flag=True,
    help="Show what would be encrypted without making changes",
)
def encrypt_cmd(content_dir: Path, config_path: Path, dry_run: bool):
    """Encrypt marked content files.

    Processes all .md files in content-dir that have `encrypted: true`
    in their front matter or inherit encryption from _index.md cascade.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    salt = config["salt_bytes"]
    encrypted_count = 0
    skipped_count = 0
    error_count = 0

    # Find all markdown files
    for md_file in sorted(content_dir.rglob("*.md")):
        # Skip _index.md files
        if md_file.name == "_index.md":
            continue

        # Resolve encryption via cascade
        enc_config = resolve_encryption(md_file, content_dir)
        if enc_config is None:
            continue

        # Check if already encrypted
        content = md_file.read_text(encoding="utf-8")
        if is_already_encrypted(content):
            skipped_count += 1
            if dry_run:
                click.echo(
                    f"  [skip] {md_file.relative_to(content_dir)} (already encrypted)"
                )
            continue

        # Resolve users for this file's groups
        try:
            users = resolve_users(enc_config.groups, config)
        except CryptoidError as e:
            click.echo(
                f"Error: {e} (for {md_file.relative_to(content_dir)})", err=True
            )
            error_count += 1
            continue

        if dry_run:
            rel = md_file.relative_to(content_dir)
            group_info = enc_config.groups or ["all"]
            click.echo(
                f"  [dry run] Would encrypt: {rel} "
                f"(groups: {group_info}, users: {len(users)})"
            )
            encrypted_count += 1
        else:
            try:
                # Ensure encrypted: true in front matter if inherited
                fm, _ = parse_markdown(content)
                if "encrypted" not in fm:
                    post = frontmatter.loads(content)
                    post.metadata["encrypted"] = True
                    # Copy cascade settings to file's own front matter
                    if enc_config.groups:
                        post.metadata["groups"] = enc_config.groups
                    if enc_config.password_hint:
                        post.metadata["password_hint"] = enc_config.password_hint
                    if enc_config.remember != "ask":
                        post.metadata["remember"] = enc_config.remember
                    md_file.write_text(
                        frontmatter.dumps(post), encoding="utf-8"
                    )

                if encrypt_file(md_file, users, salt=salt):
                    click.echo(
                        f"  [encrypted] {md_file.relative_to(content_dir)}"
                    )
                    encrypted_count += 1
                else:
                    skipped_count += 1
            except Exception as e:
                click.echo(f"Error encrypting {md_file}: {e}", err=True)
                error_count += 1

    # Summary
    click.echo()
    if dry_run:
        click.echo(
            f"Dry run complete: {encrypted_count} files would be encrypted, "
            f"{skipped_count} skipped"
        )
    else:
        click.echo(
            f"Encryption complete: {encrypted_count} encrypted, "
            f"{skipped_count} skipped, {error_count} errors"
        )

    if error_count > 0:
        sys.exit(1)


@main.command()
@click.option(
    "--content-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="content",
    help="Hugo content directory",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def decrypt_cmd(content_dir: Path, config_path: Path):
    """Decrypt encrypted content files.

    Restores original plaintext for files that were encrypted with the
    encrypt command. Use this before committing to git.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    all_users = config["users"]

    decrypted_count = 0
    skipped_count = 0
    error_count = 0

    # Find all markdown files
    for md_file in sorted(content_dir.rglob("*.md")):
        content = md_file.read_text(encoding="utf-8")

        # Skip if not encrypted
        if not is_already_encrypted(content):
            continue

        try:
            if decrypt_file(md_file, all_users):
                click.echo(
                    f"  [decrypted] {md_file.relative_to(content_dir)}"
                )
                decrypted_count += 1
            else:
                skipped_count += 1
        except CryptoidError as e:
            click.echo(f"Error decrypting {md_file}: {e}", err=True)
            error_count += 1

    # Summary
    click.echo()
    click.echo(
        f"Decryption complete: {decrypted_count} decrypted, "
        f"{skipped_count} skipped, {error_count} errors"
    )

    if error_count > 0:
        sys.exit(1)


# Expose commands with proper names for Click
main.add_command(encrypt_cmd, name="encrypt")
main.add_command(decrypt_cmd, name="decrypt")


# =============================================================================
# Status command
# =============================================================================


@main.command()
@click.option(
    "--content-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="content",
    help="Hugo content directory",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
@click.option(
    "--verbose",
    is_flag=True,
    help="Show summary statistics",
)
def status(content_dir: Path, config_path: Path, verbose: bool):
    """Show encryption status of content files.

    Lists each file's encryption state, groups, and whether settings
    are inherited from _index.md or set directly.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    encrypted_files = []
    plain_files = []
    group_usage: dict[str, int] = {}
    user_access: dict[str, int] = {}

    for md_file in sorted(content_dir.rglob("*.md")):
        rel = md_file.relative_to(content_dir)

        if md_file.name == "_index.md":
            # Show _index.md cascade settings
            content = md_file.read_text(encoding="utf-8")
            fm, _ = parse_markdown(content)
            if "encrypted" in fm:
                enc_config = get_encryption_config(content)
                groups_info = enc_config.groups or ["all"]
                click.echo(f"  [cascade]   {rel}  groups={groups_info}")
            continue

        enc_config = resolve_encryption(md_file, content_dir)
        content = md_file.read_text(encoding="utf-8")
        already_enc = is_already_encrypted(content)

        if enc_config is None:
            plain_files.append(str(rel))
            click.echo(f"  [plain]     {rel}")
        else:
            # Determine source (own front matter vs inherited)
            fm, _ = parse_markdown(content)
            source = "own" if "encrypted" in fm else "inherited"
            groups_info = enc_config.groups or ["all"]
            state = "ENCRYPTED" if already_enc else "pending"

            try:
                users = resolve_users(enc_config.groups, config)
                user_count = len(users)
            except CryptoidError:
                user_count = 0

            encrypted_files.append(str(rel))
            click.echo(
                f"  [{state:9s}] {rel}  "
                f"groups={groups_info} users={user_count} source={source}"
            )

            # Track stats for verbose
            for g in groups_info:
                group_usage[g] = group_usage.get(g, 0) + 1
            for u in users:
                user_access[u] = user_access.get(u, 0) + 1

    # Summary
    click.echo()
    click.echo(
        f"Total: {len(encrypted_files)} encrypted, {len(plain_files)} plain"
    )

    if verbose and encrypted_files:
        click.echo()
        click.echo("Group usage:")
        for group, count in sorted(group_usage.items()):
            click.echo(f"  {group}: {count} files")

        click.echo()
        click.echo("Per-user access:")
        for user, count in sorted(user_access.items()):
            click.echo(f"  {user}: {count} files")


# =============================================================================
# Rewrap command
# =============================================================================


@main.command()
@click.option(
    "--content-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="content",
    help="Hugo content directory",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
@click.option(
    "--rekey",
    is_flag=True,
    help="Generate new CEK and re-encrypt content (forward secrecy)",
)
def rewrap(content_dir: Path, config_path: Path, rekey: bool):
    """Re-wrap encrypted files for current user configuration.

    Use after modifying users/groups in config. With --rekey, generates
    new content encryption keys for forward secrecy.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    all_users = config["users"]
    salt = config["salt_bytes"]

    rewrapped_count = 0
    error_count = 0

    for md_file in sorted(content_dir.rglob("*.md")):
        content = md_file.read_text(encoding="utf-8")

        if not is_already_encrypted(content):
            continue

        # Extract ciphertext
        extracted = _extract_shortcode_content(content)
        if not extracted:
            click.echo(
                f"Error: Could not extract shortcode from {md_file}", err=True
            )
            error_count += 1
            continue

        ciphertext = extracted["ciphertext"]

        # Resolve new user set for this file
        enc_config = get_encryption_config(content)
        try:
            new_users = resolve_users(enc_config.groups, config)
        except CryptoidError as e:
            click.echo(f"Error: {e} (for {md_file})", err=True)
            error_count += 1
            continue

        # Rewrap with all_users as old (any valid credential recovers CEK)
        try:
            new_payload = rewrap_keys(
                ciphertext,
                old_users=all_users,
                new_users=new_users,
                rekey=rekey,
            )
        except CryptoidError as e:
            click.echo(f"Error rewrapping {md_file}: {e}", err=True)
            error_count += 1
            continue

        # Rebuild shortcode
        mode_attr = 'mode="user"'
        hint_attr = f'hint="{extracted["hint"]}"'
        remember_attr = f'remember="{extracted["remember"]}"'
        hash_attr = f'hash="{extracted["hash"]}"'
        shortcode = f"{{{{< cryptoid-encrypted {mode_attr} {hint_attr} {remember_attr} {hash_attr} >}}}}\n{new_payload}\n{{{{< /cryptoid-encrypted >}}}}"

        # Replace shortcode in file
        post = frontmatter.loads(content)
        post.content = shortcode
        md_file.write_text(frontmatter.dumps(post), encoding="utf-8")

        rel = md_file.relative_to(content_dir)
        action = "rekeyed" if rekey else "rewrapped"
        click.echo(f"  [{action}] {rel} (users: {len(new_users)})")
        rewrapped_count += 1

    click.echo()
    click.echo(
        f"Rewrap complete: {rewrapped_count} files, {error_count} errors"
    )

    if error_count > 0:
        sys.exit(1)


# =============================================================================
# Protect / Unprotect commands
# =============================================================================


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--groups",
    multiple=True,
    help="Group names to grant access (repeatable, omit for all users)",
)
@click.option(
    "--hint",
    default=None,
    help="Password hint to display in the browser",
)
@click.option(
    "--remember",
    type=click.Choice(["none", "session", "local", "ask"]),
    default=None,
    help="Browser credential storage mode",
)
def protect(path: Path, groups: tuple[str, ...], hint: str | None, remember: str | None):
    """Mark a file or directory for encryption.

    If PATH is a directory, creates or updates its _index.md with
    encryption settings. If PATH is a file, updates its front matter.

    This does not encrypt content — it configures what will be encrypted
    when you run 'cryptoid encrypt'.

    Examples:

        cryptoid protect content/private/ --groups team

        cryptoid protect content/secret.md --groups admin --hint "Ask the lead"
    """
    path = path.resolve()

    if path.is_dir():
        _protect_directory(path, groups, hint, remember)
    elif path.is_file() and path.suffix == ".md":
        _protect_file(path, groups, hint, remember)
    else:
        click.echo(f"Error: {path} must be a directory or .md file", err=True)
        sys.exit(1)


def _protect_directory(
    dir_path: Path,
    groups: tuple[str, ...],
    hint: str | None,
    remember: str | None,
) -> None:
    """Create or update _index.md in a directory to enable encryption cascade."""
    index_path = dir_path / "_index.md"

    if index_path.exists():
        content = index_path.read_text(encoding="utf-8")
        post = frontmatter.loads(content)
    else:
        post = frontmatter.Post("")
        post.metadata["title"] = dir_path.name.replace("-", " ").replace("_", " ").title()

    post.metadata["encrypted"] = True

    if groups:
        post.metadata["groups"] = list(groups)
    # Don't remove existing groups if --groups not specified

    if hint is not None:
        post.metadata["password_hint"] = hint
    if remember is not None:
        post.metadata["remember"] = remember

    index_path.write_text(frontmatter.dumps(post), encoding="utf-8")

    groups_info = list(groups) if groups else post.metadata.get("groups", ["all"])
    action = "Updated" if index_path.exists() else "Created"
    click.echo(f"{action} {index_path}")
    click.echo(f"  encrypted: true, groups: {groups_info}")
    click.echo()
    click.echo("Run 'cryptoid encrypt' to encrypt content in this directory.")


def _protect_file(
    file_path: Path,
    groups: tuple[str, ...],
    hint: str | None,
    remember: str | None,
) -> None:
    """Update a file's front matter to enable encryption."""
    content = file_path.read_text(encoding="utf-8")
    post = frontmatter.loads(content)

    post.metadata["encrypted"] = True

    if groups:
        post.metadata["groups"] = list(groups)

    if hint is not None:
        post.metadata["password_hint"] = hint
    if remember is not None:
        post.metadata["remember"] = remember

    file_path.write_text(frontmatter.dumps(post), encoding="utf-8")

    groups_info = list(groups) if groups else post.metadata.get("groups", ["all"])
    click.echo(f"Updated {file_path}")
    click.echo(f"  encrypted: true, groups: {groups_info}")
    click.echo()
    click.echo("Run 'cryptoid encrypt' to encrypt this file.")


@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path))
def unprotect(path: Path):
    """Remove encryption marking from a file or directory.

    If PATH is a directory, updates its _index.md to disable the encryption
    cascade. If PATH is a file, sets encrypted: false in its front matter
    (this also overrides any inherited cascade).

    This does not decrypt content — use 'cryptoid decrypt' first if the
    file is already encrypted.

    Examples:

        cryptoid unprotect content/private/

        cryptoid unprotect content/secret.md
    """
    path = path.resolve()

    if path.is_dir():
        _unprotect_directory(path)
    elif path.is_file() and path.suffix == ".md":
        _unprotect_file(path)
    else:
        click.echo(f"Error: {path} must be a directory or .md file", err=True)
        sys.exit(1)


def _unprotect_directory(dir_path: Path) -> None:
    """Update _index.md to disable encryption cascade."""
    index_path = dir_path / "_index.md"

    if not index_path.exists():
        click.echo(f"No _index.md found in {dir_path} — nothing to unprotect")
        return

    content = index_path.read_text(encoding="utf-8")
    post = frontmatter.loads(content)

    if "encrypted" not in post.metadata:
        click.echo(f"{index_path} has no encryption settings — nothing to unprotect")
        return

    # Remove encryption-related fields
    post.metadata.pop("encrypted", None)
    post.metadata.pop("groups", None)
    post.metadata.pop("password_hint", None)
    post.metadata.pop("remember", None)

    # If _index.md has no remaining meaningful content, remove it
    remaining_meta = {k: v for k, v in post.metadata.items() if k != "title"}
    if not remaining_meta and not post.content.strip():
        index_path.unlink()
        click.echo(f"Removed {index_path} (no remaining content)")
    else:
        index_path.write_text(frontmatter.dumps(post), encoding="utf-8")
        click.echo(f"Updated {index_path}")
        click.echo("  Encryption settings removed")

    click.echo()
    click.echo("Files in this directory will no longer inherit encryption.")


def _unprotect_file(file_path: Path) -> None:
    """Set encrypted: false in a file's front matter."""
    content = file_path.read_text(encoding="utf-8")

    if is_already_encrypted(content):
        click.echo(
            f"Warning: {file_path} is currently encrypted. "
            "Run 'cryptoid decrypt' first, then unprotect.",
            err=True,
        )
        sys.exit(1)

    post = frontmatter.loads(content)

    # Set encrypted: false (explicit opt-out, overrides cascade)
    post.metadata["encrypted"] = False

    # Remove groups since they're no longer relevant
    post.metadata.pop("groups", None)
    post.metadata.pop("password_hint", None)
    post.metadata.pop("remember", None)

    file_path.write_text(frontmatter.dumps(post), encoding="utf-8")

    click.echo(f"Updated {file_path}")
    click.echo("  encrypted: false (explicit opt-out)")


# =============================================================================
# Validate command
# =============================================================================


@main.command()
@click.option(
    "--content-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default="content",
    help="Hugo content directory",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def validate(content_dir: Path, config_path: Path):
    """Validate configuration and content consistency.

    Checks that the config is well-formed, all group references in content
    are valid, encrypted files are decryptable, and content hashes verify.
    Reports errors and warnings separately.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # --- Check 1: Config loading ---
    click.echo("Checking config...")
    try:
        config = load_config(config_path)
        click.echo(f"  Config OK: {len(config['users'])} users, "
                    f"{len(config['groups'])} groups")
    except FileNotFoundError as e:
        click.echo(f"  ERROR: {e}", err=True)
        errors.append(str(e))
        _print_validate_summary(errors, warnings)
        sys.exit(1)
    except CryptoidError as e:
        click.echo(f"  ERROR: {e}", err=True)
        errors.append(str(e))
        _print_validate_summary(errors, warnings)
        sys.exit(1)

    # --- Check 2: Group references in front matter ---
    click.echo("Checking group references...")
    referenced_groups: set[str] = set()

    for md_file in sorted(content_dir.rglob("*.md")):
        rel = md_file.relative_to(content_dir)
        content = md_file.read_text(encoding="utf-8")
        fm, _ = parse_markdown(content)

        file_groups = fm.get("groups")
        if file_groups:
            if isinstance(file_groups, str):
                file_groups = [file_groups]
            for group_name in file_groups:
                referenced_groups.add(group_name)
                if group_name != "all" and group_name not in config["groups"]:
                    msg = f"File '{rel}' references undefined group '{group_name}'"
                    click.echo(f"  ERROR: {msg}")
                    errors.append(msg)

    if not errors:
        click.echo("  All group references OK")

    # --- Check 3: Cascade resolution ---
    click.echo("Checking cascade resolution...")
    cascade_errors = 0

    for md_file in sorted(content_dir.rglob("*.md")):
        if md_file.name == "_index.md":
            continue
        rel = md_file.relative_to(content_dir)

        enc_config = resolve_encryption(md_file, content_dir)
        if enc_config is None:
            continue

        try:
            users = resolve_users(enc_config.groups, config)
            if not users:
                msg = f"File '{rel}' resolves to empty user set"
                click.echo(f"  ERROR: {msg}")
                errors.append(msg)
                cascade_errors += 1
        except CryptoidError as e:
            msg = f"File '{rel}': {e}"
            click.echo(f"  ERROR: {msg}")
            errors.append(msg)
            cascade_errors += 1

    if cascade_errors == 0:
        click.echo("  Cascade resolution OK")

    # --- Check 4: Encrypted file decryption verification ---
    click.echo("Checking encrypted files...")
    all_users = config["users"]
    encrypted_file_count = 0
    decrypt_errors = 0

    for md_file in sorted(content_dir.rglob("*.md")):
        content = md_file.read_text(encoding="utf-8")
        if not is_already_encrypted(content):
            continue

        encrypted_file_count += 1
        rel = md_file.relative_to(content_dir)
        extracted = _extract_shortcode_content(content)

        if not extracted:
            msg = f"File '{rel}' has encrypted marker but no valid shortcode"
            click.echo(f"  ERROR: {msg}")
            errors.append(msg)
            decrypt_errors += 1
            continue

        ciphertext = extracted["ciphertext"]
        expected_hash = extracted["hash"]

        # Try decrypting with any available credential
        plaintext = None
        for username, password in all_users.items():
            try:
                plaintext = decrypt(ciphertext, password, username)
                break
            except CryptoidError:
                continue

        if plaintext is None:
            msg = (f"File '{rel}' cannot be decrypted with any "
                   "configured credentials")
            click.echo(f"  ERROR: {msg}")
            errors.append(msg)
            decrypt_errors += 1
            continue

        # --- Check 5: Content hash integrity ---
        if expected_hash:
            actual_hash = content_hash(plaintext)
            if actual_hash != expected_hash:
                msg = (f"File '{rel}' has content hash mismatch "
                       f"(expected {expected_hash[:8]}..., "
                       f"got {actual_hash[:8]}...)")
                click.echo(f"  ERROR: {msg}")
                errors.append(msg)
                decrypt_errors += 1
                continue

        click.echo(f"  OK: {rel}")

    if encrypted_file_count == 0:
        click.echo("  No encrypted files found")
    elif decrypt_errors == 0:
        click.echo(f"  All {encrypted_file_count} encrypted files OK")

    # --- Check 6: Unused groups ---
    click.echo("Checking for unused groups...")
    for group_name in config["groups"]:
        if group_name == "admin":
            continue  # admin is implicitly used everywhere
        if group_name not in referenced_groups:
            msg = f"Group '{group_name}' is defined but not referenced by any content"
            click.echo(f"  WARNING: {msg}")
            warnings.append(msg)

    # --- Check 7: Users without group membership ---
    click.echo("Checking user coverage...")
    all_group_members: set[str] = set()
    for members in config["groups"].values():
        all_group_members.update(members)

    for username in config["users"]:
        if username not in all_group_members:
            msg = f"User '{username}' is not a member of any group"
            click.echo(f"  WARNING: {msg}")
            warnings.append(msg)

    if not warnings:
        click.echo("  All users have group membership")

    # --- Summary ---
    _print_validate_summary(errors, warnings)

    if errors:
        sys.exit(1)


def _print_validate_summary(errors: list[str], warnings: list[str]) -> None:
    """Print validation summary."""
    click.echo()
    if errors:
        click.echo(f"Validation FAILED: {len(errors)} error(s), "
                    f"{len(warnings)} warning(s)")
    elif warnings:
        click.echo(f"Validation passed with {len(warnings)} warning(s)")
    else:
        click.echo("Validation passed: no errors or warnings")


# =============================================================================
# Hugo integration commands
# =============================================================================

# Path to bundled Hugo files (relative to this module)
HUGO_FILES_DIR = Path(__file__).parent.parent.parent / "hugo"

# Hugo config file names to detect
HUGO_CONFIG_FILES = ["hugo.toml", "hugo.yaml", "hugo.yml", "config.toml", "config.yaml", "config.yml"]


def _find_hugo_root(start_dir: Path) -> Path | None:
    """Find Hugo site root by looking for config files."""
    current = start_dir.resolve()
    for _ in range(10):
        for config_name in HUGO_CONFIG_FILES:
            if (current / config_name).exists():
                return current
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _is_hugo_site(path: Path) -> bool:
    """Check if path is a Hugo site root."""
    for config_name in HUGO_CONFIG_FILES:
        if (path / config_name).exists():
            return True
    return False


def _get_cryptoid_files(site_dir: Path) -> dict[str, Path]:
    """Get paths to cryptoid files in a Hugo site."""
    return {
        "shortcode": site_dir / "layouts" / "shortcodes" / "cryptoid-encrypted.html",
        "js": site_dir / "assets" / "js" / "cryptoid.js",
    }


def _get_source_files() -> dict[str, Path]:
    """Get paths to source cryptoid files bundled with the package."""
    return {
        "shortcode": HUGO_FILES_DIR / "layouts" / "shortcodes" / "cryptoid-encrypted.html",
        "js": HUGO_FILES_DIR / "assets" / "js" / "cryptoid.js",
    }


@main.group()
def hugo():
    """Manage Hugo site integration."""
    pass


@hugo.command("status")
@click.option(
    "--site-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Hugo site directory (auto-detected if not specified)",
)
def hugo_status(site_dir: Path | None):
    """Check cryptoid installation status in Hugo site."""
    if site_dir is None:
        site_dir = _find_hugo_root(Path.cwd())
        if site_dir is None:
            click.echo("Error: Not in a Hugo site (no hugo.toml/config.toml found)", err=True)
            sys.exit(1)
    elif not _is_hugo_site(site_dir):
        click.echo(f"Error: {site_dir} is not a Hugo site (no hugo.toml/config.toml found)", err=True)
        sys.exit(1)

    click.echo(f"Hugo site: {site_dir}")
    click.echo()

    files = _get_cryptoid_files(site_dir)
    all_installed = True

    for name, path in files.items():
        if path.exists():
            click.echo(f"  [installed] {path.relative_to(site_dir)}")
        else:
            click.echo(f"  [missing]   {path.relative_to(site_dir)}")
            all_installed = False

    click.echo()
    if all_installed:
        click.echo("Status: cryptoid is installed")
    else:
        click.echo("Status: cryptoid is not installed (run 'cryptoid hugo install')")


@hugo.command("install")
@click.option(
    "--site-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Hugo site directory (auto-detected if not specified)",
)
def hugo_install(site_dir: Path | None):
    """Install cryptoid shortcode and JavaScript into Hugo site."""
    if site_dir is None:
        site_dir = _find_hugo_root(Path.cwd())
        if site_dir is None:
            click.echo("Error: Not in a Hugo site (no hugo.toml/config.toml found)", err=True)
            sys.exit(1)
    elif not _is_hugo_site(site_dir):
        click.echo(f"Error: {site_dir} is not a Hugo site (no hugo.toml/config.toml found)", err=True)
        sys.exit(1)

    click.echo(f"Installing cryptoid to: {site_dir}")

    source_files = _get_source_files()
    dest_files = _get_cryptoid_files(site_dir)

    for name, source_path in source_files.items():
        dest_path = dest_files[name]
        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if source_path.exists():
            dest_path.write_text(source_path.read_text())
            click.echo(f"  [installed] {dest_path.relative_to(site_dir)}")
        else:
            click.echo(f"  [error] Source file not found: {source_path}", err=True)
            sys.exit(1)

    click.echo()
    click.echo("Installation complete!")


@hugo.command("uninstall")
@click.option(
    "--site-dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Hugo site directory (auto-detected if not specified)",
)
def hugo_uninstall(site_dir: Path | None):
    """Remove cryptoid files from Hugo site."""
    if site_dir is None:
        site_dir = _find_hugo_root(Path.cwd())
        if site_dir is None:
            click.echo("Error: Not in a Hugo site (no hugo.toml/config.toml found)", err=True)
            sys.exit(1)
    elif not _is_hugo_site(site_dir):
        click.echo(f"Error: {site_dir} is not a Hugo site (no hugo.toml/config.toml found)", err=True)
        sys.exit(1)

    click.echo(f"Uninstalling cryptoid from: {site_dir}")

    files = _get_cryptoid_files(site_dir)
    removed_any = False

    for name, path in files.items():
        if path.exists():
            path.unlink()
            click.echo(f"  [removed] {path.relative_to(site_dir)}")
            removed_any = True
        else:
            click.echo(f"  [skipped] {path.relative_to(site_dir)} (not found)")

    click.echo()
    if removed_any:
        click.echo("Uninstallation complete!")
    else:
        click.echo("Nothing to uninstall (cryptoid was not installed)")


# =============================================================================
# Claude Code skill management commands
# =============================================================================

# Path to bundled Claude skill (relative to this module)
CLAUDE_SKILL_DIR = Path(__file__).parent.parent.parent / "claude" / "skills" / "cryptoid"

# Skill file name
SKILL_FILENAME = "SKILL.md"


def _get_local_skill_path() -> Path:
    """Get path to local (project-specific) skill installation."""
    return Path.cwd() / ".claude" / "skills" / "cryptoid" / SKILL_FILENAME


def _get_global_skill_path() -> Path:
    """Get path to global (user-wide) skill installation."""
    return Path.home() / ".claude" / "skills" / "cryptoid" / SKILL_FILENAME


def _get_source_skill_path() -> Path:
    """Get path to bundled skill file."""
    return CLAUDE_SKILL_DIR / SKILL_FILENAME


@main.group()
def claude():
    """Manage Claude Code skill integration."""
    pass


@claude.command("status")
def claude_status():
    """Check cryptoid skill installation status."""
    local_path = _get_local_skill_path()
    global_path = _get_global_skill_path()

    click.echo("Claude Code skill status:")
    click.echo()

    if local_path.exists():
        click.echo(f"  [installed] local:  {local_path}")
    else:
        click.echo(f"  [missing]   local:  {local_path}")

    if global_path.exists():
        click.echo(f"  [installed] global: {global_path}")
    else:
        click.echo(f"  [missing]   global: {global_path}")

    click.echo()

    if local_path.exists() or global_path.exists():
        click.echo("Status: cryptoid skill is installed")
    else:
        click.echo("Status: cryptoid skill is not installed (run 'cryptoid claude install')")


@claude.command("install")
@click.option(
    "--local/--global",
    "local",
    default=True,
    help="Install locally (project) or globally (user-wide)",
)
def claude_install(local: bool):
    """Install cryptoid skill for Claude Code."""
    source_path = _get_source_skill_path()
    dest_path = _get_local_skill_path() if local else _get_global_skill_path()
    scope = "local" if local else "global"

    if not source_path.exists():
        click.echo(f"Error: Source skill file not found: {source_path}", err=True)
        sys.exit(1)

    dest_path.parent.mkdir(parents=True, exist_ok=True)
    dest_path.write_text(source_path.read_text(encoding="utf-8"), encoding="utf-8")

    click.echo(f"Installed cryptoid skill ({scope}):")
    click.echo(f"  {dest_path}")


@claude.command("uninstall")
@click.option(
    "--local/--global",
    "local",
    default=True,
    help="Uninstall from local (project) or global (user-wide)",
)
def claude_uninstall(local: bool):
    """Remove cryptoid skill from Claude Code."""
    skill_path = _get_local_skill_path() if local else _get_global_skill_path()
    scope = "local" if local else "global"

    if not skill_path.exists():
        click.echo(f"Cryptoid skill is not installed ({scope})")
        return

    skill_path.unlink()

    skill_dir = skill_path.parent
    try:
        skill_dir.rmdir()
        skill_dir.parent.rmdir()
    except OSError:
        pass

    click.echo(f"Uninstalled cryptoid skill ({scope}):")
    click.echo(f"  {skill_path}")
