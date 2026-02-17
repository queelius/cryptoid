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
    generate_salt,
    salt_to_hex,
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


def _get_global_config_path() -> Path:
    """Return the global config file path.

    Uses $XDG_CONFIG_HOME/cryptoid/config.yaml if XDG_CONFIG_HOME is set,
    otherwise ~/.config/cryptoid/config.yaml.
    """
    import os

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        base = Path(xdg)
    else:
        base = Path.home() / ".config"
    return base / "cryptoid" / "config.yaml"


def _load_global_config() -> dict[str, Any]:
    """Load global config if it exists, otherwise return empty dict.

    The global config may contain:
        - users: personal credentials merged into every project
        - content_dir: default Hugo content directory

    Global config never contains groups or salt (those are project-specific).
    """
    path = _get_global_config_path()
    if not path.exists():
        return {}

    with open(path) as f:
        config = yaml.safe_load(f) or {}

    # Validate global users if present
    users = config.get("users")
    if users and isinstance(users, dict):
        for username, password in users.items():
            validate_username(str(username))
            if not password:
                raise CryptoidError(
                    f"Global config: password for user '{username}' cannot be empty"
                )
        config["users"] = {str(k): str(v) for k, v in users.items()}

    return config


def load_config(config_path: Path) -> dict[str, Any]:
    """Load cryptoid configuration, merging global and local configs.

    Merge semantics:
        - users: union, local wins on password conflict (with warning)
        - groups: union of members for same-named groups (additive)
        - salt: local overrides global
        - content_dir: local overrides global
        - admin: local overrides global

    If no local config exists but a global config does, returns global-only
    config (users + content_dir + groups, no salt).

    Args:
        config_path: Path to local .cryptoid.yaml

    Returns:
        Validated configuration dictionary.

    Raises:
        FileNotFoundError: If neither local nor global config exists.
        CryptoidError: If merged config is invalid.
    """
    global_config = _load_global_config()

    if config_path.exists():
        with open(config_path) as f:
            config = yaml.safe_load(f) or {}
    elif global_config:
        config = {}
    else:
        raise FileNotFoundError(f"Config file not found: {config_path}")

    # Merge users (global first, local overrides on conflict)
    global_users = global_config.get("users", {})
    local_users = config.get("users", {})

    # Warn about password conflicts
    for username in global_users:
        if username in local_users and str(global_users[username]) != str(local_users[username]):
            click.echo(
                f"Note: user '{username}' has different passwords in "
                f"global and local config (using local)",
                err=True,
            )

    merged_users = {**global_users, **local_users}

    if not merged_users:
        raise CryptoidError("Config must have a non-empty 'users' dict")

    # Validate merged users
    for username, password in merged_users.items():
        validate_username(str(username))
        if not password:
            raise CryptoidError(f"Password for user '{username}' cannot be empty")

    config["users"] = {str(k): str(v) for k, v in merged_users.items()}

    # Merge groups (additive union of members for same-named groups)
    global_groups = global_config.get("groups", {})
    local_groups = config.get("groups", {})
    merged_groups: dict[str, list[str]] = {}

    all_group_names = set(global_groups.keys()) | set(local_groups.keys())
    for group_name in all_group_names:
        global_members = global_groups.get(group_name, [])
        local_members = local_groups.get(group_name, [])
        if not isinstance(global_members, list):
            raise CryptoidError(f"Global group '{group_name}' members must be a list")
        if not isinstance(local_members, list):
            raise CryptoidError(f"Group '{group_name}' members must be a list")
        # Union of members, preserving order (local first, then global additions)
        seen = set()
        combined = []
        for member in list(local_members) + list(global_members):
            m = str(member)
            if m not in seen:
                seen.add(m)
                combined.append(m)
        merged_groups[group_name] = combined

    # Validate group members exist in merged users
    for group_name, members in merged_groups.items():
        for member in members:
            if member not in config["users"]:
                raise CryptoidError(
                    f"Group '{group_name}' member '{member}' not found in users"
                )

    config["groups"] = merged_groups

    # Validate salt (local only)
    salt_hex = config.get("salt")
    if not salt_hex and "salt" in global_config:
        salt_hex = global_config["salt"]
        config["salt"] = salt_hex
    if salt_hex:
        config["salt_bytes"] = hex_to_salt(str(salt_hex))
    else:
        config["salt_bytes"] = None

    # Resolve content_dir: local > global
    if "content_dir" not in config and "content_dir" in global_config:
        config["content_dir"] = global_config["content_dir"]

    # Resolve admin: local > global
    if "admin" not in config and "admin" in global_config:
        config["admin"] = global_config["admin"]

    # Validate admin exists in merged users
    admin = config.get("admin")
    if admin and str(admin) not in config["users"]:
        raise CryptoidError(
            f"admin '{admin}' not found in users"
        )
    if admin:
        config["admin"] = str(admin)

    return config


def save_config(config_path: Path, config_data: dict[str, Any]) -> None:
    """Write cryptoid configuration to YAML file.

    Writes user-facing keys, excluding internal derived fields like salt_bytes.

    Args:
        config_path: Path to .cryptoid.yaml
        config_data: Configuration dictionary to write.
    """
    # Ordered list of keys to persist (skip internal fields like salt_bytes)
    persist_keys = ["users", "groups", "salt", "content_dir", "admin"]
    output = {k: config_data[k] for k in persist_keys if k in config_data}

    with open(config_path, "w", encoding="utf-8") as f:
        yaml.dump(output, f, default_flow_style=False, sort_keys=False)


def _load_raw_config(config_path: Path) -> dict[str, Any]:
    """Load raw YAML config without validation.

    Used by mutating commands that need to modify and re-save the config
    without the side effects of full validation (like salt_bytes injection).

    Args:
        config_path: Path to .cryptoid.yaml

    Returns:
        Raw configuration dictionary.

    Raises:
        FileNotFoundError: If config file doesn't exist.
    """
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(config_path) as f:
        return yaml.safe_load(f) or {}


def _merged_users(raw: dict[str, Any]) -> dict[str, str]:
    """Return merged users from global config + the given raw config.

    Used by mutation commands that need to validate user existence against
    the effective user set (global + local), not just the tier being modified.
    """
    global_users = _load_global_config().get("users", {})
    local_users = raw.get("users", {})
    return {**global_users, **local_users}


# =============================================================================
# Content directory resolution
# =============================================================================


def _resolve_content_dir(
    cli_value: Path | None,
    config: dict[str, Any] | None = None,
) -> Path:
    """Resolve content directory from CLI > env > config.

    Args:
        cli_value: Value from --content-dir flag (None if not specified).
        config: Loaded config dict (may contain 'content_dir' from local or global).

    Returns:
        Resolved Path to content directory.
    """
    import os

    source: str
    result: str

    # Priority: CLI > env > config (no default)
    if cli_value is not None:
        return cli_value  # Click already validated existence if exists=True
    elif os.environ.get("CRYPTOID_CONTENT_DIR"):
        result = os.environ["CRYPTOID_CONTENT_DIR"]
        source = "CRYPTOID_CONTENT_DIR environment variable"
    elif config and "content_dir" in config:
        result = config["content_dir"]
        source = "config file"
    else:
        click.echo(
            "Error: no content directory specified. Use --content-dir, "
            "set CRYPTOID_CONTENT_DIR, or add content_dir to your config.",
            err=True,
        )
        sys.exit(1)

    resolved = Path(result).expanduser()
    if not resolved.is_absolute():
        resolved = Path.cwd() / resolved

    if not resolved.is_dir():
        click.echo(
            f"Error: content directory '{result}' does not exist "
            f"(from {source})",
            err=True,
        )
        sys.exit(1)

    return resolved


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
    groups = config.get("groups", {})

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

    # Always inject admin user if configured
    admin_user = config.get("admin")
    if admin_user and admin_user in all_users:
        resolved[admin_user] = all_users[admin_user]

    return resolved


# =============================================================================
# Shortcode attribute helpers
# =============================================================================


def _escape_shortcode_attr(value: str) -> str:
    """Escape a value for use in a Hugo shortcode attribute.

    Strips double quotes to prevent attribute injection in shortcode
    attributes like hint="...".
    """
    return value.replace('"', "")


def _build_shortcode(hint: str, remember: str, hash_value: str, ciphertext: str) -> str:
    """Build a cryptoid-encrypted Hugo shortcode.

    Args:
        hint: Password hint (will be escaped for shortcode safety).
        remember: Remember mode (none/session/local/ask).
        hash_value: Content hash for integrity verification.
        ciphertext: Base64-encoded encrypted payload.

    Returns:
        Complete Hugo shortcode string.
    """
    mode_attr = 'mode="user"'
    hint_value = _escape_shortcode_attr(hint)
    hint_attr = f'hint="{hint_value}"'
    remember_attr = f'remember="{remember}"'
    hash_attr = f'hash="{hash_value}"'
    return (
        f"{{{{< cryptoid-encrypted {mode_attr} {hint_attr} {remember_attr} {hash_attr} >}}}}\n"
        f"{ciphertext}\n"
        f"{{{{< /cryptoid-encrypted >}}}}"
    )


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


def _try_decrypt_any_user(ciphertext: str, users: dict[str, str]) -> str | None:
    """Try decrypting ciphertext with each user credential.

    Args:
        ciphertext: Base64-encoded v2 payload.
        users: Dict of {username: password} to try.

    Returns:
        Decrypted plaintext if any credential succeeds, None otherwise.
    """
    for username, password in users.items():
        try:
            return decrypt(ciphertext, password, username)
        except CryptoidError:
            continue
    return None


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
    shortcode = _build_shortcode(
        hint=config.password_hint or "",
        remember=config.remember,
        hash_value=hash_value,
        ciphertext=ciphertext,
    )

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
    plaintext = _try_decrypt_any_user(ciphertext, users)
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


# =============================================================================
# Config command group
# =============================================================================


@main.group()
def config():
    """Manage and inspect cryptoid configuration."""
    pass


@config.command("status")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_status(config_path: Path):
    """Show the location of config files and their status."""
    # Global config
    global_path = _get_global_config_path()
    if global_path.exists():
        global_config = _load_global_config()
        global_users = list(global_config.get("users", {}).keys())
        click.echo(f"Global config: {global_path}")
        if global_users:
            click.echo(f"  Users: {', '.join(global_users)}")
        if "content_dir" in global_config:
            click.echo(f"  Content dir: {global_config['content_dir']}")
    else:
        click.echo(f"Global config: {global_path} (not found)")

    # Local config
    config_path = config_path.resolve()
    if config_path.exists():
        click.echo(f"Local config:  {config_path}")
    else:
        click.echo(f"Local config:  {config_path} (not found)")


@config.command("show")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
@click.option(
    "--show-passwords",
    is_flag=True,
    help="Show passwords in plaintext (masked by default)",
)
def config_show(config_path: Path, show_passwords: bool):
    """Display the effective configuration with source annotations.

    Shows where each value comes from: local config, global config,
    or merged from both. Passwords are masked by default.
    """
    config_path = config_path.resolve()
    has_local = config_path.exists()
    global_config = _load_global_config()
    has_global = bool(global_config)
    global_path = _get_global_config_path()

    if not has_local and not has_global:
        click.echo("No config found (no local .cryptoid.yaml and no global config).", err=True)
        click.echo("Run 'cryptoid init' to create a local config.", err=True)
        click.echo("Run 'cryptoid init --global' to create a global config.", err=True)
        sys.exit(1)

    local_config: dict[str, Any] = {}
    if has_local:
        try:
            local_config = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
        except OSError as e:
            click.echo(f"Error reading config file: {e}", err=True)
            sys.exit(1)

    # Header: show config file paths
    if has_local:
        click.echo(f"Local:  {config_path}")
    if has_global:
        click.echo(f"Global: {global_path}")
    click.echo()

    # Users — show source for each
    global_users = global_config.get("users", {})
    local_users = local_config.get("users", {})
    merged_users = {**global_users, **local_users}

    if merged_users:
        click.echo("users:")
        for username, password in merged_users.items():
            masked = password if show_passwords else (
                password[:2] + "***" if len(password) > 2 else "***"
            )
            if username in local_users and username in global_users:
                source = "local (overrides global)"
            elif username in local_users:
                source = "local"
            else:
                source = "global"
            click.echo(f"  {username}: {masked}  # {source}")

    # Groups — show source for each, with merged members
    global_groups = global_config.get("groups", {})
    local_groups = local_config.get("groups", {})
    all_group_names = list(dict.fromkeys(list(local_groups.keys()) + list(global_groups.keys())))

    if all_group_names:
        click.echo("groups:")
        for group_name in all_group_names:
            g_members = set(str(m) for m in global_groups.get(group_name, []))
            l_members = set(str(m) for m in local_groups.get(group_name, []))
            combined = list(dict.fromkeys(
                [str(m) for m in local_groups.get(group_name, [])] +
                [str(m) for m in global_groups.get(group_name, [])]
            ))
            if g_members and l_members:
                source = "merged (local + global)"
            elif l_members:
                source = "local"
            else:
                source = "global"
            click.echo(f"  {group_name}: [{', '.join(combined)}]  # {source}")

    # Salt — show source
    local_salt = local_config.get("salt")
    global_salt = global_config.get("salt")
    if local_salt:
        click.echo(f"salt: {local_salt}  # local")
    elif global_salt:
        click.echo(f"salt: {global_salt}  # global")

    # Content dir — show source
    local_cdir = local_config.get("content_dir")
    global_cdir = global_config.get("content_dir")
    if local_cdir:
        click.echo(f"content_dir: {local_cdir}  # local")
    elif global_cdir:
        click.echo(f"content_dir: {global_cdir}  # global")

    # Admin — show source
    local_admin = local_config.get("admin")
    global_admin = global_config.get("admin")
    if local_admin:
        click.echo(f"admin: {local_admin}  # local")
    elif global_admin:
        click.echo(f"admin: {global_admin}  # global")


def _mask_passwords(users: dict[str, str], show: bool) -> dict[str, str]:
    """Mask user passwords unless show is True."""
    if show:
        return users
    return {
        username: password[:2] + "***" if len(password) > 2 else "***"
        for username, password in users.items()
    }


@config.command("validate")
@click.option(
    "--content-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Hugo content directory (default: from config or 'content')",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_validate(content_dir: Path | None, config_path: Path):
    """Validate configuration and content consistency.

    Checks that the config is well-formed, all group references in content
    are valid, encrypted files are decryptable, and content hashes verify.
    Reports errors and warnings separately.
    """
    errors: list[str] = []
    warnings: list[str] = []

    # --- Check 1: Config loading ---
    click.echo("Checking config...")
    global_path = _get_global_config_path()
    if global_path.exists():
        global_cfg = _load_global_config()
        global_user_count = len(global_cfg.get("users", {}))
        if global_user_count:
            click.echo(f"  Global config: {global_path} ({global_user_count} users)")
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

    # Resolve content directory
    content_dir = _resolve_content_dir(content_dir, config)

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
        plaintext = _try_decrypt_any_user(ciphertext, all_users)
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


@config.command("generate-salt")
@click.option(
    "--apply",
    is_flag=True,
    help="Write the generated salt to the config file",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Apply to global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_generate_salt(apply: bool, is_global: bool, config_path: Path):
    """Generate a new random salt.

    Prints the hex-encoded salt. With --apply, writes it to the config file.
    After applying a new salt, run `cryptoid rewrap --rekey` to re-encrypt
    all content with the new salt.
    """
    new_salt = salt_to_hex(generate_salt())
    click.echo(f"Generated salt: {new_salt}")

    if apply:
        try:
            if is_global:
                raw = _load_raw_global()
            else:
                raw = _load_raw_config(config_path)
        except FileNotFoundError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

        raw["salt"] = new_salt
        if is_global:
            _save_global(raw)
            click.echo(f"Salt written to global config.")
        else:
            save_config(config_path, raw)
            click.echo(f"Salt written to {config_path}")
        click.echo("Run 'cryptoid rewrap --rekey' to re-encrypt content with the new salt.")


@config.command("list-users")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_list_users(config_path: Path):
    """List all configured users and their group memberships."""
    try:
        cfg = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    users = cfg["users"]
    groups = cfg["groups"]

    if not users:
        click.echo("No users configured.")
        return

    # Build user → groups mapping
    user_groups: dict[str, list[str]] = {u: [] for u in users}
    for group_name, members in groups.items():
        for member in members:
            if member in user_groups:
                user_groups[member].append(group_name)

    # Column widths
    max_name = max(len(u) for u in users)
    max_name = max(max_name, len("USERNAME"))
    header = f"{'USERNAME':<{max_name}}   GROUPS"
    click.echo(header)

    for username in users:
        grps = user_groups[username]
        grps_str = ", ".join(grps) if grps else "(none)"
        click.echo(f"{username:<{max_name}}   {grps_str}")


@config.command("list-groups")
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_list_groups(config_path: Path):
    """List all configured groups and their members."""
    try:
        cfg = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    groups = cfg["groups"]

    if not groups:
        click.echo("(no groups defined)")
        return

    # Column widths
    max_name = max(len(g) for g in groups)
    max_name = max(max_name, len("GROUP"))
    header = f"{'GROUP':<{max_name}}   MEMBERS"
    click.echo(header)

    for group_name, members in groups.items():
        members_str = ", ".join(members) if members else "(empty)"
        click.echo(f"{group_name:<{max_name}}   {members_str}")


@config.command("add-user")
@click.argument("username", required=False, default=None)
@click.option(
    "--group",
    "groups",
    multiple=True,
    help="Add user to this group (repeatable)",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Add to global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_add_user(username: str | None, groups: tuple[str, ...], is_global: bool, config_path: Path):
    """Add a new user to the configuration.

    If USERNAME is omitted, prompts interactively for username, password,
    and group membership. After adding a user, run `cryptoid rewrap` to
    grant them access to encrypted content.
    """
    # Load raw config
    try:
        if is_global:
            raw = _load_raw_global()
        else:
            raw = _load_raw_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    existing_groups = raw.get("groups", {})

    # Prompt for username if not provided
    if username is None:
        while True:
            username = click.prompt("Username")
            try:
                validate_username(username)
                break
            except CryptoidError as e:
                click.echo(f"Invalid username: {e}")
    else:
        try:
            validate_username(username)
        except CryptoidError as e:
            click.echo(f"Error: {e}", err=True)
            sys.exit(1)

    users = raw.get("users", {})
    if username in users:
        click.echo(f"Error: User '{username}' already exists", err=True)
        sys.exit(1)

    # Prompt for password
    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    # Resolve group membership
    if not groups and existing_groups:
        # No --group flags: prompt interactively
        available = list(existing_groups.keys())
        click.echo(f"Available groups: {', '.join(available)}")
        group_input = click.prompt(
            "Add to groups (comma-separated, Enter to skip)",
            default="",
            show_default=False,
        )
        if group_input.strip():
            groups = tuple(g.strip() for g in group_input.split(",") if g.strip())

    # Validate requested groups exist
    for g in groups:
        if g not in existing_groups:
            click.echo(f"Error: Group '{g}' does not exist", err=True)
            sys.exit(1)

    # Add user
    users[username] = password
    raw["users"] = users

    # Add to groups
    for g in groups:
        if username not in existing_groups[g]:
            existing_groups[g].append(username)
    raw["groups"] = existing_groups

    target = "global" if is_global else "local"
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)
    click.echo(f"User '{username}' added ({target}).")
    if groups:
        click.echo(f"Added to groups: {', '.join(groups)}")
    click.echo("Run 'cryptoid rewrap' to grant access to encrypted content.")


@config.command("remove-user")
@click.argument("username")
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Remove from global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_remove_user(username: str, is_global: bool, config_path: Path):
    """Remove a user from the configuration.

    Also removes the user from all groups. After removing a user, run
    `cryptoid rewrap --rekey` to revoke their access.
    """
    try:
        if is_global:
            raw = _load_raw_global()
        else:
            raw = _load_raw_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    users = raw.get("users", {})
    if username not in users:
        # Check if the user exists in the other tier
        other_tier = "global" if not is_global else "local"
        merged = _merged_users(raw)
        if username in merged:
            click.echo(
                f"Error: User '{username}' is not in {'global' if is_global else 'local'} config "
                f"(exists in {other_tier}; use {'--global' if not is_global else '--config'} to remove)",
                err=True,
            )
        else:
            click.echo(f"Error: User '{username}' not found", err=True)
        sys.exit(1)

    # Check merged users — removing from one tier is fine if the other has users
    merged = _merged_users(raw)
    remaining = {u for u in merged if u != username}
    if not remaining:
        click.echo("Error: Cannot remove the last user", err=True)
        sys.exit(1)

    # Remove from users
    del users[username]
    raw["users"] = users

    # Remove from all groups
    groups = raw.get("groups", {})
    for group_name, members in groups.items():
        if username in members:
            members.remove(username)
            if not members:
                click.echo(f"Warning: Group '{group_name}' is now empty")

    raw["groups"] = groups
    target = "global" if is_global else "local"
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)
    click.echo(f"User '{username}' removed ({target}).")
    click.echo("Run 'cryptoid rewrap --rekey' to revoke access to encrypted content.")


@config.command("add-group")
@click.argument("name")
@click.option(
    "--members",
    default="",
    help="Comma-separated list of usernames to add as members",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Add to global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_add_group(name: str, members: str, is_global: bool, config_path: Path):
    """Add a new group to the configuration."""
    try:
        if is_global:
            raw = _load_raw_global()
        else:
            raw = _load_raw_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    groups = raw.get("groups", {})
    if name in groups:
        click.echo(f"Error: Group '{name}' already exists", err=True)
        sys.exit(1)

    all_users = _merged_users(raw)

    # Parse and validate members
    member_list = [m.strip() for m in members.split(",") if m.strip()] if members else []
    for m in member_list:
        if m not in all_users:
            click.echo(f"Error: User '{m}' not found in config", err=True)
            sys.exit(1)

    groups[name] = member_list
    raw["groups"] = groups
    target = "global" if is_global else "local"
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)

    if member_list:
        click.echo(f"Group '{name}' created with members: {', '.join(member_list)} ({target})")
    else:
        click.echo(f"Group '{name}' created (empty, {target}).")


@config.command("remove-group")
@click.argument("name")
@click.option(
    "--force",
    is_flag=True,
    help="Allow removing the admin group",
)
@click.option(
    "--content-dir",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
    default=None,
    help="Scan content directory for group references before removing",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Remove from global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_remove_group(name: str, force: bool, content_dir: Path | None, is_global: bool, config_path: Path):
    """Remove a group from the configuration.

    Refuses to remove the 'admin' group unless --force is given.
    After removing a group, run `cryptoid rewrap` to update encrypted content.
    """
    try:
        if is_global:
            raw = _load_raw_global()
        else:
            raw = _load_raw_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    groups = raw.get("groups", {})
    if name not in groups:
        click.echo(f"Error: Group '{name}' not found", err=True)
        sys.exit(1)

    if name == "admin" and not force:
        click.echo(
            "Error: Refusing to remove 'admin' group. Use --force to override.",
            err=True,
        )
        sys.exit(1)

    # Scan content for references if content-dir provided
    if content_dir is not None:
        referencing_files = []
        for md_file in sorted(content_dir.rglob("*.md")):
            content = md_file.read_text(encoding="utf-8")
            fm, _ = parse_markdown(content)
            file_groups = fm.get("groups")
            if file_groups:
                if isinstance(file_groups, str):
                    file_groups = [file_groups]
                if name in file_groups:
                    referencing_files.append(md_file.relative_to(content_dir))

        if referencing_files:
            click.echo(f"Warning: Group '{name}' is referenced by:")
            for f in referencing_files:
                click.echo(f"  {f}")

    del groups[name]
    raw["groups"] = groups
    target = "global" if is_global else "local"
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)
    click.echo(f"Group '{name}' removed ({target}).")
    click.echo("Run 'cryptoid rewrap' to update encrypted content.")


@config.command("add-to-group")
@click.argument("group")
@click.argument("username")
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Modify global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_add_to_group(group: str, username: str, is_global: bool, config_path: Path):
    """Add an existing user to an existing group.

    \b
    Examples:
      cryptoid config add-to-group team alice
      cryptoid config add-to-group team alice --global
    """
    try:
        if is_global:
            raw = _load_raw_global()
        else:
            raw = _load_raw_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    all_users = _merged_users(raw)
    groups = raw.get("groups", {})

    if username not in all_users:
        click.echo(f"Error: User '{username}' not found", err=True)
        sys.exit(1)

    if group not in groups:
        click.echo(f"Error: Group '{group}' not found", err=True)
        sys.exit(1)

    if username in groups[group]:
        click.echo(f"User '{username}' is already in group '{group}'.")
        return

    groups[group].append(username)
    raw["groups"] = groups
    target = "global" if is_global else "local"
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)
    click.echo(f"Added '{username}' to group '{group}' ({target}).")
    click.echo("Run 'cryptoid rewrap' to update encrypted content.")


@config.command("remove-from-group")
@click.argument("group")
@click.argument("username")
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Modify global config",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def config_remove_from_group(group: str, username: str, is_global: bool, config_path: Path):
    """Remove a user from a group (without deleting the user).

    \b
    Examples:
      cryptoid config remove-from-group team alice
      cryptoid config remove-from-group team alice --global
    """
    try:
        if is_global:
            raw = _load_raw_global()
        else:
            raw = _load_raw_config(config_path)
    except FileNotFoundError as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    groups = raw.get("groups", {})

    if group not in groups:
        click.echo(f"Error: Group '{group}' not found", err=True)
        sys.exit(1)

    if username not in groups[group]:
        click.echo(f"Error: User '{username}' is not in group '{group}'", err=True)
        sys.exit(1)

    groups[group].remove(username)
    if not groups[group]:
        click.echo(f"Warning: Group '{group}' is now empty")
    raw["groups"] = groups
    target = "global" if is_global else "local"
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)
    click.echo(f"Removed '{username}' from group '{group}' ({target}).")
    click.echo("Run 'cryptoid rewrap' to update encrypted content.")


def _load_raw_global() -> dict[str, Any]:
    """Load global config without validation, for mutation."""
    path = _get_global_config_path()
    if not path.exists():
        raise FileNotFoundError(f"Global config not found: {path}")
    with open(path) as f:
        return yaml.safe_load(f) or {}


def _save_global(data: dict[str, Any]) -> None:
    """Write global config back to disk."""
    path = _get_global_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        yaml.dump(data, f, default_flow_style=False, sort_keys=False)


@config.command("set-content-dir")
@click.argument("path", type=click.Path())
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Set in global config (~/.config/cryptoid/config.yaml)",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to local config file",
)
def config_set_content_dir(path: str, is_global: bool, config_path: Path):
    """Set the Hugo content directory.

    PATH is the relative or absolute path to the Hugo content directory.
    It is stored in the config and used by encrypt, decrypt, status, and rewrap
    when --content-dir is not specified on the command line.

    \b
    Examples:
      cryptoid config set-content-dir content/       # Set in local config
      cryptoid config set-content-dir content/ --global  # Set in global config
    """
    if is_global:
        try:
            raw = _load_raw_global()
        except FileNotFoundError:
            click.echo("Error: no global config. Run 'cryptoid init --global' first.", err=True)
            sys.exit(1)
        raw["content_dir"] = path
        _save_global(raw)
        click.echo(f"content_dir set to: {path} (global)")
    else:
        try:
            raw = _load_raw_config(config_path)
        except FileNotFoundError:
            click.echo(f"Error: {config_path} not found. Run 'cryptoid init' first.", err=True)
            sys.exit(1)
        raw["content_dir"] = path
        save_config(config_path, raw)
        click.echo(f"content_dir set to: {path}")


@config.command("set-admin")
@click.argument("username", required=False)
@click.option(
    "--unset",
    is_flag=True,
    help="Remove the admin setting",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Set in global config (~/.config/cryptoid/config.yaml)",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to local config file",
)
def config_set_admin(username: str | None, unset: bool, is_global: bool, config_path: Path):
    """Set or remove the admin user.

    The admin user always gets access to all encrypted content, regardless
    of group membership. Typically set in the global config so it applies
    to all projects.

    \b
    Examples:
      cryptoid config set-admin alice            # Set in local config
      cryptoid config set-admin alice --global   # Set in global config
      cryptoid config set-admin --unset          # Remove from local
      cryptoid config set-admin --unset --global # Remove from global
    """
    if unset and username:
        click.echo("Error: cannot use --unset with a username.", err=True)
        sys.exit(1)

    if not unset and not username:
        click.echo("Error: provide a username or use --unset.", err=True)
        sys.exit(1)

    # Load the target config
    if is_global:
        try:
            raw = _load_raw_global()
        except FileNotFoundError:
            click.echo("Error: no global config. Run 'cryptoid init --global' first.", err=True)
            sys.exit(1)
        target_label = "global"
    else:
        try:
            raw = _load_raw_config(config_path)
        except FileNotFoundError:
            click.echo(f"Error: {config_path} not found. Run 'cryptoid init' first.", err=True)
            sys.exit(1)
        target_label = "local"

    if unset:
        if "admin" in raw:
            del raw["admin"]
            if is_global:
                _save_global(raw)
            else:
                save_config(config_path, raw)
            click.echo(f"admin setting removed ({target_label}).")
        else:
            click.echo(f"No admin setting to remove ({target_label}).")
        return

    # Validate username exists in merged users
    try:
        config = load_config(config_path)
    except FileNotFoundError:
        # No local config — check global users only
        config = {"users": _load_global_config().get("users", {})}

    if username not in config["users"]:
        available = ", ".join(config["users"].keys()) if config["users"] else "(none)"
        click.echo(
            f"Error: user '{username}' not found in config. "
            f"Available users: {available}",
            err=True,
        )
        sys.exit(1)

    raw["admin"] = username
    if is_global:
        _save_global(raw)
    else:
        save_config(config_path, raw)
    click.echo(f"admin set to: {username} ({target_label})")


# =============================================================================
# Init command
# =============================================================================



def _init_global(force: bool, default_content_dir: Path | None) -> None:
    """Create a global user configuration."""
    global_path = _get_global_config_path()

    if global_path.exists() and not force:
        click.echo(
            f"Error: {global_path} already exists. Use --force to overwrite.",
            err=True,
        )
        sys.exit(1)

    # Prompt for user credentials
    while True:
        username = click.prompt("Username")
        try:
            validate_username(username)
            break
        except CryptoidError as e:
            click.echo(f"Invalid username: {e}")

    password = click.prompt("Password", hide_input=True, confirmation_prompt=True)

    # Prompt for default content dir if not given via flag
    if default_content_dir is None:
        dir_input = click.prompt(
            "Default content directory (Enter to skip)",
            default="",
            show_default=False,
        )
        if dir_input.strip():
            default_content_dir = Path(dir_input.strip())

    # Build config
    config_data: dict[str, Any] = {
        "users": {username: password},
    }
    if default_content_dir is not None:
        config_data["content_dir"] = str(default_content_dir)

    # Create parent directory
    global_path.parent.mkdir(parents=True, exist_ok=True)

    # Write config
    with open(global_path, "w", encoding="utf-8") as f:
        yaml.dump(config_data, f, default_flow_style=False, sort_keys=False)

    click.echo(f"Created {global_path}")
    click.echo(f"  User: {username}")
    if default_content_dir:
        click.echo(f"  Content dir: {default_content_dir}")
    click.echo()
    click.echo("Your credentials will be merged into every project's config.")


@main.command()
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Config file name to create",
)
@click.option(
    "--force",
    is_flag=True,
    help="Overwrite existing config file",
)
@click.option(
    "--global",
    "is_global",
    is_flag=True,
    help="Create global user config (~/.config/cryptoid/config.yaml)",
)
@click.option(
    "--content-dir",
    "default_content_dir",
    type=click.Path(path_type=Path),
    default=None,
    help="Default Hugo content directory (global config only)",
)
def init(config_path: Path, force: bool, is_global: bool, default_content_dir: Path | None):
    """Initialize a new cryptoid configuration.

    Creates a .cryptoid.yaml config file with a salt for this project.
    Users are inherited from your global config if available.

    With --global, creates ~/.config/cryptoid/config.yaml with your personal
    credentials that are automatically merged into every project's config.
    """
    if is_global:
        _init_global(force=force, default_content_dir=default_content_dir)
        return

    if config_path.exists() and not force:
        click.echo(
            f"Error: {config_path} already exists. Use --force to overwrite.",
            err=True,
        )
        sys.exit(1)

    # Check for global users
    global_config = _load_global_config()
    global_users = global_config.get("users", {})

    config_data: dict[str, Any] = {
        "salt": salt_to_hex(generate_salt()),
    }

    if global_users:
        click.echo(f"Global users available: {', '.join(global_users.keys())}")
        add_local = click.confirm("Add a local user?", default=False)
    else:
        click.echo("No global config found — need at least one user.")
        add_local = True

    if add_local:
        while True:
            username = click.prompt("Username")
            try:
                validate_username(username)
                break
            except CryptoidError as e:
                click.echo(f"Invalid username: {e}")

        password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        config_data["users"] = {username: password}
        config_data["groups"] = {"admin": [username]}

    # Content directory
    global_cdir = global_config.get("content_dir")
    if global_cdir:
        click.echo(f"Content directory: {global_cdir} (from global config)")
        set_local_cdir = click.confirm("Set a different local content directory?", default=False)
    else:
        set_local_cdir = True

    if set_local_cdir:
        cdir_input = click.prompt(
            "Content directory",
            default="content",
        )
        cdir_input = cdir_input.strip()
        if cdir_input:
            config_data["content_dir"] = cdir_input

    # Optional group
    add_group = click.confirm("Create a group?", default=False)
    if add_group:
        group_name = click.prompt("Group name")
        group_name = group_name.strip()
        if group_name:
            # Add all known users (local + global) as members
            all_users = list(global_users.keys())
            if "users" in config_data:
                all_users.extend(config_data["users"].keys())
            if all_users:
                click.echo(f"Available users: {', '.join(all_users)}")
                members_input = click.prompt(
                    "Members (comma-separated, Enter for all)",
                    default="",
                    show_default=False,
                )
                if members_input.strip():
                    members = [m.strip() for m in members_input.split(",") if m.strip()]
                else:
                    members = all_users
            else:
                members = []

            if "groups" not in config_data:
                config_data["groups"] = {}
            config_data["groups"][group_name] = members

    save_config(config_path, config_data)
    click.echo(f"Created {config_path}")
    click.echo(f"  Salt: {config_data['salt'][:8]}...")
    if "content_dir" in config_data:
        click.echo(f"  Content dir: {config_data['content_dir']}")
    if "users" in config_data:
        click.echo(f"  Local users: {', '.join(config_data['users'].keys())}")
    if "groups" in config_data:
        click.echo(f"  Groups: {', '.join(config_data['groups'].keys())}")

    # Add to .gitignore (same directory as config file)
    gitignore = config_path.parent / ".gitignore"
    config_name = config_path.name
    if gitignore.exists():
        content = gitignore.read_text(encoding="utf-8")
        if config_name not in content.splitlines():
            with open(gitignore, "a", encoding="utf-8") as f:
                if not content.endswith("\n"):
                    f.write("\n")
                f.write(f"{config_name}\n")
            click.echo(f"Added '{config_name}' to .gitignore")
        else:
            click.echo(f"'{config_name}' already in .gitignore")
    else:
        gitignore.write_text(f"{config_name}\n", encoding="utf-8")
        click.echo(f"Created .gitignore with '{config_name}'")


@main.command()
@click.option(
    "--content-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Hugo content directory (default: from config or 'content')",
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
def encrypt_cmd(content_dir: Path | None, config_path: Path, dry_run: bool):
    """Encrypt marked content files.

    Processes all .md files in content-dir that have `encrypted: true`
    in their front matter or inherit encryption from _index.md cascade.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    content_dir = _resolve_content_dir(content_dir, config)
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
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Hugo content directory (default: from config or 'content')",
)
@click.option(
    "--config",
    "config_path",
    type=click.Path(path_type=Path),
    default=".cryptoid.yaml",
    help="Path to config file",
)
def decrypt_cmd(content_dir: Path | None, config_path: Path):
    """Decrypt encrypted content files.

    Restores original plaintext for files that were encrypted with the
    encrypt command. Use this before committing to git.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    content_dir = _resolve_content_dir(content_dir, config)
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
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Hugo content directory (default: from config or 'content')",
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
def status(content_dir: Path | None, config_path: Path, verbose: bool):
    """Show encryption status of content files.

    Lists each file's encryption state, groups, and whether settings
    are inherited from _index.md or set directly.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    content_dir = _resolve_content_dir(content_dir, config)

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
    type=click.Path(file_okay=False, path_type=Path),
    default=None,
    help="Hugo content directory (default: from config or 'content')",
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
def rewrap(content_dir: Path | None, config_path: Path, rekey: bool):
    """Re-wrap encrypted files for current user configuration.

    Use after modifying users/groups in config. With --rekey, generates
    new content encryption keys for forward secrecy.
    """
    try:
        config = load_config(config_path)
    except (FileNotFoundError, CryptoidError) as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)

    content_dir = _resolve_content_dir(content_dir, config)

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
        shortcode = _build_shortcode(
            hint=extracted["hint"],
            remember=extracted["remember"],
            hash_value=extracted["hash"],
            ciphertext=new_payload,
        )

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
    is_update = index_path.exists()

    if is_update:
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
    action = "Updated" if is_update else "Created"
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


# Backward compatibility: expose validate at top level as well
main.add_command(config_validate, name="validate")


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
        "js": site_dir / "static" / "js" / "cryptoid.js",
        "marked": site_dir / "static" / "js" / "marked.min.js",
    }


def _get_source_files() -> dict[str, Path]:
    """Get paths to source cryptoid files bundled with the package."""
    return {
        "shortcode": HUGO_FILES_DIR / "layouts" / "shortcodes" / "cryptoid-encrypted.html",
        "js": HUGO_FILES_DIR / "static" / "js" / "cryptoid.js",
        "marked": HUGO_FILES_DIR / "static" / "js" / "marked.min.js",
    }


def _resolve_hugo_site(site_dir: Path | None) -> Path:
    """Resolve and validate the Hugo site directory.

    Auto-detects site root if not specified, validates if given explicitly.

    Returns:
        Validated Hugo site root path.

    Exits with code 1 if no valid Hugo site is found.
    """
    if site_dir is None:
        site_dir = _find_hugo_root(Path.cwd())
        if site_dir is None:
            click.echo("Error: Not in a Hugo site (no hugo.toml/config.toml found)", err=True)
            sys.exit(1)
    elif not _is_hugo_site(site_dir):
        click.echo(f"Error: {site_dir} is not a Hugo site (no hugo.toml/config.toml found)", err=True)
        sys.exit(1)
    return site_dir


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
    site_dir = _resolve_hugo_site(site_dir)

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
    site_dir = _resolve_hugo_site(site_dir)

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
    site_dir = _resolve_hugo_site(site_dir)

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
