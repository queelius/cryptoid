# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Is

Cryptoid provides client-side encrypted content for Hugo static sites. Markdown pages marked for encryption are encrypted at build time (Python, AES-256-GCM with per-user key wrapping) and decrypted in the browser (JavaScript, WebCrypto API). Zero server-side components. Supports multi-user access control with group-based permissions and directory-level cascade via `_index.md`.

## Commands

```bash
# Install for development
pip install -e ".[dev]"

# Run all tests
pytest tests/ -v

# Run a single test file
pytest tests/test_crypto.py -v

# Run a single test by name
pytest tests/ -k "test_encrypt_decrypt_roundtrip" -v

# Test coverage
pytest tests/ --cov=cryptoid --cov-report=term-missing

# CLI usage
cryptoid config status                                               # show config location
cryptoid config show [--config PATH]                                 # display full config
cryptoid config validate [--content-dir ...] [--verbose]             # validate config + content
cryptoid encrypt --content-dir content/ --config .cryptoid.yaml [--dry-run]
cryptoid decrypt --content-dir content/ --config .cryptoid.yaml
cryptoid status  --content-dir content/ --config .cryptoid.yaml [--verbose]
cryptoid rewrap  --content-dir content/ --config .cryptoid.yaml [--rekey]
cryptoid protect  content/private/ --groups team [--hint "..."] [--remember ask]
cryptoid unprotect content/private/
cryptoid hugo status|install|uninstall
cryptoid claude status|install|uninstall
```

## Architecture

### Cross-platform crypto contract

The Python (`src/cryptoid/crypto.py`) and JavaScript (`hugo/assets/js/cryptoid.js`) implementations must produce identical cryptographic results. They share these parameters:

- AES-256-GCM encryption, PBKDF2-SHA256 key derivation, 310,000 iterations
- 16-byte salt, 12-byte IV, 32-byte CEK (content encryption key)
- v2 ciphertext format: base64-encoded JSON with fields `v`, `alg`, `kdf`, `iter`, `salt`, `iv`, `ct`, `keys`
- Per-user key wrapping: CEK is wrapped (encrypted) individually for each authorized user
- PBKDF2 secret format: `"username:password"` — single derivation per login attempt
- Content hash: truncated SHA-256 (128 bits / 32 hex chars)
- Inner JSON wrapper: `{"c": plaintext, "m": null}`

**Any change to crypto constants in one implementation must be mirrored in the other.** Integration tests in `test_integration.py` verify cross-compatibility.

### Module responsibilities

- **`src/cryptoid/crypto.py`** — v2 encryption/decryption with multi-user key wrapping, CEK management, PBKDF2 key derivation, `rewrap_keys()` for user set changes, content hashing. Custom `CryptoidError` exception for all crypto failures.
- **`src/cryptoid/frontmatter.py`** — Parses markdown front matter to extract `EncryptionConfig` dataclass (encrypted, groups, password_hint, remember). Detects whether a file should be encrypted or is already encrypted (via shortcode regex).
- **`src/cryptoid/cli.py`** — Click CLI with commands: `encrypt`, `decrypt`, `status`, `rewrap`, `hugo` (status/install/uninstall), `claude` (status/install/uninstall). Handles config loading from `.cryptoid.yaml` (users/groups/salt), `_index.md` cascade resolution, group-to-user resolution with admin injection, and file processing logic.
- **`hugo/layouts/shortcodes/cryptoid-encrypted.html`** — Hugo shortcode with `mode="user"` parameter, renders username+password form, embeds ciphertext.
- **`hugo/assets/js/cryptoid.js`** — Browser-side v2 decryption (key blob iteration, CEK unwrapping), credential storage (JSON `{u,p}` in localStorage/sessionStorage), and basic markdown rendering.

### Encryption flow

1. CLI scans `content/` for `.md` files with `encrypted: true` in front matter or inherited from `_index.md` cascade
2. Group-to-user resolution determines who gets key blobs (union of named groups + admin group)
3. Front matter is preserved; only the body is encrypted
4. A random CEK encrypts the body (wrapped in `{"c": ..., "m": null}` JSON); CEK is then wrapped per-user
5. Body is replaced with a `{{< cryptoid-encrypted mode="user" >}}` Hugo shortcode containing base64 ciphertext
6. Content hash is computed pre-encryption and embedded in shortcode for integrity verification
7. Decryption reverses this: extracts ciphertext from shortcode, tries each user's credentials to unwrap CEK, decrypts, verifies hash, restores body

### Cascade resolution

Encryption settings propagate from `_index.md` files to all content in that directory and subdirectories:

1. If a file's own front matter has `encrypted` field → use it
2. Walk up parent directories checking each `_index.md`
3. First `_index.md` with `encrypted` field wins (nearest override)
4. Nothing found → not encrypted

Rules: `_index.md` files themselves are never encrypted. `encrypted: false` overrides any inherited `true`. A file's `groups` fully replaces inherited groups (no merging).

### Configuration

Users, groups, and optional salt are in `.cryptoid.yaml` (gitignored). Files reference groups via `groups` front matter field (list of group names). The special `admin` group always gets access to all encrypted content. The `remember` field controls browser credential storage: `"none"`, `"session"`, `"local"`, or `"ask"`.

## Conventions

- Python 3.10+ with `|` union syntax for type hints
- `pathlib.Path` for all file system operations
- `CryptoidError` for all user-facing errors from the crypto module
- Tests use `tmp_path` fixtures; test Hugo site fixtures live in `tests/fixtures/hugo-site/`
- Encryption is idempotent — `encrypt_file` skips already-encrypted files
- `_index.md` files are never encrypted themselves, only used for cascade
