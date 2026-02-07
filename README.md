# cryptoid

Client-side encrypted content for Hugo static sites with multi-user access control. Pages marked for encryption are processed at build time with AES-256-GCM and per-user key wrapping. Visitors enter a username and password in the browser to decrypt and view content. Zero server-side components.

## Installation

```bash
pip install cryptoid
```

## Quick Start

### 1. Create configuration file

Create `.cryptoid.yaml` in your Hugo site root:

```yaml
users:
  alice: "strong-passphrase-for-alice"
  bob: "strong-passphrase-for-bob"
  carol: "strong-passphrase-for-carol"

groups:
  admin: [alice]           # admin group gets access to ALL encrypted content
  team: [alice, bob, carol]
  members: [bob, carol]
```

Add `.cryptoid.yaml` to your `.gitignore`.

### 2. Mark content for encryption

Protect a directory (creates `_index.md` cascade):

```bash
cryptoid protect content/private/ --groups team
```

Or protect individual files:

```bash
cryptoid protect content/secret-post.md --groups admin --hint "Ask the team lead"
```

Or add `encrypted: true` directly to front matter:

```yaml
---
title: "Secret Notes"
encrypted: true
groups: ["team"]
password_hint: "The usual"
remember: "ask"
---

Your secret content here...
```

### 3. Set up Hugo integration

```bash
cryptoid hugo install
```

Or manually copy the files:

```bash
cryptoid hugo status  # check what's installed
```

### 4. Build workflow

```bash
# Validate configuration
cryptoid validate --content-dir content/

# Encrypt marked pages
cryptoid encrypt --content-dir content/

# Build your site
hugo

# Restore plaintext for git
cryptoid decrypt --content-dir content/
```

## How It Works

### Multi-User Key Wrapping

Each encrypted page uses a random Content Encryption Key (CEK). The CEK is then wrapped (encrypted) individually for each authorized user using a key derived from `"username:password"` via PBKDF2. This means:

- Adding/removing users only requires re-wrapping the CEK, not re-encrypting content
- Each user has their own credentials — no shared passwords
- The browser only needs one PBKDF2 derivation per login attempt

### Cascade Encryption

Encryption settings propagate from `_index.md` files to all content in that directory and subdirectories:

```
content/
  _index.md              # encrypted: true, groups: ["all"]
  public-post.md         # encrypted: false  (explicit opt-out)
  private/
    _index.md            # encrypted: true, groups: ["team"]  (overrides parent)
    notes.md             # inherits: encrypted for team + admin
    internal/
      _index.md          # encrypted: true, groups: ["admin"]  (overrides)
      strategy.md        # inherits: encrypted for admin only
```

Rules:
- Nearest `_index.md` with `encrypted` field wins
- `encrypted: false` on a file overrides any cascade
- `_index.md` files themselves are never encrypted
- A file's `groups` replaces inherited groups (no merging)

### Admin Group

If a group named `admin` exists in your config, its members automatically get access to all encrypted content regardless of which groups a file specifies.

## CLI Reference

### Content Configuration

```bash
# Mark a directory for encryption (creates/updates _index.md)
cryptoid protect content/private/ --groups team

# Mark a file for encryption
cryptoid protect content/secret.md --groups admin --hint "Ask the lead" --remember session

# Remove encryption from a directory
cryptoid unprotect content/private/

# Remove encryption from a file (sets encrypted: false as cascade override)
cryptoid unprotect content/secret.md
```

### Crypto Operations

```bash
# Encrypt all marked content
cryptoid encrypt --content-dir content/ --config .cryptoid.yaml

# Preview what would be encrypted
cryptoid encrypt --content-dir content/ --dry-run

# Decrypt all encrypted content
cryptoid decrypt --content-dir content/ --config .cryptoid.yaml
```

### Configuration Management

```bash
# Show config file location
cryptoid config status

# Display full config file
cryptoid config show [--config PATH]

# Validate config and content consistency
cryptoid config validate --content-dir content/ [--config PATH]
```

### Maintenance

```bash
# Show encryption status of all files
cryptoid status --content-dir content/ --config .cryptoid.yaml
cryptoid status --verbose  # include group/user statistics

# Re-wrap keys after changing users/groups (no decrypt needed)
cryptoid rewrap --content-dir content/ --config .cryptoid.yaml

# Re-wrap with new CEK for forward secrecy (after removing a user)
cryptoid rewrap --content-dir content/ --rekey
```

### Hugo Integration

```bash
cryptoid hugo status              # check installation
cryptoid hugo install             # install shortcode + JS
cryptoid hugo uninstall           # remove cryptoid files
```

## Configuration

### `.cryptoid.yaml`

```yaml
users:
  alice: "alice-password"
  bob: "bob-password"

groups:
  admin: [alice]              # special: universal access
  team: [alice, bob]

# Optional: shared PBKDF2 salt (32 hex chars = 16 bytes)
# salt: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
```

### Front Matter Options

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encrypted` | bool | `false` | Enable encryption for this page |
| `groups` | list | all users | Group names that get access |
| `password_hint` | string | `null` | Hint displayed on the login form |
| `remember` | string | `"ask"` | Credential storage behavior |

### Remember Options

- `"none"` -- Never store credentials, always prompt
- `"session"` -- Store in sessionStorage (cleared when tab closes)
- `"local"` -- Store in localStorage (persists across sessions)
- `"ask"` -- Show checkbox, let visitor decide

## Security

### Cryptographic Parameters

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-GCM |
| KDF | PBKDF2-SHA256 |
| Iterations | 310,000 |
| Salt | 16 bytes (random per page) |
| IV | 12 bytes (random per encryption) |
| Key wrapping | AES-256-GCM per user |
| Auth Tag | 128 bits |
| Content hash | Truncated SHA-256 (128 bits) |

### Ciphertext Format

Base64-encoded JSON (v2):

```json
{
  "v": 2,
  "alg": "aes-256-gcm",
  "kdf": "pbkdf2-sha256",
  "iter": 310000,
  "salt": "<base64 16 bytes>",
  "iv": "<base64 12-byte content IV>",
  "ct": "<base64 AES-GCM encrypted content>",
  "keys": [
    {"iv": "<base64 12-byte wrap IV>", "ct": "<base64 wrapped CEK>"},
    ...
  ]
}
```

### Threat Model

**What cryptoid protects against:**
- Casual browsing of protected content
- Search engine indexing of encrypted content
- Static analysis of your HTML files

**What cryptoid does NOT protect against:**
- Weak passwords (use strong, unique passphrases)
- Malicious JavaScript injection on your site
- Someone with access to your `.cryptoid.yaml`
- Shoulder surfing / screen capture

## Development

```bash
pip install -e ".[dev]"
pytest tests/ -v
pytest tests/ --cov=cryptoid --cov-report=term-missing
```

## License

MIT
