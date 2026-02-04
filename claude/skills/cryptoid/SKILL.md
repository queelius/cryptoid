---
name: cryptoid
description: >-
  Use when working with cryptoid-encrypted Hugo content. Invoke for encrypting/decrypting
  markdown files, managing .cryptoid.yaml config, or troubleshooting encryption issues.
---

# cryptoid

Client-side encrypted content for Hugo static sites. Pages marked for encryption are processed at build time with AES-256-GCM. Visitors enter a password in the browser to decrypt and view content.

## Quick Reference

```bash
# Encrypt marked content files
cryptoid encrypt --content-dir content/

# Preview without modifying files
cryptoid encrypt --content-dir content/ --dry-run

# Decrypt (restore plaintext for git)
cryptoid decrypt --content-dir content/

# Hugo integration
cryptoid hugo status       # Check if shortcode/JS are installed
cryptoid hugo install      # Install shortcode and JS
cryptoid hugo uninstall    # Remove cryptoid files

# Claude Code skill management
cryptoid claude status     # Check skill installation
cryptoid claude install    # Install skill (--local or --global)
cryptoid claude uninstall  # Remove skill
```

## Configuration

### .cryptoid.yaml

Create in Hugo site root:

```yaml
passwords:
  default: "your-strong-passphrase"
  members: "another-passphrase"

# Optional: auto-encrypt directories
encrypt_dirs:
  - content/private/
  - content/members-only/
```

**Important:** Add `.cryptoid.yaml` to `.gitignore`!

### Front Matter Options

```yaml
---
title: "Secret Page"
encrypted: true              # Enable encryption
password_name: "default"     # Key in .cryptoid.yaml (default: "default")
password_hint: "The usual"   # Shown on password form
remember: "ask"              # Password storage: "none", "session", "local", "ask"
---
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `encrypted` | bool | `false` | Enable encryption |
| `password_name` | string | `"default"` | Password key in config |
| `password_hint` | string | `null` | Hint for visitors |
| `remember` | string | `"ask"` | Storage behavior |

### Remember Options

- `"none"` — Never store, always prompt
- `"session"` — sessionStorage (cleared on tab close)
- `"local"` — localStorage (persists)
- `"ask"` — Checkbox lets visitor decide

## Workflow

### Standard Build Process

```bash
# 1. Encrypt before Hugo build
cryptoid encrypt --content-dir content/

# 2. Build site
hugo

# 3. Decrypt for git (keeps source readable)
cryptoid decrypt --content-dir content/
```

### Directory-Based Encryption

Files in `encrypt_dirs` are auto-encrypted. Opt out with `encrypted: false`:

```yaml
---
title: "Public Page in Private Dir"
encrypted: false
---
```

## Troubleshooting

### "Password not found in config"

Ensure `password_name` in front matter matches a key in `.cryptoid.yaml`:

```yaml
# Front matter
password_name: "members"

# .cryptoid.yaml must have:
passwords:
  members: "the-password"
```

### "Config file not found"

Create `.cryptoid.yaml` or specify path:

```bash
cryptoid encrypt --config /path/to/.cryptoid.yaml
```

### Already Encrypted Files

Running `encrypt` on already-encrypted files is safe—they're skipped. The shortcode `{{< cryptoid-encrypted >}}` indicates encryption.

### Decryption Fails in Browser

1. Check password matches the one used for encryption
2. Ensure JavaScript is loaded (check browser console)
3. Verify the shortcode HTML wasn't corrupted

## Security Notes

- AES-256-GCM encryption with PBKDF2-SHA256 key derivation
- 310,000 iterations, random 16-byte salt per page
- Security depends on password strength—use 20+ characters
- Never commit `.cryptoid.yaml` to version control
