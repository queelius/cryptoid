"""Cascade resolution for cryptoid.

`_index.md` front matter sets encryption settings that propagate to all content
in that directory and its subdirectories. This module is the single source of
truth for that cascade walk.

Three public callables:

- `_walk_cascade_from(start_dir, content_dir)`: walk upward from a directory,
  returning the nearest active EncryptionConfig from an `_index.md`. Bypasses
  any file's own front matter; pure directory-tier walk.
- `resolve_encryption(file_path, content_dir)`: full cascade resolution for a
  single markdown file. Checks the file's own front matter first, then walks
  the cascade. For `_index.md` files, the walk skips its own directory to
  avoid self-cascade.
- `evaluate(file_path, content_dir)`: high-level value object (`CascadeResult`)
  that bundles the cascade config, source classification (own/inherited/
  cascade-source/opt-out/plain), and `is_already_encrypted` into a single read
  + parse pass. Use this from listing commands (`status`, `validate`) instead
  of calling `resolve_encryption` + `read_text` + `parse_markdown` separately.

Plus `_build_content_tree(content_dir)`: scans `content_dir` and produces the
cascade-aware flat entry list consumed by the Textual TUI in `tui.py`.

Importing pattern: `cli.py` imports everything here it needs; `tui.py` may
import `_walk_cascade_from` directly (this module has no cli.py dependency).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .frontmatter import (
    EncryptionConfig,
    get_encryption_config,
    is_already_encrypted,
    parse_markdown,
)


def _walk_cascade_from(
    start_dir: Path, content_dir: Path
) -> EncryptionConfig | None:
    """Walk up from start_dir to content_dir, returning nearest _index.md cascade.

    Starts at start_dir itself (checks start_dir/_index.md first), then walks
    upward. Returns the first EncryptionConfig found via an _index.md's
    'encrypted: true' field, or None if an 'encrypted: false' is found first,
    or if no 'encrypted' field is found before reaching content_dir.

    Used by `resolve_encryption()` (for files, after checking own front matter),
    `_build_content_tree()` (for directory cascade state), and
    `_unprotect_directory()` in `cli.py` (to detect inherited cascade so an
    explicit opt-out can be written).

    Args:
        start_dir: Directory to begin the walk at.
        content_dir: Root content directory (walk stops here).

    Returns:
        EncryptionConfig if cascade applies, None otherwise.
    """
    try:
        start_dir.relative_to(content_dir)
    except ValueError:
        return None

    current = start_dir
    while True:
        index_file = current / "_index.md"
        if index_file.exists():
            index_content = index_file.read_text(encoding="utf-8")
            index_fm, _ = parse_markdown(index_content)
            if "encrypted" in index_fm:
                if index_fm["encrypted"] is False:
                    return None
                if index_fm["encrypted"] is True:
                    return get_encryption_config(index_content)
        if current == content_dir:
            return None
        parent = current.parent
        if parent == current:
            return None
        current = parent


def resolve_encryption(
    file_path: Path, content_dir: Path
) -> EncryptionConfig | None:
    """Resolve effective encryption config for a file using _index.md cascade.

    Algorithm:
        1. If file's own front matter has 'encrypted' field, use it.
        2. Walk up parent dirs to content_dir, checking each _index.md.
        3. First _index.md with 'encrypted' field wins (nearest override).
        4. Nothing found, returns None (not encrypted).

    For `_index.md` files: step 1 checks own front matter as usual, but step 2
    starts from the parent directory (skips its own dir to avoid self-cascade).

    Args:
        file_path: Path to the markdown file.
        content_dir: Root content directory.

    Returns:
        EncryptionConfig if encryption applies, None if not.
    """
    content = file_path.read_text(encoding="utf-8")
    fm, _ = parse_markdown(content)

    if "encrypted" in fm:
        if fm["encrypted"] is False:
            return None
        if fm["encrypted"] is True:
            return get_encryption_config(content)

    # Walk up parent directories.
    # For _index.md: start from parent dir (skip own dir to avoid self-cascade).
    # For regular files: start from own dir.
    if file_path.name == "_index.md":
        start_dir = file_path.parent.parent
    else:
        start_dir = file_path.parent

    return _walk_cascade_from(start_dir, content_dir)


# Source labels used by `CascadeResult.source` and the `status` command.
# - "plain": no encryption (no own field, no inherited cascade)
# - "own": the file's own front matter sets `encrypted: true`
# - "inherited": cascade-encrypted from a parent _index.md
# - "cascade-source": an `_index.md` with its own `encrypted: true` (both
#   cascade source AND has its own encrypted body under v2 semantics)
# - "opt-out": an `_index.md` whose own `encrypted: false` blocks cascade
#   (no encryption applies, but the cascade intent is reportable)
SOURCE_PLAIN = "plain"
SOURCE_OWN = "own"
SOURCE_INHERITED = "inherited"
SOURCE_CASCADE_SOURCE = "cascade-source"
SOURCE_OPT_OUT = "opt-out"


@dataclass
class CascadeResult:
    """Bundled cascade state for a single markdown file.

    Computed in one pass (`evaluate(file_path, content_dir)`) so callers don't
    re-read the file or re-parse the front matter to ask follow-up questions
    like "where did this encryption come from?" or "is the body already
    encrypted on disk?"

    Attributes:
        config: Effective EncryptionConfig if the file is (or would be)
            encrypted; None otherwise. Same value `resolve_encryption` returns.
        source: One of SOURCE_PLAIN / SOURCE_OWN / SOURCE_INHERITED /
            SOURCE_CASCADE_SOURCE / SOURCE_OPT_OUT. See module-level comments
            for semantics.
        is_already_encrypted: Whether the file's body is already encrypted on
            disk (i.e., contains the `cryptoid-encrypted` shortcode).
        content: Raw file contents as read from disk.
    """

    config: EncryptionConfig | None
    source: str
    is_already_encrypted: bool
    content: str


def evaluate(file_path: Path, content_dir: Path) -> CascadeResult:
    """Compute the full cascade picture for a file in a single read+parse pass.

    Equivalent to `resolve_encryption()` plus the source-classification logic
    that listing commands (`status`, `validate`) used to derive inline by
    re-parsing the front matter. Prefer this over calling `resolve_encryption()`
    + `read_text()` + `parse_markdown()` separately when you also need to know
    where the encryption came from.

    Source classification:
        - file with own `encrypted: true`: SOURCE_OWN (or SOURCE_CASCADE_SOURCE
          for `_index.md`, which is both an encrypted file AND a cascade source)
        - file with own `encrypted: false`: SOURCE_OPT_OUT (no encryption
          applies, but the file's intent is to override an inherited cascade)
        - file with no own field, encrypted via parent cascade: SOURCE_INHERITED
        - everything else: SOURCE_PLAIN

    Args:
        file_path: Path to the markdown file.
        content_dir: Root content directory.

    Returns:
        CascadeResult bundling config, source, body-encrypted state, and content.
    """
    content = file_path.read_text(encoding="utf-8")
    fm, _ = parse_markdown(content)
    body_encrypted = is_already_encrypted(content)

    own_field = fm.get("encrypted") if "encrypted" in fm else None

    if own_field is True:
        config = get_encryption_config(content)
        if file_path.name == "_index.md":
            source = SOURCE_CASCADE_SOURCE
        else:
            source = SOURCE_OWN
        return CascadeResult(config, source, body_encrypted, content)

    if own_field is False:
        return CascadeResult(None, SOURCE_OPT_OUT, body_encrypted, content)

    # No own field: walk the cascade.
    if file_path.name == "_index.md":
        start_dir = file_path.parent.parent
    else:
        start_dir = file_path.parent

    inherited = _walk_cascade_from(start_dir, content_dir)
    if inherited is not None:
        return CascadeResult(inherited, SOURCE_INHERITED, body_encrypted, content)

    return CascadeResult(None, SOURCE_PLAIN, body_encrypted, content)


def _build_content_tree(content_dir: Path) -> list[dict[str, Any]]:
    """Walk content_dir recursively and build a flat list of entries for display.

    Each entry is a dict with:
        - label: Display string with tree connectors for nested files.
        - path: Path to the file or directory.
        - type: "dir" or "file".
        - encrypted: bool, current effective encryption status (cascade-aware).

    Rules:
        - _index.md files are NOT listed as file entries; they are represented
          by their containing directory entry (toggling the dir == toggling the
          _index.md's cascade AND body, which are the same file under the new
          v2 semantics).
        - Non-.md files are excluded.
        - All directories containing any .md file (directly or transitively)
          are emitted, including intermediate directories with no .md files
          of their own. Emitting intermediates ensures the TUI's tree-builder
          never has to synthesize ancestor nodes with a default encrypted state.
        - Every entry's encrypted state is computed via the full cascade walk
          (resolve_encryption for files, _walk_cascade_from for dirs), so the
          TUI checkbox state matches what 'cryptoid encrypt' would actually do.
        - Directories are sorted alphabetically by their relative path; files
          within each directory are sorted alphabetically.
        - Root-level files appear without tree connectors.

    Args:
        content_dir: Root content directory to scan.

    Returns:
        Flat list of entry dicts suitable for interactive selection.
    """
    entries: list[dict[str, Any]] = []

    # Collect all regular .md files grouped by their parent directory.
    # _index.md files are skipped: they are represented by the directory entry.
    # Use setdefault so a dir with only _index.md still appears as a key.
    dir_files: dict[Path, list[Path]] = defaultdict(list)

    for md_file in sorted(content_dir.rglob("*.md")):
        if md_file.name == "_index.md":
            # Ensure the directory is tracked even if it has no other .md files
            if md_file.parent != content_dir:
                dir_files.setdefault(md_file.parent, [])
            continue
        dir_files[md_file.parent].append(md_file)

    # Expand to include all intermediate directories on the path from
    # content_dir down to every directory in dir_files. This prevents the
    # TUI from having to synthesize ancestor nodes with unknown cascade state.
    all_dirs: set[Path] = set(dir_files.keys())
    all_dirs.discard(content_dir)
    for leaf in list(all_dirs):
        current = leaf.parent
        while current != content_dir and current != current.parent:
            try:
                current.relative_to(content_dir)
            except ValueError:
                break
            all_dirs.add(current)
            current = current.parent

    # Root-level regular files (no tree connectors)
    root_files = sorted(dir_files.pop(content_dir, []), key=lambda p: p.name)
    for f in root_files:
        enc_config = resolve_encryption(f, content_dir)
        entries.append({
            "label": f.name,
            "path": f,
            "type": "file",
            "encrypted": enc_config is not None,
        })

    # Sort directories by their relative path so ancestors precede descendants
    sorted_dirs = sorted(all_dirs, key=lambda p: p.relative_to(content_dir).parts)

    for dir_path in sorted_dirs:
        files = sorted(dir_files.get(dir_path, []), key=lambda p: p.name)

        # Cascade-aware directory state: walk from dir_path up through
        # its own _index.md (if any) then ancestors. This matches how files
        # inside the dir resolve their encryption.
        dir_encrypted = _walk_cascade_from(dir_path, content_dir) is not None

        rel = dir_path.relative_to(content_dir)
        entries.append({
            "label": f"{rel}/",
            "path": dir_path,
            "type": "dir",
            "encrypted": dir_encrypted,
        })

        # Add files with tree connectors
        for i, f in enumerate(files):
            is_last = i == len(files) - 1
            connector = "└──" if is_last else "├──"
            enc_config = resolve_encryption(f, content_dir)

            entries.append({
                "label": f"  {connector} {f.name}",
                "path": f,
                "type": "file",
                "encrypted": enc_config is not None,
            })

    return entries
