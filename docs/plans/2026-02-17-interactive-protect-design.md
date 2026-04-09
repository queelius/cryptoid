# Interactive Protect Mode — Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add `-i`/`--interactive` flag to `cryptoid protect` that opens a tree navigator for selecting content to protect/unprotect.

**Architecture:** Walk `content_dir` (from config), build a tree-formatted flat list of directories and `.md` files with their current encryption status, present via `simple-term-menu` multi-select with pre-checked encrypted items, then apply changes using existing `_protect_*`/`_unprotect_*` helpers.

**Tech Stack:** `simple-term-menu>=1.6.0` for terminal multi-select, existing `resolve_encryption()` for status detection.

---

### Task 1: Add `simple-term-menu` dependency

**Files:**
- Modify: `pyproject.toml:27-32`

**Step 1: Add dependency**

In `pyproject.toml`, add `simple-term-menu` to the dependencies list:

```toml
dependencies = [
    "cryptography>=41.0.0",
    "click>=8.0.0",
    "pyyaml>=6.0",
    "python-frontmatter>=1.0.0",
    "simple-term-menu>=1.6.0",
]
```

**Step 2: Install**

Run: `pip install -e ".[dev]"`

**Step 3: Verify import**

Run: `python -c "from simple_term_menu import TerminalMenu; print('ok')"`
Expected: `ok`

**Step 4: Commit**

```bash
git add pyproject.toml
git commit -m "Add simple-term-menu dependency for interactive protect"
```

---

### Task 2: Build content tree scanner — `_build_content_tree()`

**Files:**
- Modify: `src/cryptoid/cli.py` (add after `resolve_encryption()` at ~line 381)
- Test: `tests/test_cli.py`

**Step 1: Write the failing tests**

Add to `tests/test_cli.py`:

```python
class TestBuildContentTree:
    """Tests for _build_content_tree() helper."""

    def test_flat_files(self, tmp_path):
        """Files in root content dir appear as top-level entries."""
        from cryptoid.cli import _build_content_tree

        (tmp_path / "post.md").write_text("---\ntitle: Post\n---\nHello")
        (tmp_path / "about.md").write_text("---\ntitle: About\n---\nAbout")

        entries = _build_content_tree(tmp_path)
        labels = [e["label"] for e in entries]
        assert "about.md" in labels
        assert "post.md" in labels
        assert all(e["type"] == "file" for e in entries)

    def test_nested_directory(self, tmp_path):
        """Directory with .md files appears as a dir entry followed by indented file entries."""
        from cryptoid.cli import _build_content_tree

        blog = tmp_path / "blog"
        blog.mkdir()
        (blog / "_index.md").write_text("---\ntitle: Blog\n---\n")
        (blog / "post-1.md").write_text("---\ntitle: Post 1\n---\nContent")

        entries = _build_content_tree(tmp_path)
        labels = [e["label"] for e in entries]
        assert "blog/" in labels
        assert any("post-1.md" in l for l in labels)

    def test_index_md_excluded(self, tmp_path):
        """_index.md files are not listed as individual entries."""
        from cryptoid.cli import _build_content_tree

        (tmp_path / "_index.md").write_text("---\ntitle: Home\n---\n")
        (tmp_path / "page.md").write_text("---\ntitle: Page\n---\nContent")

        entries = _build_content_tree(tmp_path)
        labels = [e["label"] for e in entries]
        assert not any("_index.md" in l for l in labels)

    def test_encryption_status_detected(self, tmp_path):
        """Pre-encrypted files marked as encrypted in entries."""
        from cryptoid.cli import _build_content_tree

        (tmp_path / "secret.md").write_text("---\ntitle: Secret\nencrypted: true\ngroups:\n  - admin\n---\nBody")
        (tmp_path / "public.md").write_text("---\ntitle: Public\n---\nBody")

        entries = _build_content_tree(tmp_path)
        by_path = {str(e["path"].name): e for e in entries}
        assert by_path["secret.md"]["encrypted"] is True
        assert by_path["public.md"]["encrypted"] is False

    def test_cascade_detected(self, tmp_path):
        """Files in encrypted directory detected via cascade."""
        from cryptoid.cli import _build_content_tree

        priv = tmp_path / "private"
        priv.mkdir()
        (priv / "_index.md").write_text("---\ntitle: Private\nencrypted: true\ngroups:\n  - team\n---\n")
        (priv / "doc.md").write_text("---\ntitle: Doc\n---\nContent")

        entries = _build_content_tree(tmp_path)
        by_label = {e["label"]: e for e in entries}
        assert by_label["private/"]["encrypted"] is True
        doc_entry = [e for e in entries if "doc.md" in e["label"]][0]
        assert doc_entry["encrypted"] is True

    def test_non_md_files_excluded(self, tmp_path):
        """Non-markdown files are not included."""
        from cryptoid.cli import _build_content_tree

        (tmp_path / "image.png").write_bytes(b"\x89PNG")
        (tmp_path / "page.md").write_text("---\ntitle: Page\n---\nContent")

        entries = _build_content_tree(tmp_path)
        labels = [e["label"] for e in entries]
        assert not any("image" in l for l in labels)
        assert len(entries) == 1

    def test_empty_dir_excluded(self, tmp_path):
        """Directories with no .md files are not shown."""
        from cryptoid.cli import _build_content_tree

        (tmp_path / "empty").mkdir()
        (tmp_path / "page.md").write_text("---\ntitle: Page\n---\nContent")

        entries = _build_content_tree(tmp_path)
        labels = [e["label"] for e in entries]
        assert not any("empty" in l for l in labels)
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py::TestBuildContentTree -v`
Expected: FAIL — `ImportError: cannot import name '_build_content_tree'`

**Step 3: Write implementation**

Add to `src/cryptoid/cli.py` after `resolve_encryption()` (~line 381):

```python
def _build_content_tree(content_dir: Path) -> list[dict[str, Any]]:
    """Build a flat list of content entries with tree-style labels and encryption status.

    Returns a list of dicts, each with:
        - label: Display string (e.g. "private/" or "  ├── doc.md")
        - path: Path to the file or directory
        - type: "dir" or "file"
        - encrypted: bool — current encryption status
    """
    entries: list[dict[str, Any]] = []

    # Collect all .md files (excluding _index.md) and directories with .md files
    all_md_files: list[Path] = sorted(
        f for f in content_dir.rglob("*.md") if f.name != "_index.md"
    )

    # Group files by their parent directory relative to content_dir
    from collections import defaultdict

    by_dir: dict[Path, list[Path]] = defaultdict(list)
    for f in all_md_files:
        by_dir[f.parent].append(f)

    # Sort directories: content_dir first, then alphabetically
    sorted_dirs = sorted(by_dir.keys(), key=lambda d: d.relative_to(content_dir).parts)

    for dir_path in sorted_dirs:
        files = sorted(by_dir[dir_path])
        is_root = dir_path == content_dir

        if not is_root:
            # Add directory entry
            rel = dir_path.relative_to(content_dir)
            # Check encryption via _index.md cascade
            index_file = dir_path / "_index.md"
            dir_encrypted = False
            if index_file.exists():
                index_content = index_file.read_text(encoding="utf-8")
                fm, _ = parse_markdown(index_content)
                dir_encrypted = fm.get("encrypted", False) is True
            else:
                # Check parent cascade
                enc = resolve_encryption(dir_path / "_dummy.md", content_dir)
                dir_encrypted = enc is not None if enc else False

            entries.append({
                "label": f"{rel}/",
                "path": dir_path,
                "type": "dir",
                "encrypted": dir_encrypted,
            })

        for f in files:
            enc_config = resolve_encryption(f, content_dir)
            is_encrypted = enc_config is not None

            if is_root:
                label = f.name
            else:
                # Tree-style indent
                is_last = f == files[-1]
                connector = "└── " if is_last else "├── "
                label = f"  {connector}{f.name}"

            entries.append({
                "label": label,
                "path": f,
                "type": "file",
                "encrypted": is_encrypted,
            })

    return entries
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py::TestBuildContentTree -v`
Expected: All 7 pass

**Step 5: Commit**

```bash
git add src/cryptoid/cli.py tests/test_cli.py
git commit -m "Add _build_content_tree() helper for interactive protect"
```

---

### Task 3: Implement `_interactive_protect()` and wire into `protect` command

**Files:**
- Modify: `src/cryptoid/cli.py:2330-2371` (protect command) and add `_interactive_protect()` before it
- Test: `tests/test_cli.py`

**Step 1: Write the failing tests**

These tests mock `TerminalMenu` since it requires a real terminal. Add to `tests/test_cli.py`:

```python
from unittest.mock import patch, MagicMock


class TestInteractiveProtect:
    """Tests for cryptoid protect --interactive."""

    def _make_site(self, tmp_path):
        """Create a content dir with a mix of protected and unprotected files."""
        content = tmp_path / "content"
        content.mkdir()

        # Unprotected files
        (content / "public.md").write_text("---\ntitle: Public\n---\nPublic content")

        # Protected directory
        priv = content / "private"
        priv.mkdir()
        (priv / "_index.md").write_text("---\ntitle: Private\nencrypted: true\ngroups:\n  - team\n---\n")
        (priv / "secret.md").write_text("---\ntitle: Secret\n---\nSecret stuff")

        # Config
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            "users:\n  alice: password1\n  bob: password2\n"
            "groups:\n  admin:\n    - alice\n  team:\n    - alice\n    - bob\n"
            "salt: aa11bb22cc33dd44ee55ff6677889900\n"
            f"content_dir: {content}\n"
        )
        return content, config_path

    def test_interactive_flag_exists(self, runner, tmp_path):
        """The --interactive / -i flag is accepted."""
        content, config_path = self._make_site(tmp_path)
        with patch("cryptoid.cli._interactive_protect") as mock:
            mock.return_value = None
            result = runner.invoke(main, [
                "protect", "-i", "--config", str(config_path),
            ])
            assert result.exit_code == 0
            mock.assert_called_once()

    def test_path_required_without_interactive(self, runner, tmp_path):
        """Without -i, PATH argument is required."""
        _, config_path = self._make_site(tmp_path)
        result = runner.invoke(main, [
            "protect", "--config", str(config_path),
        ])
        assert result.exit_code != 0

    def test_interactive_applies_protect(self, runner, tmp_path):
        """Selecting an unprotected file marks it encrypted."""
        content, config_path = self._make_site(tmp_path)

        # Simulate user selecting public.md (index 0=private/, 1=secret.md, 2=public.md)
        # The mock returns all indices (user checks public.md in addition to existing)
        with patch("cryptoid.cli.TerminalMenu") as MockMenu:
            instance = MagicMock()
            # User selects all items (protect public.md too)
            instance.show.return_value = (0, 1, 2)
            MockMenu.return_value = instance

            result = runner.invoke(main, [
                "protect", "-i", "--config", str(config_path),
            ], input="y\n")

        # public.md should now be encrypted
        import frontmatter as fm
        post = fm.load(content / "public.md")
        assert post.metadata.get("encrypted") is True

    def test_interactive_applies_unprotect(self, runner, tmp_path):
        """Deselecting a protected directory unprotects it."""
        content, config_path = self._make_site(tmp_path)

        with patch("cryptoid.cli.TerminalMenu") as MockMenu:
            instance = MagicMock()
            # User deselects everything (empty selection)
            instance.show.return_value = ()
            MockMenu.return_value = instance

            result = runner.invoke(main, [
                "protect", "-i", "--config", str(config_path),
            ], input="y\n")

        # private/_index.md should now be encrypted: false
        import frontmatter as fm
        post = fm.load(content / "private" / "_index.md")
        assert post.metadata.get("encrypted") is False

    def test_interactive_no_changes(self, runner, tmp_path):
        """When selection matches current state, report no changes."""
        content, config_path = self._make_site(tmp_path)

        with patch("cryptoid.cli.TerminalMenu") as MockMenu:
            instance = MagicMock()
            # User keeps current state: private/ and secret.md checked (indices 0, 1)
            instance.show.return_value = (0, 1)
            MockMenu.return_value = instance

            result = runner.invoke(main, [
                "protect", "-i", "--config", str(config_path),
            ])
            assert "No changes" in result.output

    def test_interactive_quit(self, runner, tmp_path):
        """When user cancels menu (q/Escape), no changes applied."""
        content, config_path = self._make_site(tmp_path)

        with patch("cryptoid.cli.TerminalMenu") as MockMenu:
            instance = MagicMock()
            instance.show.return_value = None  # cancelled
            MockMenu.return_value = instance

            result = runner.invoke(main, [
                "protect", "-i", "--config", str(config_path),
            ])
            assert result.exit_code == 0
            assert "Cancelled" in result.output

    def test_interactive_with_groups(self, runner, tmp_path):
        """--groups flag applies to newly protected items."""
        content, config_path = self._make_site(tmp_path)

        with patch("cryptoid.cli.TerminalMenu") as MockMenu:
            instance = MagicMock()
            # Select everything including public.md
            instance.show.return_value = (0, 1, 2)
            MockMenu.return_value = instance

            result = runner.invoke(main, [
                "protect", "-i", "--groups", "admin",
                "--config", str(config_path),
            ], input="y\n")

        import frontmatter as fm
        post = fm.load(content / "public.md")
        assert post.metadata.get("groups") == ["admin"]
```

**Step 2: Run tests to verify they fail**

Run: `pytest tests/test_cli.py::TestInteractiveProtect -v`
Expected: FAIL

**Step 3: Write implementation**

First, add the import at the top of `cli.py` (with existing imports):

```python
from simple_term_menu import TerminalMenu
```

Then add `_interactive_protect()` before the `protect` command (~line 2328):

```python
def _interactive_protect(
    config: dict[str, Any],
    groups: tuple[str, ...],
    hint: str | None,
    remember: str | None,
) -> None:
    """Interactive tree navigator for protect/unprotect."""
    content_dir = _resolve_content_dir(None, config)
    entries = _build_content_tree(content_dir)

    if not entries:
        click.echo("No content files found.")
        return

    # Build menu labels and preselected indices
    menu_labels = []
    preselected = []
    for i, entry in enumerate(entries):
        status = "encrypted" if entry["encrypted"] else ""
        label = entry["label"]
        if entry.get("groups_info") and entry["encrypted"]:
            label += f"  (groups={entry.get('groups_info')})"
        menu_labels.append(label)
        if entry["encrypted"]:
            preselected.append(i)

    menu = TerminalMenu(
        menu_labels,
        multi_select=True,
        show_multi_select_hint=True,
        preselected_entries=preselected,
        title="  Select content to protect/unprotect\n",
        multi_select_cursor="[x] ",
        multi_select_cursor_brackets_style=("fg_cyan", "bold"),
        multi_select_select_on_accept=False,
        multi_select_empty_ok=True,
    )

    selected = menu.show()

    if selected is None:
        click.echo("Cancelled.")
        return

    selected_set = set(selected) if selected else set()
    preselected_set = set(preselected)

    # Compute changes
    to_protect = selected_set - preselected_set
    to_unprotect = preselected_set - selected_set

    if not to_protect and not to_unprotect:
        click.echo("No changes.")
        return

    # Show summary
    click.echo()
    for i in sorted(to_protect):
        click.echo(f"  + protect: {entries[i]['label'].strip()}")
    for i in sorted(to_unprotect):
        click.echo(f"  - unprotect: {entries[i]['label'].strip()}")
    click.echo()

    if not click.confirm(f"Apply {len(to_protect) + len(to_unprotect)} changes?"):
        click.echo("Cancelled.")
        return

    # Apply changes
    for i in sorted(to_protect):
        entry = entries[i]
        if entry["type"] == "dir":
            _protect_directory(entry["path"], groups, hint, remember)
        else:
            _protect_file(entry["path"], groups, hint, remember)

    for i in sorted(to_unprotect):
        entry = entries[i]
        if entry["type"] == "dir":
            _unprotect_directory(entry["path"])
        else:
            _unprotect_file(entry["path"])
```

Then update the `protect` command signature (~line 2330):

```python
@main.command()
@click.argument("path", type=click.Path(exists=True, path_type=Path), required=False, default=None)
@click.option("-i", "--interactive", is_flag=True, help="Browse content tree to select items")
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
@click.option("--config", "config_path", type=click.Path(path_type=Path), default=None)
def protect(path: Path | None, interactive: bool, groups: tuple[str, ...],
            hint: str | None, remember: str | None, config_path: Path | None):
    """Mark a file or directory for encryption.

    Without -i, PATH is required — sets encrypted: true on the target.
    With -i/--interactive, opens a tree navigator to select content.

    Examples:

        cryptoid protect content/private/ --groups team

        cryptoid protect -i
    """
    if interactive:
        config = load_config(config_path)
        _interactive_protect(config, groups, hint, remember)
        return

    if path is None:
        click.echo("Error: PATH is required (or use --interactive / -i)", err=True)
        sys.exit(1)

    path = path.resolve()

    if path.is_dir():
        _protect_directory(path, groups, hint, remember)
    elif path.is_file() and path.suffix == ".md":
        _protect_file(path, groups, hint, remember)
    else:
        click.echo(f"Error: {path} must be a directory or .md file", err=True)
        sys.exit(1)
```

**Step 4: Run tests to verify they pass**

Run: `pytest tests/test_cli.py::TestInteractiveProtect -v`
Expected: All 7 pass

**Step 5: Run full test suite**

Run: `pytest tests/ -v`
Expected: All ~350 pass (existing protect tests unchanged)

**Step 6: Commit**

```bash
git add src/cryptoid/cli.py tests/test_cli.py
git commit -m "Add interactive protect mode with tree navigator"
```

---

### Task 4: Manual smoke test

**Step 1: Test interactive mode**

```bash
cd /path/to/hugo-site
cryptoid protect -i
```

Expected: Tree appears with current encryption status pre-checked. Space toggles, Enter confirms, q quits.

**Step 2: Test direct mode still works**

```bash
cryptoid protect content/some-dir/ --groups team
cryptoid unprotect content/some-dir/
```

Expected: Same behavior as before.

**Step 3: Test error when no content_dir in config**

Remove `content_dir` from config and run:
```bash
cryptoid protect -i
```

Expected: Error message about missing content directory.

---

Plan complete and saved to `docs/plans/2026-02-17-interactive-protect-design.md`. Two execution options:

**1. Subagent-Driven (this session)** — I dispatch fresh subagent per task, review between tasks, fast iteration

**2. Parallel Session (separate)** — Open new session with executing-plans, batch execution with checkpoints

Which approach?