"""Tests for cryptoid.tui — Textual TUI components."""

from pathlib import Path
from unittest.mock import MagicMock

from cryptoid.tui import (
    ContentEntry,
    ProtectApp,
    _cascade_check,
    _checkbox,
    _checkbox_mixed,
    _collect_leaf_states,
    _update_ancestors,
    _update_label,
    _update_parent_label,
)


class TestCheckboxHelpers:
    """Test checkbox display helpers."""

    def test_checkbox_checked(self):
        assert _checkbox(True) == "[x]"

    def test_checkbox_unchecked(self):
        assert _checkbox(False) == "[ ]"


class TestCheckboxMixed:
    """Test mixed-state checkbox for directories."""

    def _make_dir_node(self, child_states):
        """Create a mock directory node with file children having given states."""
        node = MagicMock()
        node.data = ContentEntry(
            path=Path("/content/dir"), entry_type="dir", encrypted=True, checked=True
        )
        children = []
        for checked in child_states:
            child = MagicMock()
            child.data = ContentEntry(
                path=Path("/content/dir/f.md"),
                entry_type="file",
                encrypted=True,
                checked=checked,
            )
            child.children = []
            children.append(child)
        node.children = children
        return node

    def test_all_checked(self):
        node = self._make_dir_node([True, True, True])
        assert _checkbox_mixed(node) == "[x]"

    def test_none_checked(self):
        node = self._make_dir_node([False, False, False])
        assert _checkbox_mixed(node) == "[ ]"

    def test_mixed(self):
        node = self._make_dir_node([True, False, True])
        assert _checkbox_mixed(node) == "[-]"

    def test_no_children_uses_own_state(self):
        node = MagicMock()
        node.data = ContentEntry(
            path=Path("/content/dir"), entry_type="dir", encrypted=True, checked=True
        )
        node.children = []
        assert _checkbox_mixed(node) == "[x]"

    def test_nested_subdirs_all_checked(self):
        """Mixed state should look at leaf (file) descendants, not just children."""
        # dir/ -> subdir/ -> file.md (checked)
        file_node = MagicMock()
        file_node.data = ContentEntry(
            path=Path("/content/dir/sub/f.md"), entry_type="file",
            encrypted=True, checked=True,
        )
        file_node.children = []

        sub_node = MagicMock()
        sub_node.data = ContentEntry(
            path=Path("/content/dir/sub"), entry_type="dir",
            encrypted=True, checked=True,
        )
        sub_node.children = [file_node]

        parent = MagicMock()
        parent.data = ContentEntry(
            path=Path("/content/dir"), entry_type="dir",
            encrypted=True, checked=True,
        )
        parent.children = [sub_node]
        assert _checkbox_mixed(parent) == "[x]"

    def test_nested_subdirs_mixed(self):
        """Mixed state with nested dirs: one file checked, one not."""
        file1 = MagicMock()
        file1.data = ContentEntry(
            path=Path("/content/dir/sub/a.md"), entry_type="file",
            encrypted=True, checked=True,
        )
        file1.children = []

        file2 = MagicMock()
        file2.data = ContentEntry(
            path=Path("/content/dir/sub/b.md"), entry_type="file",
            encrypted=False, checked=False,
        )
        file2.children = []

        sub_node = MagicMock()
        sub_node.data = ContentEntry(
            path=Path("/content/dir/sub"), entry_type="dir",
            encrypted=False, checked=False,
        )
        sub_node.children = [file1, file2]

        parent = MagicMock()
        parent.data = ContentEntry(
            path=Path("/content/dir"), entry_type="dir",
            encrypted=False, checked=False,
        )
        parent.children = [sub_node]
        assert _checkbox_mixed(parent) == "[-]"


class TestCollectLeafStates:
    """Test _collect_leaf_states recursive collection."""

    def test_direct_files(self):
        child = MagicMock()
        child.data = ContentEntry(
            path=Path("/f.md"), entry_type="file", encrypted=False, checked=True
        )
        child.children = []
        node = MagicMock()
        node.children = [child]
        assert _collect_leaf_states(node) == {True}

    def test_nested_files(self):
        """Collects from nested subdirectories."""
        file1 = MagicMock()
        file1.data = ContentEntry(
            path=Path("/a.md"), entry_type="file", encrypted=False, checked=True
        )
        file1.children = []

        file2 = MagicMock()
        file2.data = ContentEntry(
            path=Path("/b.md"), entry_type="file", encrypted=False, checked=False
        )
        file2.children = []

        subdir = MagicMock()
        subdir.data = ContentEntry(
            path=Path("/sub"), entry_type="dir", encrypted=False, checked=False
        )
        subdir.children = [file2]

        node = MagicMock()
        node.children = [file1, subdir]
        assert _collect_leaf_states(node) == {True, False}

    def test_empty(self):
        node = MagicMock()
        node.children = []
        assert _collect_leaf_states(node) == set()


class TestCascadeCheck:
    """Test _cascade_check recursive toggle."""

    def test_cascades_to_files(self):
        child = MagicMock()
        child.data = ContentEntry(
            path=Path("/f.md"), entry_type="file", encrypted=False, checked=False
        )
        child.children = []

        node = MagicMock()
        node.children = [child]

        _cascade_check(node, True)
        assert child.data.checked is True

    def test_cascades_through_subdirs(self):
        """Should recurse into nested directories."""
        grandchild = MagicMock()
        grandchild.data = ContentEntry(
            path=Path("/sub/f.md"), entry_type="file", encrypted=False, checked=False
        )
        grandchild.children = []

        subdir = MagicMock()
        subdir.data = ContentEntry(
            path=Path("/sub"), entry_type="dir", encrypted=False, checked=False
        )
        subdir.children = [grandchild]

        node = MagicMock()
        node.children = [subdir]

        _cascade_check(node, True)
        assert subdir.data.checked is True
        assert grandchild.data.checked is True

    def test_unchecks_all(self):
        child1 = MagicMock()
        child1.data = ContentEntry(
            path=Path("/a.md"), entry_type="file", encrypted=True, checked=True
        )
        child1.children = []
        child2 = MagicMock()
        child2.data = ContentEntry(
            path=Path("/b.md"), entry_type="file", encrypted=True, checked=True
        )
        child2.children = []

        node = MagicMock()
        node.children = [child1, child2]

        _cascade_check(node, False)
        assert child1.data.checked is False
        assert child2.data.checked is False


class TestUpdateAncestors:
    """Test _update_ancestors propagates up through all ancestor dirs."""

    def test_updates_immediate_parent(self):
        parent = MagicMock()
        parent.data = ContentEntry(
            path=Path("/dir"), entry_type="dir", encrypted=False, checked=True
        )
        parent.parent = None

        child = MagicMock()
        child.data = ContentEntry(
            path=Path("/dir/f.md"), entry_type="file", encrypted=False, checked=False
        )
        child.parent = parent
        child.children = []

        # Parent has one child (the one being toggled) which is unchecked
        parent.children = [child]

        _update_ancestors(child)
        assert parent.data.checked is False

    def test_propagates_to_grandparent(self):
        """Should update grandparent's state too."""
        grandparent = MagicMock()
        grandparent.data = ContentEntry(
            path=Path("/top"), entry_type="dir", encrypted=False, checked=True
        )
        grandparent.parent = None

        parent = MagicMock()
        parent.data = ContentEntry(
            path=Path("/top/sub"), entry_type="dir", encrypted=False, checked=True
        )
        parent.parent = grandparent

        child = MagicMock()
        child.data = ContentEntry(
            path=Path("/top/sub/f.md"), entry_type="file", encrypted=False, checked=False
        )
        child.parent = parent
        child.children = []

        parent.children = [child]
        grandparent.children = [parent]

        _update_ancestors(child)
        assert parent.data.checked is False
        assert grandparent.data.checked is False

    def test_backward_compat_alias(self):
        """_update_parent_label is an alias for _update_ancestors."""
        assert _update_parent_label is _update_ancestors


class TestContentEntry:
    """Test ContentEntry dataclass."""

    def test_create_file_entry(self):
        entry = ContentEntry(
            path=Path("/content/page.md"),
            entry_type="file",
            encrypted=False,
            checked=False,
        )
        assert entry.entry_type == "file"
        assert entry.encrypted is False
        assert entry.checked is False

    def test_create_dir_entry(self):
        entry = ContentEntry(
            path=Path("/content/private"),
            entry_type="dir",
            encrypted=True,
            checked=True,
        )
        assert entry.entry_type == "dir"
        assert entry.encrypted is True
        assert entry.checked is True

    def test_toggle_checked(self):
        entry = ContentEntry(
            path=Path("/content/page.md"),
            entry_type="file",
            encrypted=False,
            checked=False,
        )
        entry.checked = True
        assert entry.checked is True


class TestProtectApp:
    """Test ProtectApp construction."""

    def test_app_constructed_with_entries(self):
        entries = [
            {"label": "page.md", "path": Path("/content/page.md"), "type": "file", "encrypted": False},
        ]
        app = ProtectApp(entries)
        assert app._entries == entries

    def test_app_with_content_dir(self):
        entries = [
            {"label": "page.md", "path": Path("/content/page.md"), "type": "file", "encrypted": False},
        ]
        app = ProtectApp(entries, content_dir=Path("/content"))
        assert app._content_dir == Path("/content")

    def test_app_with_empty_entries(self):
        app = ProtectApp([])
        assert app._entries == []

    def test_app_with_mixed_entries(self):
        entries = [
            {"label": "private/", "path": Path("/content/private"), "type": "dir", "encrypted": True},
            {"label": "  doc.md", "path": Path("/content/private/doc.md"), "type": "file", "encrypted": True},
            {"label": "public.md", "path": Path("/content/public.md"), "type": "file", "encrypted": False},
        ]
        app = ProtectApp(entries)
        assert len(app._entries) == 3
