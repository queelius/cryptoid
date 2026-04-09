"""Textual TUI components for cryptoid.

Provides interactive tree-based content selection for protect/unprotect
operations using the Textual framework.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.widgets import Footer, Header, Static, Tree
from textual.widgets.tree import TreeNode


@dataclass
class ContentEntry:
    """Data attached to each tree node."""

    path: Path
    entry_type: str  # "dir" or "file"
    encrypted: bool  # current state (before changes)
    checked: bool  # user selection state


class ContentTree(Tree[ContentEntry]):
    """A tree widget with checkbox toggling for content entries.

    Checkboxes are rendered dynamically via render_label() from node data,
    not stored in labels. This avoids Textual's set_label render cache issues.

    Space toggles checkboxes.
    Enter expands/collapses directory nodes.
    """

    BINDINGS = [
        Binding("space", "toggle_check", "Toggle", show=True, priority=True),
        Binding("enter", "expand_collapse", "Expand/Collapse", show=True),
    ]

    def render_label(
        self, node: TreeNode[ContentEntry], base_style, style
    ) -> Text:
        """Render node label with dynamic checkbox prefix from data."""
        # Compute checkbox from live data (not cached in label)
        if node.data is not None:
            if node.data.entry_type == "dir":
                cb = _checkbox_mixed(node)
            else:
                cb = _checkbox(node.data.checked)
            prefix_text = Text(f"{cb} ", style=style)
        else:
            prefix_text = Text("")

        node_label = node._label.copy()
        node_label.stylize(style)

        # Add expand/collapse icon for nodes with children
        if node._allow_expand:
            icon = (
                self.ICON_NODE_EXPANDED if node.is_expanded else self.ICON_NODE
            )
            icon_text = Text.from_markup(icon, style=base_style)
            return Text.assemble(icon_text, prefix_text, node_label)
        else:
            return Text.assemble(prefix_text, node_label)

    def action_toggle_check(self) -> None:
        """Toggle the checked state of the current node."""
        node = self.cursor_node
        if node is None or node.data is None:
            return

        node.data.checked = not node.data.checked

        # Directory: cascade to ALL descendants (recursive)
        if node.data.entry_type == "dir":
            _cascade_check(node, node.data.checked)
        else:
            # File: update ancestor data to reflect mixed state
            _sync_ancestor_checked(node)

        # Force visual repaint by clearing the rendered line cache
        self._line_cache.clear()
        self.refresh()

    def action_toggle_node(self) -> None:
        """Override Tree's built-in Space action to prevent expand/collapse."""
        self.action_toggle_check()

    def action_expand_collapse(self) -> None:
        """Toggle expand/collapse for directory nodes via Enter key."""
        node = self.cursor_node
        if node is None or node.data is None:
            return
        if node.data.entry_type == "dir":
            node.toggle()


def _cascade_check(node: TreeNode[ContentEntry], checked: bool) -> None:
    """Recursively set checked state on all descendants."""
    for child in node.children:
        if child.data is not None:
            child.data.checked = checked
            if child.data.entry_type == "dir":
                _cascade_check(child, checked)


def _sync_ancestor_checked(node: TreeNode[ContentEntry]) -> None:
    """Sync ancestor directory checked state after a descendant toggle."""
    parent = node.parent
    while parent is not None and parent.data is not None:
        if parent.data.entry_type == "dir":
            leaf_states = _collect_leaf_states(parent)
            parent.data.checked = leaf_states == {True}
        parent = parent.parent


def _checkbox(checked: bool) -> str:
    """Checkbox indicator: [x] checked, [ ] unchecked."""
    return "[x]" if checked else "[ ]"


def _checkbox_mixed(node: TreeNode[ContentEntry]) -> str:
    """Checkbox for a directory: [x] all checked, [ ] none checked, [-] mixed."""
    if not node.children:
        return _checkbox(node.data.checked if node.data else False)
    states = _collect_leaf_states(node)
    if states == {True}:
        return "[x]"
    elif states == {False}:
        return "[ ]"
    else:
        return "[-]"


def _collect_leaf_states(node: TreeNode[ContentEntry]) -> set[bool]:
    """Collect checked states from all leaf (file) descendants."""
    states: set[bool] = set()
    for child in node.children:
        if child.data is None:
            continue
        if child.data.entry_type == "file":
            states.add(child.data.checked)
        else:
            states |= _collect_leaf_states(child)
    return states


# Backward-compatible aliases for tests
def _update_label(node: TreeNode[ContentEntry]) -> None:
    """No-op — labels are rendered dynamically via render_label()."""
    pass


def _update_ancestors(node: TreeNode[ContentEntry]) -> None:
    """Alias for _sync_ancestor_checked."""
    _sync_ancestor_checked(node)


_update_parent_label = _update_ancestors


class ProtectApp(App[list[dict[str, Any]] | None]):
    """Interactive content tree for selecting files to protect/unprotect."""

    TITLE = "cryptoid protect"
    CSS = """
    ContentTree {
        height: 1fr;
    }
    #status {
        dock: bottom;
        height: 3;
        padding: 0 1;
        background: $surface;
        color: $text-muted;
    }
    """
    BINDINGS = [
        Binding("a", "apply", "Apply", show=True),
        Binding("q", "quit_app", "Quit", show=True),
    ]

    def __init__(
        self,
        entries: list[dict[str, Any]],
        content_dir: Path | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self._entries = entries
        self._content_dir = content_dir

    def compose(self) -> ComposeResult:
        yield Header()
        tree: ContentTree = ContentTree("Content", id="content-tree")
        tree.show_root = False
        tree.guide_depth = 3
        yield tree
        yield Static("Space=toggle  Enter=expand/collapse  a=apply  q=quit", id="status")
        yield Footer()

    def on_mount(self) -> None:
        tree = self.query_one(ContentTree)
        self._populate_tree(tree)
        tree.focus()

    def _ensure_ancestor(
        self,
        parent_path: Path,
        tree: ContentTree,
        dir_nodes: dict[Path, TreeNode[ContentEntry]],
    ) -> TreeNode[ContentEntry]:
        """Ensure parent_path exists as a tree node, creating intermediates.

        Under the current design, `_build_content_tree` pre-emits entries for
        every intermediate directory, so this method's synthesis path is a
        defensive fallback for directories that fall outside the expected
        hierarchy (e.g. symlink weirdness, a content_dir mismatch). Synthesized
        nodes use `encrypted=False` as a safe default — treating unknown state
        as "not encrypted" means the user sees the checkbox unchecked and must
        explicitly opt in, which avoids accidental unprotects.
        """
        if parent_path in dir_nodes:
            return dir_nodes[parent_path]
        if self._content_dir is not None and parent_path == self._content_dir:
            return tree.root
        if parent_path.parent == parent_path:
            return tree.root

        grandparent_node = self._ensure_ancestor(
            parent_path.parent, tree, dir_nodes
        )

        data = ContentEntry(
            path=parent_path,
            entry_type="dir",
            encrypted=False,
            checked=False,
        )
        # Label is just the name — checkbox is added by render_label()
        node = grandparent_node.add(
            parent_path.name + "/", data=data, expand=False
        )
        dir_nodes[parent_path] = node
        return node

    def _populate_tree(self, tree: ContentTree) -> None:
        """Build tree nodes from content entries, nesting subdirs under parents."""
        dir_nodes: dict[Path, TreeNode[ContentEntry]] = {}

        for entry in self._entries:
            path = entry["path"]
            encrypted = entry["encrypted"]
            entry_type = entry["type"]
            data = ContentEntry(
                path=path,
                entry_type=entry_type,
                encrypted=encrypted,
                checked=encrypted,
            )

            if entry_type == "dir":
                parent_node = self._ensure_ancestor(
                    path.parent, tree, dir_nodes
                )
                # Label is just the name — checkbox added by render_label()
                node = parent_node.add(
                    path.name + "/", data=data, expand=False
                )
                dir_nodes[path] = node
            else:
                parent_node = dir_nodes.get(path.parent)
                if parent_node is not None:
                    parent_node.add_leaf(path.name, data=data)
                else:
                    tree.root.add_leaf(path.name, data=data)

    def _count_changes(self) -> tuple[list[ContentEntry], list[ContentEntry]]:
        """Return (to_protect, to_unprotect) lists."""
        to_protect: list[ContentEntry] = []
        to_unprotect: list[ContentEntry] = []
        tree = self.query_one(ContentTree)

        def walk(node: TreeNode[ContentEntry]) -> None:
            if node.data is not None:
                if node.data.checked and not node.data.encrypted:
                    to_protect.append(node.data)
                elif not node.data.checked and node.data.encrypted:
                    to_unprotect.append(node.data)
            for child in node.children:
                walk(child)

        walk(tree.root)
        return to_protect, to_unprotect

    def on_tree_node_highlighted(
        self, event: Tree.NodeHighlighted[ContentEntry]
    ) -> None:
        """Update status bar with change count."""
        to_protect, to_unprotect = self._count_changes()
        total = len(to_protect) + len(to_unprotect)
        if total == 0:
            msg = "No changes  |  Space=toggle  Enter=expand/collapse  a=apply  q=quit"
        else:
            parts = []
            if to_protect:
                parts.append(f"+{len(to_protect)} protect")
            if to_unprotect:
                parts.append(f"-{len(to_unprotect)} unprotect")
            msg = f"{total} changes ({', '.join(parts)})  |  Space=toggle  Enter=expand/collapse  a=apply  q=quit"
        self.query_one("#status", Static).update(msg)

    def action_apply(self) -> None:
        """Apply changes and exit."""
        to_protect, to_unprotect = self._count_changes()
        if not to_protect and not to_unprotect:
            self.exit(None)
            return

        changes: list[dict[str, Any]] = []
        for entry in to_protect:
            changes.append({
                "action": "protect",
                "path": entry.path,
                "type": entry.entry_type,
            })
        for entry in to_unprotect:
            changes.append({
                "action": "unprotect",
                "path": entry.path,
                "type": entry.entry_type,
            })
        self.exit(changes)

    def action_quit_app(self) -> None:
        """Cancel and exit."""
        self.exit(None)
