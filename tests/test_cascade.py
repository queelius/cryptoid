"""Tests for cryptoid.cascade — the cascade resolution module."""

import pytest

from cryptoid.cascade import (
    CascadeResult,
    SOURCE_CASCADE_SOURCE,
    SOURCE_INHERITED,
    SOURCE_OPT_OUT,
    SOURCE_OWN,
    SOURCE_PLAIN,
    _walk_cascade_from,
    evaluate,
    resolve_encryption,
)


@pytest.fixture
def site(tmp_path):
    """Build a site with a parent cascade and several variations underneath."""
    content = tmp_path / "content"
    content.mkdir()

    private = content / "private"
    private.mkdir()
    (private / "_index.md").write_text(
        '---\ntitle: Private\nencrypted: true\ngroups:\n  - team\n---\n'
    )
    (private / "secret.md").write_text("---\ntitle: Secret\n---\nInherited.\n")
    (private / "explicit.md").write_text(
        '---\ntitle: Explicit\nencrypted: true\ngroups: ["admin"]\n---\nOwn.\n'
    )
    (private / "optout.md").write_text(
        "---\ntitle: Opt Out\nencrypted: false\n---\nNo encryption.\n"
    )

    sub = private / "sub"
    sub.mkdir()
    (sub / "page.md").write_text("---\ntitle: Sub Page\n---\nInherited too.\n")
    # Sub's _index.md inherits from parent (no own encrypted field)
    (sub / "_index.md").write_text("---\ntitle: Sub\n---\n")

    public = content / "public.md"
    public.write_text("---\ntitle: Public\n---\nNothing here.\n")

    return content


class TestWalkCascadeFrom:
    """The pure directory-tier cascade walker."""

    def test_returns_none_outside_content_dir(self, tmp_path):
        outside = tmp_path / "elsewhere"
        outside.mkdir()
        content = tmp_path / "content"
        content.mkdir()
        assert _walk_cascade_from(outside, content) is None

    def test_returns_config_when_dir_has_encrypted_index(self, site):
        result = _walk_cascade_from(site / "private", site)
        assert result is not None
        assert result.encrypted is True

    def test_returns_config_via_ancestor(self, site):
        # A subdir with no _index.md (or _index.md without encrypted field)
        # still inherits from a grandparent.
        result = _walk_cascade_from(site / "private" / "sub", site)
        assert result is not None
        assert result.encrypted is True

    def test_opt_out_in_walk_returns_none(self, tmp_path):
        content = tmp_path / "content"
        content.mkdir()
        parent = content / "p"
        parent.mkdir()
        (parent / "_index.md").write_text(
            "---\ntitle: P\nencrypted: true\n---\n"
        )
        child = parent / "c"
        child.mkdir()
        (child / "_index.md").write_text(
            "---\ntitle: C\nencrypted: false\n---\n"
        )
        # Walking from `child` hits its own opt-out before the parent's truthy
        # cascade, so the result is None.
        assert _walk_cascade_from(child, content) is None


class TestResolveEncryption:
    """End-to-end file resolution (own front matter + cascade)."""

    def test_plain_file_no_cascade(self, site):
        assert resolve_encryption(site / "public.md", site) is None

    def test_inherited_from_parent_index(self, site):
        cfg = resolve_encryption(site / "private" / "secret.md", site)
        assert cfg is not None
        assert cfg.groups == ["team"]

    def test_own_encrypted_overrides_inherited(self, site):
        cfg = resolve_encryption(site / "private" / "explicit.md", site)
        assert cfg is not None
        assert cfg.groups == ["admin"]

    def test_own_optout_blocks_cascade(self, site):
        assert resolve_encryption(site / "private" / "optout.md", site) is None

    def test_index_md_skips_self_cascade(self, site):
        # private/sub/_index.md has no own encrypted field; the cascade walk
        # for it must START from `private/`, not from `sub/`. So it should
        # inherit `encrypted: true` from `private/_index.md`.
        cfg = resolve_encryption(site / "private" / "sub" / "_index.md", site)
        assert cfg is not None
        assert cfg.groups == ["team"]


class TestEvaluate:
    """The high-level value object."""

    def test_plain_returns_plain_source(self, site):
        result = evaluate(site / "public.md", site)
        assert isinstance(result, CascadeResult)
        assert result.config is None
        assert result.source == SOURCE_PLAIN
        assert result.is_already_encrypted is False
        assert "Nothing here" in result.content

    def test_own_encrypted_classifies_as_own(self, site):
        result = evaluate(site / "private" / "explicit.md", site)
        assert result.source == SOURCE_OWN
        assert result.config is not None
        assert result.config.groups == ["admin"]

    def test_inherited_classifies_as_inherited(self, site):
        result = evaluate(site / "private" / "secret.md", site)
        assert result.source == SOURCE_INHERITED
        assert result.config is not None
        assert result.config.groups == ["team"]

    def test_index_md_with_own_encrypted_is_cascade_source(self, site):
        result = evaluate(site / "private" / "_index.md", site)
        assert result.source == SOURCE_CASCADE_SOURCE
        assert result.config is not None
        assert result.config.groups == ["team"]

    def test_optout_classifies_as_opt_out(self, site):
        result = evaluate(site / "private" / "optout.md", site)
        assert result.source == SOURCE_OPT_OUT
        assert result.config is None  # nothing applies, despite cascade above

    def test_index_md_without_encrypted_field_inherits(self, site):
        # private/sub/_index.md has only `title: Sub` — no own encrypted field.
        # It must inherit from the parent (skipping its own dir to avoid
        # self-cascade) and get classified as SOURCE_INHERITED.
        result = evaluate(site / "private" / "sub" / "_index.md", site)
        assert result.source == SOURCE_INHERITED
        assert result.config is not None
        assert result.config.groups == ["team"]

    def test_already_encrypted_body_is_detected(self, tmp_path):
        content = tmp_path / "content"
        content.mkdir()
        encrypted = content / "secret.md"
        encrypted.write_text(
            '---\ntitle: Secret\nencrypted: true\n---\n'
            '{{< cryptoid-encrypted ciphertext="abc" hash="ff" >}}\n'
        )
        result = evaluate(encrypted, content)
        assert result.is_already_encrypted is True
        assert result.source == SOURCE_OWN
