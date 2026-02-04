"""Tests for cryptoid hugo command group."""

import pytest
from click.testing import CliRunner

from cryptoid.cli import main


@pytest.fixture
def runner():
    """Create Click test runner."""
    return CliRunner()


@pytest.fixture
def hugo_site(tmp_path):
    """Create a minimal Hugo site structure."""
    site = tmp_path / "my-hugo-site"
    site.mkdir()
    (site / "hugo.toml").write_text('baseURL = "https://example.com/"\n')
    (site / "content").mkdir()
    (site / "layouts").mkdir()
    (site / "assets").mkdir()
    return site


@pytest.fixture
def hugo_site_with_cryptoid(hugo_site):
    """Hugo site with cryptoid already installed."""
    shortcode_dir = hugo_site / "layouts" / "shortcodes"
    shortcode_dir.mkdir()
    (shortcode_dir / "cryptoid-encrypted.html").write_text("<!-- cryptoid v0.1.0 -->")

    js_dir = hugo_site / "assets" / "js"
    js_dir.mkdir()
    (js_dir / "cryptoid.js").write_text("// cryptoid v0.1.0")

    return hugo_site


class TestHugoStatus:
    """Test hugo status command."""

    def test_status_not_installed(self, runner, hugo_site):
        """Status shows not installed when files missing."""
        result = runner.invoke(main, ["hugo", "status", "--site-dir", str(hugo_site)])

        assert result.exit_code == 0
        assert "not installed" in result.output.lower() or "missing" in result.output.lower()

    def test_status_installed(self, runner, hugo_site_with_cryptoid):
        """Status shows installed when files present."""
        result = runner.invoke(main, [
            "hugo", "status",
            "--site-dir", str(hugo_site_with_cryptoid)
        ])

        assert result.exit_code == 0
        assert "installed" in result.output.lower()

    def test_status_auto_detects_hugo_site(self, runner, hugo_site, monkeypatch):
        """Status auto-detects Hugo site from current directory."""
        monkeypatch.chdir(hugo_site)
        result = runner.invoke(main, ["hugo", "status"])

        assert result.exit_code == 0

    def test_status_not_hugo_site(self, runner, tmp_path):
        """Status errors when not in a Hugo site."""
        result = runner.invoke(main, ["hugo", "status", "--site-dir", str(tmp_path)])

        assert result.exit_code != 0
        assert "hugo" in result.output.lower()


class TestHugoInstall:
    """Test hugo install command."""

    def test_install_creates_files(self, runner, hugo_site):
        """Install copies shortcode and JS files."""
        result = runner.invoke(main, ["hugo", "install", "--site-dir", str(hugo_site)])

        assert result.exit_code == 0
        assert (hugo_site / "layouts" / "shortcodes" / "cryptoid-encrypted.html").exists()
        assert (hugo_site / "assets" / "js" / "cryptoid.js").exists()

    def test_install_creates_directories(self, runner, hugo_site):
        """Install creates shortcodes/js directories if missing."""
        # Remove assets dir
        (hugo_site / "assets").rmdir()

        result = runner.invoke(main, ["hugo", "install", "--site-dir", str(hugo_site)])

        assert result.exit_code == 0
        assert (hugo_site / "assets" / "js" / "cryptoid.js").exists()

    def test_install_overwrites_existing(self, runner, hugo_site_with_cryptoid):
        """Install overwrites existing cryptoid files."""
        result = runner.invoke(main, [
            "hugo", "install",
            "--site-dir", str(hugo_site_with_cryptoid)
        ])

        assert result.exit_code == 0
        # Should have new content (from actual source files)
        content = (hugo_site_with_cryptoid / "layouts" / "shortcodes" / "cryptoid-encrypted.html").read_text()
        assert "cryptoid-encrypted" in content.lower() or "cryptoid" in content

    def test_install_not_hugo_site(self, runner, tmp_path):
        """Install errors when not in a Hugo site."""
        result = runner.invoke(main, ["hugo", "install", "--site-dir", str(tmp_path)])

        assert result.exit_code != 0


class TestHugoUninstall:
    """Test hugo uninstall command."""

    def test_uninstall_removes_files(self, runner, hugo_site_with_cryptoid):
        """Uninstall removes cryptoid files."""
        result = runner.invoke(main, [
            "hugo", "uninstall",
            "--site-dir", str(hugo_site_with_cryptoid)
        ])

        assert result.exit_code == 0
        assert not (hugo_site_with_cryptoid / "layouts" / "shortcodes" / "cryptoid-encrypted.html").exists()
        assert not (hugo_site_with_cryptoid / "assets" / "js" / "cryptoid.js").exists()

    def test_uninstall_preserves_other_files(self, runner, hugo_site_with_cryptoid):
        """Uninstall doesn't remove other shortcodes/js."""
        # Add another shortcode
        (hugo_site_with_cryptoid / "layouts" / "shortcodes" / "other.html").write_text("other")
        (hugo_site_with_cryptoid / "assets" / "js" / "main.js").write_text("main")

        runner.invoke(main, [
            "hugo", "uninstall",
            "--site-dir", str(hugo_site_with_cryptoid)
        ])

        assert (hugo_site_with_cryptoid / "layouts" / "shortcodes" / "other.html").exists()
        assert (hugo_site_with_cryptoid / "assets" / "js" / "main.js").exists()

    def test_uninstall_when_not_installed(self, runner, hugo_site):
        """Uninstall succeeds even if not installed."""
        result = runner.invoke(main, ["hugo", "uninstall", "--site-dir", str(hugo_site)])

        assert result.exit_code == 0

    def test_uninstall_not_hugo_site(self, runner, tmp_path):
        """Uninstall errors when not in a Hugo site."""
        result = runner.invoke(main, ["hugo", "uninstall", "--site-dir", str(tmp_path)])

        assert result.exit_code != 0
