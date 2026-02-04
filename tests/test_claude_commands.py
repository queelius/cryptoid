"""Tests for cryptoid claude command group."""

import pytest
from pathlib import Path
from click.testing import CliRunner

from cryptoid.cli import main


@pytest.fixture
def runner():
    """Create Click test runner."""
    return CliRunner()


@pytest.fixture
def isolated_fs(runner):
    """Run tests in isolated filesystem."""
    with runner.isolated_filesystem():
        yield Path.cwd()


class TestClaudeStatus:
    """Test claude status command."""

    def test_status_not_installed(self, runner, isolated_fs, monkeypatch):
        """Status shows not installed when skill is missing."""
        # Use isolated filesystem as home
        monkeypatch.setenv("HOME", str(isolated_fs))
        monkeypatch.chdir(isolated_fs)

        result = runner.invoke(main, ["claude", "status"])

        assert result.exit_code == 0
        assert "not installed" in result.output.lower() or "missing" in result.output.lower()

    def test_status_local_installed(self, runner, isolated_fs, monkeypatch):
        """Status shows installed when local skill exists."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        # Create local skill
        skill_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("# cryptoid skill")

        result = runner.invoke(main, ["claude", "status"])

        assert result.exit_code == 0
        assert "[installed] local" in result.output

    def test_status_global_installed(self, runner, isolated_fs, monkeypatch):
        """Status shows installed when global skill exists."""
        home = isolated_fs / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(isolated_fs)

        # Create global skill
        skill_path = home / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("# cryptoid skill")

        result = runner.invoke(main, ["claude", "status"])

        assert result.exit_code == 0
        assert "[installed] global" in result.output

    def test_status_both_installed(self, runner, isolated_fs, monkeypatch):
        """Status shows both when local and global skills exist."""
        home = isolated_fs / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(isolated_fs)

        # Create local skill
        local_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        local_path.mkdir(parents=True)
        (local_path / "SKILL.md").write_text("# local cryptoid skill")

        # Create global skill
        global_path = home / ".claude" / "skills" / "cryptoid"
        global_path.mkdir(parents=True)
        (global_path / "SKILL.md").write_text("# global cryptoid skill")

        result = runner.invoke(main, ["claude", "status"])

        assert result.exit_code == 0
        assert "[installed] local" in result.output
        assert "[installed] global" in result.output
        assert "cryptoid skill is installed" in result.output


class TestClaudeInstall:
    """Test claude install command."""

    def test_install_local_default(self, runner, isolated_fs, monkeypatch):
        """Install creates local skill by default."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        result = runner.invoke(main, ["claude", "install"])

        assert result.exit_code == 0
        assert (isolated_fs / ".claude" / "skills" / "cryptoid" / "SKILL.md").exists()
        assert "local" in result.output

    def test_install_local_explicit(self, runner, isolated_fs, monkeypatch):
        """Install --local creates local skill."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        result = runner.invoke(main, ["claude", "install", "--local"])

        assert result.exit_code == 0
        assert (isolated_fs / ".claude" / "skills" / "cryptoid" / "SKILL.md").exists()

    def test_install_global(self, runner, isolated_fs, monkeypatch):
        """Install --global creates global skill."""
        home = isolated_fs / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(isolated_fs)

        result = runner.invoke(main, ["claude", "install", "--global"])

        assert result.exit_code == 0
        assert (home / ".claude" / "skills" / "cryptoid" / "SKILL.md").exists()
        assert "global" in result.output

    def test_install_creates_directories(self, runner, isolated_fs, monkeypatch):
        """Install creates parent directories if missing."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        # No .claude directory exists
        assert not (isolated_fs / ".claude").exists()

        result = runner.invoke(main, ["claude", "install"])

        assert result.exit_code == 0
        assert (isolated_fs / ".claude" / "skills" / "cryptoid").is_dir()

    def test_install_overwrites_existing(self, runner, isolated_fs, monkeypatch):
        """Install overwrites existing skill file."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        # Create existing skill
        skill_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        old_content = "# old skill content"
        (skill_path / "SKILL.md").write_text(old_content)

        result = runner.invoke(main, ["claude", "install"])

        assert result.exit_code == 0
        new_content = (skill_path / "SKILL.md").read_text()
        assert new_content != old_content
        assert "cryptoid" in new_content

    def test_install_copies_actual_content(self, runner, isolated_fs, monkeypatch):
        """Install copies actual skill content from bundled file."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        result = runner.invoke(main, ["claude", "install"])

        assert result.exit_code == 0
        content = (isolated_fs / ".claude" / "skills" / "cryptoid" / "SKILL.md").read_text()
        # Check for expected skill content markers
        assert "name: cryptoid" in content
        assert "description:" in content
        assert "Quick Reference" in content


class TestClaudeUninstall:
    """Test claude uninstall command."""

    def test_uninstall_local(self, runner, isolated_fs, monkeypatch):
        """Uninstall --local removes local skill."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        # Create local skill
        skill_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("# cryptoid skill")

        result = runner.invoke(main, ["claude", "uninstall", "--local"])

        assert result.exit_code == 0
        assert not (skill_path / "SKILL.md").exists()
        assert "local" in result.output

    def test_uninstall_global(self, runner, isolated_fs, monkeypatch):
        """Uninstall --global removes global skill."""
        home = isolated_fs / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(isolated_fs)

        # Create global skill
        skill_path = home / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("# cryptoid skill")

        result = runner.invoke(main, ["claude", "uninstall", "--global"])

        assert result.exit_code == 0
        assert not (skill_path / "SKILL.md").exists()
        assert "global" in result.output

    def test_uninstall_removes_empty_dirs(self, runner, isolated_fs, monkeypatch):
        """Uninstall removes empty parent directories."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        # Create local skill (only thing in .claude/)
        skill_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("# cryptoid skill")

        result = runner.invoke(main, ["claude", "uninstall"])

        assert result.exit_code == 0
        # cryptoid/ and skills/ should be removed
        assert not (isolated_fs / ".claude" / "skills" / "cryptoid").exists()
        assert not (isolated_fs / ".claude" / "skills").exists()
        # .claude/ is preserved (may contain other files in real usage)

    def test_uninstall_preserves_other_files(self, runner, isolated_fs, monkeypatch):
        """Uninstall preserves other skills/files."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        # Create cryptoid skill
        skill_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        skill_path.mkdir(parents=True)
        (skill_path / "SKILL.md").write_text("# cryptoid skill")

        # Create another skill
        other_skill = isolated_fs / ".claude" / "skills" / "other-tool"
        other_skill.mkdir(parents=True)
        (other_skill / "SKILL.md").write_text("# other skill")

        result = runner.invoke(main, ["claude", "uninstall"])

        assert result.exit_code == 0
        assert not (skill_path / "SKILL.md").exists()
        assert (other_skill / "SKILL.md").exists()

    def test_uninstall_not_installed(self, runner, isolated_fs, monkeypatch):
        """Uninstall succeeds even if not installed."""
        monkeypatch.setenv("HOME", str(isolated_fs / "home"))
        monkeypatch.chdir(isolated_fs)

        result = runner.invoke(main, ["claude", "uninstall"])

        assert result.exit_code == 0
        assert "not installed" in result.output.lower()

    def test_uninstall_default_is_local(self, runner, isolated_fs, monkeypatch):
        """Uninstall defaults to local (same as install)."""
        home = isolated_fs / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.chdir(isolated_fs)

        # Create both local and global skills
        local_path = isolated_fs / ".claude" / "skills" / "cryptoid"
        local_path.mkdir(parents=True)
        (local_path / "SKILL.md").write_text("# local")

        global_path = home / ".claude" / "skills" / "cryptoid"
        global_path.mkdir(parents=True)
        (global_path / "SKILL.md").write_text("# global")

        result = runner.invoke(main, ["claude", "uninstall"])

        assert result.exit_code == 0
        # Local should be removed
        assert not (local_path / "SKILL.md").exists()
        # Global should remain
        assert (global_path / "SKILL.md").exists()
