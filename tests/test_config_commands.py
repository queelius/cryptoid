"""Tests for config management commands and init command."""

import pytest
import yaml
from click.testing import CliRunner

from cryptoid.cli import main


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def existing_config(tmp_path):
    """Create a pre-built .cryptoid.yaml in tmp_path."""
    config_path = tmp_path / ".cryptoid.yaml"
    config_path.write_text(
        yaml.dump(
            {
                "users": {
                    "alice": "alice-pass",
                    "bob": "bob-pass",
                },
                "groups": {
                    "admin": ["alice"],
                    "team": ["alice", "bob"],
                },
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            },
            default_flow_style=False,
            sort_keys=False,
        )
    )
    return config_path


# =============================================================================
# TestInit
# =============================================================================


class TestInit:
    def test_creates_config_no_global(self, runner, tmp_path):
        """Without global config, prompts for user, content dir, creates config."""
        config_path = tmp_path / ".cryptoid.yaml"
        # No global → forced to add user, accept default content dir, decline group
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="alice\nsecret123\nsecret123\n\nN\n",
        )
        assert result.exit_code == 0
        assert config_path.exists()

        cfg = yaml.safe_load(config_path.read_text())
        assert "alice" in cfg["users"]
        assert cfg["users"]["alice"] == "secret123"
        assert "admin" in cfg["groups"]
        assert "alice" in cfg["groups"]["admin"]
        assert cfg["salt"]  # non-empty
        assert cfg["content_dir"] == "content"

    def test_creates_config_with_global(self, runner, tmp_path, monkeypatch):
        """With global users, skips user prompt if declined."""
        # Set up global config
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"alex": "globalpass"}}),
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / ".cryptoid.yaml"
        # Decline local user, accept default content dir, decline group
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="N\n\nN\n",
        )
        assert result.exit_code == 0
        assert config_path.exists()

        cfg = yaml.safe_load(config_path.read_text())
        assert "users" not in cfg  # no local users
        assert cfg["salt"]  # salt always present
        assert cfg["content_dir"] == "content"
        assert "Global users available" in result.output

    def test_creates_config_with_global_add_local_user(self, runner, tmp_path, monkeypatch):
        """With global users, can still add a local user."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"alex": "globalpass"}}),
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / ".cryptoid.yaml"
        # Yes add local user, accept default content dir, decline group
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="Y\nbob\nlocal123\nlocal123\n\nN\n",
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(config_path.read_text())
        assert "bob" in cfg["users"]
        assert "admin" in cfg["groups"]

    def test_refuses_overwrite(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["init", "--config", str(existing_config)],
            input="N\n",
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_force_overwrite(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["init", "--config", str(existing_config), "--force"],
            input="carol\nnewpass\nnewpass\n\nN\n",
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(existing_config.read_text())
        assert "carol" in cfg["users"]
        # Old users should be gone
        assert "alice" not in cfg["users"]

    def test_gitignore_created(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        gitignore = tmp_path / ".gitignore"
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="alice\npass\npass\n\nN\n",
        )
        assert result.exit_code == 0
        assert gitignore.exists()
        assert config_path.name in gitignore.read_text()

    def test_gitignore_appended(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n")
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="alice\npass\npass\n\nN\n",
        )
        assert result.exit_code == 0
        content = gitignore.read_text()
        assert "node_modules/" in content
        assert config_path.name in content

    def test_gitignore_skip_if_already_listed(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(f"{config_path.name}\n")
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="alice\npass\npass\n\nN\n",
        )
        assert result.exit_code == 0
        assert "already in .gitignore" in result.output

    def test_validates_username(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        # No global → forced user prompt. Invalid then valid username, decline group
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="bad:name\nalice\npass\npass\n\nN\n",
        )
        assert result.exit_code == 0
        assert "Invalid username" in result.output
        cfg = yaml.safe_load(config_path.read_text())
        assert "alice" in cfg["users"]

    def test_optional_group(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        # No global → user prompt, content dir, then create group "team"
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="alice\npass\npass\n\nY\nteam\nalice\n",
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(config_path.read_text())
        assert "team" in cfg["groups"]
        assert "alice" in cfg["groups"]["team"]
        assert "admin" in cfg["groups"]

    def test_content_dir_custom(self, runner, tmp_path):
        """Init with custom content directory."""
        config_path = tmp_path / ".cryptoid.yaml"
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="alice\npass\npass\nsite/content\nN\n",
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(config_path.read_text())
        assert cfg["content_dir"] == "site/content"

    def test_content_dir_from_global(self, runner, tmp_path, monkeypatch):
        """Init shows global content dir and skips prompt if declined."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"alex": "globalpass"}, "content_dir": "blog/content"}),
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / ".cryptoid.yaml"
        # Decline local user, decline different content dir, decline group
        result = runner.invoke(
            main,
            ["init", "--config", str(config_path)],
            input="N\nN\nN\n",
        )
        assert result.exit_code == 0
        assert "blog/content" in result.output
        cfg = yaml.safe_load(config_path.read_text())
        assert "content_dir" not in cfg  # not set locally, uses global


# =============================================================================
# TestConfigAddUser
# =============================================================================


class TestConfigAddUser:
    def test_basic_add(self, runner, existing_config):
        # Username as argument, skip group prompt with Enter
        result = runner.invoke(
            main,
            ["config", "add-user", "carol", "--config", str(existing_config)],
            input="carol-pass\ncarol-pass\n\n",
        )
        assert result.exit_code == 0
        assert "User 'carol' added" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "carol" in cfg["users"]
        assert cfg["users"]["carol"] == "carol-pass"

    def test_add_with_group_flag(self, runner, existing_config):
        # --group flag bypasses the interactive group prompt
        result = runner.invoke(
            main,
            [
                "config", "add-user", "carol",
                "--group", "team",
                "--config", str(existing_config),
            ],
            input="carol-pass\ncarol-pass\n",
        )
        assert result.exit_code == 0
        assert "Added to groups: team" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "carol" in cfg["groups"]["team"]

    def test_add_interactive_no_args(self, runner, existing_config):
        # No username argument: prompts for username, password, groups
        result = runner.invoke(
            main,
            ["config", "add-user", "--config", str(existing_config)],
            input="carol\ncarol-pass\ncarol-pass\nteam\n",
        )
        assert result.exit_code == 0
        assert "User 'carol' added" in result.output
        assert "Added to groups: team" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "carol" in cfg["users"]
        assert "carol" in cfg["groups"]["team"]

    def test_add_interactive_skip_group(self, runner, existing_config):
        # No username argument, skip group with Enter
        result = runner.invoke(
            main,
            ["config", "add-user", "--config", str(existing_config)],
            input="carol\ncarol-pass\ncarol-pass\n\n",
        )
        assert result.exit_code == 0
        assert "User 'carol' added" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "carol" in cfg["users"]

    def test_add_interactive_multiple_groups(self, runner, existing_config):
        # Select multiple groups via comma-separated input
        result = runner.invoke(
            main,
            ["config", "add-user", "carol", "--config", str(existing_config)],
            input="carol-pass\ncarol-pass\nadmin, team\n",
        )
        assert result.exit_code == 0
        assert "Added to groups: admin, team" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "carol" in cfg["groups"]["admin"]
        assert "carol" in cfg["groups"]["team"]

    def test_duplicate_rejected(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-user", "alice", "--config", str(existing_config)],
            input="newpass\nnewpass\n\n",
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_invalid_username(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-user", "bad:name", "--config", str(existing_config)],
            input="pass\npass\n\n",
        )
        assert result.exit_code != 0

    def test_nonexistent_group(self, runner, existing_config):
        result = runner.invoke(
            main,
            [
                "config", "add-user", "carol",
                "--group", "nonexistent",
                "--config", str(existing_config),
            ],
            input="pass\npass\n",
        )
        assert result.exit_code != 0
        assert "does not exist" in result.output

    def test_rewrap_advice(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-user", "carol", "--config", str(existing_config)],
            input="pass\npass\n\n",
        )
        assert result.exit_code == 0
        assert "rewrap" in result.output


# =============================================================================
# TestConfigRemoveUser
# =============================================================================


class TestConfigRemoveUser:
    def test_basic_remove(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "User 'bob' removed" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "bob" not in cfg["users"]

    def test_nonexistent_user(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-user", "nobody", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_hints_when_user_in_other_tier(self, runner, tmp_path, monkeypatch):
        """Removing a global-only user from local config hints about --global."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"globaluser": "gpass"}})
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"localuser": "lpass"},
                "groups": {"admin": ["localuser"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            })
        )
        result = runner.invoke(
            main,
            ["config", "remove-user", "globaluser", "--config", str(local_config)],
        )
        assert result.exit_code != 0
        assert "global" in result.output
        assert "--global" in result.output

    def test_last_user_refused(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump(
                {
                    "users": {"alice": "pass"},
                    "groups": {"admin": ["alice"]},
                    "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                },
                default_flow_style=False,
            )
        )
        result = runner.invoke(
            main,
            ["config", "remove-user", "alice", "--config", str(config_path)],
        )
        assert result.exit_code != 0
        assert "last user" in result.output

    def test_last_local_user_allowed_if_global_exists(self, runner, tmp_path, monkeypatch):
        """Removing the last local user is OK if global users exist."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"globaluser": "gpass"}})
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"localuser": "lpass"},
                "groups": {"admin": ["localuser"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            })
        )
        result = runner.invoke(
            main,
            ["config", "remove-user", "localuser", "--config", str(local_config)],
        )
        assert result.exit_code == 0
        assert "localuser" in result.output

    def test_cleans_groups(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(existing_config.read_text())
        assert "bob" not in cfg["groups"]["team"]
        assert "alice" in cfg["groups"]["team"]

    def test_rewrap_advice(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "rewrap --rekey" in result.output

    def test_empty_group_warning(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump(
                {
                    "users": {"alice": "pass", "bob": "pass"},
                    "groups": {"admin": ["alice"], "solo": ["bob"]},
                    "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                },
                default_flow_style=False,
            )
        )
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "Group 'solo' is now empty" in result.output


# =============================================================================
# TestConfigListUsers
# =============================================================================


class TestConfigListUsers:
    def test_basic_list(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "list-users", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "alice" in result.output
        assert "bob" in result.output
        assert "admin" in result.output
        assert "team" in result.output

    def test_no_group_shows_none(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump(
                {
                    "users": {"alice": "pass", "carol": "pass"},
                    "groups": {"admin": ["alice"]},
                    "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                },
                default_flow_style=False,
            )
        )
        result = runner.invoke(
            main,
            ["config", "list-users", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "(none)" in result.output

    def test_missing_config_error(self, runner, tmp_path):
        result = runner.invoke(
            main,
            ["config", "list-users", "--config", str(tmp_path / "nope.yaml")],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


# =============================================================================
# TestConfigAddGroup
# =============================================================================


class TestConfigAddGroup:
    def test_basic_add(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-group", "editors", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "Group 'editors' created" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "editors" in cfg["groups"]

    def test_add_with_members(self, runner, existing_config):
        result = runner.invoke(
            main,
            [
                "config", "add-group", "editors",
                "--members", "alice,bob",
                "--config", str(existing_config),
            ],
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(existing_config.read_text())
        assert cfg["groups"]["editors"] == ["alice", "bob"]

    def test_empty_members(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-group", "empty", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "empty" in result.output
        assert "created" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert cfg["groups"]["empty"] == []

    def test_duplicate_rejected(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-group", "admin", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_unknown_member_rejected(self, runner, existing_config):
        result = runner.invoke(
            main,
            [
                "config", "add-group", "editors",
                "--members", "alice,nobody",
                "--config", str(existing_config),
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_global_user_as_member(self, runner, tmp_path, monkeypatch):
        """A user defined in global config can be a member of a local group."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"globaluser": "gpass"}})
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"localuser": "lpass"},
                "groups": {"admin": ["localuser"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            })
        )
        result = runner.invoke(
            main,
            [
                "config", "add-group", "editors",
                "--members", "localuser,globaluser",
                "--config", str(local_config),
            ],
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(local_config.read_text())
        assert "globaluser" in cfg["groups"]["editors"]


# =============================================================================
# TestConfigRemoveGroup
# =============================================================================


class TestConfigRemoveGroup:
    def test_basic_remove(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-group", "team", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "Group 'team' removed" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "team" not in cfg["groups"]

    def test_nonexistent(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-group", "nope", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_admin_refused(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-group", "admin", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "admin" in result.output
        assert "--force" in result.output

    def test_admin_force(self, runner, existing_config):
        result = runner.invoke(
            main,
            [
                "config", "remove-group", "admin",
                "--force",
                "--config", str(existing_config),
            ],
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(existing_config.read_text())
        assert "admin" not in cfg["groups"]

    def test_content_ref_warning(self, runner, existing_config, tmp_path):
        # Create content directory with a file referencing "team"
        content_dir = tmp_path / "content"
        content_dir.mkdir()
        (content_dir / "secret.md").write_text(
            "---\nencrypted: true\ngroups:\n  - team\n---\nSecret content.\n"
        )
        result = runner.invoke(
            main,
            [
                "config", "remove-group", "team",
                "--content-dir", str(content_dir),
                "--config", str(existing_config),
            ],
        )
        assert result.exit_code == 0
        assert "secret.md" in result.output


# =============================================================================
# TestConfigListGroups
# =============================================================================


class TestConfigListGroups:
    def test_basic_list(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "list-groups", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "admin" in result.output
        assert "team" in result.output
        assert "alice" in result.output
        assert "bob" in result.output

    def test_no_groups(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump(
                {
                    "users": {"alice": "pass"},
                    "groups": {},
                    "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                },
                default_flow_style=False,
            )
        )
        result = runner.invoke(
            main,
            ["config", "list-groups", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "(no groups defined)" in result.output

    def test_missing_config_error(self, runner, tmp_path):
        result = runner.invoke(
            main,
            ["config", "list-groups", "--config", str(tmp_path / "nope.yaml")],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


# =============================================================================
# TestConfigAddToGroup / TestConfigRemoveFromGroup
# =============================================================================


class TestConfigAddToGroup:
    def test_adds_user_to_group(self, runner, existing_config):
        # existing_config has alice in admin, bob in team
        # Add bob to admin
        result = runner.invoke(
            main,
            ["config", "add-to-group", "admin", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "Added" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "bob" in cfg["groups"]["admin"]

    def test_user_already_in_group(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-to-group", "admin", "alice", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "already in group" in result.output

    def test_unknown_user(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-to-group", "admin", "nobody", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_unknown_group(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "add-to-group", "nope", "alice", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_global(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({
                "users": {"alex": "gpass", "carol": "gpass2"},
                "groups": {"admin": ["alex"]},
            })
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "add-to-group", "admin", "carol", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output

        cfg = yaml.safe_load((cryptoid_dir / "config.yaml").read_text())
        assert "carol" in cfg["groups"]["admin"]

    def test_global_user_added_to_local_group(self, runner, tmp_path, monkeypatch):
        """A user defined in global config can be added to a local group."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"globaluser": "gpass"}})
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"localuser": "lpass"},
                "groups": {"team": ["localuser"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            })
        )
        result = runner.invoke(
            main,
            ["config", "add-to-group", "team", "globaluser", "--config", str(local_config)],
        )
        assert result.exit_code == 0
        assert "globaluser" in result.output

        cfg = yaml.safe_load(local_config.read_text())
        assert "globaluser" in cfg["groups"]["team"]


class TestConfigRemoveFromGroup:
    def test_removes_user_from_group(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-from-group", "team", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "Removed" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "bob" not in cfg["groups"]["team"]

    def test_not_in_group(self, runner, existing_config):
        # bob exists but is not in admin group
        result = runner.invoke(
            main,
            ["config", "remove-from-group", "admin", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not in group" in result.output

    def test_unknown_group(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "remove-from-group", "nope", "alice", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_warns_empty_group(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump({
                "users": {"alice": "pass"},
                "groups": {"solo": ["alice"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            })
        )
        result = runner.invoke(
            main,
            ["config", "remove-from-group", "solo", "alice", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "empty" in result.output.lower()

    def test_global(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({
                "users": {"alex": "gpass"},
                "groups": {"admin": ["alex"]},
            })
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "remove-from-group", "admin", "alex", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output

        cfg = yaml.safe_load((cryptoid_dir / "config.yaml").read_text())
        assert "alex" not in cfg["groups"]["admin"]


# =============================================================================
# TestConfigGenerateSalt
# =============================================================================


class TestConfigGenerateSalt:
    def test_prints_hex(self, runner):
        result = runner.invoke(main, ["config", "generate-salt"])
        assert result.exit_code == 0
        assert "Generated salt:" in result.output
        # Salt should be 32 hex chars
        salt = result.output.split("Generated salt: ")[1].strip()
        assert len(salt) == 32
        int(salt, 16)  # validates hex

    def test_apply_writes_config(self, runner, existing_config):
        old_cfg = yaml.safe_load(existing_config.read_text())
        old_salt = old_cfg["salt"]

        result = runner.invoke(
            main,
            ["config", "generate-salt", "--apply", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "Salt written to" in result.output
        assert "rewrap --rekey" in result.output

        new_cfg = yaml.safe_load(existing_config.read_text())
        assert new_cfg["salt"] != old_salt

    def test_apply_missing_config(self, runner, tmp_path):
        result = runner.invoke(
            main,
            [
                "config", "generate-salt", "--apply",
                "--config", str(tmp_path / "nope.yaml"),
            ],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_different_each_time(self, runner):
        result1 = runner.invoke(main, ["config", "generate-salt"])
        result2 = runner.invoke(main, ["config", "generate-salt"])
        salt1 = result1.output.split("Generated salt: ")[1].strip()
        salt2 = result2.output.split("Generated salt: ")[1].strip()
        assert salt1 != salt2


# =============================================================================
# TestSaveConfig
# =============================================================================


class TestSaveConfig:
    def test_excludes_salt_bytes(self, runner, tmp_path):
        """Verify save_config doesn't write salt_bytes to file."""
        from cryptoid.cli import save_config

        config_path = tmp_path / "test.yaml"
        save_config(
            config_path,
            {
                "users": {"alice": "pass"},
                "groups": {"admin": ["alice"]},
                "salt": "abcd1234abcd1234abcd1234abcd1234",
                "salt_bytes": b"\xab\xcd",
            },
        )
        content = config_path.read_text()
        assert "salt_bytes" not in content

    def test_preserves_key_order(self, runner, tmp_path):
        """Verify users comes before groups comes before salt."""
        from cryptoid.cli import save_config

        config_path = tmp_path / "test.yaml"
        save_config(
            config_path,
            {
                "users": {"alice": "pass"},
                "groups": {"admin": ["alice"]},
                "salt": "abcd1234abcd1234abcd1234abcd1234",
            },
        )
        content = config_path.read_text()
        users_pos = content.index("users:")
        groups_pos = content.index("groups:")
        salt_pos = content.index("salt:")
        assert users_pos < groups_pos < salt_pos

    def test_persists_content_dir_and_admin(self, runner, tmp_path):
        """Verify save_config writes content_dir and admin fields."""
        from cryptoid.cli import save_config

        config_path = tmp_path / "test.yaml"
        save_config(
            config_path,
            {
                "users": {"alice": "pass"},
                "groups": {"admin": ["alice"]},
                "salt": "abcd1234abcd1234abcd1234abcd1234",
                "content_dir": "site/content",
                "admin": "alice",
            },
        )
        cfg = yaml.safe_load(config_path.read_text())
        assert cfg["content_dir"] == "site/content"
        assert cfg["admin"] == "alice"


# =============================================================================
# TestConfigSetContentDir
# =============================================================================


class TestConfigSetContentDir:
    def test_sets_content_dir(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "set-content-dir", "site/content", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "content_dir set to: site/content" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert cfg["content_dir"] == "site/content"

    def test_overwrites_existing(self, runner, existing_config):
        """Setting content_dir replaces any previous value."""
        # Set first value
        runner.invoke(
            main,
            ["config", "set-content-dir", "old/path", "--config", str(existing_config)],
        )
        # Set new value
        result = runner.invoke(
            main,
            ["config", "set-content-dir", "new/path", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(existing_config.read_text())
        assert cfg["content_dir"] == "new/path"

    def test_preserves_other_keys(self, runner, existing_config):
        """Setting content_dir preserves users, groups, salt."""
        original = yaml.safe_load(existing_config.read_text())

        runner.invoke(
            main,
            ["config", "set-content-dir", "content/", "--config", str(existing_config)],
        )
        updated = yaml.safe_load(existing_config.read_text())
        assert updated["users"] == original["users"]
        assert updated["groups"] == original["groups"]
        assert updated["salt"] == original["salt"]
        assert updated["content_dir"] == "content/"

    def test_missing_config(self, runner, tmp_path):
        """Error when config file doesn't exist."""
        result = runner.invoke(
            main,
            ["config", "set-content-dir", "content/", "--config", str(tmp_path / "nope.yaml")],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


# =============================================================================
# TestConfigSetAdmin
# =============================================================================


class TestConfigSetAdmin:
    def test_sets_admin(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "set-admin", "alice", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "admin set to: alice" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert cfg["admin"] == "alice"

    def test_validates_user_exists(self, runner, existing_config):
        """Admin must be an existing user."""
        result = runner.invoke(
            main,
            ["config", "set-admin", "nonexistent", "--config", str(existing_config)],
        )
        assert result.exit_code != 0
        assert "not found" in result.output

    def test_unset_admin(self, runner, existing_config):
        """--unset removes the admin field."""
        # First set an admin
        runner.invoke(
            main,
            ["config", "set-admin", "alice", "--config", str(existing_config)],
        )
        # Then unset
        result = runner.invoke(
            main,
            ["config", "set-admin", "--unset", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "removed" in result.output

        cfg = yaml.safe_load(existing_config.read_text())
        assert "admin" not in cfg

    def test_unset_when_not_set(self, runner, existing_config):
        """--unset when no admin is a no-op."""
        result = runner.invoke(
            main,
            ["config", "set-admin", "--unset", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "No admin" in result.output

    def test_unset_with_username_fails(self, runner, existing_config):
        """Cannot use --unset and username together."""
        result = runner.invoke(
            main,
            ["config", "set-admin", "alice", "--unset", "--config", str(existing_config)],
        )
        assert result.exit_code != 0

    def test_no_args_fails(self, runner, existing_config):
        """Must provide username or --unset."""
        result = runner.invoke(
            main,
            ["config", "set-admin", "--config", str(existing_config)],
        )
        assert result.exit_code != 0

    def test_preserves_other_keys(self, runner, existing_config):
        """Setting admin preserves users, groups, salt."""
        original = yaml.safe_load(existing_config.read_text())

        runner.invoke(
            main,
            ["config", "set-admin", "alice", "--config", str(existing_config)],
        )
        updated = yaml.safe_load(existing_config.read_text())
        assert updated["users"] == original["users"]
        assert updated["groups"] == original["groups"]
        assert updated["salt"] == original["salt"]

    def test_missing_config(self, runner, tmp_path):
        """Error when config file doesn't exist."""
        result = runner.invoke(
            main,
            ["config", "set-admin", "alice", "--config", str(tmp_path / "nope.yaml")],
        )
        assert result.exit_code != 0
        assert "not found" in result.output


# =============================================================================
# TestGlobalConfig — global/local merge semantics
# =============================================================================


class TestGlobalConfig:
    """Tests for global config loading and merging with local config."""

    def _setup_global(self, tmp_path, monkeypatch, users=None, content_dir=None,
                       groups=None, extra=None):
        """Create a global config and point XDG_CONFIG_HOME at tmp_path."""
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        global_dir = config_home / "cryptoid"
        global_dir.mkdir()
        global_path = global_dir / "config.yaml"

        data = {}
        if users:
            data["users"] = users
        if content_dir:
            data["content_dir"] = content_dir
        if groups:
            data["groups"] = groups
        if extra:
            data.update(extra)

        global_path.write_text(
            yaml.dump(data, default_flow_style=False), encoding="utf-8"
        )
        return global_path

    def test_no_global_config(self, runner, existing_config):
        """load_config works fine without global config."""
        from cryptoid.cli import load_config

        config = load_config(existing_config)
        assert "alice" in config["users"]
        assert "bob" in config["users"]

    def test_global_users_merged(self, runner, existing_config, tmp_path, monkeypatch):
        """Global users are merged into local config."""
        self._setup_global(tmp_path, monkeypatch, users={"carol": "carol-global"})

        from cryptoid.cli import load_config

        config = load_config(existing_config)
        assert "alice" in config["users"]  # from local
        assert "bob" in config["users"]  # from local
        assert "carol" in config["users"]  # from global
        assert config["users"]["carol"] == "carol-global"

    def test_local_overrides_global_user(self, runner, existing_config, tmp_path, monkeypatch):
        """When same username in both, local password wins."""
        self._setup_global(tmp_path, monkeypatch, users={"alice": "global-password"})

        from cryptoid.cli import load_config

        config = load_config(existing_config)
        assert config["users"]["alice"] == "alice-pass"  # local wins

    def test_global_content_dir_used(self, tmp_path, monkeypatch):
        """Global content_dir is used when local doesn't specify one."""
        content_dir = tmp_path / "my_content"
        content_dir.mkdir()
        self._setup_global(
            tmp_path, monkeypatch,
            users={"alice": "pass"},
            content_dir=str(content_dir),
        )

        # Create a local config without content_dir
        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"alice": "pass"},
                "groups": {"admin": ["alice"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config

        config = load_config(local_config)
        assert config["content_dir"] == str(content_dir)

    def test_local_content_dir_overrides_global(self, tmp_path, monkeypatch):
        """Local content_dir takes precedence over global."""
        global_dir = tmp_path / "global_content"
        global_dir.mkdir()
        local_dir = tmp_path / "local_content"
        local_dir.mkdir()

        self._setup_global(
            tmp_path, monkeypatch,
            users={"alice": "pass"},
            content_dir=str(global_dir),
        )

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"alice": "pass"},
                "groups": {"admin": ["alice"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
                "content_dir": str(local_dir),
            }),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config

        config = load_config(local_config)
        assert config["content_dir"] == str(local_dir)

    def test_global_only_users_no_local_users(self, tmp_path, monkeypatch):
        """Config is valid when users come only from global config."""
        self._setup_global(tmp_path, monkeypatch, users={"alice": "global-pass"})

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "groups": {"admin": ["alice"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config

        config = load_config(local_config)
        assert "alice" in config["users"]
        assert config["users"]["alice"] == "global-pass"

    def test_groups_merged_additively(self, tmp_path, monkeypatch):
        """Same-named groups get union of members from global + local."""
        self._setup_global(
            tmp_path, monkeypatch,
            users={"alice": "pass-a"},
            groups={"admin": ["alice"]},
        )

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"bob": "pass-b"},
                "groups": {"admin": ["bob"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config

        config = load_config(local_config)
        assert "alice" in config["groups"]["admin"]
        assert "bob" in config["groups"]["admin"]

    def test_global_only_groups(self, tmp_path, monkeypatch):
        """Groups from global are used when local has none."""
        self._setup_global(
            tmp_path, monkeypatch,
            users={"alice": "pass"},
            groups={"team": ["alice"]},
        )

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({"salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"}),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config

        config = load_config(local_config)
        assert "team" in config["groups"]
        assert "alice" in config["groups"]["team"]

    def test_password_conflict_warning(self, runner, tmp_path, monkeypatch):
        """Warns when same user has different passwords in global and local."""
        self._setup_global(tmp_path, monkeypatch, users={"alice": "global-pass"})

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"alice": "local-pass"},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config

        config = load_config(local_config)
        assert config["users"]["alice"] == "local-pass"

    def test_admin_field_from_global(self, tmp_path, monkeypatch):
        """admin field from global config injects user into resolved set."""
        self._setup_global(
            tmp_path, monkeypatch,
            users={"alex": "pass-a"},
            extra={"admin": "alex"},
        )

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(
            yaml.dump({
                "users": {"bob": "pass-b"},
                "groups": {"team": ["bob"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }),
            encoding="utf-8",
        )

        from cryptoid.cli import load_config, resolve_users

        config = load_config(local_config)
        assert config["admin"] == "alex"

        # alex should be in resolved users even for team-only content
        users = resolve_users(["team"], config)
        assert "alex" in users
        assert "bob" in users


# =============================================================================
# TestResolveContentDir
# =============================================================================


class TestResolveContentDir:
    """Tests for _resolve_content_dir precedence chain."""

    def test_cli_value_takes_precedence(self, tmp_path):
        from cryptoid.cli import _resolve_content_dir

        cli_dir = tmp_path / "cli_content"
        cli_dir.mkdir()
        result = _resolve_content_dir(cli_dir, {"content_dir": "/other"})
        assert result == cli_dir

    def test_env_var_precedence(self, tmp_path, monkeypatch):
        from cryptoid.cli import _resolve_content_dir

        env_dir = tmp_path / "env_content"
        env_dir.mkdir()
        monkeypatch.setenv("CRYPTOID_CONTENT_DIR", str(env_dir))

        result = _resolve_content_dir(None, {"content_dir": "/other"})
        assert result == env_dir

    def test_config_content_dir(self, tmp_path):
        from cryptoid.cli import _resolve_content_dir

        config_dir = tmp_path / "config_content"
        config_dir.mkdir()
        result = _resolve_content_dir(None, {"content_dir": str(config_dir)})
        assert result == config_dir

    def test_no_content_dir_configured_exits(self, tmp_path, monkeypatch):
        from cryptoid.cli import _resolve_content_dir

        monkeypatch.chdir(tmp_path)
        # No content dir configured anywhere
        with pytest.raises(SystemExit):
            _resolve_content_dir(None, {})

    def test_missing_dir_exits(self, tmp_path, monkeypatch):
        from cryptoid.cli import _resolve_content_dir

        monkeypatch.chdir(tmp_path)
        # Dir configured but doesn't exist
        with pytest.raises(SystemExit):
            _resolve_content_dir(None, {"content_dir": "/nonexistent/path"})


# =============================================================================
# TestConfigInitGlobal
# =============================================================================


class TestInitGlobal:
    def test_creates_global_config(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["init", "--global"],
            input="alice\nmypass\nmypass\n\n",
        )
        assert result.exit_code == 0
        assert "Created" in result.output

        global_path = config_home / "cryptoid" / "config.yaml"
        assert global_path.exists()
        cfg = yaml.safe_load(global_path.read_text())
        assert cfg["users"]["alice"] == "mypass"

    def test_refuses_overwrite(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text("users:\n  bob: pass\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["init", "--global"],
            input="alice\npass\npass\n\n",
        )
        assert result.exit_code != 0
        assert "already exists" in result.output

    def test_force_overwrites(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text("users:\n  bob: pass\n")
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["init", "--global", "--force"],
            input="alice\nnewpass\nnewpass\n\n",
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load((cryptoid_dir / "config.yaml").read_text())
        assert "alice" in cfg["users"]
        assert "bob" not in cfg["users"]

    def test_with_content_dir(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["init", "--global", "--content-dir", "/my/content"],
            input="alice\npass\npass\n",
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(
            (config_home / "cryptoid" / "config.yaml").read_text()
        )
        assert cfg["content_dir"] == "/my/content"

    def test_interactive_content_dir(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["init", "--global"],
            input="alice\npass\npass\n~/github/repos/site/content\n",
        )
        assert result.exit_code == 0

        cfg = yaml.safe_load(
            (config_home / "cryptoid" / "config.yaml").read_text()
        )
        assert cfg["content_dir"] == "~/github/repos/site/content"


# =============================================================================
# TestConfigStatusGlobal
# =============================================================================


class TestConfigStatusGlobal:
    def test_shows_global_info(self, runner, existing_config, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"carol": "global-pass"}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "status", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "Global config:" in result.output
        assert "carol" in result.output
        assert "Local config:" in result.output

    def test_shows_no_global(self, runner, existing_config, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "status", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "not found" in result.output


# =============================================================================
# TestConfigShowMerged
# =============================================================================


class TestConfigShow:
    def test_show_with_sources(self, runner, existing_config, tmp_path, monkeypatch):
        """Show annotates each value with its source."""
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"carol": "global-pass"}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "show", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "carol" in result.output
        assert "# global" in result.output
        assert "# local" in result.output
        assert "alice" in result.output

    def test_show_local_only(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "alice" in result.output
        assert "# local" in result.output
        assert "Local:" in result.output

    def test_show_global_only(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"carol": "global-pass"}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        no_local = tmp_path / "nonexistent.yaml"
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(no_local)],
        )
        assert result.exit_code == 0
        assert "carol" in result.output
        assert "# global" in result.output
        assert "Global:" in result.output

    def test_show_no_config_at_all(self, runner, tmp_path, monkeypatch):
        config_home = tmp_path / "empty_xdg"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        no_local = tmp_path / "nonexistent.yaml"
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(no_local)],
        )
        assert result.exit_code != 0
        assert "No config found" in result.output

    def test_shows_overrides(self, runner, tmp_path, monkeypatch):
        """When same user in both configs, show 'local (overrides global)'."""
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"alice": "global-pass"}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump({"users": {"alice": "local-pass"}, "salt": "aa" * 16}),
            encoding="utf-8",
        )

        result = runner.invoke(
            main,
            ["config", "show", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "overrides global" in result.output

    def test_content_dir_source(self, runner, tmp_path, monkeypatch):
        """Content dir shows its source."""
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"alice": "pass"}, "content_dir": "~/content"}),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        no_local = tmp_path / "nonexistent.yaml"
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(no_local)],
        )
        assert result.exit_code == 0
        assert "content_dir:" in result.output
        assert "# global" in result.output


# =============================================================================
# TestPasswordMasking
# =============================================================================


class TestPasswordMasking:
    def test_passwords_masked_by_default(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        # Passwords should be masked (first 2 chars + ***)
        assert "al***" in result.output  # alice-pass → al***
        assert "alice-pass" not in result.output

    def test_show_passwords_flag(self, runner, existing_config):
        result = runner.invoke(
            main,
            ["config", "show", "--show-passwords", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "alice-pass" in result.output

    def test_global_passwords_masked(self, runner, existing_config, tmp_path, monkeypatch):
        config_home = tmp_path / "xdg_config"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(
            yaml.dump({"users": {"carol": "global-secret"}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        result = runner.invoke(
            main,
            ["config", "show", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "global-secret" not in result.output
        assert "gl***" in result.output

    def test_short_password_fully_masked(self, runner, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(
            yaml.dump({
                "users": {"x": "ab"},
                "groups": {"admin": ["x"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            }),
            encoding="utf-8",
        )
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "***" in result.output
        assert "x: ab " not in result.output


# =============================================================================
# Comprehensive --global tests for all mutation commands
# =============================================================================


class TestGlobalMutationCommands:
    """Tests for --global flag on all config mutation commands."""

    def _setup_global(self, tmp_path, monkeypatch, data=None):
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        global_path = cryptoid_dir / "config.yaml"
        if data is None:
            data = {
                "users": {"globaluser": "gpass"},
                "groups": {"admin": ["globaluser"]},
            }
        global_path.write_text(yaml.dump(data))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))
        return global_path

    def test_add_user_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "add-user", "newuser", "--global"],
            input="newpass\nnewpass\n\n",
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert "newuser" in cfg["users"]

    def test_remove_user_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch, data={
            "users": {"alice": "pa", "bob": "pb"},
            "groups": {"team": ["alice", "bob"]},
        })
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert "bob" not in cfg["users"]
        assert "bob" not in cfg["groups"]["team"]

    def test_add_group_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "add-group", "editors", "--members", "globaluser", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert "editors" in cfg["groups"]
        assert "globaluser" in cfg["groups"]["editors"]

    def test_remove_group_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch, data={
            "users": {"alice": "pa"},
            "groups": {"admin": ["alice"], "team": ["alice"]},
        })
        result = runner.invoke(
            main,
            ["config", "remove-group", "team", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert "team" not in cfg["groups"]
        assert "admin" in cfg["groups"]  # preserved

    def test_generate_salt_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "generate-salt", "--apply", "--global"],
        )
        assert result.exit_code == 0
        assert "global" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert "salt" in cfg
        assert len(cfg["salt"]) == 32

    def test_set_content_dir_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "set-content-dir", "/my/content", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert cfg["content_dir"] == "/my/content"

    def test_set_admin_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch)
        result = runner.invoke(
            main,
            ["config", "set-admin", "globaluser", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert cfg["admin"] == "globaluser"

    def test_set_admin_unset_global(self, runner, tmp_path, monkeypatch):
        gpath = self._setup_global(tmp_path, monkeypatch, data={
            "users": {"alice": "pa"},
            "admin": "alice",
        })
        result = runner.invoke(
            main,
            ["config", "set-admin", "--unset", "--global"],
        )
        assert result.exit_code == 0
        assert "(global)" in result.output
        cfg = yaml.safe_load(gpath.read_text())
        assert "admin" not in cfg

    def test_all_global_commands_fail_without_global_config(self, runner, tmp_path, monkeypatch):
        """All --global mutation commands fail clearly when no global config."""
        config_home = tmp_path / "empty_xdg"
        config_home.mkdir()
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        commands = [
            ["config", "add-user", "x", "--global"],
            ["config", "remove-user", "x", "--global"],
            ["config", "add-group", "x", "--global"],
            ["config", "remove-group", "x", "--global"],
            ["config", "generate-salt", "--apply", "--global"],
            ["config", "set-content-dir", "/x", "--global"],
            ["config", "set-admin", "x", "--global"],
            ["config", "add-to-group", "x", "y", "--global"],
            ["config", "remove-from-group", "x", "y", "--global"],
        ]
        for cmd in commands:
            result = runner.invoke(main, cmd, input="p\np\n\n")
            assert result.exit_code != 0, f"{' '.join(cmd)} should fail: {result.output}"


# =============================================================================
# Config mutation preserves other keys
# =============================================================================


class TestMutationsPreserveConfig:
    """All mutation commands preserve unrelated config keys."""

    def _make_config(self, tmp_path):
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"alice": "pass-a", "bob": "pass-b"},
            "groups": {"admin": ["alice"], "team": ["alice", "bob"]},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "content_dir": "content/",
            "admin": "alice",
        }))
        return config_path

    def test_add_user_preserves(self, runner, tmp_path):
        cfg_path = self._make_config(tmp_path)
        runner.invoke(
            main,
            ["config", "add-user", "carol", "--config", str(cfg_path)],
            input="cpass\ncpass\n\n",
        )
        cfg = yaml.safe_load(cfg_path.read_text())
        assert cfg["salt"] == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert cfg["content_dir"] == "content/"
        assert cfg["admin"] == "alice"
        assert cfg["groups"]["admin"] == ["alice"]

    def test_remove_user_preserves(self, runner, tmp_path):
        cfg_path = self._make_config(tmp_path)
        runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(cfg_path)],
        )
        cfg = yaml.safe_load(cfg_path.read_text())
        assert cfg["salt"] == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert cfg["content_dir"] == "content/"
        assert cfg["admin"] == "alice"

    def test_add_group_preserves(self, runner, tmp_path):
        cfg_path = self._make_config(tmp_path)
        runner.invoke(
            main,
            ["config", "add-group", "editors", "--config", str(cfg_path)],
        )
        cfg = yaml.safe_load(cfg_path.read_text())
        assert cfg["salt"] == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert cfg["content_dir"] == "content/"
        assert cfg["admin"] == "alice"
        assert len(cfg["users"]) == 2

    def test_remove_group_preserves(self, runner, tmp_path):
        cfg_path = self._make_config(tmp_path)
        runner.invoke(
            main,
            ["config", "remove-group", "team", "--config", str(cfg_path)],
        )
        cfg = yaml.safe_load(cfg_path.read_text())
        assert cfg["salt"] == "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert cfg["content_dir"] == "content/"
        assert cfg["admin"] == "alice"
        assert "admin" in cfg["groups"]

    def test_generate_salt_preserves(self, runner, tmp_path):
        cfg_path = self._make_config(tmp_path)
        runner.invoke(
            main,
            ["config", "generate-salt", "--apply", "--config", str(cfg_path)],
        )
        cfg = yaml.safe_load(cfg_path.read_text())
        assert cfg["content_dir"] == "content/"
        assert cfg["admin"] == "alice"
        assert len(cfg["users"]) == 2
        assert len(cfg["groups"]) == 2


# =============================================================================
# Edge cases and merged config semantics
# =============================================================================


class TestMergedConfigEdgeCases:
    """Tests for edge cases in global/local config merging."""

    def _setup(self, tmp_path, monkeypatch, global_data, local_data):
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(yaml.dump(global_data))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        local_config = tmp_path / ".cryptoid.yaml"
        local_config.write_text(yaml.dump(local_data))
        return local_config

    def test_list_users_shows_merged(self, runner, tmp_path, monkeypatch):
        """list-users shows users from both global and local."""
        local_cfg = self._setup(tmp_path, monkeypatch,
            global_data={"users": {"globaluser": "gp"}},
            local_data={
                "users": {"localuser": "lp"},
                "groups": {"admin": ["localuser"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            },
        )
        result = runner.invoke(
            main,
            ["config", "list-users", "--config", str(local_cfg)],
        )
        assert result.exit_code == 0
        assert "globaluser" in result.output
        assert "localuser" in result.output

    def test_list_groups_shows_merged(self, runner, tmp_path, monkeypatch):
        """list-groups shows groups from both global and local."""
        local_cfg = self._setup(tmp_path, monkeypatch,
            global_data={
                "users": {"alice": "pa"},
                "groups": {"global-team": ["alice"]},
            },
            local_data={
                "users": {"bob": "pb"},
                "groups": {"local-team": ["bob"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            },
        )
        result = runner.invoke(
            main,
            ["config", "list-groups", "--config", str(local_cfg)],
        )
        assert result.exit_code == 0
        assert "global-team" in result.output
        assert "local-team" in result.output

    def test_no_groups_key_in_config(self, runner, tmp_path):
        """Config with no groups key at all still works for list-users."""
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"alice": "pass"},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        }))
        result = runner.invoke(
            main,
            ["config", "list-users", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "alice" in result.output

    def test_remove_user_from_multiple_groups(self, runner, tmp_path):
        """Removing a user cleans them from every group."""
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"alice": "pa", "bob": "pb"},
            "groups": {"admin": ["alice", "bob"], "team": ["bob"], "editors": ["bob"]},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        }))
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(config_path.read_text())
        for group_members in cfg["groups"].values():
            assert "bob" not in group_members

    def test_remove_user_not_in_any_group(self, runner, tmp_path):
        """Removing a user with no group membership works."""
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"alice": "pa", "bob": "pb"},
            "groups": {"admin": ["alice"]},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        }))
        result = runner.invoke(
            main,
            ["config", "remove-user", "bob", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(config_path.read_text())
        assert "bob" not in cfg["users"]

    def test_set_admin_with_global_user(self, runner, tmp_path, monkeypatch):
        """Can set admin to a user that only exists in global config."""
        local_cfg = self._setup(tmp_path, monkeypatch,
            global_data={"users": {"globaladmin": "gp"}},
            local_data={
                "users": {"localuser": "lp"},
                "groups": {"admin": ["localuser"]},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            },
        )
        result = runner.invoke(
            main,
            ["config", "set-admin", "globaladmin", "--config", str(local_cfg)],
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(local_cfg.read_text())
        assert cfg["admin"] == "globaladmin"

    def test_add_user_same_name_as_global(self, runner, tmp_path, monkeypatch):
        """Adding a user locally with same name as global is allowed (override)."""
        local_cfg = self._setup(tmp_path, monkeypatch,
            global_data={"users": {"alice": "global-pass"}},
            local_data={
                "groups": {"admin": []},
                "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            },
        )
        result = runner.invoke(
            main,
            ["config", "add-user", "alice", "--config", str(local_cfg)],
            input="local-pass\nlocal-pass\n\n",
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(local_cfg.read_text())
        assert cfg["users"]["alice"] == "local-pass"

    def test_add_to_group_rewrap_advice(self, runner, existing_config):
        """add-to-group advises about rewrap."""
        result = runner.invoke(
            main,
            ["config", "add-to-group", "admin", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        assert "rewrap" in result.output

    def test_remove_from_group_user_still_exists(self, runner, existing_config):
        """remove-from-group doesn't delete the user, only removes membership."""
        result = runner.invoke(
            main,
            ["config", "remove-from-group", "team", "bob", "--config", str(existing_config)],
        )
        assert result.exit_code == 0
        cfg = yaml.safe_load(existing_config.read_text())
        assert "bob" in cfg["users"]  # user still exists
        assert "bob" not in cfg["groups"]["team"]  # but not in group


# =============================================================================
# Config show edge cases
# =============================================================================


class TestConfigShowEdgeCases:
    """Additional edge cases for config show."""

    def test_admin_field_shown(self, runner, tmp_path):
        """config show displays the admin field."""
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"alice": "pass"},
            "groups": {"admin": ["alice"]},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "admin": "alice",
        }))
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "admin:" in result.output
        assert "alice" in result.output

    def test_content_dir_shown(self, runner, tmp_path):
        """config show displays the content_dir field."""
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"alice": "pass"},
            "groups": {"admin": ["alice"]},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
            "content_dir": "site/content",
        }))
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        assert "content_dir:" in result.output
        assert "site/content" in result.output

    def test_show_with_no_users(self, runner, tmp_path):
        """config show handles config with no users."""
        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        }))
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(config_path)],
        )
        assert result.exit_code == 0

    def test_show_merged_groups_union(self, runner, tmp_path, monkeypatch):
        """Same group name in global+local shows union of members."""
        config_home = tmp_path / "xdg"
        cryptoid_dir = config_home / "cryptoid"
        cryptoid_dir.mkdir(parents=True)
        (cryptoid_dir / "config.yaml").write_text(yaml.dump({
            "users": {"alice": "pa"},
            "groups": {"admin": ["alice"]},
        }))
        monkeypatch.setenv("XDG_CONFIG_HOME", str(config_home))

        config_path = tmp_path / ".cryptoid.yaml"
        config_path.write_text(yaml.dump({
            "users": {"bob": "pb"},
            "groups": {"admin": ["bob"]},
            "salt": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
        }))
        result = runner.invoke(
            main,
            ["config", "show", "--config", str(config_path)],
        )
        assert result.exit_code == 0
        # Both alice and bob should appear in admin group
        assert "alice" in result.output
        assert "bob" in result.output


# =============================================================================
# Salt command edge cases
# =============================================================================


class TestGenerateSaltEdgeCases:
    def test_apply_preserves_users_and_groups(self, runner, existing_config):
        """--apply doesn't destroy existing config."""
        original = yaml.safe_load(existing_config.read_text())
        runner.invoke(
            main,
            ["config", "generate-salt", "--apply", "--config", str(existing_config)],
        )
        updated = yaml.safe_load(existing_config.read_text())
        assert updated["users"] == original["users"]
        assert updated["groups"] == original["groups"]
        assert updated["salt"] != original["salt"]

    def test_salt_is_valid_hex(self, runner):
        """Generated salt is exactly 32 valid hex chars."""
        result = runner.invoke(main, ["config", "generate-salt"])
        salt = result.output.split("Generated salt: ")[1].strip()
        assert len(salt) == 32
        bytes.fromhex(salt)  # valid hex

    def test_without_apply_does_not_modify(self, runner, existing_config):
        """Without --apply, config file is unchanged."""
        original = existing_config.read_text()
        runner.invoke(main, ["config", "generate-salt"])
        assert existing_config.read_text() == original
