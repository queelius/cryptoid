"""Shared test fixtures for cryptoid tests."""

import os
import tempfile

import pytest


@pytest.fixture(autouse=True)
def isolate_global_config(monkeypatch):
    """Prevent tests from reading the real ~/.config/cryptoid/config.yaml.

    Every test gets an empty XDG_CONFIG_HOME so load_config() and
    _load_global_config() never see the developer's real global config.
    Tests that need a global config should create one under this path.
    """
    with tempfile.TemporaryDirectory() as config_home:
        monkeypatch.setenv("XDG_CONFIG_HOME", config_home)
        yield
