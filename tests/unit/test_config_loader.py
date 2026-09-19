"""Tests for config_loader.py."""
import json
import pytest
from config_loader import load_config, Config, FormConfig, LoginConfig, _resolve_login


class TestLoadConfig:
    def test_load_valid_config(self, tmp_path):
        config_data = {
            "start_url": "https://example.com",
            "max_depth": 5,
            "max_clicks_per_page": 30,
            "wait_timeout": 60000,
            "network_idle_timeout": 3000,
            "form_filling": {
                "enabled": True,
                "fill_delay": 200,
                "defaults": {"#email": "test@example.com"},
            },
            "exclude_patterns": ["logout", "settings"],
        }
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps(config_data))

        config = load_config(str(config_file))

        assert config.start_url == "https://example.com"
        assert config.max_depth == 5
        assert config.max_clicks_per_page == 30
        assert config.wait_timeout == 60000
        assert config.network_idle_timeout == 3000
        assert config.form_filling.enabled is True
        assert config.form_filling.fill_delay == 200
        assert config.form_filling.defaults == {"#email": "test@example.com"}
        assert config.exclude_patterns == ["logout", "settings"]

    def test_load_minimal_config(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"start_url": "https://example.com"}))

        config = load_config(str(config_file))

        assert config.start_url == "https://example.com"
        assert config.max_depth == 3
        assert config.max_clicks_per_page == 20
        assert config.wait_timeout == 30000
        assert config.network_idle_timeout == 2000
        assert config.form_filling.enabled is True
        assert config.form_filling.defaults == {}
        # When exclude_patterns absent, Config.__post_init__ applies the default list.
        assert config.exclude_patterns == ["logout", "delete", "remove", "login", "signin"]
        assert config.login is None

    def test_load_config_missing_start_url(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"max_depth": 3}))

        with pytest.raises(KeyError):
            load_config(str(config_file))

    def test_load_config_with_form_filling(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "form_filling": {
                "enabled": False,
                "fill_delay": 300,
                "defaults": {"#user": "bob"},
            },
        }))

        config = load_config(str(config_file))
        assert config.form_filling.enabled is False
        assert config.form_filling.fill_delay == 300
        assert config.form_filling.defaults == {"#user": "bob"}

    def test_load_config_without_form_filling(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({"start_url": "https://example.com"}))

        config = load_config(str(config_file))
        assert config.form_filling.enabled is True
        assert config.form_filling.fill_delay == 100
        assert config.form_filling.defaults == {}

    def test_load_config_custom_exclude_patterns(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "exclude_patterns": ["settings", "admin"],
        }))

        config = load_config(str(config_file))
        assert config.exclude_patterns == ["settings", "admin"]

    def test_load_nonexistent_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path/config.json")

    def test_load_invalid_json(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text("not valid json {{{")

        with pytest.raises(json.JSONDecodeError):
            load_config(str(config_file))

    def test_extra_unknown_keys_ignored(self, tmp_path):
        """Unknown keys in JSON should be silently ignored."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "unknown_key": "some_value",
            "another_random": 42,
        }))

        config = load_config(str(config_file))
        assert config.start_url == "https://example.com"
        assert not hasattr(config, "unknown_key")

    def test_empty_exclude_patterns_list(self, tmp_path):
        """Explicit empty list should override dataclass default."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "exclude_patterns": [],
        }))

        config = load_config(str(config_file))
        assert config.exclude_patterns == []

    def test_form_filling_partial_config(self, tmp_path):
        """Form config with only some fields should use defaults for the rest."""
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "form_filling": {"enabled": False},
        }))

        config = load_config(str(config_file))
        assert config.form_filling.enabled is False
        assert config.form_filling.fill_delay == 100  # default
        assert config.form_filling.defaults == {}  # default

    def test_zero_max_depth(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "max_depth": 0,
        }))

        config = load_config(str(config_file))
        assert config.max_depth == 0

    def test_large_timeout_values(self, tmp_path):
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "wait_timeout": 120000,
            "network_idle_timeout": 10000,
        }))

        config = load_config(str(config_file))
        assert config.wait_timeout == 120000
        assert config.network_idle_timeout == 10000


class TestConfigDefaults:
    def test_config_post_init_exclude_patterns(self):
        """When exclude_patterns is None (not passed), __post_init__ sets defaults."""
        config = Config(start_url="https://example.com", max_depth=3, max_clicks_per_page=20)
        assert config.exclude_patterns == ["logout", "delete", "remove", "login", "signin"]

    def test_form_config_defaults(self):
        form = FormConfig()
        assert form.enabled is True
        assert form.fill_delay == 100
        assert form.defaults == {}


class TestResolveLogin:
    def test_no_login_block_returns_none(self):
        assert _resolve_login({}) is None

    def test_missing_env_var_names_raises(self):
        with pytest.raises(ValueError, match="username_env"):
            _resolve_login({"login": {"login_url": "http://x/login"}})

    def test_env_var_not_set_raises(self, monkeypatch):
        monkeypatch.delenv("TEST_USER", raising=False)
        monkeypatch.delenv("TEST_PASS", raising=False)
        with pytest.raises(ValueError, match="not set"):
            _resolve_login({"login": {
                "login_url": "http://x/login",
                "username_env": "TEST_USER",
                "password_env": "TEST_PASS",
            }})

    def test_missing_login_url_raises(self, monkeypatch):
        monkeypatch.setenv("TEST_USER", "u")
        monkeypatch.setenv("TEST_PASS", "p")
        with pytest.raises(ValueError, match="login_url"):
            _resolve_login({"login": {
                "username_env": "TEST_USER", "password_env": "TEST_PASS"
            }})

    def test_returns_login_config_with_defaults(self, monkeypatch):
        monkeypatch.setenv("TEST_USER", "alice")
        monkeypatch.setenv("TEST_PASS", "secret")
        cfg = _resolve_login({"login": {
            "login_url": "http://x/login",
            "username_env": "TEST_USER",
            "password_env": "TEST_PASS",
        }})
        assert isinstance(cfg, LoginConfig)
        assert cfg.login_url == "http://x/login"
        assert cfg.username == "alice"
        assert cfg.password == "secret"
        assert cfg.username_selector == "#username"
        assert cfg.password_selector == "input[type='password']"
        assert cfg.submit_selector == "button[type='submit']"
        assert cfg.post_login_wait_ms == 3000
        assert cfg.storage_state_path == "storage_state.json"
        assert cfg.reuse_storage_state is True

    def test_overrides_all_optional_fields(self, monkeypatch):
        monkeypatch.setenv("U", "u")
        monkeypatch.setenv("P", "p")
        cfg = _resolve_login({"login": {
            "login_url": "http://x/login",
            "username_env": "U",
            "password_env": "P",
            "username_selector": "#u",
            "password_selector": "#p",
            "submit_selector": "#go",
            "post_login_wait_ms": 999,
            "storage_state_path": "/tmp/s.json",
            "reuse_storage_state": False,
        }})
        assert cfg.username_selector == "#u"
        assert cfg.password_selector == "#p"
        assert cfg.submit_selector == "#go"
        assert cfg.post_login_wait_ms == 999
        assert cfg.storage_state_path == "/tmp/s.json"
        assert cfg.reuse_storage_state is False

    def test_load_config_with_login(self, tmp_path, monkeypatch):
        monkeypatch.setenv("APP_USER", "bob")
        monkeypatch.setenv("APP_PASS", "pw")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "start_url": "https://example.com",
            "login": {
                "login_url": "https://example.com/login",
                "username_env": "APP_USER",
                "password_env": "APP_PASS",
            },
        }))
        config = load_config(str(config_file))
        assert config.login is not None
        assert config.login.username == "bob"
        assert config.login.password == "pw"
