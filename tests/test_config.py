"""Tests for wirenose.config — YAML config loading with dataclass defaults."""

from __future__ import annotations

import textwrap

import pytest
import yaml

from wirenose.config import WireNoseConfig, load_config


class TestWireNoseConfigDefaults:
    """WireNoseConfig fields have correct defaults."""

    def test_default_values(self) -> None:
        cfg = WireNoseConfig()
        assert cfg.interface is None
        assert cfg.bpf_filter is None
        assert cfg.count == 100
        assert cfg.timeout is None
        assert cfg.output_dir == "."
        assert cfg.dashboard_refresh_rate == 4.0
        assert cfg.detection == {}
        assert cfg.report == {}


class TestLoadConfigNone:
    """load_config(None) returns pure defaults without error."""

    def test_none_path_returns_defaults(self) -> None:
        cfg = load_config(None)
        assert cfg == WireNoseConfig()

    def test_no_args_returns_defaults(self) -> None:
        cfg = load_config()
        assert cfg == WireNoseConfig()


class TestLoadConfigMissingFile:
    """Missing file path returns defaults — never crashes."""

    def test_nonexistent_path(self, tmp_path) -> None:
        cfg = load_config(tmp_path / "does_not_exist.yaml")
        assert cfg == WireNoseConfig()

    def test_nonexistent_string_path(self, tmp_path) -> None:
        cfg = load_config(str(tmp_path / "nope.yaml"))
        assert cfg == WireNoseConfig()


class TestLoadConfigPartialYAML:
    """Partial YAML file merges over defaults for specified keys only."""

    def test_partial_override(self, tmp_path) -> None:
        cfg_file = tmp_path / "partial.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            interface: eth0
            count: 500
        """))
        cfg = load_config(cfg_file)
        assert cfg.interface == "eth0"
        assert cfg.count == 500
        # Unset fields keep defaults
        assert cfg.bpf_filter is None
        assert cfg.timeout is None
        assert cfg.output_dir == "."
        assert cfg.dashboard_refresh_rate == 4.0
        assert cfg.detection == {}
        assert cfg.report == {}

    def test_only_dashboard_refresh_rate(self, tmp_path) -> None:
        cfg_file = tmp_path / "refresh.yaml"
        cfg_file.write_text("dashboard_refresh_rate: 2.0\n")
        cfg = load_config(cfg_file)
        assert cfg.dashboard_refresh_rate == 2.0
        assert cfg.count == 100  # default preserved


class TestLoadConfigFullYAML:
    """Full YAML file populates every field."""

    def test_all_fields_populated(self, tmp_path) -> None:
        cfg_file = tmp_path / "full.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            interface: wlan0
            bpf_filter: "tcp port 80"
            count: 1000
            timeout: 60
            output_dir: /tmp/captures
            dashboard_refresh_rate: 10.0
            detection:
              threshold: 50
              window: 300
            report:
              format: html
              include_raw: true
        """))
        cfg = load_config(cfg_file)
        assert cfg.interface == "wlan0"
        assert cfg.bpf_filter == "tcp port 80"
        assert cfg.count == 1000
        assert cfg.timeout == 60
        assert cfg.output_dir == "/tmp/captures"
        assert cfg.dashboard_refresh_rate == 10.0
        assert cfg.detection == {"threshold": 50, "window": 300}
        assert cfg.report == {"format": "html", "include_raw": True}


class TestLoadConfigInvalidYAML:
    """Invalid YAML raises yaml.YAMLError, not a silent default."""

    def test_broken_yaml_raises(self, tmp_path) -> None:
        cfg_file = tmp_path / "bad.yaml"
        cfg_file.write_text(":\n  - :\n    [[[invalid")
        with pytest.raises(yaml.YAMLError):
            load_config(cfg_file)


class TestLoadConfigEdgeCases:
    """Edge cases: empty file, non-mapping root, unknown keys."""

    def test_empty_file_returns_defaults(self, tmp_path) -> None:
        cfg_file = tmp_path / "empty.yaml"
        cfg_file.write_text("")
        cfg = load_config(cfg_file)
        assert cfg == WireNoseConfig()

    def test_non_mapping_raises_value_error(self, tmp_path) -> None:
        cfg_file = tmp_path / "list.yaml"
        cfg_file.write_text("- item1\n- item2\n")
        with pytest.raises(ValueError, match="must contain a YAML mapping"):
            load_config(cfg_file)

    def test_unknown_keys_ignored(self, tmp_path) -> None:
        cfg_file = tmp_path / "extra.yaml"
        cfg_file.write_text(textwrap.dedent("""\
            interface: lo
            unknown_key: should_be_ignored
            another_bogus: 42
        """))
        cfg = load_config(cfg_file)
        assert cfg.interface == "lo"
        assert cfg.count == 100  # default

    def test_string_path_accepted(self, tmp_path) -> None:
        cfg_file = tmp_path / "str_path.yaml"
        cfg_file.write_text("count: 250\n")
        cfg = load_config(str(cfg_file))
        assert cfg.count == 250
