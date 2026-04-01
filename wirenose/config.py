"""YAML-based configuration with dataclass defaults.

Provides WireNoseConfig — a plain dataclass with sensible defaults for all
fields.  load_config() reads an optional YAML file and merges it over defaults.
Missing file or None path → pure defaults, never crashes.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)


@dataclass
class WireNoseConfig:
    """Runtime configuration for WireNose.

    Every field has a default so zero-config always works.  Downstream slices
    (S03 detection, S05 reporting) use the opaque ``detection`` and ``report``
    dicts — this module passes them through without interpreting them.
    """

    interface: str | None = None
    bpf_filter: str | None = None
    count: int = 100
    timeout: int | None = None
    output_dir: str = "."
    dashboard_refresh_rate: float = 4.0
    detection: dict[str, Any] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)


def load_config(path: str | Path | None = None) -> WireNoseConfig:
    """Load configuration from a YAML file, falling back to defaults.

    Args:
        path: Filesystem path to a YAML config file.  ``None`` or a path that
              does not exist both return a default-initialised config — the
              caller never needs to guard against missing files.

    Returns:
        A fully populated :class:`WireNoseConfig`.

    Raises:
        yaml.YAMLError: When *path* exists but contains unparseable YAML.
        ValueError: When *path* exists but the top-level value is not a mapping.
    """
    if path is None:
        logger.debug("No config path provided — using defaults")
        return WireNoseConfig()

    config_path = Path(path)
    if not config_path.is_file():
        logger.debug("Config file %s not found — using defaults", config_path)
        return WireNoseConfig()

    logger.info("Loading config from %s", config_path)
    text = config_path.read_text(encoding="utf-8")
    raw = yaml.safe_load(text)

    # Empty file → yaml.safe_load returns None
    if raw is None:
        return WireNoseConfig()

    if not isinstance(raw, dict):
        raise ValueError(
            f"Config file {config_path} must contain a YAML mapping, "
            f"got {type(raw).__name__}"
        )

    # Map YAML keys to dataclass fields, ignoring unknown keys.
    known_fields = {f.name for f in WireNoseConfig.__dataclass_fields__.values()}
    filtered = {k: v for k, v in raw.items() if k in known_fields}

    unknown = set(raw) - known_fields
    if unknown:
        logger.warning("Ignoring unknown config keys: %s", ", ".join(sorted(unknown)))

    return WireNoseConfig(**filtered)
