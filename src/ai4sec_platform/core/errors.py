from __future__ import annotations


class AI4SecError(Exception):
    """Base platform error."""


class ConfigError(AI4SecError):
    """Configuration is missing or invalid."""


class PipelineError(AI4SecError):
    """Pipeline execution failed."""


class SourceError(AI4SecError):
    """Source connector failed."""
