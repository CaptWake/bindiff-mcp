"""Time and concurrency limits, configurable through the environment."""

from __future__ import annotations

import math
import os
import time
from dataclasses import dataclass

from bindiff_mcp.errors import TimeLimitError


def _seconds_from_environment(name: str, default: float) -> float:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        seconds = float(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be a number") from error
    if not math.isfinite(seconds) or seconds <= 0:
        raise ValueError(f"{name} must be positive and finite")
    return seconds


def _count_from_environment(name: str, default: int) -> int:
    raw_value = os.environ.get(name)
    if raw_value is None or not raw_value.strip():
        return default
    try:
        count = int(raw_value)
    except ValueError as error:
        raise ValueError(f"{name} must be an integer") from error
    if count < 1:
        raise ValueError(f"{name} must be at least 1")
    return count


#: Spawning an idalib worker and loading the binary or its database.
OPEN_TIMEOUT_SECONDS = _seconds_from_environment("BINDIFF_MCP_OPEN_TIMEOUT", 600.0)

#: Initial autoanalysis of one binary; large images take IDA tens of minutes.
ANALYSIS_TIMEOUT_SECONDS = _seconds_from_environment(
    "BINDIFF_MCP_ANALYSIS_TIMEOUT", 7200.0
)

#: The BinExport step itself, once autoanalysis has finished.
EXPORT_TIMEOUT_SECONDS = _seconds_from_environment("BINDIFF_MCP_EXPORT_TIMEOUT", 1800.0)

#: Everything one job does once it starts; caps every stage above.
JOB_TIMEOUT_SECONDS = _seconds_from_environment("BINDIFF_MCP_JOB_TIMEOUT", 14400.0)

#: Jobs running at once. Each holds up to two idalib workers while it exports.
MAX_JOBS = _count_from_environment("BINDIFF_MCP_MAX_JOBS", 2)


@dataclass(frozen=True, slots=True)
class Deadline:
    """The time one job has left, shared by all of its stages."""

    seconds: float
    expires_at: float

    @classmethod
    def after(cls, seconds: float) -> Deadline:
        return cls(seconds, time.monotonic() + seconds)

    def remaining(self, stage: str) -> float:
        """Seconds left for ``stage``; infinite outside a job."""
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise TimeLimitError(
                f"the job reached its {self.seconds:g} s limit before {stage}"
            )
        return remaining

    def limit(self, stage: str, seconds: float) -> float:
        """Seconds ``stage`` may take: its own limit or the job's remaining time."""
        return min(seconds, self.remaining(stage))


#: Calls made outside a job are bounded only by each stage's own limit.
UNLIMITED = Deadline(math.inf, math.inf)
