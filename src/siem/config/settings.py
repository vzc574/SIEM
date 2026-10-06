"""Small dependency-free application settings object."""

from dataclasses import dataclass
import os
from pathlib import Path


@dataclass(frozen=True, slots=True)
class Settings:
    data_dir: Path
    log_level: str

    @classmethod
    def from_environment(cls) -> "Settings":
        data_dir = Path(os.getenv("SIEM_DATA_DIR", "./data")).expanduser()
        log_level = os.getenv("SIEM_LOG_LEVEL", "INFO").upper()
        allowed_levels = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        if log_level not in allowed_levels:
            raise ValueError(f"Unsupported SIEM_LOG_LEVEL: {log_level}")
        return cls(data_dir=data_dir, log_level=log_level)

