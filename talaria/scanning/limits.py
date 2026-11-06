"""Central scan resource-limit configuration."""
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ScanLimits:
    max_file_bytes: int = 2_000_000
    max_files: int = 20_000
    max_total_bytes: int = 250_000_000
    max_depth: int = 40

    def __post_init__(self) -> None:
        for name, value in (
            ("max_file_bytes", self.max_file_bytes),
            ("max_files", self.max_files),
            ("max_total_bytes", self.max_total_bytes),
            ("max_depth", self.max_depth),
        ):
            if value <= 0:
                raise ValueError(f"{name} must be positive")
