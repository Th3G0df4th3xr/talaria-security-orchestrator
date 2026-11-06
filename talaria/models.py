from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RepositoryInput(StrictModel):
    path: str = Field(min_length=1)


class ScanInput(StrictModel):
    repository_path: str = Field(min_length=1)


class Severity(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"
