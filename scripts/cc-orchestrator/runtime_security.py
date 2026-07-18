from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


@dataclass(frozen=True)
class RuntimeSecurityError(RuntimeError):
    code: str
    message: str
    safe_details: Mapping[str, Any]
    suggested_action: str

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)
        object.__setattr__(
            self, "safe_details", MappingProxyType(dict(self.safe_details))
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "safe_details": dict(self.safe_details),
            "suggested_action": self.suggested_action,
        }


def canonical_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve(strict=True)
