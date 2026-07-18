from __future__ import annotations

from collections.abc import Mapping as MappingABC
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


def _freeze(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return MappingProxyType(
            {key: _freeze(item) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, (set, frozenset)):
        frozen_values = (_freeze(item) for item in value)
        return tuple(sorted(frozen_values, key=repr))
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise TypeError("safe_details must contain JSON-compatible values")


def _thaw(value: Any) -> Any:
    if isinstance(value, MappingABC):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw(item) for item in value]
    return value


@dataclass(frozen=True)
class RuntimeSecurityError(RuntimeError):
    code: str
    message: str
    safe_details: Mapping[str, Any]
    suggested_action: str

    def __post_init__(self) -> None:
        RuntimeError.__init__(self, self.message)
        object.__setattr__(self, "safe_details", _freeze(self.safe_details))

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "message": self.message,
            "safe_details": _thaw(self.safe_details),
            "suggested_action": self.suggested_action,
        }


def canonical_path(value: str | Path) -> Path:
    return Path(value).expanduser().resolve(strict=True)
