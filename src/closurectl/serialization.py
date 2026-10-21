"""Deterministic JSON I/O and secret-field rejection."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .errors import ValidationError

FORBIDDEN_SECRET_FIELDS = {
    "access_token",
    "api_key",
    "auth_token",
    "authorization",
    "bearer",
    "bearer_token",
    "client_secret",
    "cookie",
    "credential_value",
    "password",
    "private_key",
    "private_key_pem",
    "refresh_token",
    "secret",
    "session_cookie",
    "signing_key",
    "token",
}


def canonical_json(value: Any) -> bytes:
    """Return stable UTF-8 JSON bytes suitable for hashing and signing."""
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def digest_json(value: Any) -> str:
    return hashlib.sha256(canonical_json(value)).hexdigest()


def _normalized_field_name(value: Any) -> str:
    with_word_boundaries = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(value))
    return re.sub(r"[^A-Za-z0-9]+", "_", with_word_boundaries).strip("_").lower()


def reject_secret_fields(value: Any, path: str = "$") -> None:
    """Reject plaintext-secret-shaped fields before they reach an artifact."""
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = _normalized_field_name(key)
            if normalized in FORBIDDEN_SECRET_FIELDS:
                raise ValidationError(
                    f"{path}.{key} is forbidden: artifacts must contain handles, "
                    "never credential material"
                )
            reject_secret_fields(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            reject_secret_fields(child, f"{path}[{index}]")


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValidationError(f"duplicate JSON object key: {key!r}")
        result[key] = value
    return result


def read_json(path: str | Path, *, reject_secrets: bool = True) -> Any:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            value = json.load(handle, object_pairs_hook=_object_without_duplicate_keys)
    except FileNotFoundError as exc:
        raise ValidationError(f"file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}"
        ) from exc
    if reject_secrets:
        reject_secret_fields(value)
    return value


def write_json(path: str | Path, value: Any, *, reject_secrets: bool = True) -> None:
    if reject_secrets:
        reject_secret_fields(value)
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    temporary.replace(destination)
