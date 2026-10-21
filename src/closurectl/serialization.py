"""Deterministic JSON I/O and secret-field rejection."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
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
MAX_JSON_INTEGER = (1 << 63) - 1


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


def _reject_non_finite_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value: {value}")


def _parse_bounded_integer(value: str) -> int:
    parsed = int(value)
    if not -MAX_JSON_INTEGER - 1 <= parsed <= MAX_JSON_INTEGER:
        raise ValueError("JSON integer exceeds the signed 64-bit safety limit")
    return parsed


def parse_json_text(value: str, *, source: str = "JSON") -> Any:
    try:
        return json.loads(
            value,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_non_finite_constant,
            parse_int=_parse_bounded_integer,
        )
    except json.JSONDecodeError as exc:
        raise ValidationError(
            f"invalid JSON in {source} at line {exc.lineno}, column {exc.colno}"
        ) from exc
    except (ValueError, RecursionError) as exc:
        raise ValidationError(f"invalid JSON value in {source}") from exc


def read_json(path: str | Path, *, reject_secrets: bool = True) -> Any:
    try:
        with Path(path).open("r", encoding="utf-8") as handle:
            value = parse_json_text(handle.read(), source=str(path))
    except FileNotFoundError as exc:
        raise ValidationError(f"file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise ValidationError(f"JSON file is not valid UTF-8: {path}") from exc
    if reject_secrets:
        reject_secret_fields(value)
    return value


def atomic_write_bytes(
    path: str | Path,
    content: bytes,
    *,
    overwrite: bool = True,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if not overwrite:
        try:
            descriptor = os.open(
                destination,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError as exc:
            raise ValidationError(f"refusing to overwrite existing file: {destination}") from exc
        try:
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
        finally:
            if descriptor != -1:
                os.close(descriptor)
        return

    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if descriptor != -1:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def write_json(
    path: str | Path,
    value: Any,
    *,
    reject_secrets: bool = True,
    overwrite: bool = True,
) -> None:
    if reject_secrets:
        reject_secret_fields(value)
    rendered = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    atomic_write_bytes(path, rendered.encode("utf-8"), overwrite=overwrite)
