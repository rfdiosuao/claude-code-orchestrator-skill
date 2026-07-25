#!/usr/bin/env python3
"""Create, sign, and verify canonical release manifests without third-party code."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys

ALGORITHM = "rsa-pkcs1v15-sha256"
MANIFEST_NAME = "release-manifest.json"
SIGNATURE_NAME = "release-manifest.sig"
SHA256_DIGEST_INFO = bytes.fromhex("3031300d060960864801650304020105000420")


class ManifestError(ValueError):
    pass


def _reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def canonical_bytes(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _relative_files(root: Path) -> dict[str, Path]:
    excluded = {MANIFEST_NAME, SIGNATURE_NAME}
    files: dict[str, Path] = {}
    for path in root.rglob("*"):
        details = path.lstat()
        attributes = getattr(details, "st_file_attributes", 0)
        reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
        if stat.S_ISLNK(details.st_mode) or attributes & reparse_flag:
            raise ManifestError(f"release tree contains a link: {path}")
        if stat.S_ISDIR(details.st_mode):
            continue
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            raise ManifestError(
                f"release tree contains a non-regular or hard-linked file: {path}"
            )
        relative = path.relative_to(root).as_posix()
        if relative in excluded:
            continue
        files[relative] = path
    return files


def build_manifest(root: Path) -> dict[str, object]:
    files = _relative_files(root)
    entries = []
    for relative in sorted(files, key=lambda item: item.encode("utf-8")):
        content = files[relative].read_bytes()
        entries.append(
            {
                "length": len(content),
                "path": relative,
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        )
    return {"algorithm": "sha256", "files": entries, "schema_version": 1}


def _load_json(path: Path) -> tuple[object, bytes]:
    raw = path.read_bytes()
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"invalid JSON in {path}: {exc}") from exc
    return value, raw


def _load_key(path: Path, private: bool = False) -> tuple[int, int]:
    value, _ = _load_json(path)
    if not isinstance(value, dict) or value.get("algorithm") != ALGORITHM:
        raise ManifestError("unsupported or malformed key")
    member = "d" if private else "e"
    try:
        n = int(str(value["n"]), 16)
        exponent = int(str(value[member]), 16) if private else int(value[member])
    except (KeyError, TypeError, ValueError) as exc:
        raise ManifestError(f"malformed {'private' if private else 'public'} key") from exc
    if n.bit_length() < 2048 or exponent <= 1:
        raise ManifestError("RSA key must be at least 2048 bits")
    return n, exponent


def _encoded_digest(message: bytes, size: int) -> bytes:
    digest_info = SHA256_DIGEST_INFO + hashlib.sha256(message).digest()
    padding_length = size - len(digest_info) - 3
    if padding_length < 8:
        raise ManifestError("RSA key is too short")
    return b"\x00\x01" + b"\xff" * padding_length + b"\x00" + digest_info


def sign(manifest: Path, private_key: Path, signature: Path) -> None:
    value, raw = _load_json(manifest)
    if raw != canonical_bytes(value):
        raise ManifestError("manifest is not canonically encoded")
    n, d = _load_key(private_key, private=True)
    size = (n.bit_length() + 7) // 8
    encoded = _encoded_digest(raw, size)
    signed = pow(int.from_bytes(encoded, "big"), d, n).to_bytes(size, "big")
    signature.write_text(base64.b64encode(signed).decode("ascii") + "\n", encoding="ascii")


def verify(root: Path, manifest: Path, signature: Path, public_key: Path) -> None:
    value, raw = _load_json(manifest)
    if raw != canonical_bytes(value):
        raise ManifestError("manifest is not canonically encoded")
    if not isinstance(value, dict) or set(value) != {"algorithm", "files", "schema_version"}:
        raise ManifestError("manifest has missing or unexpected top-level fields")
    if value["algorithm"] != "sha256" or value["schema_version"] != 1:
        raise ManifestError("unsupported manifest algorithm or schema")
    entries = value["files"]
    if not isinstance(entries, list):
        raise ManifestError("manifest files must be an array")

    expected: dict[str, tuple[int, str]] = {}
    ordered_paths: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {"length", "path", "sha256"}:
            raise ManifestError("file entry has missing or unexpected fields")
        path = entry["path"]
        length = entry["length"]
        digest = entry["sha256"]
        if not isinstance(path, str) or not path or "\\" in path:
            raise ManifestError("manifest path is invalid")
        pure = PurePosixPath(path)
        if pure.is_absolute() or ".." in pure.parts or path != pure.as_posix():
            raise ManifestError(f"unsafe manifest path: {path}")
        if path in expected:
            raise ManifestError(f"duplicate manifest path: {path}")
        if not isinstance(length, int) or isinstance(length, bool) or length < 0:
            raise ManifestError(f"invalid length for {path}")
        if not isinstance(digest, str) or len(digest) != 64:
            raise ManifestError(f"invalid SHA-256 for {path}")
        try:
            int(digest, 16)
        except ValueError as exc:
            raise ManifestError(f"invalid SHA-256 for {path}") from exc
        expected[path] = (length, digest)
        ordered_paths.append(path)
    if ordered_paths != sorted(ordered_paths, key=lambda item: item.encode("utf-8")):
        raise ManifestError("manifest paths are not canonically sorted")

    actual = _relative_files(root)
    missing = sorted(set(expected) - set(actual))
    extra = sorted(set(actual) - set(expected))
    if missing or extra:
        raise ManifestError(f"artifact file set mismatch; missing={missing}, extra={extra}")
    for relative, (length, digest) in expected.items():
        content = actual[relative].read_bytes()
        if len(content) != length or hashlib.sha256(content).hexdigest() != digest:
            raise ManifestError(f"artifact file was modified: {relative}")

    n, e = _load_key(public_key)
    size = (n.bit_length() + 7) // 8
    try:
        signed = base64.b64decode(signature.read_text(encoding="ascii").strip(), validate=True)
    except (OSError, UnicodeError, ValueError) as exc:
        raise ManifestError("signature is missing or malformed") from exc
    if len(signed) != size:
        raise ManifestError("signature has the wrong length")
    recovered = pow(int.from_bytes(signed, "big"), e, n).to_bytes(size, "big")
    if recovered != _encoded_digest(raw, size):
        raise ManifestError("release signature verification failed")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("root", type=Path)
    create_parser.add_argument("--output", type=Path)
    sign_parser = subparsers.add_parser("sign")
    sign_parser.add_argument("manifest", type=Path)
    sign_parser.add_argument("--private-key", required=True, type=Path)
    sign_parser.add_argument("--signature", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("root", type=Path)
    verify_parser.add_argument("--manifest", type=Path)
    verify_parser.add_argument("--signature", type=Path)
    verify_parser.add_argument("--public-key", required=True, type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            output = args.output or args.root / MANIFEST_NAME
            output.write_bytes(canonical_bytes(build_manifest(args.root)))
        elif args.command == "sign":
            sign(args.manifest, args.private_key, args.signature or args.manifest.with_name(SIGNATURE_NAME))
        else:
            verify(
                args.root,
                args.manifest or args.root / MANIFEST_NAME,
                args.signature or args.root / SIGNATURE_NAME,
                args.public_key,
            )
    except (ManifestError, OSError) as exc:
        print(f"release manifest error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
