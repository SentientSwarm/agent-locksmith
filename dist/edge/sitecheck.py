"""Value checks for site files: each returns the value or raises SiteError."""

from __future__ import annotations

import ipaddress
import re
from pathlib import PurePosixPath

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
MEMORY_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")
RESERVED_USERS = {"root", "nobody"}


class SiteError(ValueError):
    """The site file is invalid; the message names the offending value's place."""


def cidr(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise SiteError(f"{where}: ingress CIDR must be a string")
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except ValueError:
        raise SiteError(f"{where}: invalid CIDR {value!r}") from None


def state_root(value: object) -> str:
    text = as_text(value, "[site] state_root")
    path = PurePosixPath(text)
    if not PATH_RE.match(text) or ".." in path.parts or str(path) != text:
        raise SiteError(
            "[site] state_root must be a normalized absolute path other than /"
        )
    return text


def command(value: object, where: str) -> str:
    text = as_text(value, f"{where} command")
    if not text.startswith("/"):
        raise SiteError(f"{where}: command must start with an absolute executable path")
    return text


def env(value: object, where: str) -> dict[str, str]:
    table = as_table(value, f"{where} env")
    out: dict[str, str] = {}
    for key, val in table.items():
        if not ENV_NAME_RE.match(key):
            raise SiteError(
                f"{where}: env name {key!r} is not an upper-case identifier"
            )
        out[key] = as_text(val, f"{where} env {key}")
    return out


def user(value: object, where: str) -> str:
    if (
        not isinstance(value, str)
        or not USER_RE.match(value)
        or value in RESERVED_USERS
    ):
        raise SiteError(f"{where}: user must be a non-root system user name")
    return value


def name(value: object, where: str) -> str:
    if not isinstance(value, str) or not NAME_RE.match(value):
        raise SiteError(f"{where}: name must match {NAME_RE.pattern}")
    return value


def address(value: object, where: str) -> str:
    try:
        return str(ipaddress.ip_address(value if isinstance(value, str) else ""))
    except ValueError:
        raise SiteError(f"{where}: invalid address {value!r}") from None


def cpu(value: object, where: str) -> int:
    if type(value) is not int or value < 1:
        raise SiteError(f"{where}: cpu must be a positive integer")
    return value


def memory(value: object, where: str) -> str:
    if not isinstance(value, str) or not MEMORY_RE.match(value):
        raise SiteError(f"{where}: memory must look like 2GiB or 512MiB")
    return value


def optional(table: dict, key: str, where: str, check):
    return check(table[key], where) if key in table else None


def as_text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise SiteError(f"{where} must be a non-empty string")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SiteError(f"{where} contains a control character")
    return value


def as_bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise SiteError(f"{where} must be true or false")
    return value


def as_table(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise SiteError(f"{where} must be a table")
    return value


def as_list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise SiteError(f"{where} must be a list")
    return value


def keys(table: dict, allowed: set[str], where: str) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise SiteError(f"{where}: unknown key {extra[0]!r}")


def unique(names: list[str], message: str) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise SiteError(f"{message} {name!r}")
        seen.add(name)
