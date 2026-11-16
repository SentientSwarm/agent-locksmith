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
# Accounts a stock Ubuntu or Debian image already has: sysusers would not
# create them, so the service would run as an existing system account.
RESERVED_USERS = {
    "root",
    "nobody",
    "daemon",
    "bin",
    "sys",
    "sync",
    "games",
    "man",
    "lp",
    "mail",
    "news",
    "uucp",
    "proxy",
    "www-data",
    "backup",
    "list",
    "irc",
    "gnats",
    "messagebus",
    "sshd",
    "syslog",
    "polkitd",
    "uuidd",
    "tcpdump",
    "landscape",
    "lxd",
    "dnsmasq",
    "ubuntu",
    "_apt",
    "tss",
    "usbmux",
}
# Unit names render.py owns: locksmith-edge-input.service and each
# component's locksmith-edge-<component>-guard.service.
# custody and environment are the guard's directories in the state root.
RESERVED_NAMES = {"input", "custody", "environment"}
# The sandbox hides or replaces these (ProtectHome, PrivateTmp, /run, API fs).
HIDDEN_ROOTS = ("/home", "/root", "/tmp", "/var/tmp", "/run", "/proc", "/sys", "/dev")
RESERVED_SUFFIX = "-guard"


class SiteError(ValueError):
    """The site file is invalid; the message names the offending value's place."""


def cidr(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise SiteError(f"{where}: ingress CIDR must be a string")
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError:
        raise SiteError(f"{where}: invalid CIDR {value!r}") from None
    if getattr(network.network_address, "scope_id", None) is not None:
        raise SiteError(f"{where}: invalid CIDR {value!r} (no IPv6 scope IDs)")
    return str(network)


def state_root(value: object) -> str:
    text = as_text(value, "[site] state_root")
    path = PurePosixPath(text)
    hidden = any(text == r or text.startswith(r + "/") for r in HIDDEN_ROOTS)
    if (
        not PATH_RE.fullmatch(text)
        or ".." in path.parts
        or str(path) != text
        or text.startswith("//")
        or hidden
    ):
        raise SiteError(
            "[site] state_root must be a normalized absolute path other than /"
        )
    return text


def command(value: object, where: str) -> str:
    text = as_text(value, f"{where} command")
    if not text.startswith("/"):
        raise SiteError(f"{where}: command must start with an absolute executable path")
    if text.endswith("\\"):
        # systemd would continue the line into the next directive.
        raise SiteError(f"{where}: command must not end with a backslash")
    if ";" in text.split():
        # systemd reads a lone ; as a second command.
        raise SiteError(f"{where}: command must not contain a lone ;")
    return text


def env(value: object, where: str) -> dict[str, str]:
    table = as_table(value, f"{where} env")
    out: dict[str, str] = {}
    for key, val in table.items():
        if not ENV_NAME_RE.fullmatch(key):
            raise SiteError(
                f"{where}: env name {key!r} is not an upper-case identifier"
            )
        out[key] = as_text(val, f"{where} env {key}")
    return out


def user(value: object, where: str) -> str:
    if (
        not isinstance(value, str)
        or not USER_RE.fullmatch(value)
        or value in RESERVED_USERS
        or value.startswith("systemd-")
    ):
        raise SiteError(f"{where}: user must be a non-root system user name")
    return value


def name(value: object, where: str) -> str:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise SiteError(f"{where}: name must match {NAME_RE.pattern}")
    if value in RESERVED_NAMES or value.endswith(RESERVED_SUFFIX):
        raise SiteError(f"{where}: name {value!r} is reserved for units render.py owns")
    return value


def address(value: object, where: str) -> str:
    try:
        parsed = ipaddress.ip_address(value if isinstance(value, str) else "")
    except ValueError:
        raise SiteError(f"{where}: invalid address {value!r}") from None
    if getattr(parsed, "scope_id", None) is not None:
        raise SiteError(f"{where}: invalid address {value!r} (no IPv6 scope IDs)")
    return str(parsed)


def cpu(value: object, where: str) -> int:
    if type(value) is not int or value < 1:
        raise SiteError(f"{where}: cpu must be a positive integer")
    return value


def memory(value: object, where: str) -> str:
    if not isinstance(value, str) or not MEMORY_RE.fullmatch(value):
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
