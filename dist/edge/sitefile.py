"""Site file schema for dist/edge: parse and validate, refusing anything unknown.

A site file is TOML kept in the site's private repo. Every value here can
reach a systemd unit or an nft table, so the validation is strict: unknown
keys, duplicate names, unsafe paths, bad CIDRs and control characters are
errors, never warnings.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

NAME_RE = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
ENV_NAME_RE = re.compile(r"^[A-Z_][A-Z0-9_]*$")
PATH_RE = re.compile(r"^/[A-Za-z0-9._/-]+$")
MEMORY_RE = re.compile(r"^[1-9][0-9]*(MiB|GiB)$")
RESERVED_USERS = {"root", "nobody"}

SITE_KEYS = {"state_root", "require_zfs"}
INSTANCE_KEYS = {"name", "address", "cpu", "memory", "component"}
COMPONENT_KEYS = {
    "name",
    "user",
    "command",
    "environment_file",
    "jit",
    "env",
    "ingress",
}
INGRESS_KEYS = {"port", "from"}


class SiteError(ValueError):
    """The site file is invalid; the message names the offending value's place."""


@dataclass(frozen=True)
class Ingress:
    port: int
    sources: list[str]


@dataclass(frozen=True)
class Component:
    name: str
    user: str
    command: str
    environment_file: bool = False
    jit: bool = False
    env: dict[str, str] = field(default_factory=dict)
    ingress: list[Ingress] = field(default_factory=list)


@dataclass(frozen=True)
class Instance:
    name: str
    components: list[Component]
    address: str | None = None
    cpu: int | None = None
    memory: str | None = None


@dataclass(frozen=True)
class Site:
    state_root: str
    instances: list[Instance]
    require_zfs: bool = True


def load(path: Path) -> Site:
    return parse(Path(path).read_text(encoding="utf-8"))


def parse(text: str) -> Site:
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError as err:
        raise SiteError(f"invalid TOML: {err}") from None
    _keys(doc, {"site", "instance"}, "top level")
    site = _table(doc.get("site"), "[site]")
    _keys(site, SITE_KEYS, "[site]")
    instances = [
        _instance(raw, i)
        for i, raw in enumerate(_list(doc.get("instance"), "instance"))
    ]
    if not instances:
        raise SiteError("at least one [[instance]] is required")
    _unique([i.name for i in instances], "duplicate instance name")
    _unique(
        [c.name for i in instances for c in i.components], "duplicate component name"
    )
    return Site(
        state_root=_state_root(site.get("state_root")),
        instances=instances,
        require_zfs=_bool(site.get("require_zfs", True), "[site] require_zfs"),
    )


def _instance(raw: object, index: int) -> Instance:
    where = f"instance[{index}]"
    table = _table(raw, where)
    _keys(table, INSTANCE_KEYS, where)
    name = _name(table.get("name"), f"{where} name")
    where = f"instance {name}"
    comps = [
        _component(c, where)
        for c in _list(table.get("component"), f"{where} component")
    ]
    if not comps:
        raise SiteError(f"{where}: at least one [[instance.component]] is required")
    return Instance(
        name=name,
        components=comps,
        address=_optional(table, "address", where, _address),
        cpu=_optional(table, "cpu", where, _cpu),
        memory=_optional(table, "memory", where, _memory),
    )


def _component(raw: object, parent: str) -> Component:
    table = _table(raw, f"{parent} component")
    _keys(table, COMPONENT_KEYS, f"{parent} component")
    name = _name(table.get("name"), f"{parent} component name")
    where = f"component {name}"
    return Component(
        name=name,
        user=_user(table.get("user"), where),
        command=_command(table.get("command"), where),
        environment_file=_bool(
            table.get("environment_file", False), f"{where} environment_file"
        ),
        jit=_bool(table.get("jit", False), f"{where} jit"),
        env=_env(table.get("env", {}), where),
        ingress=[
            _ingress(r, where)
            for r in _list(table.get("ingress", []), f"{where} ingress")
        ],
    )


def _ingress(raw: object, where: str) -> Ingress:
    table = _table(raw, f"{where} ingress")
    _keys(table, INGRESS_KEYS, f"{where} ingress")
    port = table.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise SiteError(f"{where}: ingress port must be an integer 1-65535")
    sources = _list(table.get("from"), f"{where} ingress from")
    if not sources:
        raise SiteError(f"{where}: ingress from must list at least one CIDR")
    return Ingress(port=port, sources=[_cidr(s, where) for s in sources])


def _cidr(value: object, where: str) -> str:
    if not isinstance(value, str):
        raise SiteError(f"{where}: ingress CIDR must be a string")
    try:
        return str(ipaddress.ip_network(value, strict=True))
    except ValueError:
        raise SiteError(f"{where}: invalid CIDR {value!r}") from None


def _state_root(value: object) -> str:
    text = _text(value, "[site] state_root")
    path = PurePosixPath(text)
    if not PATH_RE.match(text) or ".." in path.parts or str(path) != text:
        raise SiteError(
            "[site] state_root must be a normalized absolute path other than /"
        )
    return text


def _command(value: object, where: str) -> str:
    text = _text(value, f"{where} command")
    if not text.startswith("/"):
        raise SiteError(f"{where}: command must start with an absolute executable path")
    return text


def _env(value: object, where: str) -> dict[str, str]:
    table = _table(value, f"{where} env")
    out: dict[str, str] = {}
    for key, val in table.items():
        if not ENV_NAME_RE.match(key):
            raise SiteError(
                f"{where}: env name {key!r} is not an upper-case identifier"
            )
        out[key] = _text(val, f"{where} env {key}")
    return out


def _user(value: object, where: str) -> str:
    if (
        not isinstance(value, str)
        or not USER_RE.match(value)
        or value in RESERVED_USERS
    ):
        raise SiteError(f"{where}: user must be a non-root system user name")
    return value


def _name(value: object, where: str) -> str:
    if not isinstance(value, str) or not NAME_RE.match(value):
        raise SiteError(f"{where}: name must match {NAME_RE.pattern}")
    return value


def _address(value: object, where: str) -> str:
    try:
        return str(ipaddress.ip_address(value if isinstance(value, str) else ""))
    except ValueError:
        raise SiteError(f"{where}: invalid address {value!r}") from None


def _cpu(value: object, where: str) -> int:
    if type(value) is not int or value < 1:
        raise SiteError(f"{where}: cpu must be a positive integer")
    return value


def _memory(value: object, where: str) -> str:
    if not isinstance(value, str) or not MEMORY_RE.match(value):
        raise SiteError(f"{where}: memory must look like 2GiB or 512MiB")
    return value


def _optional(table: dict, key: str, where: str, check):
    return check(table[key], where) if key in table else None


def _text(value: object, where: str) -> str:
    if not isinstance(value, str) or not value:
        raise SiteError(f"{where} must be a non-empty string")
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise SiteError(f"{where} contains a control character")
    return value


def _bool(value: object, where: str) -> bool:
    if not isinstance(value, bool):
        raise SiteError(f"{where} must be true or false")
    return value


def _table(value: object, where: str) -> dict:
    if not isinstance(value, dict):
        raise SiteError(f"{where} must be a table")
    return value


def _list(value: object, where: str) -> list:
    if not isinstance(value, list):
        raise SiteError(f"{where} must be a list")
    return value


def _keys(table: dict, allowed: set[str], where: str) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise SiteError(f"{where}: unknown key {extra[0]!r}")


def _unique(names: list[str], message: str) -> None:
    seen: set[str] = set()
    for name in names:
        if name in seen:
            raise SiteError(f"{message} {name!r}")
        seen.add(name)
