"""Site file schema for dist/edge: parse and validate, refusing anything unknown.

A site file is TOML kept in the site's private repo. Every value here can
reach a systemd unit or an nft table, so the validation is strict: unknown
keys, duplicate names, unsafe paths, bad CIDRs and control characters are
errors, never warnings.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import sitecheck as check
from sitecheck import SiteError

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
    "closed",
}
INGRESS_KEYS = {"port", "from"}


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
    # Ports rejected for every source, e.g. an admin listener reached only
    # from inside the container.
    closed: list[int] = field(default_factory=list)


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
    check.keys(doc, {"site", "instance"}, "top level")
    site = check.as_table(doc.get("site"), "[site]")
    check.keys(site, SITE_KEYS, "[site]")
    instances = [
        _instance(raw, i)
        for i, raw in enumerate(check.as_list(doc.get("instance"), "instance"))
    ]
    if not instances:
        raise SiteError("at least one [[instance]] is required")
    check.unique([i.name for i in instances], "duplicate instance name")
    check.unique(
        [c.name for i in instances for c in i.components], "duplicate component name"
    )
    return Site(
        state_root=check.state_root(site.get("state_root")),
        instances=instances,
        require_zfs=check.as_bool(site.get("require_zfs", True), "[site] require_zfs"),
    )


def _instance(raw: object, index: int) -> Instance:
    where = f"instance[{index}]"
    table = check.as_table(raw, where)
    check.keys(table, INSTANCE_KEYS, where)
    name = check.name(table.get("name"), f"{where} name")
    where = f"instance {name}"
    comps = [
        _component(c, where)
        for c in check.as_list(table.get("component"), f"{where} component")
    ]
    if not comps:
        raise SiteError(f"{where}: at least one [[instance.component]] is required")
    opened = {r.port for c in comps for r in c.ingress}
    both = sorted(opened & {p for c in comps for p in c.closed})
    if both:
        raise SiteError(f"{where}: port {both[0]} is both ingress and closed")
    return Instance(
        name=name,
        components=comps,
        address=check.optional(table, "address", where, check.address),
        cpu=check.optional(table, "cpu", where, check.cpu),
        memory=check.optional(table, "memory", where, check.memory),
    )


def _component(raw: object, parent: str) -> Component:
    table = check.as_table(raw, f"{parent} component")
    check.keys(table, COMPONENT_KEYS, f"{parent} component")
    name = check.name(table.get("name"), f"{parent} component name")
    where = f"component {name}"
    ingress = [
        _ingress(r, where)
        for r in check.as_list(table.get("ingress", []), f"{where} ingress")
    ]
    closed = _closed(table.get("closed", []), where)
    both = sorted({r.port for r in ingress} & set(closed))
    if both:
        raise SiteError(f"{where}: port {both[0]} is both ingress and closed")
    return Component(
        name=name,
        user=check.user(table.get("user"), where),
        command=check.command(table.get("command"), where),
        environment_file=check.as_bool(
            table.get("environment_file", False), f"{where} environment_file"
        ),
        jit=check.as_bool(table.get("jit", False), f"{where} jit"),
        env=check.env(table.get("env", {}), where),
        ingress=ingress,
        closed=closed,
    )


def _closed(raw: object, where: str) -> list[int]:
    ports = check.as_list(raw, f"{where} closed")
    for port in ports:
        if type(port) is not int or not 1 <= port <= 65535:
            raise SiteError(f"{where}: closed port must be an integer 1-65535")
    check.unique(ports, f"{where}: duplicate closed port")
    return list(ports)


def _ingress(raw: object, where: str) -> Ingress:
    table = check.as_table(raw, f"{where} ingress")
    check.keys(table, INGRESS_KEYS, f"{where} ingress")
    port = table.get("port")
    if type(port) is not int or not 1 <= port <= 65535:
        raise SiteError(f"{where}: ingress port must be an integer 1-65535")
    sources = check.as_list(table.get("from"), f"{where} ingress from")
    if not sources:
        raise SiteError(f"{where}: ingress from must list at least one CIDR")
    return Ingress(port=port, sources=[check.cidr(s, where) for s in sources])
