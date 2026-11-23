"""The running kernel: identity, command line, build configuration, modules and
sysctls, and the standard-library helpers built on them."""

import gzip
import logging
import os
import re
from pathlib import Path

from ..logging_setup import LOGGER_NAME
from .base import cached, read_text

log = logging.getLogger(LOGGER_NAME)

MODPROBE_DIRS = ("/etc/modprobe.d", "/run/modprobe.d", "/usr/local/lib/modprobe.d",
                 "/usr/lib/modprobe.d", "/lib/modprobe.d")
# 'install <module> <command>' with one of these commands prevents loading.
DISABLING_COMMANDS = {"/bin/false", "/bin/true", "/usr/bin/false", "/usr/bin/true",
                      "false", "true", "/dev/null"}


@cached
def uname() -> dict[str, str]:
    """The running kernel's uname fields."""
    info = os.uname()
    return {"sysname": info.sysname, "nodename": info.nodename, "release": info.release,
            "version": info.version, "machine": info.machine}


def kernel_release() -> str:
    """The running kernel's release, as `uname -r` prints it."""
    return uname()["release"]


@cached
def kernel_cmdline() -> dict[str, str] | None:
    """/proc/cmdline as a map; flags map to "", repeated keys keep the last value."""
    text = read_text("/proc/cmdline")
    if text is None:
        return None
    params: dict[str, str] = {}
    # A token is a run of non-space characters, where double-quoted parts may
    # contain spaces: key="a b" is one token.
    for token in re.findall(r'(?:[^\s"]|"[^"]*")+', text):
        key, sep, value = token.partition("=")
        params[key.replace('"', "")] = value.replace('"', "") if sep else ""
    return params


# ── Build configuration ───────────────────────────────────────────────────────

def _read_config_text() -> str | None:
    release = kernel_release()
    for path in (f"/boot/config-{release}", f"/lib/modules/{release}/config",
                 f"/usr/lib/modules/{release}/config"):
        text = read_text(path, limit=None)
        if text is not None:
            log.debug("loaded kernel config from %s", path)
            return text
    try:
        with gzip.open("/proc/config.gz", "rt", errors="replace") as handle:
            return handle.read()
    except Exception as exc:
        log.debug("could not read /proc/config.gz: %s", exc)
    log.warning("kernel config unavailable (no /boot/config-*, no /proc/config.gz)")
    return None


@cached
def kernel_config_map() -> dict[str, str] | None:
    """The running kernel's build configuration as {CONFIG_X: value}, from
    /boot/config-*, /lib/modules/*/config or /proc/config.gz. None if absent.
    """
    text = _read_config_text()
    if text is None:
        return None
    options: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        match = re.match(r"^# (CONFIG_[A-Za-z0-9_]+) is not set$", line)
        if match:
            options[match.group(1)] = "n"
            continue
        name, sep, value = line.partition("=")
        if sep and name.startswith("CONFIG_"):
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            options[name] = value
    return options


def kernel_config(name: str) -> str | None:
    """"y", "m", the value, or "n" if not set; None if no configuration exists."""
    options = kernel_config_map()
    if options is None:
        return None
    return options.get(name, "n")


# ── Modules ───────────────────────────────────────────────────────────────────

def _normalize(module: str) -> str:
    return module.replace("-", "_")


@cached
def kernel_modules() -> list[dict] | None:
    """The loaded modules from /proc/modules."""
    text = read_text("/proc/modules", limit=None)
    if text is None:
        return None
    modules = []
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 5:
            continue
        used_by = [m for m in fields[3].split(",") if m and m != "-"]
        modules.append({
            "name": fields[0],
            "size": int(fields[1]) if fields[1].isdigit() else -1,
            "refcount": int(fields[2]) if fields[2].lstrip("-").isdigit() else -1,
            "used_by": used_by,
            "state": fields[4],
        })
    return modules


def _modules_dir() -> Path | None:
    release = kernel_release()
    for base in ("/lib/modules", "/usr/lib/modules"):
        path = Path(base) / release
        if path.is_dir():
            return path
    return None


def _module_names_in(filename: str) -> set[str] | None:
    """Module names listed in modules.builtin / modules.dep, normalized."""
    directory = _modules_dir()
    if directory is None:
        return None
    text = read_text(str(directory / filename), limit=None)
    if text is None:
        return None
    names = set()
    for line in text.splitlines():
        path = line.split(":", 1)[0].strip()
        if path:
            base = path.rsplit("/", 1)[-1]
            names.add(_normalize(base.split(".ko", 1)[0]))
    return names


@cached
def builtin_modules() -> set[str] | None:
    """Names of the modules built into the running kernel (modules.builtin)."""
    return _module_names_in("modules.builtin")


@cached
def module_files() -> set[str] | None:
    """Names of the loadable modules installed for the running kernel (modules.dep)."""
    return _module_names_in("modules.dep")


@cached
def modprobe_policy() -> tuple[dict[str, str], set[str]]:
    """({module: install command}, {blacklisted modules}) from modprobe.d.

    A file name in an earlier directory shadows the same name in later ones.
    """
    files: dict[str, Path] = {}
    for directory in MODPROBE_DIRS:
        try:
            for path in sorted(Path(directory).glob("*.conf")):
                files.setdefault(path.name, path)
        except OSError:
            continue
    paths = [files[name] for name in sorted(files)]
    if Path("/etc/modprobe.conf").is_file():
        paths.append(Path("/etc/modprobe.conf"))

    installs: dict[str, str] = {}
    blacklist: set[str] = set()
    for path in paths:
        text = read_text(str(path), limit=None) or ""
        for line in text.replace("\\\n", " ").splitlines():
            fields = line.split("#", 1)[0].split()
            if len(fields) >= 3 and fields[0] == "install":
                installs[_normalize(fields[1])] = " ".join(fields[2:])
            elif len(fields) >= 2 and fields[0] == "blacklist":
                blacklist.add(_normalize(fields[1]))
    return installs, blacklist


# ── sysctls ───────────────────────────────────────────────────────────────────

_SYSCTL_NAME_RE = re.compile(r"^[A-Za-z0-9_\-]+([./][A-Za-z0-9_\-]+)*$")


@cached
def sysctl(name: str) -> str | None:
    """A sysctl's value with whitespace collapsed, or None if it does not exist."""
    if not _SYSCTL_NAME_RE.match(name):
        return None
    text = read_text("/proc/sys/" + name.replace(".", "/"))
    if text is None:
        return None
    return " ".join(text.split())


# ── Standard-library helpers ──────────────────────────────────────────────────

def kernel_feature(config_opt: str, module: str | None) -> str | None:
    """How a kernel feature is available; see the IoV specification for the
    decision order."""
    config = kernel_config(config_opt)
    name = _normalize(module) if module else None

    if name is not None:
        loaded = kernel_modules()
        if loaded is not None and any(_normalize(m["name"]) == name for m in loaded):
            return "loaded"

    builtin = builtin_modules()
    if config == "y" or (name is not None and builtin is not None and name in builtin):
        return "builtin"

    files = module_files()
    has_file = None if name is None else (None if files is None else name in files)
    if config == "m" or has_file:
        installs, blacklist = modprobe_policy()
        command = installs.get(name or "", "").split()
        disabled_by_install = bool(command) and command[0] in DISABLING_COMMANDS
        if sysctl("kernel.modules_disabled") == "1" or disabled_by_install:
            return "disabled"
        if name in blacklist:
            return "blacklisted"
        return "module"

    if config == "n" and (name is None or has_file is False):
        return "absent"
    return None


def userns_unprivileged_allowed() -> bool | None:
    """Whether unprivileged users can create user namespaces with capabilities."""
    if kernel_config("CONFIG_USER_NS") == "n":
        return False
    if sysctl("kernel.unprivileged_userns_clone") == "0":
        return False
    max_namespaces = sysctl("user.max_user_namespaces")
    if max_namespaces == "0":
        return False
    if sysctl("kernel.apparmor_restrict_unprivileged_userns") == "1":
        return False
    return True if max_namespaces is not None else None
