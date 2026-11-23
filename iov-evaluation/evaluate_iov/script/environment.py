"""The CEL environment an IoV script runs in: the confidence constants, the
host facts exposed as identifiers, and the read-only built-in functions.

Any source whose data is unavailable yields null. Built-ins raise a CEL error
for bad arguments (wrong type, invalid regex, unknown algorithm) and when a
sandbox limit is exceeded; the latter is also recorded in `limit_exceeded` so
the result can say so. Regexes are searched unanchored. The IoV specification
calls for RE2; these are evaluated with Python's `re`, which accepts every RE2
construct an IoV realistically uses but also accepts a few that RE2 rejects.
"""

import logging
import re
from collections.abc import Callable

import celpy
from celpy import celtypes

from .. import releases
from ..host import base, configs, files, kernel, network, pkgdb, services, system
from ..logging_setup import LOGGER_NAME
from ..versions import COMPARATORS

log = logging.getLogger(LOGGER_NAME)

LEVELS = {"ABSENT": 0, "LOW": 1, "MEDIUM": 2, "DEFAULT": 2, "HIGH": 3}
CONSTANT_NAMES = ("uname", "os_release", "kernel_cmdline")

# CEL's own global functions, which a script may call besides the built-ins.
STANDARD_FUNCTIONS = {
    "size", "int", "uint", "double", "string", "bytes", "bool", "dyn", "type", "duration",
    "timestamp", "has", "matches", "contains", "startsWith", "endsWith",
}

# Set when a built-in exceeds a sandbox limit during the current script run.
limit_exceeded: str | None = None


def _compare_with_null(cls) -> None:
    """Give a cel-python type CEL's heterogeneous equality with null.

    CEL defines `[1] != null` and `1 == null` as plain booleans, and the IoV
    specification relies on it for the `x != null && ...` and `x == null`
    guards. cel-python 0.5 raises "no such overload" for numbers, lists and
    maps (strings, bools and bytes already work), so every guard on an int-,
    list- or map-returning built-in, like version_compare(), would be a
    runtime error. Patching __eq__ covers `null == x` too, since Python falls
    back to the reflected comparison.
    """
    eq, ne = cls.__eq__, cls.__ne__
    cls.__eq__ = lambda self, other: False if other is None else eq(self, other)
    cls.__ne__ = lambda self, other: True if other is None else ne(self, other)


for _cls in (celtypes.IntType, celtypes.UintType, celtypes.DoubleType,
             celtypes.TimestampType, celtypes.DurationType,
             celtypes.ListType, celtypes.MapType):
    _compare_with_null(_cls)


def _compact_logical(original):
    """Make a cel-python || or && report a non-boolean operand by type only.

    cel-python 0.5 raises a TypeError quoting the repr of both operands when
    neither is a bool. exists() and all() fold their elements with || and &&,
    so after the first error one operand is the previous error, whose repr is
    quoted again: the message doubles with every element. A script like
    `procs.exists(p, some_string)` on a host with a hundred processes then
    exhausts the memory of the host.
    """
    def operator(x, y):
        if not isinstance(x, celtypes.BoolType) and not isinstance(y, celtypes.BoolType):
            raise TypeError(f"no such overload for {type(x).__name__} and {type(y).__name__}")
        return original(x, y)
    operator.__name__ = original.__name__
    return operator


# The macros look the operators up in celtypes at call time; the operator
# table in evaluation holds its own references.
for _name, _symbol in (("logical_or", "_||_"), ("logical_and", "_&&_")):
    _patched = _compact_logical(getattr(celtypes, _name))
    setattr(celtypes, _name, _patched)
    celpy.evaluation.base_functions[_symbol] = _patched


# ── Conversions ───────────────────────────────────────────────────────────────

def to_cel(value):
    """Convert a Python value from a host source into CEL values."""
    if value is None:
        return None
    if isinstance(value, bool):
        return celtypes.BoolType(value)
    if isinstance(value, int):
        return celtypes.IntType(value)
    if isinstance(value, float):
        return celtypes.DoubleType(value)
    if isinstance(value, str):
        return celtypes.StringType(value)
    if isinstance(value, dict):
        return celtypes.MapType({celtypes.StringType(str(k)): to_cel(v) for k, v in value.items()})
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value) if isinstance(value, (set, frozenset)) else value
        return celtypes.ListType([to_cel(v) for v in items])
    return celtypes.StringType(str(value))


class ArgumentError(ValueError):
    """A built-in was called with an argument of the wrong type."""
    pass


def as_string(value, where):
    if isinstance(value, str):
        return str(value)
    raise ArgumentError(f"{where} must be a string, got {_type_name(value)}")


def as_optional_string(value, where):
    return None if value is None else as_string(value, where)


def as_int(value, where):
    if isinstance(value, int) and not isinstance(value, bool):
        return int(value)
    raise ArgumentError(f"{where} must be an int, got {_type_name(value)}")


def as_string_list(value, where):
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return [str(v) for v in value]
    raise ArgumentError(f"{where} must be a list of strings")


def _type_name(value) -> str:
    return "null" if value is None else type(value).__name__


def builtin(name: str, func: Callable, *parameters: tuple[str, Callable]) -> Callable:
    """Wrap a host function as a CEL function with argument checking."""
    def wrapper(*args):
        global limit_exceeded
        if len(args) != len(parameters):
            raise celpy.CELEvalError(
                f"{name}() takes {len(parameters)} argument(s), got {len(args)}")
        try:
            base.check_deadline()
            converted = [convert(arg, f"{name}(): {param}")
                         for arg, (param, convert) in zip(args, parameters, strict=True)]
            return to_cel(func(*converted))
        except base.SandboxLimit as exc:
            limit_exceeded = str(exc)
            raise celpy.CELEvalError(str(exc)) from exc
        except (ValueError, re.error, TypeError) as exc:
            raise celpy.CELEvalError(f"{name}(): {exc}") from exc
    wrapper.__name__ = name
    return wrapper


# ── Built-ins that need more than a direct call ───────────────────────────────

def _limited(func: Callable, what: str) -> Callable:
    def call(*args):
        value = func(*args)
        return value if value is None else base.limit_entries(value, what)
    return call


def _installed_packages(name_regex: str) -> list[dict] | None:
    pattern = re.compile(name_regex)
    current = pkgdb.inventory()
    if current is None:
        return None
    return base.limit_entries([
        {"name": p.name, "version": p.version, "arch": p.arch, "source": p.source,
         "manager": p.manager}
        for p in current.packages if pattern.search(p.name)
    ], "installed_packages()")


def _version_compare(a: str | None, b: str | None, scheme: str) -> int | None:
    compare = COMPARATORS.get(scheme)
    if compare is None:
        raise ArgumentError(f"unknown version scheme {scheme!r}")
    if a is None or b is None:
        return None
    try:
        return compare(a, b)
    except ValueError:
        return None


FUNCTIONS = {
    name: builtin(name, func, *params) for name, func, params in [
        ("get_processes", _limited(network.processes, "get_processes()"), ()),
        ("process_environ", network.process_environ, (("pid", as_int),)),
        ("listening_sockets", network.listening_sockets, ()),
        ("service_exposed", services.service_exposed, (("names", as_string_list),)),
        ("interfaces", network.interfaces, ()),
        ("routes", _limited(network.routes, "routes()"), ()),
        ("kernel_config", kernel.kernel_config, (("name", as_string),)),
        ("kernel_modules", kernel.kernel_modules, ()),
        ("kernel_feature", kernel.kernel_feature,
         (("config_opt", as_string), ("module", as_optional_string))),
        ("sysctl", kernel.sysctl, (("name", as_string),)),
        ("userns_unprivileged_allowed", kernel.userns_unprivileged_allowed, ()),
        ("cpu", system.cpu, ()),
        ("pci_devices", system.pci_devices, ()),
        ("mounts", _limited(system.mounts, "mounts()"), ()),
        ("systemd_unit", services.systemd_unit, (("name", as_string),)),
        ("systemd_units", services.systemd_units, (("name_regex", as_string),)),
        ("systemd_unit_property", services.systemd_unit_property,
         (("name", as_string), ("property", as_string))),
        ("selinux", system.selinux, ()),
        ("apparmor", system.apparmor, ()),
        ("file_info", files.file_info, (("path", as_string),)),
        ("list_dir", files.list_dir, (("path", as_string),)),
        ("find_files", files.find_files,
         (("root", as_string), ("name_regex", as_string), ("max_depth", as_int))),
        ("glob", files.glob, (("pattern", as_string),)),
        ("file_hash", files.file_hash, (("path", as_string), ("algorithm", as_string))),
        ("read_file", files.read_file, (("path", as_string),)),
        ("file_matches", files.file_matches, (("paths", as_string_list), ("regex", as_string))),
        ("find_all", files.find_all, (("text", as_optional_string), ("regex", as_string))),
        ("directive_values", configs.directive_values,
         (("paths", as_string_list), ("keyword", as_string), ("precedence", as_string))),
        ("ini_values", configs.ini_values,
         (("path", as_string), ("section", as_string), ("key", as_string))),
        ("xml_query", configs.xml_query, (("path", as_string), ("xpath", as_string))),
        ("json_query", configs.json_query, (("path", as_string), ("jsonpath", as_string))),
        ("yaml_query", configs.yaml_query, (("path", as_string), ("jsonpath", as_string))),
        ("installed_packages", _installed_packages, (("name_regex", as_string),)),
        ("package_owner", pkgdb.package_owner, (("path", as_string),)),
        ("package_verify", _limited(pkgdb.package_verify, "package_verify()"),
         (("name", as_string),)),
        ("version_compare", _version_compare,
         (("a", as_optional_string), ("b", as_optional_string), ("scheme", as_string))),
        ("users", _limited(system.users, "users()"), ()),
        ("groups", _limited(system.groups, "groups()"), ()),
        ("shadow", _limited(system.shadow, "shadow()"), ()),
    ]
}


def constants() -> dict:
    """The identifiers every script starts with."""
    values = {name: celtypes.IntType(level) for name, level in LEVELS.items()}
    values["uname"] = to_cel(kernel.uname())
    values["os_release"] = to_cel(releases.os_release())
    values["kernel_cmdline"] = to_cel(kernel.kernel_cmdline())
    return values


# Names a 'let' must not rebind: the script keywords, CEL's reserved words, and
# the built-in functions and constants.
RESERVED = (
    {"let", "return", "if", "elif", "else", "end"}
    | {
        "false", "true", "null", "in", "as", "break", "const", "continue", "for",
        "function", "import", "loop", "package", "namespace", "var", "void", "while",
    }
    | set(FUNCTIONS)
    | set(LEVELS)
    | set(CONSTANT_NAMES)
)
