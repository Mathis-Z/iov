"""Files and directories: metadata, listings, hashes and content matching."""

import contextlib
import glob as globmodule
import grp
import hashlib
import logging
import os
import pwd
import re
import stat

from ..logging_setup import LOGGER_NAME
from .base import MAX_ENTRIES, SandboxLimit, check_deadline, limit_entries, read_text

log = logging.getLogger(LOGGER_NAME)

HASH_ALGORITHMS = ("md5", "sha1", "sha256", "sha512")
MAX_FIND_DEPTH = 10
PSEUDO_FILESYSTEMS = ("/proc", "/sys", "/dev")

_FILE_INFO_FIELDS = ("type", "mode", "permissions", "uid", "gid", "user", "group", "size",
                     "mtime", "symlink_target", "has_extended_acl", "selinux_context")


def _file_type(mode: int) -> str:
    for test, name in ((stat.S_ISREG, "file"), (stat.S_ISDIR, "directory"),
                       (stat.S_ISLNK, "symlink"), (stat.S_ISCHR, "char"),
                       (stat.S_ISBLK, "block"), (stat.S_ISFIFO, "fifo"),
                       (stat.S_ISSOCK, "socket")):
        if test(mode):
            return name
    return ""


def _xattr(path: str, name: str) -> bytes | None:
    try:
        return os.getxattr(path, name, follow_symlinks=False)
    except OSError:
        return None


def _name(lookup, key: int) -> str:
    try:
        return lookup(key)[0]
    except (KeyError, OverflowError):
        return ""


def require_absolute(path: str) -> None:
    """Reject relative paths, whose meaning depends on the daemon's working directory."""
    if not path.startswith("/"):
        raise ValueError(f"path must be absolute: {path!r}")


def file_info(path: str) -> dict | None:
    """lstat() metadata of a path. A missing path yields exists=false with null
    fields; None means the path could not be examined.
    """
    require_absolute(path)
    try:
        st = os.lstat(path)
    except (FileNotFoundError, NotADirectoryError):
        return {"path": path, "exists": False, **dict.fromkeys(_FILE_INFO_FIELDS)}
    except OSError as exc:
        log.debug("cannot stat %s: %s", path, exc)
        return None

    symlink_target = ""
    if stat.S_ISLNK(st.st_mode):
        with contextlib.suppress(OSError):
            symlink_target = os.readlink(path)
    context = _xattr(path, "security.selinux")
    return {
        "path": path,
        "exists": True,
        "type": _file_type(st.st_mode),
        "mode": f"{stat.S_IMODE(st.st_mode):04o}",
        "permissions": stat.filemode(st.st_mode)[1:],
        "uid": st.st_uid,
        "gid": st.st_gid,
        "user": _name(pwd.getpwuid, st.st_uid),
        "group": _name(grp.getgrgid, st.st_gid),
        "size": st.st_size,
        "mtime": int(st.st_mtime),
        "symlink_target": symlink_target,
        "has_extended_acl": _xattr(path, "system.posix_acl_access") is not None,
        "selinux_context": context.decode(errors="replace").rstrip("\x00") if context else "",
    }


def _entry(path: str, name: str) -> dict:
    info = file_info(path) or {"path": path, "exists": None, **dict.fromkeys(_FILE_INFO_FIELDS)}
    return {"name": name, **info}


def list_dir(path: str) -> list[dict] | None:
    """file_info() of every entry of a directory, by name. None if unreadable."""
    require_absolute(path)
    try:
        names = sorted(os.listdir(path))
    except OSError:
        return None
    limit_entries(names, "list_dir()")
    return [_entry(os.path.join(path, name), name) for name in names]


def find_files(root: str, name_regex: str, max_depth: int) -> list[dict] | None:
    """Entries below `root` whose name matches the regex, breadth-first up to
    `max_depth` levels, without descending into /proc, /sys or /dev or
    following symlinks. None if `root` is not a readable directory.
    """
    require_absolute(root)
    if not 1 <= max_depth <= MAX_FIND_DEPTH:
        raise ValueError(f"max_depth must be between 1 and {MAX_FIND_DEPTH}, got {max_depth}")
    pattern = re.compile(name_regex)
    if not os.path.isdir(root):
        return None

    found: list[dict] = []
    level = [root]
    for _ in range(max_depth):
        next_level = []
        for directory in level:
            check_deadline()
            try:
                entries = sorted(os.scandir(directory), key=lambda e: e.name)
            except OSError:
                if directory == root:
                    return None
                continue
            for entry in entries:
                if pattern.search(entry.name):
                    found.append(_entry(entry.path, entry.name))
                    if len(found) > MAX_ENTRIES:
                        raise SandboxLimit(f"find_files() matched more than {MAX_ENTRIES} entries")
                try:
                    is_dir = entry.is_dir(follow_symlinks=False)
                except OSError:
                    is_dir = False
                if is_dir and not entry.path.startswith(PSEUDO_FILESYSTEMS):
                    next_level.append(entry.path)
        level = next_level
    return sorted(found, key=lambda e: e["path"])


def glob(pattern: str) -> list[str]:
    """The paths a shell glob pattern matches, sorted."""
    require_absolute(pattern)
    return limit_entries(sorted(globmodule.glob(pattern)), "glob()")


def file_hash(path: str, algorithm: str) -> str | None:
    """The hex digest of a regular file, or None if it is not one or unreadable."""
    require_absolute(path)
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"unknown hash algorithm {algorithm!r}")
    try:
        if not stat.S_ISREG(os.stat(path).st_mode):
            return None
        digest = hashlib.new(algorithm)
        with open(path, "rb") as handle:
            while chunk := handle.read(1024 * 1024):
                check_deadline()
                digest.update(chunk)
    except OSError:
        return None
    return digest.hexdigest()


def read_file(path: str) -> str | None:
    """The first MAX_FILE_BYTES of a file as text, or None if unreadable."""
    require_absolute(path)
    return read_text(path)


def expand_paths(paths: list[str]) -> list[str]:
    """Expand glob patterns (sorted) and keep plain paths; drop duplicates."""
    expanded: list[str] = []
    for path in paths:
        require_absolute(path)
        candidates = sorted(globmodule.glob(path)) if globmodule.has_magic(path) else [path]
        for candidate in candidates:
            if candidate not in expanded:
                expanded.append(candidate)
    return expanded


def _matches(text: str, pattern: re.Pattern) -> list[dict]:
    return [{"match": m.group(0), "groups": [g or "" for g in m.groups()],
             "start": m.start()} for m in pattern.finditer(text)]


def file_matches(paths: list[str], regex: str) -> list[dict] | None:
    """Every regex match in the given files (globs allowed) with path and line.
    None if none of the files is readable.
    """
    pattern = re.compile(regex)
    results: list[dict] = []
    read_any = False
    for path in expand_paths(paths):
        check_deadline()
        text = read_text(path)
        if text is None:
            continue
        read_any = True
        for match in _matches(text, pattern):
            line = text.count("\n", 0, match.pop("start")) + 1
            results.append({"path": path, "line": line, **match})
            if len(results) > MAX_ENTRIES:
                raise SandboxLimit(f"file_matches() found more than {MAX_ENTRIES} matches")
    return results if read_any else None


def find_all(text: str | None, regex: str) -> list[dict] | None:
    """Every regex match in a string, with its groups. None for a null string."""
    pattern = re.compile(regex)
    if text is None:
        return None
    results = _matches(text, pattern)
    for match in results:
        del match["start"]
    return limit_entries(results, "find_all()")

