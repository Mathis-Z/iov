import gzip
import io
import tarfile
from pathlib import Path

import pytest
from conftest import pkg

from evaluate_iov.host import origin, pkgdb

# A throwaway ed25519 key with a cv25519 subkey, generated for this test. gpg
# reports the key IDs 06A0677E23318A29 (primary) and 6097728A6FBA1C98 (subkey).
TEST_KEY = """-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEaran1RYJKwYBBAHaRw8BAQdA0u2Mw01sdwC/hunqbx6VTHMEohGbyGoddkfc
Mi4J7QW0I0lvViBUZXN0IEtleSA8dGVzdEBleGFtcGxlLmludmFsaWQ+iJMEExYK
ADsWIQSNk++cslyEkviEZp0GoGd+IzGKKQUCaran1QIbAwULCQgHAgIiAgYVCgkI
CwIEFgIDAQIeBwIXgAAKCRAGoGd+IzGKKeE3AP41l1W/t7q0qeHTdRTT/dHNTgR8
ZtdL0gFFDQbde1YGwgD/Tw06LdQJcSJL8UbjsoaixnUulmV6DXaJ0a1g453w2gW4
OARqtqfVEgorBgEEAZdVAQUBAQdAHJ0OGJQWiCXi+5SSWpBkBwKnczWvifU78RQQ
BXgE/GkDAQgHiHgEGBYKACAWIQSNk++cslyEkviEZp0GoGd+IzGKKQUCaran1QIb
DAAKCRAGoGd+IzGKKSZPAQD9avMVnaV+1x9bx4FTVFVCNp9rL4s9oGeIAG3PlHJm
9wD/fervpI5uHKNnRdpFe+FXpv10xaFis5yo25diHiBGGA8=
=xiiw
-----END PGP PUBLIC KEY BLOCK-----
"""


# ── Package databases ─────────────────────────────────────────────────────────

@pytest.mark.parametrize("signature, key_id", [
    ("RSA/SHA256, Tue Apr 16 2024 10:00:00 AM UTC, Key ID 199e2f91fd431d51", "199e2f91fd431d51"),
    ("EdDSA/SHA512, Mon 01 Sep 2025, Key fingerprint: 0123456789ABCDEF0123456789ABCDEF199E2F91FD431D51",
     "199e2f91fd431d51"),
    ("(none)", ""),
])
def test_rpm_key_id(signature, key_id):
    assert pkgdb.rpm_key_id(signature) == key_id


def test_rpm_inventory_parsing(monkeypatch):
    monkeypatch.setattr(pkgdb, "run_command", lambda *cmd: (
        "openssh-server\t8.7p1-38.el9_4.1\tx86_64\topenssh-8.7p1-38.el9_4.1.src.rpm\tRSA/SHA256, x, Key ID 199e2f91fd431d51\n"
        "openssl-libs\t1:3.0.7-27.el9\ti686\topenssl-3.0.7-27.el9.src.rpm\t(none)\n"
        "gpg-pubkey\tfd431d51-4ae0493b\t(none)\t(none)\t(none)\n"))
    assert pkgdb._read_rpm() == [
        pkg("openssh-server", "8.7p1-38.el9_4.1", "x86_64", "rpm", "199e2f91fd431d51")._replace(source="openssh"),
        pkg("openssl-libs", "1:3.0.7-27.el9", "i686", "rpm")._replace(source="openssl"),
    ]


def test_dpkg_inventory_parsing(monkeypatch):
    monkeypatch.setattr(pkgdb, "run_command", lambda *cmd: (
        "installed\tlibssl3\t3.0.11-1~deb12u2\tamd64\topenssl\n"
        "installed\tlibc6\t2.36-9+deb12u4\ti386\tglibc (2.36-9+deb12u4)\n"
        "installed\tbash\t5.2.15-2+b2\tamd64\t\n"
        "config-files\told\t\tamd64\t\n"))
    assert [(p.name, p.arch, p.source) for p in pkgdb._read_dpkg()] == [
        ("libssl3", "amd64", "openssl"), ("libc6", "i386", "glibc"), ("bash", "amd64", "bash")]


def test_apk_database_parsing(tmp_path, monkeypatch):
    db = tmp_path / "installed"
    db.write_text("C:Q1abc\nP:libssl3\nV:3.3.2-r0\nA:x86_64\no:openssl\nF:usr/lib\nR:libssl.so.3\n\n"
                  "P:busybox\nV:1.36.1-r29\nA:x86_64\nF:bin\nR:busybox\nF:etc\nR:securetty\n")
    monkeypatch.setattr(pkgdb, "APK_DB", str(db))
    assert pkgdb._read_apk() == [
        pkg("libssl3", "3.3.2-r0", "x86_64", "apk")._replace(source="openssl"),
        pkg("busybox", "1.36.1-r29", "x86_64", "apk"),
    ]
    assert pkgdb.package_files(pkgdb._read_apk()[1]) == ["/bin/busybox", "/etc/securetty"]


def test_pacman_local_database_parsing(tmp_path, monkeypatch):
    entry = tmp_path / "openssh-9.8p1-1"
    entry.mkdir()
    (entry / "desc").write_text("%NAME%\nopenssh\n\n%VERSION%\n9.8p1-1\n\n%BASE%\nopenssh\n\n%ARCH%\nx86_64\n")
    (entry / "files").write_text("%FILES%\nusr/\nusr/bin/ssh\n\n%BACKUP%\netc/ssh/sshd_config\tabc\n")
    monkeypatch.setattr(pkgdb, "PACMAN_LOCAL", str(tmp_path))
    packages = pkgdb._read_pacman()
    assert packages == [pkg("openssh", "9.8p1-1", "x86_64", "pacman")]
    assert pkgdb.package_files(packages[0]) == ["/usr/", "/usr/bin/ssh"]


def test_the_distributions_package_manager_is_preferred(monkeypatch):
    monkeypatch.setattr(pkgdb.releases, "host_release", lambda: pkgdb.releases.Release("ubuntu", "22.04"))
    monkeypatch.setattr(pkgdb, "_manager_present", lambda m: m in ("rpm", "dpkg"))
    monkeypatch.setattr(pkgdb, "_READERS", {"dpkg": lambda: [], "rpm": lambda: [], "apk": None, "pacman": None})
    assert pkgdb.inventory().manager == "dpkg"


def test_rpm_verify_parsing():
    output = ("S.5....T.  c /etc/ssh/sshd_config\n"
              "missing     /usr/bin/ssh\n"
              ".....UG..    /usr/libexec/sftp-server\n"
              "..?......    /usr/sbin/sshd\n")
    results = pkgdb._verify_rpm_style(output, set(pkgdb._VERIFY_FIELDS))
    assert results[0] == {"path": "/etc/ssh/sshd_config", "config": True, "missing": False,
                          "digest_changed": True, "size_changed": True, "mode_changed": False,
                          "owner_changed": False, "mtime_changed": True}
    assert results[1]["missing"] is True and results[1]["digest_changed"] is None
    assert results[2]["owner_changed"] is True
    assert results[3]["digest_changed"] is None


def test_dpkg_verify_parsing():
    results = pkgdb._verify_rpm_style("??5?????? c /etc/ssh/sshd_config\n", {"missing", "digest_changed"})
    assert results == [{"path": "/etc/ssh/sshd_config", "config": True, "missing": False,
                        "digest_changed": True, "size_changed": None, "mode_changed": None,
                        "owner_changed": None, "mtime_changed": None}]


# ── Origin ────────────────────────────────────────────────────────────────────

def test_openpgp_key_ids_match_gpg():
    assert origin._openpgp_key_ids(TEST_KEY) == {"06a0677e23318a29", "6097728a6fba1c98"}
    assert origin._openpgp_key_ids("not a key") == set()


def test_rpm_origin(monkeypatch):
    monkeypatch.setattr(origin, "_trusted_rpm_keys", lambda: frozenset({"199e2f91fd431d51"}))
    ours = pkg("openssl-libs", "1:3.0.7-27.el9", "x86_64", "rpm", "199e2f91fd431d51")
    theirs = pkg("nginx", "1.26.1-1.el9.ngx", "x86_64", "rpm", "abf5bd827bd9bf62")
    unsigned = pkg("custom", "1.0-1", "x86_64", "rpm")
    assert origin._check_rpm(ours, "rhel")[0] is True
    assert origin._check_rpm(theirs, "rhel") == (
        False, "it is signed with key abf5bd827bd9bf62, which is not a rhel key")
    assert origin._check_rpm(unsigned, "rhel") == (None, "it is unsigned")


@pytest.fixture
def apt_lists(tmp_path, monkeypatch):
    lists = tmp_path / "lists"
    lists.mkdir()
    (lists / "deb.debian.org_debian_dists_bookworm_InRelease").write_text(
        "-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nLabel: Debian\n")
    (lists / "nginx.org_packages_debian_dists_bookworm_InRelease").write_text("Origin: nginx\n")
    with gzip.open(lists / "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.gz", "wt") as f:
        f.write("Package: nginx\nVersion: 1.22.1-9\nArchitecture: amd64\n\n"
                "Package: tzdata\nVersion: 2024a-0+deb12u1\nArchitecture: all\n")
    (lists / "nginx.org_packages_debian_dists_bookworm_nginx_binary-amd64_Packages").write_text(
        "Package: nginx\nVersion: 1.26.1-1~bookworm\nArchitecture: amd64\n")
    monkeypatch.setattr(origin, "APT_LISTS", str(lists))


def test_dpkg_origin(apt_lists):
    assert origin._check_dpkg(pkg("nginx", "1.22.1-9"), "debian")[0] is True
    assert origin._check_dpkg(pkg("tzdata", "2024a-0+deb12u1"), "debian")[0] is True
    # A superseded distribution build: no longer offered, but older than Debian's.
    assert origin._check_dpkg(pkg("nginx", "1.22.1-8"), "debian") == (
        True, "an older debian build (debian now ships 1.22.1-9)")
    # Offered by another source.
    assert origin._check_dpkg(pkg("nginx", "1.26.1-1~bookworm"), "debian") == (
        False, "version 1.26.1-1~bookworm comes from a non-debian source")
    # A local build newer than anything Debian ships.
    assert origin._check_dpkg(pkg("nginx", "1.27.0-1"), "debian")[0] is None
    assert origin._check_dpkg(pkg("unknown-pkg", "1.0"), "debian") == (
        None, "no debian source offers unknown-pkg")
    assert origin._check_dpkg(pkg("nginx", "1.22.1-9"), "gentoo")[0] is None


def test_lz4_lists_are_read_through_apt_helper(apt_lists, monkeypatch, tmp_path):
    lists = Path(origin.APT_LISTS)
    (lists / "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.gz").unlink()
    (lists / "deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4").write_bytes(b"\x04\x22")
    monkeypatch.setattr(origin, "run_command", lambda *cmd: (
        "Package: nginx\nVersion: 1.22.1-9\nArchitecture: amd64\n"
        if cmd[:2] == (origin.APT_HELPER, "cat-file") else None))
    assert origin._check_dpkg(pkg("nginx", "1.22.1-9"), "debian")[0] is True


def test_apk_origin(monkeypatch):
    monkeypatch.setattr(origin, "run_command", lambda *cmd: (
        "libssl3 policy:\n"
        "  3.3.2-r0:\n    lib/apk/db/installed\n    https://dl-cdn.alpinelinux.org/alpine/v3.20/main\n"
        "  3.3.9-r0:\n    https://example.com/custom\n"))
    assert origin._check_apk(pkg("libssl3", "3.3.2-r0", "x86_64", "apk"), "alpine")[0] is True
    assert origin._check_apk(pkg("libssl3", "3.3.1-r0", "x86_64", "apk"), "alpine")[0] is True
    assert origin._check_apk(pkg("libssl3", "3.3.9-r0", "x86_64", "apk"), "alpine")[0] is False


def test_pacman_origin(tmp_path, monkeypatch):
    for repository, version in (("core", "9.8p1-1"), ("thirdparty", "9.9p1-7")):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            data = f"%NAME%\nopenssh\n\n%VERSION%\n{version}\n\n".encode()
            info = tarfile.TarInfo(f"openssh-{version}/desc")
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
        (tmp_path / f"{repository}.db").write_bytes(buffer.getvalue())
    monkeypatch.setattr(origin, "PACMAN_SYNC", str(tmp_path))
    assert origin._check_pacman(pkg("openssh", "9.8p1-1", "x86_64", "pacman"), "arch")[0] is True
    assert origin._check_pacman(pkg("openssh", "9.7p1-2", "x86_64", "pacman"), "arch")[0] is True
    assert origin._check_pacman(pkg("openssh", "9.9p1-7", "x86_64", "pacman"), "arch")[0] is False
    assert origin._check_pacman(pkg("openssh", "10.0p1-1", "x86_64", "pacman"), "arch")[0] is None
