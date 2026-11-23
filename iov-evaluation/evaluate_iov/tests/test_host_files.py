import hashlib
import os
import re

import pytest

from evaluate_iov.host import base, configs, files


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "a.conf").write_text("enable_x = 1\nport=80\n")
    (tmp_path / "etc" / "b.conf").write_text("enable_x = 0\n")
    (tmp_path / "etc" / "sub").mkdir()
    (tmp_path / "etc" / "sub" / "deep.conf").write_text("x\n")
    (tmp_path / "etc" / "link").symlink_to("a.conf")
    os.chmod(tmp_path / "etc" / "a.conf", 0o4755)
    return tmp_path


# ── Files and directories ─────────────────────────────────────────────────────

def test_file_info(tree):
    info = files.file_info(str(tree / "etc" / "a.conf"))
    assert info["exists"] is True
    assert (info["type"], info["mode"], info["permissions"]) == ("file", "4755", "rwsr-xr-x")
    assert info["size"] == len("enable_x = 1\nport=80\n")
    assert info["uid"] == os.getuid() and isinstance(info["user"], str)
    assert info["symlink_target"] == "" and info["has_extended_acl"] is False


def test_file_info_does_not_follow_symlinks(tree):
    info = files.file_info(str(tree / "etc" / "link"))
    assert (info["type"], info["symlink_target"]) == ("symlink", "a.conf")


def test_file_info_of_a_missing_path(tree):
    info = files.file_info(str(tree / "nope"))
    assert info["exists"] is False and info["type"] is None and info["mode"] is None


def test_file_info_requires_an_absolute_path():
    with pytest.raises(ValueError):
        files.file_info("etc/passwd")


def test_list_dir(tree):
    entries = files.list_dir(str(tree / "etc"))
    assert [(e["name"], e["type"]) for e in entries] == [
        ("a.conf", "file"), ("b.conf", "file"), ("link", "symlink"), ("sub", "directory")]
    assert entries[0]["path"] == str(tree / "etc" / "a.conf")
    assert files.list_dir(str(tree / "etc" / "a.conf")) is None
    assert files.list_dir(str(tree / "nope")) is None


def test_list_dir_respects_the_entry_limit(tree, monkeypatch):
    monkeypatch.setattr(base, "MAX_ENTRIES", 3)
    with pytest.raises(base.SandboxLimit):
        files.list_dir(str(tree / "etc"))


def test_find_files(tree):
    found = files.find_files(str(tree), r"\.conf$", 3)
    assert [e["path"].removeprefix(str(tree)) for e in found] == [
        "/etc/a.conf", "/etc/b.conf", "/etc/sub/deep.conf"]
    assert [e["name"] for e in files.find_files(str(tree), r"\.conf$", 2)] == ["a.conf", "b.conf"]
    with pytest.raises(ValueError):
        files.find_files(str(tree), ".", 11)


def test_glob(tree):
    assert files.glob(str(tree / "etc" / "*.conf")) == [str(tree / "etc" / "a.conf"), str(tree / "etc" / "b.conf")]
    assert files.glob(str(tree / "none" / "*")) == []


def test_file_hash(tree):
    path = tree / "etc" / "b.conf"
    assert files.file_hash(str(path), "sha256") == hashlib.sha256(path.read_bytes()).hexdigest()
    assert files.file_hash(str(tree / "etc"), "sha256") is None
    with pytest.raises(ValueError):
        files.file_hash(str(path), "crc32")


def test_read_file_is_limited_in_bytes(tmp_path):
    path = tmp_path / "wide.txt"
    path.write_text("ä" * base.MAX_FILE_BYTES, encoding="utf-8")  # two bytes per character
    text = files.read_file(str(path))
    assert len(text.encode("utf-8")) == base.MAX_FILE_BYTES
    assert files.read_file(str(tmp_path / "missing")) is None


def test_file_matches(tree):
    matches = files.file_matches([str(tree / "etc" / "*.conf")], r"(?m)^enable_x\s*=\s*(\d)")
    assert matches == [
        {"path": str(tree / "etc" / "a.conf"), "line": 1, "match": "enable_x = 1", "groups": ["1"]},
        {"path": str(tree / "etc" / "b.conf"), "line": 1, "match": "enable_x = 0", "groups": ["0"]},
    ]
    assert files.file_matches([str(tree / "etc" / "a.conf")], r"(?m)^port=(\d+)")[0]["line"] == 2
    assert files.file_matches([str(tree / "etc" / "a.conf")], "absent") == []
    assert files.file_matches([str(tree / "nope")], "x") is None


def test_find_all():
    assert files.find_all("a=1 b=2 c", r"(\w)=(\d)?") == [
        {"match": "a=1", "groups": ["a", "1"]}, {"match": "b=2", "groups": ["b", "2"]}]
    assert files.find_all(None, "x") is None
    with pytest.raises(re.error):
        files.find_all("x", "(")


# ── Keyword/value configuration ───────────────────────────────────────────────

@pytest.fixture
def sshd(tmp_path):
    (tmp_path / "sshd_config.d").mkdir()
    (tmp_path / "sshd_config.d" / "10-first.conf").write_text("LoginGraceTime 0\n")
    (tmp_path / "sshd_config.d" / "20-second.conf").write_text("logingracetime=30\n")
    (tmp_path / "sshd_config").write_text(
        "# comment\n"
        "Include sshd_config.d/*.conf\n"
        "LoginGraceTime 120\n"
        "PermitRootLogin \"no\"\n"
        "Match User alice\n"
        "  LoginGraceTime 5\n"
    )
    return tmp_path


@pytest.mark.parametrize("precedence, expected", [
    ("first", ["0"]), ("last", ["120"]), ("all", ["0", "30", "120"]),
])
def test_directive_values_follow_includes_and_skip_match_blocks(sshd, precedence, expected):
    assert configs.directive_values([str(sshd / "sshd_config")], "LoginGraceTime", precedence) == expected


def test_directive_values_unquotes_and_reports_absence(sshd):
    config = [str(sshd / "sshd_config")]
    assert configs.directive_values(config, "permitrootlogin", "first") == ["no"]
    assert configs.directive_values(config, "X11Forwarding", "first") == []
    assert configs.directive_values([str(sshd / "nope")], "X", "first") is None
    with pytest.raises(ValueError):
        configs.directive_values(config, "X", "most")


def test_directive_values_skip_blocks(tmp_path):
    (tmp_path / "nginx.conf").write_text(
        "worker_processes 4;\nhttp {\n  server_tokens off;\n  server {\n    listen 80;\n  }\n}\n"
        "<VirtualHost *:80>\nServerTokens Full\n</VirtualHost>\nServerTokens Prod\n")
    path = [str(tmp_path / "nginx.conf")]
    assert configs.directive_values(path, "worker_processes", "all") == ["4"]
    assert configs.directive_values(path, "server_tokens", "all") == []
    assert configs.directive_values(path, "ServerTokens", "all") == ["Prod"]


def test_ini_values(tmp_path):
    (tmp_path / "php.ini").write_text(
        "top = 1\n[PHP]\n; comment\nexpose_php = On\nallow_url_include: Off\nexpose_php = Off\n[other]\nexpose_php = X\n")
    path = str(tmp_path / "php.ini")
    assert configs.ini_values(path, "PHP", "expose_php") == ["On", "Off"]
    assert configs.ini_values(path, "PHP", "allow_url_include") == ["Off"]
    assert configs.ini_values(path, "", "top") == ["1"]
    assert configs.ini_values(path, "PHP", "missing") == []
    assert configs.ini_values(str(tmp_path / "nope"), "a", "b") is None


# ── XML, JSON, YAML ───────────────────────────────────────────────────────────

def test_xml_query(tmp_path):
    (tmp_path / "server.xml").write_text(
        '<Server port="8005"><Service><Connector port="8080" protocol="HTTP/1.1"/>'
        '<Connector port="8009" protocol="AJP/1.3"/><Name>cat<b>alina</b></Name></Service></Server>')
    path = str(tmp_path / "server.xml")
    assert configs.xml_query(path, "//Connector/@port") == ["8080", "8009"]
    assert configs.xml_query(path, "//Connector[@protocol='AJP/1.3']/@port") == ["8009"]
    assert configs.xml_query(path, "//Name") == ["catalina"]
    assert configs.xml_query(path, "count(//Connector)") == ["2"]
    with pytest.raises(ValueError):
        configs.xml_query(path, "//[")


def test_xml_query_never_resolves_external_entities(tmp_path):
    secret = tmp_path / "secret"
    secret.write_text("TOP SECRET")
    (tmp_path / "evil.xml").write_text(
        f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file://{secret}">]><r>&x;</r>')
    assert "TOP SECRET" not in "".join(configs.xml_query(str(tmp_path / "evil.xml"), "/r") or [])


def test_xml_query_of_malformed_xml(tmp_path):
    (tmp_path / "bad.xml").write_text("<a><b></a>")
    assert configs.xml_query(str(tmp_path / "bad.xml"), "/a") is None


def test_json_query(tmp_path):
    (tmp_path / "daemon.json").write_text('{"features": {"buildkit": true}, "hosts": ["unix://", "tcp://0.0.0.0:2375"]}')
    path = str(tmp_path / "daemon.json")
    assert configs.json_query(path, "$.features.buildkit") == [True]
    assert configs.json_query(path, "$.hosts[?search(@, 'tcp://')]") == ["tcp://0.0.0.0:2375"]
    assert configs.json_query(path, "$.missing") == []
    with pytest.raises(ValueError):
        configs.json_query(path, "$[")


def test_yaml_query_over_several_documents(tmp_path):
    (tmp_path / "k8s.yaml").write_text(
        "kind: Pod\nspec:\n  hostNetwork: true\n---\nkind: Service\nspec:\n  created: 2024-01-01\n")
    path = str(tmp_path / "k8s.yaml")
    assert configs.yaml_query(path, "$.kind") == ["Pod", "Service"]
    assert configs.yaml_query(path, "$.spec.hostNetwork") == [True]
    assert configs.yaml_query(path, "$.spec.created") == ["2024-01-01"]
    (tmp_path / "bad.yaml").write_text("a: [unclosed\n")
    assert configs.yaml_query(str(tmp_path / "bad.yaml"), "$.a") is None
