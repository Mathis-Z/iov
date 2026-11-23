import pytest

from evaluate_iov.host import network, services


def test_socket_address_decoding():
    assert network._decode_address("0100007F", "ipv4") == "127.0.0.1"
    assert network._decode_address("00000000", "ipv4") == "0.0.0.0"
    assert network._decode_address("00000000000000000000000001000000", "ipv6") == "::1"
    assert network._decode_address("0000000000000000FFFF00000A00A8C0", "ipv6") == "::ffff:192.168.0.10"


def test_socket_table(monkeypatch):
    tables = {
        "/proc/net/tcp": (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1001 1\n"
            "   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1002 1\n"
            "   2: 0100007F:0CEA 0100007F:D431 01 00000000:00000000 00:00000000 00000000   999        0 1003 1\n"),
        "/proc/net/tcp6": (
            "  sl  local_address remote_address st ...\n"
            "   0: 00000000000000000000000000000000:0016 00000000000000000000000000000000:0000 0A 0 0 0 0     0 0 1004 1\n"),
        "/proc/net/udp": None,
        "/proc/net/udp6": None,
    }
    monkeypatch.setattr(network, "read_text", lambda path, limit=None: tables[path])
    table = network._socket_table()
    assert [(s["local_address"], s["local_port"], s["wildcard"], s["loopback"], s["family"])
            for s in table] == [
        ("0.0.0.0", 22, True, False, "ipv4"),
        ("127.0.0.1", 3306, False, True, "ipv4"),
        ("::", 22, True, False, "ipv6"),
    ]
    assert table[1]["uid"] == 999


@pytest.mark.parametrize("tty_nr, name", [(0, ""), (34816, "pts/0"), (34817, "pts/1"), (1025, "tty1"), (1088, "ttyS0")])
def test_tty_names(tty_nr, name):
    assert network._tty_name(tty_nr) == name


def test_processes_of_this_machine_have_the_documented_fields():
    process = next(p for p in network.processes() if p["pid"] == __import__("os").getpid())
    assert set(process) == {
        "pid", "ppid", "name", "exe", "cmdline", "cwd", "uid", "euid", "gid", "loginuid",
        "session_id", "tty", "start_time", "capabilities", "selinux_context", "has_listening_socket"}
    assert process["ppid"] > 0 and process["start_time"] > 0 and isinstance(process["capabilities"], list)


# ── systemd ───────────────────────────────────────────────────────────────────

def test_systemctl_show_parsing():
    units = services._parse_show(
        "Id=ssh.socket\nLoadState=loaded\nActiveState=active\nSubState=listening\n"
        "UnitFileState=enabled\nTriggers=ssh@.service\nListen=[::]:22 (Stream)\nListen=/run/x.sock (Stream)\n"
        "\n"
        "Id=nope.service\nLoadState=not-found\nActiveState=inactive\n")
    assert units[0]["name"] == "ssh.socket" and units[0]["triggers"] == ["ssh@.service"]
    assert units[0]["listen"] == ["[::]:22 (Stream)", "/run/x.sock (Stream)"]
    assert units[1] == {**units[1], "load_state": "not-found", "listen": [], "wants": []}


@pytest.mark.parametrize("entry, local", [
    ("[::]:22 (Stream)", False), ("0.0.0.0:22 (Stream)", False), ("22 (Stream)", False),
    ("127.0.0.1:631 (Stream)", True), ("[::1]:631 (Stream)", True),
    ("/run/cups/cups.sock (Stream)", True), ("192.0.2.1:53 (Datagram)", False),
])
def test_listen_entries(entry, local):
    assert services._listen_is_local(entry) is local


@pytest.fixture
def service_host(monkeypatch):
    def configure(procs=(), sockets=(), units=None, cgroups=None, executables=()):
        monkeypatch.setattr(services, "processes", lambda: None if procs is None else list(procs))
        monkeypatch.setattr(services, "listening_sockets", lambda: None if sockets is None else list(sockets))
        monkeypatch.setattr(services, "process_cgroups", lambda: cgroups or {})
        monkeypatch.setattr(services, "systemd_unit", lambda name: (units or {}).get(name))
        monkeypatch.setattr(services.os.path, "isfile", lambda path: path in executables)
    return configure


def proc(pid, name, exe=""):
    return {"pid": pid, "name": name, "exe": exe}


def sock(pid, loopback):
    return {"pid": pid, "loopback": loopback}


def unit(name, active="inactive", load="loaded", listen=()):
    return {"name": name, "active_state": active, "load_state": load, "listen": list(listen)}


@pytest.mark.parametrize("setup, expected", [
    (dict(procs=[proc(7, "sshd")], sockets=[sock(7, False)]), "network"),
    (dict(procs=[proc(7, "sshd")], sockets=[sock(7, True), sock(7, False)]), "network"),
    (dict(procs=[proc(7, "sshd")], sockets=[sock(7, True)]), "loopback"),
    (dict(procs=[proc(7, "x", "/usr/sbin/sshd")], sockets=[sock(7, False)]), "network"),
    (dict(procs=[proc(7, "worker")], sockets=[sock(7, False)],
          cgroups={7: "/system.slice/sshd.service"}), "network"),
    (dict(units={"ssh.socket": unit("ssh.socket", "active", listen=["[::]:22 (Stream)"])}), "network"),
    (dict(units={"ssh.socket": unit("ssh.socket", "active", listen=["127.0.0.1:22 (Stream)"])}), "loopback"),
    (dict(procs=[proc(7, "sshd")]), "running"),
    (dict(units={"sshd.service": unit("sshd.service", "active")}), "running"),
    (dict(units={"sshd.service": unit("sshd.service")}), "installed"),
    (dict(executables={"/usr/sbin/sshd"}), "installed"),
    (dict(units={"sshd.service": unit("sshd.service", load="not-found")}), "absent"),
    (dict(), "absent"),
    (dict(procs=None), None),
    (dict(sockets=None), None),
    # Another program's sockets never count.
    (dict(procs=[proc(7, "sshd"), proc(8, "nginx")], sockets=[sock(8, False)]), "running"),
])
def test_service_exposed(service_host, setup, expected):
    service_host(**setup)
    assert services.service_exposed(["sshd", "ssh"]) == expected
