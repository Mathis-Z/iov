import pytest

from evaluate_iov.host import kernel


@pytest.fixture
def kernel_state(monkeypatch):
    """Pin the kernel's configuration, modules and modprobe policy."""
    def configure(config=None, loaded=(), builtin=(), module_files=(), installs=None,
                  blacklist=(), sysctls=None):
        monkeypatch.setattr(kernel, "kernel_config_map", lambda: config)
        monkeypatch.setattr(kernel, "kernel_modules",
                            lambda: None if loaded is None else [{"name": m} for m in loaded])
        monkeypatch.setattr(kernel, "builtin_modules", lambda: None if builtin is None else set(builtin))
        monkeypatch.setattr(kernel, "module_files",
                            lambda: None if module_files is None else set(module_files))
        monkeypatch.setattr(kernel, "modprobe_policy", lambda: (installs or {}, set(blacklist)))
        monkeypatch.setattr(kernel, "sysctl", lambda name: (sysctls or {}).get(name))
    return configure


def test_kernel_cmdline_parsing(monkeypatch):
    monkeypatch.setattr(kernel, "read_text", lambda path: (
        'BOOT_IMAGE=/vmlinuz-6.1 root=UUID=abc ro quiet mitigations=off '
        'dyndbg="file foo.c +p" mitigations=auto,nosmt\n'))
    assert kernel.kernel_cmdline() == {
        "BOOT_IMAGE": "/vmlinuz-6.1", "root": "UUID=abc", "ro": "", "quiet": "",
        "mitigations": "auto,nosmt", "dyndbg": "file foo.c +p"}


def test_kernel_config_parsing(monkeypatch):
    monkeypatch.setattr(kernel, "_read_config_text", lambda: (
        "CONFIG_NF_TABLES=m\nCONFIG_USER_NS=y\n# CONFIG_BPF_JIT is not set\n"
        'CONFIG_LOCALVERSION="-custom"\nCONFIG_HZ=250\n'))
    assert kernel.kernel_config("CONFIG_NF_TABLES") == "m"
    assert kernel.kernel_config("CONFIG_BPF_JIT") == "n"
    assert kernel.kernel_config("CONFIG_NOT_THERE") == "n"
    assert kernel.kernel_config("CONFIG_LOCALVERSION") == "-custom"
    assert kernel.kernel_config("CONFIG_HZ") == "250"


def test_kernel_config_unavailable(monkeypatch):
    monkeypatch.setattr(kernel, "_read_config_text", lambda: None)
    assert kernel.kernel_config("CONFIG_NF_TABLES") is None


def test_kernel_modules_parsing(monkeypatch):
    monkeypatch.setattr(kernel, "read_text", lambda path, limit=None: (
        "nf_tables 311296 12 nft_compat,nft_chain_nat, Live 0x0000000000000000\n"
        "loop 36864 0 - Live 0x0000000000000000\n"))
    assert kernel.kernel_modules() == [
        {"name": "nf_tables", "size": 311296, "refcount": 12,
         "used_by": ["nft_compat", "nft_chain_nat"], "state": "Live"},
        {"name": "loop", "size": 36864, "refcount": 0, "used_by": [], "state": "Live"},
    ]


@pytest.mark.parametrize("setup, expected", [
    (dict(config={"CONFIG_NF_TABLES": "m"}, loaded=["nf_tables"]), "loaded"),
    (dict(config={"CONFIG_NF_TABLES": "y"}), "builtin"),
    (dict(config=None, builtin=["nf_tables"]), "builtin"),
    (dict(config={"CONFIG_NF_TABLES": "m"}, module_files=["nf_tables"]), "module"),
    (dict(config=None, module_files=["nf_tables"]), "module"),
    (dict(config={"CONFIG_NF_TABLES": "m"}, blacklist=["nf_tables"]), "blacklisted"),
    (dict(config={"CONFIG_NF_TABLES": "m"}, installs={"nf_tables": "/bin/false"}), "disabled"),
    (dict(config={"CONFIG_NF_TABLES": "m"}, installs={"nf_tables": "/usr/bin/true --x"},
          blacklist=["nf_tables"]), "disabled"),
    (dict(config={"CONFIG_NF_TABLES": "m"}, sysctls={"kernel.modules_disabled": "1"}), "disabled"),
    (dict(config={"CONFIG_NF_TABLES": "m"}, installs={"nf_tables": "/sbin/modprobe --ignore-install nf_tables"}), "module"),
    (dict(config={}), "absent"),
    (dict(config={}, module_files=None), None),       # an out-of-tree module cannot be ruled out
    (dict(config=None, builtin=None, module_files=None), None),
])
def test_kernel_feature_decision_order(kernel_state, setup, expected):
    kernel_state(**setup)
    assert kernel.kernel_feature("CONFIG_NF_TABLES", "nf_tables") == expected


def test_kernel_feature_without_a_module(kernel_state):
    kernel_state(config={})
    assert kernel.kernel_feature("CONFIG_IO_URING", None) == "absent"
    kernel_state(config={"CONFIG_IO_URING": "y"})
    assert kernel.kernel_feature("CONFIG_IO_URING", None) == "builtin"


def test_module_names_are_normalized(kernel_state):
    kernel_state(config={}, loaded=["nf_conntrack_ftp"])
    assert kernel.kernel_feature("CONFIG_NF_CONNTRACK_FTP", "nf-conntrack-ftp") == "loaded"


@pytest.mark.parametrize("config, sysctls, expected", [
    ({"CONFIG_USER_NS": "n"}, {"user.max_user_namespaces": "1000"}, False),
    ({}, {"kernel.unprivileged_userns_clone": "0", "user.max_user_namespaces": "1000"}, False),
    ({}, {"user.max_user_namespaces": "0"}, False),
    ({}, {"kernel.apparmor_restrict_unprivileged_userns": "1", "user.max_user_namespaces": "9"}, False),
    ({"CONFIG_USER_NS": "y"}, {"kernel.unprivileged_userns_clone": "1", "user.max_user_namespaces": "9"}, True),
    (None, {"user.max_user_namespaces": "9"}, True),
    (None, {}, None),
])
def test_userns_unprivileged_allowed(kernel_state, config, sysctls, expected):
    kernel_state(config=config, sysctls=sysctls)
    assert kernel.userns_unprivileged_allowed() is expected


def test_sysctl_rejects_path_traversal():
    assert kernel.sysctl("../../etc/shadow") is None
    assert kernel.sysctl("kernel/../../../etc") is None


def test_uname_has_every_field():
    assert set(kernel.uname()) == {"sysname", "nodename", "release", "version", "machine"}
