import json
import textwrap

import pytest

from evaluate_iov.script import environment, interpreter
from evaluate_iov.script.interpreter import (
    ScriptError,
    ScriptOutcome,
    check_script,
    parse,
    run_script,
    unsupported_functions,
)
from evaluate_iov.validation import SCHEMA_PATH

EXAMPLES = {e["cve"]: e["script"] for e in json.loads(SCHEMA_PATH.read_text())["examples"]}
REGRESSHION = EXAMPLES["CVE-2024-6387"]
NF_TABLES = EXAMPLES["CVE-2024-26581"]


@pytest.fixture(autouse=True)
def stub_host(monkeypatch):
    """Pin the constants so the tests do not depend on the machine they run on."""
    monkeypatch.setattr(environment.kernel, "uname", lambda: {
        "sysname": "Linux", "nodename": "test", "release": "6.1.0-18-amd64",
        "version": "#1 SMP Debian 6.1.76-1", "machine": "x86_64"})
    monkeypatch.setattr(environment.kernel, "kernel_cmdline",
                        lambda: {"BOOT_IMAGE": "/vmlinuz", "root": "/dev/sda1", "mitigations": "off", "quiet": ""})
    monkeypatch.setattr(environment.releases, "os_release", lambda: {"ID": "debian", "VERSION_ID": "12"})


@pytest.fixture
def stub(monkeypatch):
    """Replace built-ins with functions returning fixed values."""
    def configure(**values):
        for name, value in values.items():
            assert name in environment.FUNCTIONS, name
            monkeypatch.setitem(environment.FUNCTIONS, name,
                                lambda *args, v=value: environment.to_cel(v))
    return configure


def run(source: str) -> int | None:
    return run_script(textwrap.dedent(source).strip("\n")).value


# ── The example scripts from the IoV specification ────────────────────────────

@pytest.mark.parametrize("exposure, grace, machine, expected", [
    ("installed", None, "x86_64", 1),
    ("absent", ["0"], "x86_64", 1),
    ("network", ["0"], "i686", 1),        # mitigated beats 32-bit
    ("network", ["0s"], "x86_64", 1),
    ("loopback", [], "x86_64", 1),
    ("network", [], "i686", 3),
    ("network", ["120"], "armv7l", 3),
    ("network", [], "x86_64", 2),
    ("running", None, "x86_64", 2),
    (None, None, "x86_64", 2),            # exposure unknown
])
def test_regresshion_example(stub, monkeypatch, exposure, grace, machine, expected):
    stub(service_exposed=exposure, directive_values=grace)
    monkeypatch.setattr(environment.kernel, "uname", lambda: {"machine": machine})
    assert run_script(REGRESSHION).value == expected


@pytest.mark.parametrize("feature, userns, expected", [
    ("absent", True, 0),
    (None, True, None),
    ("disabled", True, 1),
    ("blacklisted", None, 1),
    ("loaded", False, 1),
    ("builtin", False, 1),
    ("loaded", True, 3),
    ("builtin", True, 3),
    ("loaded", None, 2),
    ("module", True, 2),
    ("module", None, 2),
])
def test_nf_tables_example(stub, feature, userns, expected):
    stub(kernel_feature=feature, userns_unprivileged_allowed=userns)
    assert run_script(NF_TABLES).value == expected


def test_every_example_uses_only_known_built_ins():
    for script in EXAMPLES.values():
        assert unsupported_functions(script) == set()


# ── Control flow ──────────────────────────────────────────────────────────────

def test_constants_and_host_facts():
    assert run("return HIGH") == 3
    assert run("return DEFAULT") == 2
    assert run("return MEDIUM") == 2
    assert run("return LOW") == 1
    assert run("return ABSENT") == 0
    assert run('if uname.release == "6.1.0-18-amd64"\n  return HIGH\nend\nreturn ABSENT') == 3
    assert run('if kernel_cmdline["mitigations"] == "off"\n  return HIGH\nend\nreturn ABSENT') == 3
    assert run('if "quiet" in kernel_cmdline && kernel_cmdline.quiet == ""\n  return HIGH\nend\nreturn ABSENT') == 3
    assert run('if os_release.ID == "debian"\n  return HIGH\nend\nreturn ABSENT') == 3


def test_falling_off_the_end_is_null():
    assert run("let x := 1") is None
    assert run("return null") is None


def test_let_rebinding_and_use():
    assert run("""
        let x := 1
        let x := x + 2
        if x == 3
          return HIGH
        end
        return ABSENT
    """) == 3


def test_nested_if_and_elif_else():
    source = """
        let arch := uname.machine
        if arch == "aarch64"
          return ABSENT
        elif arch == "x86_64"
          if "mitigations" in kernel_cmdline
            return HIGH
          else
            return LOW
          end
        else
          return MEDIUM
        end
    """
    assert run(source) == 3


def test_comments_and_blank_lines_are_ignored():
    assert run("""
        // leading comment

            // indented comment
        return HIGH
    """) == 3


def test_double_slash_inside_an_expression_is_not_a_comment():
    assert run('if read_file("/nonexistent//file") == null\n  return HIGH\nend\nreturn ABSENT') == 3
    assert run('''
        let path := "//etc//hosts"
        if path.startsWith("//")
          return HIGH
        end
        return ABSENT
    ''') == 3


def test_identifier_starting_with_a_keyword_is_not_a_keyword():
    assert run("""
        let iffy := 3
        let ending := 0
        return iffy - ending
    """) == 3


# ── Runtime and parse errors produce no output ────────────────────────────────

@pytest.mark.parametrize("source", [
    "return undefined_variable",
    "if null\n  return HIGH\nend\nreturn ABSENT",          # non-boolean condition
    "if 1\n  return HIGH\nend\nreturn ABSENT",             # non-boolean condition
    "return 7",                                            # out of range
    "return true",                                         # not an int level
    'return "HIGH"',                                       # not an int level
    "return read_file(\"/nonexistent\").matches(r\"x\")",  # method call on null
    "let x := !read_file(\"/nonexistent\")",              # operator on null
    "return kernel_cmdline[\"missing\"]",                  # missing map key
    "return file_info(\"relative/path\")",                # built-in argument error
    "return sysctl(1)",                                    # wrong argument type
    "return sysctl()",                                     # wrong argument count
    "return ABSENT +",                                     # CEL parse error
    "let := 1",                                            # no variable name
    "let x = 1",                                           # ':=' missing
    "let ABSENT := 1",                                     # reserved name
    "let return := 1",                                     # reserved name
    "if true\n  return HIGH",                              # 'if' never closed
    "return HIGH\nend",                                    # stray 'end'
    "else\nreturn HIGH",                                   # stray 'else'
    "if true\nelse\nreturn HIGH\nelse\nreturn LOW\nend",   # duplicate 'else'
    "if true\nelse\nreturn HIGH\nelif false\nreturn LOW\nend",  # 'elif' after 'else'
    "if true\n  return HIGH\nend extra",                   # 'end' must stand alone
    "frobnicate()",                                        # not a statement
])
def test_failures_produce_no_output(source):
    outcome = run_script(source)
    assert outcome.value is None and outcome.error and not outcome.limit


def test_variable_from_an_untaken_branch_is_undefined():
    assert run("""
        if false
          let only_here := HIGH
        end
        return only_here
    """) is None


def test_statement_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(interpreter, "MAX_STATEMENTS", 5)
    assert run_script("\n".join(["let x := 1"] * 6)) == ScriptOutcome(
        None, "the script exceeded 5 statements", True)


def test_time_limit_is_enforced(monkeypatch):
    monkeypatch.setattr(interpreter, "TIME_LIMIT", -1)
    outcome = run_script("let x := 1\nreturn HIGH")
    assert outcome.value is None and outcome.limit
    assert "time limit" in outcome.error


def test_a_built_in_entry_limit_is_a_sandbox_limit(monkeypatch):
    monkeypatch.setattr(environment.base, "MAX_ENTRIES", 2)
    monkeypatch.setattr(environment.system, "users", lambda: [{"name": str(n)} for n in range(3)])
    outcome = run_script("return size(users())")
    assert outcome.value is None and outcome.limit
    assert "more than 2 entries" in outcome.error


def test_the_deadline_is_cleared_after_a_run(monkeypatch):
    run_script("return HIGH")
    environment.base.check_deadline()   # would raise if the deadline leaked


def test_unsupported_functions_are_found():
    assert unsupported_functions("let x := lsmod()\nif foo(1) && size([]) == 0\n  return bar()\nend\nreturn null") == {"lsmod", "foo", "bar"}
    assert unsupported_functions("return int(\"3\") + size(glob(\"/etc/*\"))") == set()
    # A script that does not parse is reported when it runs, not here.
    assert unsupported_functions("if true") == set()


def test_successful_outcome():
    assert run_script("return HIGH") == ScriptOutcome(3)


def test_parse_reports_the_offending_line():
    with pytest.raises(ScriptError, match="line 3"):
        parse("let x := 1\n\nlet y = 2\n")


def test_lists_and_maps_compare_with_null(stub):
    # CEL's heterogeneous equality; cel-python needs a shim for it.
    stub(directive_values=["0"], systemd_unit={"active_state": "active"})
    assert run('if directive_values(["/x"], "k", "first") != null && null != systemd_unit("x")\n'
               '  return HIGH\nend\nreturn ABSENT') == 3
    assert run('if [1] == null || {"a": 1} == null\n  return HIGH\nend\nreturn ABSENT') == 0


@pytest.mark.parametrize("value", [
    "1", "-1", "1u", "1.5", '"x"', "true", 'b"x"', "[1]", '{"a": 1}',
    'timestamp("2024-01-01T00:00:00Z")', 'duration("1s")',
])
def test_every_type_compares_with_null(value):
    # 1 == null raised "no such overload" in cel-python for numbers.
    assert run(f"if {value} == null || null == {value}\n  return HIGH\nend\n"
               f"if {value} != null && null != {value}\n  return LOW\nend\nreturn ABSENT") == 1


@pytest.mark.parametrize("macro", ["exists", "all"])
def test_a_non_boolean_macro_condition_fails_with_a_short_error(stub, macro):
    # cel-python quoted the previous error in each new one, so the message
    # doubled per element; with a real process list it exhausted the memory.
    stub(get_processes=[{"pid": i, "name": f"p{i}"} for i in range(200)])
    outcome = run_script(f'let s := "x"\nif get_processes().{macro}(p, s)\n  return HIGH\nend\nreturn LOW')
    assert outcome.value is None and len(outcome.error) < 1000


def test_boolean_operators_keep_error_absorption():
    # true || error is true, false && error is false; only two non-booleans fail.
    assert run('return true || "x" ? HIGH : ABSENT') == 3
    assert run('return false && "x" ? HIGH : ABSENT') == 0
    assert run('if "x" || "y"\n  return HIGH\nend\nreturn LOW') is None


def test_version_compare_result_can_be_null_checked():
    assert run('''
        let c := version_compare("6.1.0", "5.11", "generic")
        if c == null
          return null
        end
        return c > 0 ? HIGH : ABSENT
    ''') == 3


def test_numbers_still_compare_normally():
    assert run("return 1 == 1 && 1 != 2 && 1.5 == 1.5 && -1 < 0 ? HIGH : ABSENT") == 3


# ── Static checks at ingestion ────────────────────────────────────────────────

def test_the_examples_pass_the_static_checks():
    for cve, script in EXAMPLES.items():
        assert check_script(script) is None, cve


@pytest.mark.parametrize("source, problem", [
    # Reassignment without 'let', as generated for CVE-2026-90003.
    ('let fixed := ""\nif true\n  fixed := "6.1.188"\nend\nreturn LOW',
     "parse error: line 3: 'fixed := \"6.1.188\"' is missing 'let'; there is no plain assignment, "
     "'let fixed := ...' redefines the variable"),
    # A stray 'end' after the final return, as generated for CVE-2026-53180.
    ("return MEDIUM\nend", "parse error: line 2: 'end' without a matching 'if'"),
    ("let x := 1 +\nreturn LOW", "line 1: '1 +' is not a valid CEL expression"),
    ("if true\n  return LOW\nelif (\n  return HIGH\nend\nreturn LOW",
     "line 3: '(' is not a valid CEL expression"),
    ("return frobnicate(1)", "neither built-ins nor part of CEL: frobnicate()"),
    ("let x := 1", "can fall off its end"),
    ("if true\n  return LOW\nend", "the 'if' on line 1 has a branch without a 'return', or no 'else'"),
    ("if true\n  return LOW\nelse\n  let x := 1\nend", "the 'if' on line 1"),
    ("if true\n  if false\n    return LOW\n  end\nelse\n  return HIGH\nend", "the 'if' on line 1"),
])
def test_static_check_problems(source, problem):
    assert problem in check_script(source)


@pytest.mark.parametrize("source", [
    "return null",
    "if true\n  return LOW\nelif false\n  return HIGH\nelse\n  return null\nend",
    "if true\n  return LOW\nend\nreturn HIGH",
    # An if without else is fine as long as a return follows it.
    "if true\n  if false\n    return LOW\n  else\n    return HIGH\n  end\nelse\n  return MEDIUM\nend",
])
def test_static_check_accepts_complete_scripts(source):
    assert check_script(source) is None
