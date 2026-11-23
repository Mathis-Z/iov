"""Interpreter for the IoV script language.

The language is a thin statement layer over CEL expressions:

    script     = { line }
    line       = blank | comment | statement
    comment    = "//" text            (first non-whitespace characters of a line)
    statement  = "let" IDENT ":=" CEL
               | "return" CEL
               | "if" CEL NEWLINE block { "elif" CEL NEWLINE block } [ "else" NEWLINE block ] "end"

Each statement occupies exactly one line and expressions cannot span lines.
There are no loops and no user-defined functions. Reaching the end of the
script is equivalent to 'return null'.

Any failure -- a parse error, a CEL evaluation error, an undefined variable, a
non-boolean condition, an invalid return value, a sandbox limit -- makes the
script produce no output. run_script reports the value together with the error,
so the evaluation result can say why a script made no statement.
"""

import logging
import re
from typing import NamedTuple

import celpy
from celpy import celtypes

from ..host import base
from ..logging_setup import LOGGER_NAME
from . import environment

log = logging.getLogger(LOGGER_NAME)

MAX_STATEMENTS = 10_000
TIME_LIMIT = 30.0  # seconds of wall-clock time per script; the specification requires >= 10
IDENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")

VALID_RETURN_VALUES = range(0, 4)


class ScriptError(Exception):
    """The script produces no output."""


class ScriptOutcome(NamedTuple):
    """What a script run produced."""
    value: int | None          # the returned level; None for null or no output
    error: str | None = None   # why the script produced no output, if it failed
    limit: bool = False        # the failure was a sandbox limit


class Let(NamedTuple):
    """let NAME := EXPRESSION"""
    line: int
    name: str
    expression: str


class Return(NamedTuple):
    """return EXPRESSION"""
    line: int
    expression: str


class Branch(NamedTuple):
    """One arm of an if statement."""
    line: int
    # condition is None for the 'else' arm.
    condition: str | None
    body: list


class If(NamedTuple):
    """if/elif/else/end"""
    line: int
    branches: list[Branch]


# ── Parser ────────────────────────────────────────────────────────────────────

def _split_lines(source: str) -> list[tuple[int, str]]:
    """Drop blank and comment lines, keeping 1-based line numbers."""
    lines = []
    for number, raw in enumerate(source.splitlines(), start=1):
        stripped = raw.strip()
        if stripped and not stripped.startswith("//"):
            lines.append((number, stripped))
    return lines


def _keyword(text: str, keyword: str) -> str | None:
    """Return the rest of the line if it starts with the keyword, else None.

    A keyword must be followed by whitespace or end the line, so an expression
    beginning with an identifier like 'iface_up' is not read as 'if'.
    """
    if not text.startswith(keyword):
        return None
    rest = text[len(keyword):]
    if rest and not rest[0].isspace():
        return None
    return rest.strip()


class _Parser:
    def __init__(self, lines: list[tuple[int, str]]):
        self._lines = lines
        self._pos = 0

    def parse(self) -> list:
        body = self._block(terminators=())
        if self._pos < len(self._lines):
            number, text = self._lines[self._pos]
            raise ScriptError(f"line {number}: unexpected {text!r}")
        return body

    def _block(self, terminators: tuple[str, ...], opened_at: int | None = None) -> list:
        body = []
        while self._pos < len(self._lines):
            number, text = self._lines[self._pos]
            if any(_keyword(text, word) is not None for word in terminators):
                return body
            self._pos += 1
            body.append(self._statement(number, text))
        if terminators:
            raise ScriptError(f"line {opened_at}: 'if' is never closed by 'end'")
        return body

    def _statement(self, number: int, text: str):
        rest = _keyword(text, "let")
        if rest is not None:
            name, separator, expression = rest.partition(":=")
            name = name.strip()
            if not separator:
                raise ScriptError(f"line {number}: 'let' without ':='")
            if not IDENT_RE.match(name):
                raise ScriptError(f"line {number}: {name!r} is not a valid variable name")
            if name in environment.RESERVED:
                raise ScriptError(f"line {number}: {name!r} is reserved")
            if not expression.strip():
                raise ScriptError(f"line {number}: 'let {name}' without an expression")
            return Let(number, name, expression.strip())

        rest = _keyword(text, "return")
        if rest is not None:
            if not rest:
                raise ScriptError(f"line {number}: 'return' without an expression")
            return Return(number, rest)

        rest = _keyword(text, "if")
        if rest is not None:
            return self._if(number, rest)

        for word in ("elif", "else", "end"):
            if _keyword(text, word) is not None:
                raise ScriptError(f"line {number}: {word!r} without a matching 'if'")
        name, separator, _ = text.partition(":=")
        if separator and IDENT_RE.match(name.strip()):
            raise ScriptError(f"line {number}: {text!r} is missing 'let'; there is no plain "
                              f"assignment, 'let {name.strip()} := ...' redefines the variable")
        raise ScriptError(f"line {number}: not a statement: {text!r}")

    def _if(self, number: int, condition: str):
        if not condition:
            raise ScriptError(f"line {number}: 'if' without a condition")

        branches = [Branch(number, condition, self._block(("elif", "else", "end"), number))]
        seen_else = False
        while True:
            if self._pos >= len(self._lines):
                raise ScriptError(f"line {number}: 'if' is never closed by 'end'")
            line_number, text = self._lines[self._pos]
            self._pos += 1

            rest = _keyword(text, "elif")
            if rest is not None:
                if seen_else:
                    raise ScriptError(f"line {line_number}: 'elif' after 'else'")
                if not rest:
                    raise ScriptError(f"line {line_number}: 'elif' without a condition")
                body = self._block(("elif", "else", "end"), number)
                branches.append(Branch(line_number, rest, body))
                continue

            rest = _keyword(text, "else")
            if rest is not None:
                if seen_else:
                    raise ScriptError(f"line {line_number}: duplicate 'else'")
                if rest:
                    raise ScriptError(f"line {line_number}: 'else' must stand alone")
                seen_else = True
                body = self._block(("elif", "else", "end"), number)
                branches.append(Branch(line_number, None, body))
                continue

            rest = _keyword(text, "end")
            if rest is not None:
                if rest:
                    raise ScriptError(f"line {line_number}: 'end' must stand alone")
                return If(number, branches)

            raise ScriptError(f"line {line_number}: expected 'elif', 'else' or 'end', got {text!r}")


def parse(source: str) -> list:
    """Parse a script into statements, raising ScriptError if it is malformed."""
    return _Parser(_split_lines(source)).parse()


def _expressions(body: list):
    """Every CEL expression in the script, with its line number."""
    for statement in body:
        if isinstance(statement, (Let, Return)):
            yield statement.line, statement.expression
        else:
            for branch in statement.branches:
                if branch.condition is not None:
                    yield branch.line, branch.condition
                yield from _expressions(branch.body)


def unsupported_functions(source: str) -> set[str]:
    """Global function calls that are neither built-ins nor part of CEL.

    Returns an empty set if the script does not parse; run_script reports that.
    """
    try:
        body = parse(source)
    except ScriptError:
        return set()
    env = celpy.Environment()
    known = set(environment.FUNCTIONS) | environment.STANDARD_FUNCTIONS
    called = set()
    for _, expression in _expressions(body):
        try:
            tree = env.compile(expression)
        except Exception:
            continue  # a compile error surfaces when the script runs
        for node in tree.iter_subtrees():
            if node.data == "ident_arg" and node.children:
                called.add(str(node.children[0]))
    return called - known


def _always_returns(body: list) -> bool:
    """Whether every execution path through the block ends in a 'return'."""
    for statement in body:
        if isinstance(statement, Return):
            return True
        if (isinstance(statement, If) and statement.branches[-1].condition is None
                and all(_always_returns(branch.body) for branch in statement.branches)):
            return True
    return False


def check_script(source: str) -> str | None:
    """Why the script breaks the format's static constraints, or None.

    The agent tolerates more than the format allows -- falling off the end is
    'return null' -- but an IoV must parse, compile, call only known functions
    and end every execution path in an explicit 'return'. The IoV server checks
    generated IoVs with this at ingestion.
    """
    try:
        body = parse(source)
    except ScriptError as exc:
        return f"parse error: {exc}"

    env = celpy.Environment()
    for line, expression in _expressions(body):
        try:
            env.compile(expression)
        except Exception as exc:
            return f"line {line}: {expression!r} is not a valid CEL expression: {exc}"

    unknown = unsupported_functions(source)
    if unknown:
        names = ", ".join(f"{name}()" for name in sorted(unknown))
        return f"calls functions that are neither built-ins nor part of CEL: {names}"

    if not _always_returns(body):
        last = body[-1] if body else None
        where = (f" (the 'if' on line {last.line} has a branch without a 'return', or no 'else')"
                 if isinstance(last, If) else "")
        return ("not every execution path ends in an explicit 'return': "
                f"the script can fall off its end{where}")
    return None


# ── Executor ──────────────────────────────────────────────────────────────────

class _Returned(Exception):
    def __init__(self, value):
        super().__init__(value)
        self.value = value


class _Interpreter:
    def __init__(self, activation: dict):
        self._activation = activation
        self._env = celpy.Environment()
        self._programs: dict[str, celpy.Runner] = {}
        self._statements = 0

    def _evaluate(self, expression: str, line: int):
        try:
            base.check_deadline()
        except base.SandboxLimit as exc:
            environment.limit_exceeded = str(exc)
            raise ScriptError(f"line {line}: {exc}") from exc
        program = self._programs.get(expression)
        if program is None:
            try:
                program = self._env.program(
                    self._env.compile(expression), functions=environment.FUNCTIONS
                )
            except Exception as exc:
                raise ScriptError(f"line {line}: cannot compile {expression!r}: {exc}") from exc
            self._programs[expression] = program

        try:
            value = program.evaluate(self._activation)
        except Exception as exc:
            raise ScriptError(f"line {line}: evaluating {expression!r} failed: {exc}") from exc
        # celpy reports some errors by returning them rather than raising.
        if isinstance(value, celpy.CELEvalError):
            raise ScriptError(f"line {line}: evaluating {expression!r} failed: {value}")
        return value

    def run(self, body: list) -> int | None:
        try:
            self._execute(body)
        except _Returned as returned:
            return returned.value
        return None  # falling off the end is 'return null'

    def _execute(self, body: list) -> None:
        for statement in body:
            self._statements += 1
            if self._statements > MAX_STATEMENTS:
                environment.limit_exceeded = f"the script exceeded {MAX_STATEMENTS} statements"
                raise ScriptError(environment.limit_exceeded)

            if isinstance(statement, Let):
                self._activation[statement.name] = self._evaluate(
                    statement.expression, statement.line
                )
            elif isinstance(statement, Return):
                raise _Returned(self._return_value(statement))
            else:
                self._execute_if(statement)

    def _return_value(self, statement: Return) -> int | None:
        value = self._evaluate(statement.expression, statement.line)
        if value is None:
            return None
        # BoolType subclasses int, so 'return true' must be rejected explicitly.
        if (isinstance(value, celtypes.IntType) and not isinstance(value, celtypes.BoolType)
                and int(value) in VALID_RETURN_VALUES):
            return int(value)
        raise ScriptError(
            f"line {statement.line}: return value must be null or an int 0..3, got {value!r}"
        )

    def _execute_if(self, statement: If) -> None:
        for branch in statement.branches:
            if branch.condition is None:
                self._execute(branch.body)
                return
            condition = self._evaluate(branch.condition, statement.line)
            if not isinstance(condition, celtypes.BoolType):
                raise ScriptError(
                    f"line {statement.line}: condition {branch.condition!r} "
                    f"is not a boolean, got {condition!r}"
                )
            if condition:
                self._execute(branch.body)
                return


def run_script(source: str) -> ScriptOutcome:
    """Run an IoV script and return its confidence level, or why it has none."""
    try:
        body = parse(source)
    except ScriptError as exc:
        log.warning("script parse error: %s", exc)
        return ScriptOutcome(None, f"parse error: {exc}")

    environment.limit_exceeded = None
    base.set_deadline(TIME_LIMIT)
    try:
        result = _Interpreter(environment.constants()).run(body)
    except ScriptError as exc:
        limit = environment.limit_exceeded is not None
        log.warning("script %s: %s", "hit a sandbox limit" if limit else "runtime error", exc)
        return ScriptOutcome(None, str(exc), limit)
    except Exception as exc:
        log.exception("unexpected failure while running the IoV script")
        return ScriptOutcome(None, f"internal error: {exc}")
    finally:
        base.set_deadline(None)

    log.info("script returned %s", result)
    return ScriptOutcome(result)
