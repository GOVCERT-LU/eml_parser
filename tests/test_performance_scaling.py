"""Performance scaling tests: the cost of parsing a message must grow linearly with the size of its content.

Why
---
eml_parser is used to triage untrusted mail (incident response, phishing analysis, sandboxes), so every input it parses
is attacker controlled. If any part of the parser does work that grows faster than linearly with some property of the
message, a small message can tie up an analysis worker for a long time. MSL-2026-030 was such a case: collecting the
header values called ``Message.get_all()`` once per header name, and every call scans all header fields, so the cost was
quadratic in the number of fields. A compliant 1 MiB message with 21,000 small fields took about 44 s to parse, the same
1 MiB as a single field took 11 ms.

Such regressions are easy to reintroduce with an innocent looking change, and an ordinary functional test does not notice
them. These tests build messages in which one property (header fields, body URLs, MIME parts, ...) grows while everything
else stays the same, and fail if the parsing cost grows faster than that property.

What is measured
----------------
Every shape in ``SHAPES`` builds one message per size, e.g. 5,250, 10,500 and 21,000 header fields (the sizes of the
MSL-2026-030 report). Two measurements are taken:

1. Function calls (deterministic). ``sys.setprofile`` counts every Python and C-level function call made while the message
   is parsed. A quadratic Python loop shows up as a quadratic number of calls, e.g. the ``str.lower()`` per header field
   per ``get_all()`` call of MSL-2026-030. The count is the same on every run on a given interpreter, so it does not
   depend on the speed or load of the machine. For each step between two sizes the growth exponent
   ``log(calls ratio) / log(size ratio)`` is computed: 1.0 is linear, 2.0 is quadratic. Every step must stay at or below
   ``MAX_CALL_EXPONENT`` (or the shape's own limit).

2. CPU time. A single C-level call can hide any amount of work, e.g. a regular expression that backtracks over its whole
   input, so call counts alone cannot see super-linear behaviour inside C code. The CPU time (best of
   ``CPU_REPETITIONS`` runs) of the smallest and the largest size gives a second exponent, which must stay at or below
   ``MAX_CPU_EXPONENT``. This limit is looser, as timings have noise.

Only ratios between sizes are compared, never absolute numbers, so the tests work on any machine and Python version.

Measurement details
-------------------
* Header cache: ``CustomPolicy._fetch_fixed_header`` caches parsed header values in a bounded LRU cache. When a message has
  more distinct values than the cache holds, accesses miss and values are parsed more than once. That is a constant
  factor, but it starts at a size threshold and would look like super-linear growth between sizes on either side of it.
  The tests therefore give the cache an unbounded size and clear it before each measurement.
* Header parsing limits: beyond ``constants.MAX_PARSED_HEADER_FIELDS`` fields or ``MAX_PARSED_HEADER_BYTES`` bytes, header
  values are kept raw instead of being parsed. That would hide the cost of the structured parsing above the limit (21,000
  fields is above it), so the limits are switched off, except for shapes that test the limits themselves
  (``header_limits=True``). The limits are defence in depth; the algorithms must be linear without them.
* Garbage collection is paused while timing. The collector's work grows with the number of live objects and adds
  super-linear noise to the CPU time of allocation heavy shapes, which says nothing about the parser's algorithms.
* Fail fast: a run that exceeds the budget of the allowed exponent is stopped (call count via the profiler, CPU time via
  ``signal.setitimer`` where available), so a quadratic regression fails within seconds or minutes instead of parsing for
  a very long time.

How to run
----------
These tests are marked ``slow`` and skipped by default, so they do not slow down the regular CI job (``pytest -v tests``).
The whole module takes a few minutes. Enable them with the ``--run-slow`` option (defined in ``tests/conftest.py``)::

    pytest --run-slow tests/test_performance_scaling.py -v                          # all scaling tests
    pytest --run-slow tests/test_performance_scaling.py -v -k 'header-fields'       # one shape
    pytest --run-slow -m slow tests                                                 # all slow tests of the suite
    pytest --run-slow tests                                                         # the whole suite, slow tests included

How to read a failure
---------------------
The failure message lists the measurement per size and the growth exponent per step. An exponent well above 1 means that
the shape's property makes the parser do more work per unit than before, e.g. a loop over all header fields for each
header field. Profile the largest message of the shape to find the code whose call count grows faster than the size.

Regular expressions
-------------------
The body is searched in slices of at most about 8 KiB (``EmlParser.string_sliding_window_loop()``), which caps the cost of a
pattern that is super-linear in the length of a single token, so such a pattern is hardly visible when parsing a message.
The patterns in ``REGEX_SHAPES`` are therefore also measured on their own, on one long token, by CPU time only (a search is
a single C-level call).

Adding a shape
--------------
Add an entry to ``SHAPES`` that varies exactly one property. Keep the smallest size large enough that fixed per-message
costs do not dominate (CPU time of the smallest message at least about 20 ms) and keep all sizes on the same side of any
size limit of the parser (e.g. ``EmlParser.MULTIPART_RECURSION_LIMIT`` or ``constants.MAX_PARSED_HEADER_SIZE``).
"""

import base64
import contextlib
import dataclasses
import functools
import gc
import logging
import math
import signal
import sys
import threading
import time
import typing

import pytest

import eml_parser
import eml_parser.constants
import eml_parser.parser
import eml_parser.regexes

# Growth exponent limits: 1.0 is linear, 2.0 is quadratic. N log N stays below 1.1 at the sizes used here.
MAX_CALL_EXPONENT = 1.3
MAX_CPU_EXPONENT = 1.5
CPU_REPETITIONS = 3

# The sizes of the MSL-2026-030 report.
REPORT_FIELD_COUNTS = (5_250, 10_500, 21_000)

HEAD = 'From: a@example.test\r\nTo: b@example.test\r\nSubject: scaling\r\nDate: Thu, 15 Oct 2026 12:00:00 +0000\r\nMIME-Version: 1.0\r\n'


# ---------------------------------------------------------------------------------------------------------------------
# Message builders
# ---------------------------------------------------------------------------------------------------------------------


def _message(body: str = 'body', content_type: str = 'text/plain; charset=us-ascii', headers: typing.Iterable[str] = ()) -> bytes:
    """A message with the base headers, the given extra header lines and body."""
    extra = ''.join(f'{line}\r\n' for line in headers)
    return f'{HEAD}{extra}Content-Type: {content_type}\r\n\r\n{body}\r\n'.encode()


def _lines(items: typing.Iterable[str], per_line: int = 5) -> str:
    """Join items into body lines of per_line items, keeping every line well below 998 characters."""
    items = list(items)
    return '\r\n'.join(' '.join(items[i : i + per_line]) for i in range(0, len(items), per_line))


def _multipart(parts: typing.Iterable[str], boundary: str = 'b0') -> bytes:
    body = ''.join(f'--{boundary}\r\n{part}\r\n' for part in parts) + f'--{boundary}--'
    return _message(body, f'multipart/mixed; boundary="{boundary}"')


def _attachment(i: int, size: int = 64) -> str:
    data = base64.encodebytes(bytes((i * 7 + j) % 256 for j in range(size))).decode().replace('\n', '\r\n')
    return (
        f'Content-Type: application/octet-stream; name="f{i}.bin"\r\n'
        f'Content-Disposition: attachment; filename="f{i}.bin"\r\n'
        f'Content-Transfer-Encoding: base64\r\n\r\n{data}'
    )


def _nested_multipart(depth: int) -> bytes:
    """Multiparts nested depth levels deep, every level with a text sibling."""
    inner = 'Content-Type: text/plain\r\n\r\nleaf http://leaf.example.test/\r\n'
    for d in range(depth):
        inner = (
            f'Content-Type: multipart/mixed; boundary="n{d}"\r\n\r\n'
            f'--n{d}\r\n{inner}\r\n'
            f'--n{d}\r\nContent-Type: text/plain\r\n\r\nsibling {d} http://s{d}.example.test/\r\n'
            f'--n{d}--\r\n'
        )
    return (HEAD + inner).encode()


def _report_message(n: int) -> bytes:
    """The MSL-2026-030 proof of concept message: exactly 1 MiB, the header block split into n fields of equal size."""
    total = 1_048_576
    head = [
        'From: Alice <alice@sender.test>',
        'To: <cost@sink.test>',
        'Subject: MSL-2026-030 repro',
        'Date: Thu, 15 Oct 2026 12:00:00 +0000',
        'Content-Type: text/plain; charset=us-ascii',
    ]
    header_bytes = total - 1024 - len(head[0])
    per_field = (header_bytes - (n - 1) * 2) // n
    slack = header_bytes - (n * per_field + (n - 1) * 2)
    for i in range(n):
        name = f'X-F{i}'
        head.append(f'{name}: {"F" * (per_field - len(name) - 2 + (1 if i < slack else 0))}')
    head.insert(3, f'X-Lab-Trace-ID: msl030-fields{n}')
    head.insert(4, f'Message-ID: <msl030-fields{n}@msl030.test>')
    head_block = ('\r\n'.join(head) + '\r\n\r\n').encode()

    remaining = total - len(head_block) - len('msl030-body') - 2
    lines = ['msl030-body']
    while remaining >= 66:
        lines.append('P' * 64)
        remaining -= 66
    if remaining >= 2:
        lines.append('P' * (remaining - 2))
    elif remaining == 1:
        lines[-1] += 'P'
    raw = head_block + ('\r\n'.join(lines) + '\r\n').encode()
    assert len(raw) == total
    return raw


# ---------------------------------------------------------------------------------------------------------------------
# Shapes: one property of the message grows, everything else stays the same
# ---------------------------------------------------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class Shape:
    build: typing.Callable[[int], bytes]
    sizes: tuple[int, int, int]
    unit: str
    max_call_exponent: float = MAX_CALL_EXPONENT
    # False for shapes whose smallest message parses too quickly for a meaningful timing.
    check_cpu: bool = True
    # An exception the parser raises on purpose for this shape (e.g. when a limit is exceeded).
    expected_exception: type[Exception] | None = None
    # True to measure with the production header parsing limits, False (the default) to measure the parsing algorithms without them.
    header_limits: bool = False


SHAPES: dict[str, Shape] = {
    # --- header fields (MSL-2026-030), at the sizes of the report ---
    # the reporter's exact input: constant 1 MiB, the header block split into more and more distinct fields
    'header-fields-report-1MiB': Shape(_report_message, REPORT_FIELD_COUNTS, 'header fields'),
    'header-fields-distinct-names': Shape(lambda n: _message(headers=(f'X-F{i}: value-{i}' for i in range(n))), REPORT_FIELD_COUNTS, 'header fields'),
    # names differing only in case must be grouped, not processed once per spelling
    'header-fields-mixed-case-names': Shape(
        lambda n: _message(headers=(f'{"X-F" if i % 2 else "x-f"}{i // 2}: value-{i}' for i in range(n))), REPORT_FIELD_COUNTS, 'header fields'
    ),
    'header-fields-same-name': Shape(lambda n: _message(headers=(f'X-Same: value-{i}' for i in range(n))), REPORT_FIELD_COUNTS, 'header fields'),
    # Received lines are parsed into the routing information
    'header-fields-received': Shape(
        lambda n: _message(headers=(f'Received: from h{i}.example.test by mx.example.test; Thu, 15 Oct 2026 12:00:00 +0000' for i in range(n))),
        REPORT_FIELD_COUNTS,
        'header fields',
    ),
    # address headers are parsed by the stdlib address parser and the address extraction
    'header-fields-cc': Shape(lambda n: _message(headers=(f'Cc: c{i}@example.test' for i in range(n))), REPORT_FIELD_COUNTS, 'header fields'),
    # RFC 2047 encoded words are decoded per field
    'header-fields-encoded-words': Shape(
        lambda n: _message(headers=(f'X-E{i}: =?utf-8?q?h=C3=A9llo_{i}?=' for i in range(n))), REPORT_FIELD_COUNTS, 'header fields'
    ),
    # --- content of a single header field ---
    # many addresses in one folded Cc field (above MAX_PARSED_HEADER_SIZE at every size, so always the fallback path)
    'header-value-addresses': Shape(
        lambda n: _message(headers=['Cc: ' + ',\r\n '.join(f'u{i} <u{i}@d{i}.example.test>' for i in range(n))]), (2_000, 4_000, 8_000), 'addresses'
    ),
    'header-value-authentication-results': Shape(
        lambda n: _message(
            headers=['Authentication-Results: mx.example.test;\r\n ' + ';\r\n '.join(f'spf=pass smtp.mailfrom=s{i}.example.test' for i in range(n))]
        ),
        (4_000, 8_000, 16_000),
        'methods',
    ),
    # --- body: the indicator extraction (sliding window, URL, e-mail, domain, IP and share regexes) ---
    'body-plain-text': Shape(lambda n: _message(_lines((f'word{i}' for i in range(n)), 10)), (50_000, 100_000, 200_000), 'words'),
    'body-urls': Shape(lambda n: _message(_lines(f'http://h{i}.example{i % 97}.test/p{i}?q={i}' for i in range(n))), REPORT_FIELD_COUNTS, 'URLs'),
    'body-html-hrefs': Shape(
        lambda n: _message(_lines(f'<a href="https://h{i}.example.test/p{i}">l{i}</a>' for i in range(n)), 'text/html; charset=us-ascii'),
        REPORT_FIELD_COUNTS,
        'links',
    ),
    'body-email-addresses': Shape(lambda n: _message(_lines(f'u{i}@h{i}.example.test' for i in range(n))), REPORT_FIELD_COUNTS, 'addresses'),
    'body-domains': Shape(lambda n: _message(_lines(f'h{i}.example{i % 89}.test' for i in range(n))), REPORT_FIELD_COUNTS, 'domains'),
    'body-ip-addresses': Shape(
        lambda n: _message(_lines(f'10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256} 2001:db8::{i:x}' for i in range(n))),
        REPORT_FIELD_COUNTS,
        'IPv4/IPv6 pairs',
    ),
    'body-unc-shares': Shape(lambda n: _message(_lines(f'\\\\h{i}.example.test\\share{i}' for i in range(n))), REPORT_FIELD_COUNTS, 'shares'),
    # --- MIME structure and attachments ---
    'mime-text-parts': Shape(
        lambda n: _multipart(f'Content-Type: text/plain\r\n\r\npart {i} http://p{i}.example.test/' for i in range(n)), (1_000, 2_000, 4_000), 'parts'
    ),
    'mime-attachments': Shape(lambda n: _multipart(_attachment(i) for i in range(n)), (1_000, 2_000, 4_000), 'attachments'),
    'mime-attachment-size': Shape(lambda n: _multipart([_attachment(0, n)]), (1_000_000, 2_000_000, 4_000_000), 'attachment bytes'),
    # multipart without boundary parameter: the boundary is guessed and the parts repaired
    'mime-broken-multipart-parts': Shape(
        lambda n: _message(''.join(f'--b0\r\nContent-Type: text/plain\r\n\r\npart {i}\r\n' for i in range(n)) + '--b0--', 'multipart/mixed'),
        (1_000, 2_000, 4_000),
        'parts',
    ),
    # Nesting up to EmlParser.MULTIPART_RECURSION_LIMIT (100). The stdlib feed parser compares every line with every
    # enclosing boundary, i.e. lines x depth, which is quadratic in the depth for this shape. That is inherent and bounded
    # by the limit, so this shape has a quadratic allowance and only guards against anything worse.
    'mime-nesting-up-to-limit': Shape(_nested_multipart, (25, 50, 100), 'nesting levels', max_call_exponent=2.2, check_cpu=False),
    # Nesting far beyond the limit must be rejected cheaply. At these depths the stdlib parser itself runs out of stack while building the
    # message, so decode_email_bytes() raises RecursionError, the same exception as for nesting beyond MULTIPART_RECURSION_LIMIT.
    'mime-nesting-beyond-limit': Shape(_nested_multipart, (4_000, 8_000, 16_000), 'nesting levels', expected_exception=RecursionError),
    # --- header parsing limits (constants.MAX_PARSED_HEADER_FIELDS / MAX_PARSED_HEADER_BYTES), with the production limits ---
    # Far beyond the field limit the values are kept raw. That handling must stay linear (and cheap) however many fields follow.
    'header-fields-beyond-parsing-limit': Shape(
        lambda n: _message(headers=(f'X-F{i}: value-{i}' for i in range(n))), (40_000, 80_000, 160_000), 'header fields', header_limits=True
    ),
}


# Regular expressions on one long token built from a repeated unit, see "Regular expressions" in the module docstring.
REGEX_SIZES = (200_000, 800_000)

REGEX_SHAPES: dict[str, tuple[typing.Any, str]] = {
    # labels of two characters: the former dom_regex took 5 s for 480 KB
    'dom-regex-two-character-labels': (eml_parser.regexes.dom_regex, 'ab.'),
    'dom-regex-hyphenated-labels': (eml_parser.regexes.dom_regex, 'a-a.'),
    'dom-regex-one-character-labels': (eml_parser.regexes.dom_regex, 'a.'),
    # the last label is checked after the labels were matched, a failing check must not restart the search inside the token
    'dom-regex-numeric-tld': (eml_parser.regexes.dom_regex, 'a.1'),
    'dom-regex-encoded-dots': (eml_parser.regexes.dom_regex, 'a.a&#46;'),
}


# ---------------------------------------------------------------------------------------------------------------------
# Measurement
# ---------------------------------------------------------------------------------------------------------------------


class _BudgetExceeded(BaseException):
    """Stops a measurement early. A BaseException, so that `except Exception` in the parser cannot swallow it."""


@pytest.fixture
def header_cache(monkeypatch: pytest.MonkeyPatch) -> typing.Any:
    """Give the parsed header cache an unbounded size for the test, see "Measurement details" in the module docstring."""
    cached = eml_parser.parser.CustomPolicy._fetch_fixed_header  # noqa: SLF001 - the cache has no public interface
    if not hasattr(cached, '__wrapped__'):
        return None

    unbounded = functools.lru_cache(maxsize=None)(cached.__wrapped__)
    monkeypatch.setattr(eml_parser.parser.CustomPolicy, '_fetch_fixed_header', unbounded)
    return unbounded


@contextlib.contextmanager
def _quiet_parse_environment(header_cache: typing.Any) -> typing.Iterator[None]:
    """Cold header cache, no log output (some shapes log a warning per field) and no garbage collection."""
    if header_cache is not None:
        header_cache.cache_clear()
    gc.collect()
    gc.disable()
    logging.disable(logging.CRITICAL)
    try:
        yield
    finally:
        logging.disable(logging.NOTSET)
        gc.enable()


def _parse(shape: Shape, raw: bytes) -> None:
    ep = eml_parser.EmlParser(include_raw_body=True, include_attachment_data=True)
    if shape.expected_exception is None:
        ep.decode_email_bytes(raw)
    else:
        with contextlib.suppress(shape.expected_exception):
            ep.decode_email_bytes(raw)


def _count_calls(shape: Shape, raw: bytes, header_cache: typing.Any, budget: float = math.inf) -> tuple[int, bool]:
    """Count the Python and C function calls made while parsing raw. Returns the count and whether the budget stopped the run."""
    calls = 0

    def profiler(frame: typing.Any, event: str, arg: typing.Any) -> None:
        nonlocal calls
        if event in ('call', 'c_call'):
            calls += 1
            if calls > budget:
                raise _BudgetExceeded

    with _quiet_parse_environment(header_cache):
        sys.setprofile(profiler)
        try:
            _parse(shape, raw)
        except _BudgetExceeded:
            return calls, True
        finally:
            sys.setprofile(None)
    return calls, False


@contextlib.contextmanager
def _cpu_time_limit(seconds: float) -> typing.Iterator[None]:
    """Raise _BudgetExceeded once the process used `seconds` of CPU time. Only on platforms with setitimer, in the main thread."""
    if not hasattr(signal, 'setitimer') or threading.current_thread() is not threading.main_thread() or math.isinf(seconds):
        yield
        return

    def on_timer(signum: int, frame: typing.Any) -> None:
        raise _BudgetExceeded

    previous = signal.signal(signal.SIGPROF, on_timer)
    signal.setitimer(signal.ITIMER_PROF, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_PROF, 0)
        signal.signal(signal.SIGPROF, previous)


def _cpu_time(run: typing.Callable[[], object], header_cache: typing.Any, budget: float = math.inf) -> tuple[float, bool]:
    """Best CPU time of CPU_REPETITIONS calls of run. Returns the time and whether the budget stopped the run."""
    best = math.inf
    for _ in range(CPU_REPETITIONS):
        with _quiet_parse_environment(header_cache):
            start = time.process_time()
            try:
                with _cpu_time_limit(budget):
                    run()
            except _BudgetExceeded:
                return time.process_time() - start, True
            best = min(best, time.process_time() - start)
    return best, False


def _exponent(value_ratio: float, size_ratio: float) -> float:
    return math.log(value_ratio) / math.log(size_ratio)


# ---------------------------------------------------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.parametrize('name', list(SHAPES))
def test_parsing_cost_scales_linearly(name: str, header_cache: typing.Any, monkeypatch: pytest.MonkeyPatch) -> None:
    shape = SHAPES[name]
    sizes = shape.sizes
    if not shape.header_limits:
        monkeypatch.setattr(eml_parser.constants, 'MAX_PARSED_HEADER_FIELDS', math.inf)
        monkeypatch.setattr(eml_parser.constants, 'MAX_PARSED_HEADER_BYTES', math.inf)
    messages = [shape.build(n) for n in sizes]

    # 1. Function calls, every step between two sizes.
    previous_calls, _ = _count_calls(shape, messages[0], header_cache)
    report = [f'{sizes[0]:,} {shape.unit}: {previous_calls:,} calls']
    for i in range(1, len(sizes)):
        size_ratio = sizes[i] / sizes[i - 1]
        budget = previous_calls * size_ratio**shape.max_call_exponent
        calls, stopped = _count_calls(shape, messages[i], header_cache, budget)
        exponent = _exponent(calls / previous_calls, size_ratio)
        if stopped:
            report.append(f'{sizes[i]:,} {shape.unit}: stopped after {calls:,} calls, exponent > {exponent:.2f}')
        else:
            report.append(f'{sizes[i]:,} {shape.unit}: {calls:,} calls, exponent {exponent:.2f}')
        assert not stopped and exponent <= shape.max_call_exponent, (
            f'{name}: the number of function calls grows super-linearly with the number of {shape.unit} '
            f'(1.0 linear, 2.0 quadratic, limit {shape.max_call_exponent}):\n  ' + '\n  '.join(report)
        )
        previous_calls = calls

    if not shape.check_cpu:
        return

    # 2. CPU time, smallest to largest size.
    size_ratio = sizes[-1] / sizes[0]
    small, _ = _cpu_time(lambda: _parse(shape, messages[0]), header_cache)
    # Generous budget: the allowed growth, doubled for timing noise, plus a second for very small timings.
    large, stopped = _cpu_time(lambda: _parse(shape, messages[-1]), header_cache, budget=2 * small * size_ratio**MAX_CPU_EXPONENT + 1)
    exponent = _exponent(large / small, size_ratio)
    timing = [f'{sizes[0]:,} {shape.unit}: {small * 1000:,.0f} ms CPU', f'{sizes[-1]:,} {shape.unit}: {large * 1000:,.0f} ms CPU']
    if stopped:
        timing[-1] = f'{sizes[-1]:,} {shape.unit}: stopped after {large * 1000:,.0f} ms CPU'
    assert not stopped and exponent <= MAX_CPU_EXPONENT, (
        f'{name}: the CPU time grows super-linearly with the number of {shape.unit} although the call count does not, '
        f'which points at C-level work such as a backtracking regular expression '
        f'(exponent {"> " if stopped else ""}{exponent:.2f}, 1.0 linear, 2.0 quadratic, limit {MAX_CPU_EXPONENT}):\n  ' + '\n  '.join(timing)
    )


@pytest.mark.slow
@pytest.mark.parametrize('name', list(REGEX_SHAPES))
def test_regex_cost_scales_linearly(name: str) -> None:
    pattern, unit = REGEX_SHAPES[name]
    small_text, large_text = (unit * n for n in REGEX_SIZES)
    size_ratio = REGEX_SIZES[-1] / REGEX_SIZES[0]

    small, _ = _cpu_time(lambda: pattern.findall(small_text), None)
    # A signal cannot interrupt a search, so the budget is enforced by the timeout of the regex module.
    budget = 2 * small * size_ratio**MAX_CPU_EXPONENT + 1
    try:
        large, stopped = _cpu_time(lambda: pattern.findall(large_text, timeout=budget), None)
    except TimeoutError:
        large, stopped = budget, True
    exponent = _exponent(large / small, size_ratio)

    assert not stopped and exponent <= MAX_CPU_EXPONENT, (
        f'{name}: the CPU time grows super-linearly with the length of the token {unit!r}... '
        f'(exponent {"> " if stopped else ""}{exponent:.2f}, 1.0 linear, 2.0 quadratic, limit {MAX_CPU_EXPONENT}): '
        f'{REGEX_SIZES[0]:,} units {small * 1000:,.0f} ms, {REGEX_SIZES[-1]:,} units {"stopped after " if stopped else ""}{large * 1000:,.0f} ms CPU'
    )
