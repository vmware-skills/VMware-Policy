"""Audit redaction runs in time linear in its input.

Found 2026-09-19 while gating AIops' guest tools: a long ``arguments`` value
kept a single MCP call busy for minutes, inside the audit write. Five rules began
with an unanchored identifier prefix (``[\\w.\\-]*`` before a credential word,
``-{1,2}[\\w\\-]*`` for CLI flags, an unbounded URI scheme after ``\\b``). The
engine tried a match at every position of an identifier and each attempt scanned
the rest of it, so a run of letters, dots or dashes cost O(n²):

    2000 chars 0.2 s · 8000 chars 3.4 s (letters) / 6.5 s (dashes)

Every tool in the family audits through this path, so any free-text argument
(a guest command, a description, an annotation) could stall a call.

The fix anchors the prefixes at the start of an identifier (the anchor's class
is the prefix's class, so no match is lost) and bounds the URI scheme. Its
output was checked against the previous rules on 200 000 generated strings with
zero differences; a naive anchoring of the flag rule differed on 524, which is
why the flag rule keeps a word prefix. The shapes that reasoning depended on are
pinned below.
"""

from __future__ import annotations

import time

import pytest

from vmware_policy.decorators import _redact_secrets_text

N = 100_000

#: Generous: the fixed rules take a few milliseconds here, the old ones took
#: hours on the worst shape. The bound only has to separate those.
BOUND_S = 2.0

SHAPES = {
    "letters": "a" * N,
    "dashes": "-" * N,
    "dotted": "a." * (N // 2),
    "hyphenated": "a-" * (N // 2),
    "dash-letter": "-a" * (N // 2),
    "underscored": "a_" * (N // 2),
}


@pytest.mark.unit
@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_long_identifier_runs_redact_in_linear_time(shape):
    text = SHAPES[shape]
    start = time.perf_counter()
    _redact_secrets_text(text)
    elapsed = time.perf_counter() - start
    assert elapsed < BOUND_S, f"{shape}: {N} chars took {elapsed:.2f}s"


@pytest.mark.unit
def test_a_secret_inside_a_long_input_is_still_redacted():
    """Positive control: speed must not come from skipping long inputs."""
    text = "a" * N + " password=hunter2 " + "-" * N + " --api-key abc123 " + "a." * 1000
    start = time.perf_counter()
    out = _redact_secrets_text(text)
    assert time.perf_counter() - start < BOUND_S
    assert "hunter2" not in out and "abc123" not in out
    assert "password=***" in out and "--api-key ***" in out


# Shapes the rewrite had to preserve. Each is a place where the new anchor could
# plausibly have lost a match that the unanchored rule found.


@pytest.mark.unit
@pytest.mark.parametrize(
    ("text", "secret"),
    [
        ("VMWARE_VC_PASSWORD=hunter2", "hunter2"),  # keyword at the tail of an identifier
        ("config.password: hunter2", "hunter2"),  # dotted identifier
        ("x-access-token='hunter2'", "hunter2"),  # hyphenated, quoted
        ("foo--token hunter2", "hunter2"),  # flag glued to a word
        ("run.sh --db-password hunter2", "hunter2"),
        ("x.auth=('admin', 'hunter2')", "hunter2"),  # tuple rule on a dotted name
        ("+http://admin:hunter2@vc.local/", "hunter2"),  # URI after a non-word char
        ("git+ssh://admin:hunter2@host/repo", "hunter2"),
    ],
)
def test_prefix_shapes_still_redact(text, secret):
    assert secret not in _redact_secrets_text(text)


@pytest.mark.unit
def test_status_words_after_a_flag_still_survive():
    assert _redact_secrets_text("--password not set") == "--password not set"
