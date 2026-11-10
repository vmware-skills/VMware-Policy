"""Credential redaction shared by audit decorators; audit copies only."""

from __future__ import annotations

import re
from typing import Any


def _redact(params: dict[str, Any], sensitive: set[str]) -> dict[str, Any]:
    """Return a copy of params with sensitive values replaced by '***'.

    Recurses into nested dicts AND lists/tuples so credentials buried inside
    collections (e.g. ``{"targets": [{"password": "x"}]}``) are redacted too.
    """
    if not sensitive:
        return params
    result: dict[str, Any] = {}
    for k, v in params.items():
        if k in sensitive:
            result[k] = "***"
        else:
            result[k] = _redact_value(v, sensitive)
    return result


def _redact_value(value: Any, sensitive: set[str]) -> Any:
    """Recursively redact sensitive keys inside dicts, lists, and tuples."""
    if isinstance(value, dict):
        return _redact(value, sensitive)
    if isinstance(value, (list, tuple)):
        return type(value)(_redact_value(item, sensitive) for item in value)
    return value


# ── Result redaction ──────────────────────────────────────────────────
#
# The audit row exists to answer "this tool was called, by whom, when, with
# which arguments, and did it succeed". A credential the tool *returned* is no
# part of that answer, and audit.db is the artefact most likely to be copied off
# the machine and attached to a ticket — so a secret filed there is worse than
# one in a log. Both redactions below rewrite the audit copy only; the caller
# always receives the real value, which is the entire point of tools like
# vmware-vks's ``issue_supervisor_kubeconfig``.

#: What a tool that declared ``sensitive_result=True`` contributes instead of
#: its return value. A truncated or hashed secret is still a finding, so the
#: field is either absent or says plainly that it was dropped.
_REDACTED_DECLARED = "[redacted: return value declared sensitive]"

#: What replaces a value filed under one of :data:`_CREDENTIAL_KEYS`.
_REDACTED_KEY = "[redacted: credential-shaped key]"

#: Key names whose value is never stored in an audit row, declaration or not.
#:
#: The declaration is the contract; this is the net for when a tool forgets it,
#: which CLAUDE.md 形态 #7 says will happen — a family-wide pattern fixed in one
#: repo and left alone in the other fourteen is this project's most repeated
#: failure. A new tool returning ``{"kubeconfig": ...}`` or ``{"token": ...}``
#: is therefore safe before anyone has thought about it.
#:
#: Matching is an EXACT (case-insensitive, ``-``/``_`` folded) key comparison
#: against this set, plus the ``_<word>`` tails in :data:`_CREDENTIAL_TAILS`
#: below — never a substring search: ``token_count`` and ``secret_manager_url``
#: are not credentials, and a check whose name promises more than it verifies is
#: its own recurring defect (形态 #4). A credential under a key matching neither
#: — say ``avi_secret_blob`` — is exactly what ``sensitive_result=True`` is for.
_CREDENTIAL_KEYS = frozenset(
    {
        "access_token",
        "api_key",
        "apikey",
        "auth",
        "auth_token",
        "authorization",
        "bearer",
        "bearer_token",
        "client_secret",
        "credential",
        "credentials",
        "kubeconfig",
        "passwd",
        "password",
        "private_key",
        "pwd",
        "refresh_token",
        "secret",
        "session_key",
        "session_token",
        "sessionkey",
        "token",
    }
)


#: Values that are already a redaction marker — left as they are, so applying
#: the net twice (once by a caller, once by audit_call) changes nothing.
_ALREADY_REDACTED = frozenset({"***", _REDACTED_KEY, _REDACTED_DECLARED})


#: Credential words that also count as the *tail* of a longer name —
#: ``vc_password``, ``new_password``, ``client_api_key``. Only after a ``_``, so
#: ``token_count`` and ``secret_manager_url`` (the word is not the tail) stay
#: readable. A probe filed ``vc_password`` in plain text before this existed.
_CREDENTIAL_TAILS = (
    "password",
    "passwd",
    "pwd",
    "token",
    "secret",
    "api_key",
    "apikey",
    "private_key",
    "credential",
    "credentials",
    "kubeconfig",
)


def _is_credential_key(key: Any) -> bool:
    name = str(key).strip().lower().replace("-", "_")
    return name in _CREDENTIAL_KEYS or any(name.endswith("_" + t) for t in _CREDENTIAL_TAILS)


def _scrub_text_values(value: Any) -> Any:
    """Run the free-form credential scrubber over every string in ``value``.

    For parameters: a credential inside free text — ``arguments="mysql
    --password=..."`` — is under no credential-shaped key, so the key net cannot
    see it. Returns the same object when nothing changed.
    """
    if isinstance(value, str):
        return _redact_secrets_text(value)
    if isinstance(value, dict):
        out = {k: _scrub_text_values(v) for k, v in value.items()}
        return value if all(out[k] is value[k] for k in value) else out
    if isinstance(value, (list, tuple)):
        items = [_scrub_text_values(v) for v in value]
        if all(a is b for a, b in zip(items, value)):
            return value
        return items if isinstance(value, list) else tuple(items)
    return value


def _redact_credential_keys(value: Any) -> Any:
    """Return ``value`` with credential-keyed entries replaced, recursively.

    Returns the *same object* when nothing matched, so an ordinary tool's result
    reaches the audit row byte-identical to what it returned and nothing is
    copied for no reason. When something does match, new containers are built —
    the object handed back to the caller is never mutated.
    """
    if isinstance(value, dict):
        redacted: dict[Any, Any] = {}
        changed = False
        for key, item in value.items():
            if _is_credential_key(key) and isinstance(item, str) and item in _ALREADY_REDACTED:
                # Declared parameters are already "***" by the time audit_call
                # applies this net to params; keep the declared marker.
                redacted[key] = item
            elif _is_credential_key(key):
                redacted[key] = _REDACTED_KEY
                changed = True
            else:
                new_item = _redact_credential_keys(item)
                changed = changed or new_item is not item
                redacted[key] = new_item
        return redacted if changed else value
    if isinstance(value, (list, tuple)):
        items = [_redact_credential_keys(item) for item in value]
        if all(new is old for new, old in zip(items, value)):
            return value
        return items if isinstance(value, list) else tuple(items)
    return value


# ── Free-form text redaction ──────────────────────────────────────────
#
# The other half of _redact_credential_keys. Key-based redaction cannot reach a
# credential that is inside an *exception message*: that is one string, not a
# dict, and the credential is in the middle of it.
#
# The keyword alternation is DERIVED from _CREDENTIAL_KEYS rather than written
# out again. Two hand-maintained lists of the same names drift, and the drift is
# invisible — a name added to one is simply not redacted by the other (CLAUDE.md
# 形态 #6). ``_`` is relaxed to ``[_-]?`` so ``api_key`` also covers ``api-key``
# and ``apikey``.
_SECRET_WORDS = "|".join(
    re.escape(k).replace("_", "[_-]?") for k in sorted(_CREDENTIAL_KEYS, key=len, reverse=True)
)

#: A credential name may be the *tail* of a longer identifier — ``access_token``,
#: ``client_secret``, ``VMWARE_VC_PASSWORD``, ``config.password``. The previous
#: pattern anchored on ``\b`` before the keyword, so every one of those leaked.
#: The keyword still has to end the identifier: the separator that follows can
#: only be ``:``/``=`` (optionally quoted), which is why ``token_count=5120`` and
#: ``secret_manager_url=...`` are not credentials and stay readable.
#:
#: The ``(?<![\w.\-])`` anchor is what keeps this linear. Without it the engine
#: tried a match at *every* position of an identifier, and each attempt scanned
#: the rest of it and backtracked: a 2000-character run of letters took 0.2 s,
#: 8000 took 3.4 s, a 50k-character guest command kept an audit write busy for
#: minutes (2026-09-19). The anchor's class is the prefix's class, so any match
#: that could start inside an identifier is also found from its start, and the
#: replacement keeps ``\1`` — the redacted text is unchanged.
_TOKEN_START = r"(?<![\w.\-])"
_KEY_PREFIX = _TOKEN_START + r"[\w.\-]*(?:" + _SECRET_WORDS + r")"

#: Value characters. ``@`` is *included* — ``password=P@ssw0rd`` used to redact a
#: single character and print the rest. DSN userinfo, which is why ``@`` was
#: excluded, has its own rule below and runs first.
#:
#: ``(`` is excluded as well as ``)``. With only the closing paren excluded,
#: ``auth=('admin', 'PASS')`` matched the opening paren alone and produced
#: ``auth=***'admin', 'PASS')`` — it destroyed the message *and* printed the
#: password. That is the most common way httpx and requests spell credentials,
#: so it reaches a traceback easily.
_VALUE = r"[^\s'\",;&\[\]\{\}\(\)<>]+"

#: Words that are a *report about* a credential, not a credential. Redacting
#: them inverts the sentence: ``password: not set`` became ``password: *** set``,
#: which reads as "a password is set". Measured over this family's own status
#: vocabulary, 12 of 17 phrases were rewritten and two of them reversed meaning.
#: Listed values are never secrets, so skipping them costs nothing.
_STATUS_WORDS = (
    r"(?!(?:not|no|none|null|unset|empty|missing|absent|set|configured|provided|"
    r"required|ok|yes|true|false|n/?a|was|is|were|are|will|has|have|been|"
    r"\*\*\*|<[^>]*>)\b)"
)

#: HTTP auth schemes. The Authorization rule below deliberately leaves the scheme
#: visible ("Basic" vs "Bearer" is the difference between two different
#: diagnoses), so the generic key=value rule that runs after it must not come
#: back and redact the scheme it just preserved.
_AUTH_SCHEMES = r"basic|bearer|digest|negotiate|ntlm|token|apikey"
_NOT_A_SCHEME = r"(?!(?:" + _AUTH_SCHEMES + r")\s)"

_REDACTIONS: tuple[tuple[re.Pattern[str], str], ...] = (
    # A credential pair spelled as a tuple: auth=('admin', 'hunter2'). This is
    # how httpx and requests are called, so it is what a traceback prints. The
    # generic key=value rule cannot help: its value class has to exclude the
    # parentheses, or it matches the opening paren alone and yields
    # ``auth=***'admin', 'PASS')`` -- the message destroyed and the password
    # still there. Redacting the whole group is the only reading that is safe
    # whichever element holds the secret.
    (
        re.compile(
            r"(?i)(" + _TOKEN_START + r"[\w.\-]*(?:auth|credential|credentials)" + r")"
            r"(\s*=\s*)\([^()]*\)"
        ),
        r"\1\2(***)",
    ),
    # PEM private key blocks — no key=value shape at all, previously untouched.
    (
        re.compile(
            r"(-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)"
            r".*?"
            r"(-----END (?:[A-Z0-9 ]+ )?PRIVATE KEY-----)",
            re.DOTALL,
        ),
        r"\1***\2",
    ),
    # URL / DSN userinfo: scheme://user:secret@host
    #
    # Both halves may contain ``@`` and the old classes excluded it from both.
    # A vSphere SSO username *always* contains one (``administrator@vsphere.local``),
    # so the rule did not fire at all on this family's own URLs; and a password
    # containing one made the match stop early and print the tail
    # (``https://admin:***@c1QJwp@nsx/`` — a real password fragment).
    # The username is non-greedy and the password greedy up to the last ``@``
    # before the host, which is what a URL parser does.
    (
        # The scheme is bounded ({0,63}) rather than anchored: a lookbehind would
        # stop ``+http://u:p@h`` matching after the ``+``, and an unbounded scheme
        # made every word boundary of ``a.a.a…`` rescan to the end (quadratic).
        re.compile(
            r"(?i)\b([a-z][a-z0-9+.\-]{0,63}://[^\s/:]*?):([^\s/]*)@(?=[^\s/@]*(?:[/\s?#]|$))"
        ),
        r"\1:***@",
    ),
    # Cookie / Set-Cookie: the whole header value is credential material.
    (re.compile(r"(?i)\b((?:set-)?cookie)(\s*[:=]\s*)[^\r\n]+"), r"\1\2***"),
    # Authorization: <scheme> <credential>. The scheme is diagnostic and stays;
    # everything after it goes. The old pattern masked the word "Basic" and left
    # the base64 — the example named in the re-test report.
    (
        re.compile(
            r"(?i)\b((?:proxy-)?authorization)"
            r"(\s*['\"]?\s*[:=]\s*['\"]?\s*)"
            r"(" + _AUTH_SCHEMES + r")"
            r"(\s+)"
            r"[^\s'\",;]+"
        ),
        r"\1\2\3\4***",
    ),
    # A bare scheme + credential, with no Authorization: in front of it. The
    # length floor keeps "Basic health check passed" and "Bearer of record"
    # readable — over-redaction destroys the teaching errors.
    (
        re.compile(r"(?i)\b(basic|bearer)(\s+)([A-Za-z0-9+/=_.\-]{16,})(?![\w+/=.\-])"),
        r"\1\2***",
    ),
    # SOAP / XML element: <password>secret</password>
    (
        re.compile(r"(?i)<(" + _KEY_PREFIX + r")>[^<]*</\1>"),
        r"<\1>***</\1>",
    ),
    # Quoted value — how a traceback prints a dict: {"token": "x"} / {'pwd': 'x'}
    (
        re.compile(
            r"(?i)("
            + _KEY_PREFIX
            + r")(['\"]?\s*[:=]\s*)(['\"])"
            + _NOT_A_SCHEME
            + r"[^'\"\r\n]*\3"
        ),
        r"\1\2\3***\3",
    ),
    # CLI flag: --password secret / -token secret (whitespace separator, but only
    # after a dash, so "password policy requires 15 characters" survives).
    (
        re.compile(
            # Anchored at the start of the dashed word and allowed a word prefix
            # (``foo--token``): matching from every dash made a run of dashes
            # quadratic. ``\1`` keeps whatever the prefix matched.
            r"(?i)((?<![\w\-])\w*-{1,2}[\w\-]*(?:"
            + _SECRET_WORDS
            + r"))(\s+)"
            + _STATUS_WORDS
            + r"[^\s'\",;]+"
        ),
        r"\1\2***",
    ),
    # Tools that carry the credential in a flag with no credential-sounding name.
    # ``curl -u user:pass``, ``--user``, ``sshpass -p``. Nothing in the text says
    # "password", so every keyword rule above walks straight past them.
    (
        re.compile(r"(?i)(\B-u|--user)(\s+)([^\s'\",;:]+):[^\s'\",;]+"),
        r"\1\2\3:***",
    ),
    (
        re.compile(r"(?i)\b(sshpass\s+-p)(\s*)[^\s'\",;]+"),
        r"\1\2***",
    ),
    # netrc: ``machine host login user password secret``. Whitespace-separated
    # with no dash, which the flag rule above deliberately requires so that
    # "password policy requires 15 characters" survives. Anchoring on the
    # preceding ``login <user>`` keeps that sentence readable.
    (
        re.compile(r"(?i)\b(login\s+\S+\s+password)(\s+)[^\s'\",;]+"),
        r"\1\2***",
    ),
    # Unquoted key=value / key: value.
    (
        re.compile(
            r"(?i)(" + _KEY_PREFIX + r")(\s*[:=]\s*)" + _NOT_A_SCHEME + _STATUS_WORDS + _VALUE
        ),
        r"\1\2***",
    ),
    # A bare JWT with no key in front of it — a Supervisor token pasted into an
    # error message is self-identifying and needs no keyword.
    (
        re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*"),
        "***",
    ),
)


def _redact_secrets_text(text: str) -> str:
    """Redact credential values in free-form text (exception messages, tracebacks).

    Ordered rules, most specific first: the DSN rule has to run before the
    generic ``key=value`` one, and the ``Authorization:`` rule before the bare
    ``Basic``/``Bearer`` one, or the broader pattern eats the narrower one's
    context and the result is less readable for no gain in safety.

    Idempotent: re-running it over already-redacted text leaves it unchanged, so
    a string that passes through two layers is not corrupted.
    """
    for pattern, replacement in _REDACTIONS:
        text = pattern.sub(replacement, text)
    return text
