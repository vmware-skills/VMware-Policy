"""Credentials inside a result's free text never reach the audit row.

Review finding D3, 2026-09-15. ``audit_call`` ran the free-text scrubber over
``params`` but only the credential-key net over ``result``. A result that quotes
text it was handed — vmware-debug's ``incident_timeline`` returns event text as
``hypotheses[].sample_text`` — carries a credential under no credential-shaped
key, so a probe with ``password=Hunter2Secret!`` and
``https://admin:S3cr3tPW@vc01`` in an event filed both secrets in the row. The
scrubber now runs over the result as well, on every surface.
"""

from __future__ import annotations

import json

import pytest

from vmware_policy import vmware_tool
from vmware_policy.cli_guard import audited
from vmware_policy.guard import audit_call

SECRETS = ("Hunter2Secret!", "S3cr3tPW")
EVENT_TEXT = "login failed password=Hunter2Secret! via https://admin:S3cr3tPW@vc01"


@pytest.fixture
def rows(monkeypatch):
    captured: list[dict] = []

    class _Recorder:
        def log(self, **kw):
            captured.append(kw)

    monkeypatch.setattr("vmware_policy.guard.get_engine", lambda: _Recorder())
    return captured


def _assert_scrubbed(row: dict) -> str:
    stored = json.dumps(row["result"], default=str)
    for secret in SECRETS:
        assert secret not in stored, f"{secret!r} reached the audit row: {stored}"
    return stored


def test_audit_call_scrubs_free_text_in_a_nested_result(rows):
    result = {
        "event_count": 1,
        "hypotheses": [{"category": "auth", "sample_text": EVENT_TEXT}],
        "classification": {"unmatched_samples": (EVENT_TEXT,)},
    }

    audit_call("debug", "incident_timeline", result=result)

    stored = _assert_scrubbed(rows[0])
    # Scrubbing, not dropping: the rest of the text stays readable.
    assert "login failed" in stored and "vc01" in stored
    # The caller's object is not mutated.
    assert result["hypotheses"][0]["sample_text"] == EVENT_TEXT


def test_audit_call_scrubs_a_bare_string_result(rows):
    audit_call("debug", "triage", result=EVENT_TEXT)
    _assert_scrubbed(rows[0])


def test_mcp_tool_result_free_text_is_scrubbed(rows):
    @vmware_tool
    def incident_timeline():
        return {"hypotheses": [{"sample_text": EVENT_TEXT}]}

    returned = incident_timeline()

    _assert_scrubbed(rows[0])
    sample = returned["hypotheses"][0]["sample_text"]
    assert sample == EVENT_TEXT, "the caller must get the real value"


def test_cli_command_error_text_is_scrubbed(rows):
    @audited("incident_timeline")
    def command(target=None):
        raise ValueError(EVENT_TEXT)

    with pytest.raises(ValueError):
        command()
    _assert_scrubbed(rows[0])


def test_ordinary_result_reaches_the_row_unchanged(rows):
    result = {"items": [{"name": "web-01", "token_count": 5120}], "note": "password: not set"}

    audit_call("monitor", "vm_list", result=result)

    assert rows[0]["result"] == result
