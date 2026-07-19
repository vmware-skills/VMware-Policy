"""Policy engine — rule-based access control for VMware MCP tools.

Rules are loaded from ``~/.vmware/rules.yaml`` with hot-reload on file change.
"""

from __future__ import annotations

import logging
import os
import threading
from dataclasses import dataclass
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from vmware_policy.paths import ops_path

_log = logging.getLogger("vmware-policy.policy")

# ── Data structures ───────────────────────────────────────────────────


@dataclass(frozen=True)
class PolicyResult:
    """Outcome of a policy check."""

    allowed: bool
    rule: str = ""
    reason: str = ""


@dataclass(frozen=True)
class TierDecision:
    """Graduated-autonomy outcome: the approval tier an operation needs.

    tier is one of APPROVAL_TIERS. ``requires_approver`` is True for tiers that
    must carry a named human approver (dual / review) — the decorator denies
    such calls when no approver is recorded.
    """

    tier: str = "none"
    rule: str = "default"
    reason: str = ""

    @property
    def requires_approver(self) -> bool:
        return self.tier in ("dual", "review")


# ── Risk levels ───────────────────────────────────────────────────────

RISK_LEVELS = ("low", "medium", "high", "critical")

# Graduated autonomy tiers, least → most oversight.
#   none    — no gate (dev / low-risk)
#   confirm — CLI double-confirm (informational at the harness layer)
#   dual    — requires a named approver to be recorded (two-person rule)
#   review  — requires a named approver + intended for explicit human review
APPROVAL_TIERS = ("none", "confirm", "dual", "review")

#: The policy baseline shipped with the package, used when the operator has
#: written no ``~/.vmware/rules.yaml`` of their own.
DEFAULT_RULES_PATH = Path(__file__).parent / "rules_default.yaml"

# Param keys whose string values are treated as resource tags / placement for
# tier matching (e.g. a VM's folder or environment tag: prod/staging/dev).
_TAG_PARAM_KEYS = ("tag", "tags", "folder", "resource_tag", "env_tier", "environment")


def risk_requires_confirmation(risk_level: str, env: str = "") -> bool:
    """Determine if a risk level requires human confirmation.

    - critical: always requires confirmation + approval in production
    - high: requires confirmation
    - medium/low: no confirmation
    """
    if risk_level == "critical":
        return True
    if risk_level == "high":
        return True
    return False



#: Values of ``require_declared_environment`` that warn instead of refusing.
#: The migration release ships ``warn``; the enforcing release ships ``true``.
_WARN_ONLY_VALUES = frozenset({"warn", "warning", "warn_only", "warn-only"})
_ENFORCE_VALUES = frozenset({"1", "true", "yes", "on"})
_OFF_VALUES = frozenset({"0", "false", "no", "off", ""})

#: Undeclared-write warnings already emitted, so a busy estate logs one line per
#: operation rather than one per call.
_warned_operations: set[str] = set()


def _parse_requirement(setting: Any) -> str:
    """Normalise ``require_declared_environment`` to 'off' / 'warn' / 'enforce'.

    Strict, like :func:`vmware_policy.readonly._parse`: the recognised strings
    mean what they say regardless of YAML quoting (``"false"`` used to be a
    truthy string that landed in the ENFORCE branch — the switch did the
    opposite of its label). Anything unrecognised fails closed to enforce, with
    a warning naming the valid values, so a typo cannot silently weaken policy.
    """
    if setting is None or setting is False:
        return "off"
    if setting is True:
        return "enforce"
    normalised = str(setting).strip().lower()
    if normalised in _OFF_VALUES:
        return "off"
    if normalised in _WARN_ONLY_VALUES:
        return "warn"
    if normalised in _ENFORCE_VALUES:
        return "enforce"
    _log.warning(
        "require_declared_environment has unrecognised value %r — enforcing "
        "(fail-closed). Use one of: true, false, warn.",
        setting,
    )
    return "enforce"


def _risk_index(risk_level: str) -> int:
    """RISK_LEVELS.index that cannot raise: unknown reads as critical.

    ``vmware-audit policy --risk hgih`` used to traceback with ValueError out
    of check_allowed. An unrecognised level is treated as the most restrictive
    one — a typo must not weaken a gate, and must not crash it either.
    """
    try:
        return RISK_LEVELS.index(risk_level)
    except ValueError:
        return len(RISK_LEVELS) - 1


def _min_risk_index(min_risk: Any) -> int:
    """Index for a rule's ``min_risk_level`` that cannot raise.

    The counterpart to :func:`_risk_index`, for the other direction. That one
    guards the level declared in code by ``@vmware_tool``; this one guards the
    level an operator hand-writes in rules.yaml, which is never validated and
    is the far likelier place for a typo — ``mediun``, or simply ``MEDIUM``.

    Unknown reads as index 0, so the rule matches every risk level instead of
    almost none. The direction matters: this threshold gates whether a rule
    *applies*, so a typo must widen the rule (deny more, require a higher
    approval tier), never quietly narrow it to the point of never firing.
    ``required_approval_tier`` keeps the highest matching tier, so a wider
    match can only raise the bar, never lower it.
    """
    if isinstance(min_risk, str):
        normalised = min_risk.strip().lower()
        if normalised in RISK_LEVELS:
            return RISK_LEVELS.index(normalised)
    _log.warning(
        "Unrecognised min_risk_level %r in a policy rule — treating it as %r so "
        "the rule still applies. Expected one of: %s.",
        min_risk, RISK_LEVELS[0], ", ".join(RISK_LEVELS),
    )
    return 0


def _is_warn_only(setting: Any) -> bool:
    """True when the setting asks for a warning rather than a refusal.

    Kept for the CLI's mode display; delegates to the strict parser so the two
    can never disagree.
    """
    return _parse_requirement(setting) == "warn"


def _warn_undeclared_once(operation: str) -> None:
    if operation in _warned_operations:
        return
    _warned_operations.add(operation)
    _log.warning(
        "%s ran against a target that declares no environment. A future release "
        "will REFUSE this. Add 'environment: <name>' to that target in the "
        "skill's config.yaml. Run 'vmware-audit policy' for details.",
        operation,
    )


# ── Rule loading with hot-reload ──────────────────────────────────────


class PolicyEngine:
    """Evaluate operations against a YAML rule set.

    Rules file is re-read when its mtime changes (hot-reload, no restart needed).
    """

    def __init__(self, rules_path: Path | str | None = None) -> None:
        self._path = Path(rules_path).expanduser() if rules_path else ops_path("rules.yaml")
        self._rules: dict[str, Any] = {}
        self._mtime: float = 0.0
        self._source: str = "none"
        self._load_rules()

    def _load_rules(self) -> None:
        """Load the user's rules; fall back to the packaged baseline if absent.

        The baseline is a *fallback*, never a merge — an operator who writes
        ``rules.yaml`` owns policy completely, and an empty ``risk_tiers: []``
        in their file means exactly that.

        A user file that exists but cannot be parsed does NOT fall back. Applying
        shipped rules the operator never wrote, while their real ones are broken,
        is the wrong surprise for a policy engine; the failure stays loud and the
        engine stays permissive so a YAML typo cannot lock anyone out.
        """
        import yaml

        if not self._path.exists():
            try:
                with open(DEFAULT_RULES_PATH) as fh:
                    self._rules = yaml.safe_load(fh) or {}
                self._source = "packaged-default"
                self._mtime = 0.0
                _log.debug("No %s — using packaged policy baseline", self._path)
            except Exception:
                _log.warning("Packaged policy baseline unreadable", exc_info=True)
                self._rules = {}
                self._source = "none"
                self._mtime = 0.0
            return

        try:
            self._mtime = self._path.stat().st_mtime
            with open(self._path) as fh:
                self._rules = yaml.safe_load(fh) or {}
            self._source = "user"
            _log.debug("Loaded %d policy rules from %s", len(self._rules), self._path)
        except Exception:
            _log.warning("Failed to load policy rules from %s", self._path, exc_info=True)
            self._rules = {}
            self._source = "user-invalid"

    def active_rules_source(self) -> str:
        """Where the rules in force came from.

        One of ``user`` (the operator's rules.yaml), ``packaged-default`` (the
        shipped baseline, because no user file exists), ``user-invalid`` (their
        file exists but would not parse — rules are empty, nothing is enforced),
        or ``none``. Surfaced so an operator can tell "my policy is active" from
        "my policy silently failed to load" without reading logs.
        """
        self._maybe_reload()
        return self._source

    def _maybe_reload(self) -> None:
        """Hot-reload if file changed."""
        if not self._path.exists():
            if self._source == "user":
                _log.warning(
                    "Policy rules file deleted: %s — falling back to the packaged baseline",
                    self._path,
                )
                self._load_rules()
            elif self._source not in ("packaged-default", "none"):
                self._load_rules()
            return
        try:
            current_mtime = self._path.stat().st_mtime
            if current_mtime != self._mtime:
                self._load_rules()
        except Exception:
            _log.warning("Failed to check policy rules file: %s", self._path, exc_info=True)

    def check_allowed(
        self,
        operation: str,
        *,
        env: str = "",
        risk_level: str = "low",
        params: dict[str, Any] | None = None,
    ) -> PolicyResult:
        """Check if an operation is allowed by policy.

        Args:
            operation: Tool function name (e.g. 'delete_segment').
            env: Target environment name (e.g. 'production').
            risk_level: Risk level declared by @vmware_tool.
            params: Operation parameters for rule evaluation.

        Returns:
            PolicyResult with allowed=True/False and reason.
        """
        # Bypass mode — log context for audit trail. Log only parameter NAMES,
        # never values: param values may carry passwords/tokens, and this path
        # can be reached by callers that did not pre-redact.
        if os.environ.get("VMWARE_POLICY_DISABLED") == "1":
            param_names = sorted(params.keys()) if isinstance(params, dict) else []
            _log.warning(
                "Policy DISABLED — bypassing check: operation=%s env=%s risk=%s param_keys=%s",
                operation, env, risk_level, param_names,
            )
            return PolicyResult(allowed=True, rule="policy_disabled")

        self._maybe_reload()

        # No rules file → allow everything
        if not self._rules:
            return PolicyResult(allowed=True, rule="no_rules")

        # ── Evaluate deny rules ───────────────────────────────────────
        deny_rules = self._rules.get("deny", [])
        for rule in deny_rules:
            if self._rule_matches(rule, operation, env, risk_level, params):
                reason = rule.get("reason", f"Denied by rule: {rule.get('name', 'unnamed')}")
                return PolicyResult(allowed=False, rule=rule.get("name", "deny"), reason=reason)

        # ── Evaluate maintenance window ───────────────────────────────
        window = self._rules.get("maintenance_window")
        if window and risk_level in ("high", "critical"):
            try:
                in_window = self._in_maintenance_window(window)
            except (ValueError, TypeError, AttributeError):
                # Fail CLOSED: a malformed window must not silently allow
                # high-risk operations around the clock.
                _log.error(
                    "Malformed maintenance_window %r in %s — failing CLOSED: "
                    "high-risk operations are blocked until the rule is fixed. "
                    "Expected 'start' and 'end' as 'HH:MM' strings, e.g. "
                    "start: \"22:00\" / end: \"06:00\".",
                    window, self._path,
                )
                return PolicyResult(
                    allowed=False,
                    rule="maintenance_window_malformed",
                    reason=(
                        f"maintenance_window in {self._path} is malformed "
                        f"({window!r}). High-risk operations are blocked until it is "
                        "fixed. Expected 'start' and 'end' as 'HH:MM' strings, "
                        'e.g. start: "22:00" / end: "06:00".'
                    ),
                )
            if not in_window:
                return PolicyResult(
                    allowed=False,
                    rule="maintenance_window",
                    reason=f"High-risk operations only allowed during {window.get('start', '?')}-{window.get('end', '?')}",
                )

        # ── Evaluate change limits (reserved, not implemented) ────────
        # change_limits is NOT an enforced feature: _check_limits only warns
        # that configured limits are ignored (it can't compute deltas without
        # before-state). Kept so misconfiguration is surfaced, not silent.
        limits = self._rules.get("change_limits", {})
        if params and limits:
            result = self._check_limits(limits, params, operation)
            if result and not result.allowed:
                return result

        # ── Require the target to declare an environment ───────────────
        # Environment-scoped rules can only protect targets whose environment is
        # known. Treating an undeclared target as safe made every such rule
        # inert on estates that never labelled anything, so an undeclared target
        # is treated as unknown and refused for anything above read-level risk.
        # Reads are never gated: inspection must keep working untouched.
        #
        # Evaluated LAST, after deny rules and the maintenance window: this
        # check can only ever refuse-or-pass, never grant. Its warn-only
        # migration form returns allowed=True, and an early return of that
        # result was found (2026-07-18 review) to bypass an operator's own
        # unscoped deny rules on exactly the unlabelled targets it protects.
        requirement = _parse_requirement(
            self._rules.get("require_declared_environment")
        )
        if (
            requirement != "off"
            and not env
            and _risk_index(risk_level) >= RISK_LEVELS.index("medium")
        ):
            # Written to be relayed to a human by an agent mid-conversation:
            # lead with the one-line fix and a copy-paste snippet, not the
            # policy internals. Reads always work, so say so.
            fix = (
                "The one-line fix: in the skill's config.yaml, under this "
                "target, add\n"
                "\n"
                "    environment: lab    # or: staging / production\n"
                "\n"
                "then retry — no restart needed. Read-only operations are not "
                "affected and keep working. ('vmware-audit policy' shows the "
                "rules in force.)"
            )
            if requirement == "warn":
                # Migration window: warn loudly, allow anyway. Flipping this
                # setting to true is the whole of the enforcing release.
                _warn_undeclared_once(operation)
                return PolicyResult(
                    allowed=True,
                    rule="undeclared_environment_warning",
                    reason=(
                        f"'{operation}' worked, but heads-up: its target hasn't "
                        f"declared which environment it is, and a future release "
                        f"will refuse state-changing operations against "
                        f"undeclared targets. {fix}"
                    ),
                )
            return PolicyResult(
                allowed=False,
                rule="undeclared_environment",
                reason=(
                    f"'{operation}' would change infrastructure state, but this "
                    f"target hasn't declared which environment it is, so the "
                    f"right safety rules can't be applied. {fix}"
                ),
            )

        return PolicyResult(allowed=True, rule="default_allow")

    def required_approval_tier(
        self,
        operation: str,
        *,
        env: str = "",
        risk_level: str = "low",
        params: dict[str, Any] | None = None,
    ) -> TierDecision:
        """Return the approval tier this operation needs (graduated autonomy).

        Evaluated from a ``risk_tiers`` list in rules.yaml — each entry matches
        on operation glob / environment / resource tag / minimum risk and maps
        to a tier (none/confirm/dual/review). The FIRST matching, HIGHEST tier
        wins so a prod-tagged destructive op can't be down-graded by a looser
        rule listed earlier. No config → tier ``none`` (backward compatible).
        """
        self._maybe_reload()
        tiers = self._rules.get("risk_tiers") if self._rules else None
        if not tiers:
            return TierDecision(tier="none", rule="no_tiers")

        tags = _extract_tags(params)
        best: TierDecision | None = None
        for rule in tiers:
            tier = str(rule.get("tier", "")).lower()
            if tier not in APPROVAL_TIERS:
                continue
            if not self._tier_rule_matches(rule, operation, env, risk_level, tags):
                continue
            if best is None or APPROVAL_TIERS.index(tier) > APPROVAL_TIERS.index(best.tier):
                best = TierDecision(
                    tier=tier,
                    rule=str(rule.get("name", "risk_tier")),
                    reason=str(rule.get("reason", "")),
                )
        return best or TierDecision(tier="none", rule="no_tier_match")

    def _tier_rule_matches(
        self,
        rule: dict[str, Any],
        operation: str,
        env: str,
        risk_level: str,
        tags: set[str],
    ) -> bool:
        """Match a risk_tiers entry against the current call."""
        if "operations" in rule:
            ops = rule["operations"]
            if not ops or not any(self._pattern_match(op, operation) for op in ops):
                return False
        envs = rule.get("environments", [])
        if envs and not env:
            return False  # rule scoped to envs but call has none → no match
        if envs and not any(self._pattern_match(e, env) for e in envs):
            return False
        rule_tags = {str(t) for t in (rule.get("tags") or [])}
        if rule_tags and not (rule_tags & tags):
            return False
        min_risk = rule.get("min_risk_level")
        if min_risk and _risk_index(risk_level) < _min_risk_index(min_risk):
            return False
        return True

    def _rule_matches(
        self,
        rule: dict[str, Any],
        operation: str,
        env: str,
        risk_level: str,
        params: dict[str, Any] | None,
    ) -> bool:
        """Check if a deny rule matches the current operation."""
        # Match by operation pattern
        # Note: "operations" key absent → match all (no filter).
        # "operations: []" → match nothing (explicit empty = no operations apply).
        if "operations" in rule:
            ops = rule["operations"]
            if not ops or not any(self._pattern_match(op, operation) for op in ops):
                return False

        # Match by environment — same semantics as _tier_rule_matches (the two
        # diverged in the 2026-07-18 release: this path kept exact matching and
        # let an EMPTY env pass the filter. With env now the *declared*
        # environment — "" for every unlabelled target — that made a
        # production-scoped deny fire on every lab target, and a glob written
        # to the documented 'prod*' idiom never fire at all).
        envs = rule.get("environments", [])
        if envs and not env:
            return False  # rule scoped to envs but target declares none → no match
        if envs and not any(self._pattern_match(e, env) for e in envs):
            return False

        # Match by risk level (minimum)
        min_risk = rule.get("min_risk_level")
        if min_risk:
            if _risk_index(risk_level) < _min_risk_index(min_risk):
                return False

        return True

    @staticmethod
    def _pattern_match(pattern: str, value: str) -> bool:
        """Glob match: 'delete_*', '*_delete' and 'vm_*_snapshot' all work.

        Previously only a trailing ``*`` was honoured — every other pattern fell
        through to an equality test, so a rule written ``operations:
        ["*_delete"]`` silently matched nothing. A deny rule that looks
        configured but never fires is worse than no rule, so this now delegates
        to :func:`fnmatch.fnmatchcase` and handles the full glob syntax.

        Case-sensitive: tool names are snake_case identifiers, and a policy that
        quietly matched ``VM_Delete`` would be surprising in the other direction.
        """
        if pattern == "*":
            return True
        return fnmatchcase(value, pattern)

    @staticmethod
    def _in_maintenance_window(window: dict[str, str]) -> bool:
        """Check if current time is within the maintenance window (UTC).

        Raises ValueError/TypeError/AttributeError when the window is
        malformed — the caller fails CLOSED with a teaching message.
        """
        from datetime import datetime, timezone

        now = datetime.now(tz=timezone.utc)
        start_h, start_m = map(int, str(window.get("start", "22:00")).split(":"))
        end_h, end_m = map(int, str(window.get("end", "06:00")).split(":"))

        current_minutes = now.hour * 60 + now.minute
        start_minutes = start_h * 60 + start_m
        end_minutes = end_h * 60 + end_m

        if start_minutes <= end_minutes:
            return start_minutes <= current_minutes <= end_minutes
        # Wraps midnight (e.g. 22:00 - 06:00)
        return current_minutes >= start_minutes or current_minutes <= end_minutes

    @staticmethod
    def _check_limits(
        limits: dict[str, Any], params: dict[str, Any], operation: str
    ) -> PolicyResult | None:
        """Check parameter-based limits (e.g. max CPU change %).

        NOTE: Not yet implemented — requires before-state to compute deltas.
        Logs a warning when limits are configured so operators know they are
        not being enforced.
        """
        if limits:
            _log.warning(
                "change_limits configured for '%s' but limit enforcement is not yet "
                "implemented — limits are NOT being enforced. Params: %s",
                operation, list(params.keys()),
            )
        return None


def _extract_tags(params: dict[str, Any] | None) -> set[str]:
    """Collect resource-tag-like string values from params for tier matching.

    Looks at a fixed set of keys (tag/tags/folder/...) and flattens list values
    so ``{"tags": ["prod", "pci"]}`` and ``{"folder": "prod"}`` both yield
    ``{"prod", ...}``.
    """
    if not params:
        return set()
    out: set[str] = set()
    for key in _TAG_PARAM_KEYS:
        if key not in params:
            continue
        val = params[key]
        if isinstance(val, str):
            out.add(val)
        elif isinstance(val, (list, tuple, set)):
            out.update(str(v) for v in val)
    return out


# ── Singleton ─────────────────────────────────────────────────────────

_engine: PolicyEngine | None = None
_engine_lock = threading.Lock()


def get_policy_engine(rules_path: Path | str | None = None) -> PolicyEngine:
    """Return the global PolicyEngine singleton (lazy, lock-guarded).

    A ``rules_path`` differing from the one the singleton was created with is
    ignored with a warning — call :func:`reset_policy_engine` first to rebind.
    """
    global _engine
    if _engine is None:
        with _engine_lock:
            if _engine is None:
                _engine = PolicyEngine(rules_path)
                return _engine
    if rules_path is not None:
        requested = Path(rules_path).expanduser()
        if requested != _engine._path:
            _log.warning(
                "get_policy_engine(%s) ignored — singleton already initialized "
                "with %s; call reset_policy_engine() first to rebind.",
                requested, _engine._path,
            )
    return _engine


def reset_policy_engine() -> None:
    """Reset the singleton. Mirrors patterns.reset_pattern_engine()."""
    global _engine
    with _engine_lock:
        _engine = None
