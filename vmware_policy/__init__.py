"""VMware Policy — unified audit, policy enforcement, and sanitization for VMware MCP skills."""

__version__ = "1.8.3"

from vmware_policy.audit import AuditEngine, get_engine
from vmware_policy.budget import BudgetExceeded, BudgetTracker, get_budget
from vmware_policy.decorators import PolicyDenied, report_tool_failure, vmware_tool
from vmware_policy.envelope import ENVELOPE_KEYS, paginated
from vmware_policy.environment import (
    mtime_cached_loader,
    resolve_environment,
    set_environment_resolver,
)
from vmware_policy.patterns import Pattern, PatternMatch, get_pattern_engine
from vmware_policy.policy import TierDecision, get_policy_engine
from vmware_policy.readonly import (
    FAMILY_ENV,
    ReadOnlyGateError,
    apply_read_only_gate,
    read_only_enabled,
)
from vmware_policy.sanitize import sanitize
from vmware_policy.undo import UndoStore, get_undo_store

__all__ = [
    "vmware_tool",
    "report_tool_failure",
    "sanitize",
    "apply_read_only_gate",
    "paginated",
    "ENVELOPE_KEYS",
    "mtime_cached_loader",
    "set_environment_resolver",
    "resolve_environment",
    "read_only_enabled",
    "ReadOnlyGateError",
    "FAMILY_ENV",
    "Pattern",
    "PatternMatch",
    "get_pattern_engine",
    "PolicyDenied",
    "get_engine",
    "get_policy_engine",
    "AuditEngine",
    "BudgetExceeded",
    "BudgetTracker",
    "get_budget",
    "TierDecision",
    "UndoStore",
    "get_undo_store",
]
