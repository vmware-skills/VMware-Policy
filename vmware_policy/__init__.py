"""VMware Policy — unified audit, policy enforcement, and sanitization for VMware MCP skills."""

__version__ = "1.5.36"

from vmware_policy.audit import AuditEngine, get_engine
from vmware_policy.decorators import PolicyDenied, vmware_tool
from vmware_policy.patterns import Pattern, PatternMatch, get_pattern_engine
from vmware_policy.policy import get_policy_engine
from vmware_policy.sanitize import sanitize

__all__ = [
    "vmware_tool",
    "sanitize",
    "Pattern",
    "PatternMatch",
    "get_pattern_engine",
    "PolicyDenied",
    "get_engine",
    "get_policy_engine",
    "AuditEngine",
]
