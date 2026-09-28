import ipaddress
import re
from typing import Dict, Any, Tuple
from app.config import settings

class ToolPolicy:
    """
    Enforces tool execution policies:
    1. Tool Allowlist: only pre-approved tools can be invoked.
    2. Argument Validation: checks for dangerous parameters (e.g. SQL injection in queries,
       attempts to block critical DNS/localhost infrastructure).
    3. Risky Action Interception: flags operations requiring human approval (e.g. block_ip).
    """

    ALLOWED_TOOLS = set(settings.ALLOWED_TOOLS)
    RISKY_TOOLS = set(settings.RISKY_TOOLS)

    # Protected infrastructure IPs that must never be blocked automatically
    PROTECTED_IPS = {
        "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",  # Public Root DNS
        "127.0.0.1", "0.0.0.0", "::1",               # Localhost / loopback
        "192.168.1.1", "10.0.0.1"                    # Standard default gateways
    }

    SQL_FORBIDDEN_KEYWORDS = [
        r"\bDROP\b", r"\bDELETE\b", r"\bUPDATE\b", r"\bINSERT\b",
        r"\bALTER\b", r"\bTRUNCATE\b", r"\bEXEC\b", r"\bSHUTDOWN\b",
        r";\s*SELECT", r"--"
    ]

    def validate_tool_call(self, tool_name: str, arguments: Dict[str, Any]) -> Tuple[bool, bool, str]:
        """
        Validates an intended tool call.
        Returns:
            is_allowed (bool): True if tool is on allowlist and arguments are safe.
            is_risky (bool): True if operation requires human approval gate.
            reason (str): Explanation for approval requirement or block reason.
        """
        # 1. Allowlist Check
        if tool_name not in self.ALLOWED_TOOLS:
            return False, False, f"Tool '{tool_name}' is not in allowed tools list."

        # 2. Argument Validation by Tool
        if tool_name == "lookup_ip_reputation":
            ip = arguments.get("ip", "").strip()
            if not ip:
                return False, False, "Missing required argument 'ip'."
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                return False, False, f"Invalid IP address format: '{ip}'"

        elif tool_name == "query_alert_db":
            query = arguments.get("query", "").strip()
            if not query:
                return False, False, "Missing required argument 'query'."
            # Enforce read-only SELECT
            if not query.upper().startswith("SELECT"):
                return False, False, "Only read-only SELECT queries are permitted on alert database."
            for forbidden in self.SQL_FORBIDDEN_KEYWORDS:
                if re.search(forbidden, query, re.IGNORECASE):
                    return False, False, f"Dangerous SQL clause detected: '{forbidden}'"

        elif tool_name == "block_ip":
            ip = arguments.get("ip", "").strip()
            if not ip:
                return False, False, "Missing required argument 'ip'."
            try:
                ip_obj = ipaddress.ip_address(ip)
                if str(ip_obj) in self.PROTECTED_IPS:
                    return False, False, f"Policy violation: Protected infrastructure IP '{ip}' cannot be blocked."
            except ValueError:
                return False, False, f"Invalid IP address format: '{ip}'"

        # 3. Risky Tool Gate
        is_risky = tool_name in self.RISKY_TOOLS
        if is_risky:
            return True, True, f"Tool '{tool_name}' is classified as HIGH-RISK. Requires human authorization."

        return True, False, "Tool call validated and authorized."
