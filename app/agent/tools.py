import json
from typing import Dict, Any

# Mock threat intelligence database for realistic SOC lookups
MOCK_INTEL_DB: Dict[str, Dict[str, Any]] = {
    "198.51.100.23": {
        "ip": "198.51.100.23",
        "reputation_score": 92,  # 0 (clean) to 100 (critical threat)
        "verdict": "MALICIOUS",
        "category": "C2_SERVER",
        "isp": "BadHost Networks Inc",
        "country": "RU",
        "threat_tags": ["Mirai", "CobaltStrike", "KnownScanner"]
    },
    "203.0.113.50": {
        "ip": "203.0.113.50",
        "reputation_score": 85,
        "verdict": "MALICIOUS",
        "category": "PHISHING_HOST",
        "isp": "Bulletproof Hosting Ltd",
        "country": "NL",
        "threat_tags": ["CredentialHarvester", "SpamSource"]
    },
    "192.168.1.105": {
        "ip": "192.168.1.105",
        "reputation_score": 0,
        "verdict": "CLEAN",
        "category": "INTERNAL_ENDPOINT",
        "isp": "Internal Subnet",
        "country": "LOCAL",
        "threat_tags": ["EmployeeWorkstation"]
    },
    "8.8.8.8": {
        "ip": "8.8.8.8",
        "reputation_score": 0,
        "verdict": "BENIGN",
        "category": "PUBLIC_DNS",
        "isp": "Google LLC",
        "country": "US",
        "threat_tags": ["RootDNS", "Infrastructure"]
    }
}

def lookup_ip_reputation(ip: str) -> Dict[str, Any]:
    """
    Look up external threat intelligence reputation for an IP address.
    """
    ip_clean = ip.strip()
    if ip_clean in MOCK_INTEL_DB:
        return MOCK_INTEL_DB[ip_clean]
    
    # Heuristic for unknown IPs
    return {
        "ip": ip_clean,
        "reputation_score": 45,
        "verdict": "SUSPICIOUS",
        "category": "UNKNOWN_HOST",
        "isp": "Hosting Provider",
        "country": "UNKNOWN",
        "threat_tags": ["Unclassified"]
    }

def query_alert_db(query: str) -> Dict[str, Any]:
    """
    Execute read-only SQL query against historical alerts.
    """
    query_upper = query.upper().strip()
    if not query_upper.startswith("SELECT"):
        return {"error": "Security policy violation: Only SELECT queries are permitted."}

    # Mock historical results for alert correlation
    return {
        "query_executed": query,
        "rows_returned": 2,
        "results": [
            {"alert_id": "ALT-PREV-102", "timestamp": "2026-09-28T12:00:00Z", "event": "Failed SSH login", "user": "root"},
            {"alert_id": "ALT-PREV-103", "timestamp": "2026-09-28T12:05:00Z", "event": "Failed SSH login", "user": "admin"}
        ]
    }

def block_ip(ip: str, reason: str = "Automated SOC containment") -> Dict[str, Any]:
    """
    Risky tool: blocks network traffic from target IP on firewall.
    Requires human authorization gate.
    """
    return {
        "action": "block_ip",
        "target_ip": ip,
        "reason": reason,
        "status": "FIREWALL_RULE_ENFORCED",
        "policy_id": "FW-RULE-9941"
    }

AVAILABLE_TOOLS = {
    "lookup_ip_reputation": lookup_ip_reputation,
    "query_alert_db": query_alert_db,
    "block_ip": block_ip
}
