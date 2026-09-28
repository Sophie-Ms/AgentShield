from typing import List, Dict

STANDARD_PLAYBOOKS: List[Dict[str, str]] = [
    {
        "id": "PB-001",
        "category": "PHISHING",
        "title": "Phishing & Suspicious Email Investigation Playbook",
        "content": (
            "1. Triage: Verify email sender headers, SPF/DKIM/DMARC status, and URLs.\n"
            "2. Investigation: Call lookup_ip_reputation on sending server IP.\n"
            "3. Database Search: Call query_alert_db with safe SELECT to see if multiple users received this email.\n"
            "4. Containment: If sender IP or URL is verified malicious, propose block_ip. "
            "Note: block_ip is a HIGH-RISK action and strictly requires human analyst authorization."
        )
    },
    {
        "id": "PB-002",
        "category": "BRUTE_FORCE",
        "title": "Authentication Brute Force & Password Spraying Playbook",
        "content": (
            "1. Triage: Identify targeted accounts and authentication protocol (SSH, RDP, Okta).\n"
            "2. Investigation: Check failure threshold and velocity. Call lookup_ip_reputation on attacker IP.\n"
            "3. Database Search: Query alert database for historical login attempts from this subnet.\n"
            "4. Containment: If external attacker IP persists, request human approval to block_ip. "
            "Never block internal DNS or default gateways."
        )
    },
    {
        "id": "PB-003",
        "category": "MALWARE",
        "title": "Malware C2 Communication & Endpoint Containment Playbook",
        "content": (
            "1. Triage: Assess malware family, host process name, and network telemetry.\n"
            "2. Investigation: Run lookup_ip_reputation on remote Command & Control (C2) IP.\n"
            "3. Database Search: Query database to identify if other endpoints communicate with the C2.\n"
            "4. Containment: Request human authorization to block_ip for active external C2 servers."
        )
    },
    {
        "id": "PB-004",
        "category": "DATA_EXFILTRATION",
        "title": "Data Exfiltration & High-Volume Outbound Transfer Playbook",
        "content": (
            "1. Triage: Assess bytes transferred and affected sensitive tables/repositories.\n"
            "2. Investigation: Correlate user session token and destination endpoint IP.\n"
            "3. Containment: Revoke user credentials, isolate machine, and request analyst review."
        )
    },
    {
        "id": "PB-005",
        "category": "RECONNAISSANCE",
        "title": "External Network Reconnaissance & Port Scanning Playbook",
        "content": (
            "1. Triage: Determine scan profile (SYN scan, vulnerability probe, discovery).\n"
            "2. Investigation: Call lookup_ip_reputation on scanning IP.\n"
            "3. Database Search: Check if scanner is known authorized penetration testing vendor.\n"
            "4. Mitigation: If confirmed unauthorized hostile recon, propose block_ip via approval gate."
        )
    },
    {
        "id": "PB-006",
        "category": "BENIGN",
        "title": "Standard Operating Procedure for False Positive / Benign Activity",
        "content": (
            "1. Triage: Confirm activity corresponds to routine maintenance, authorized DevOps, or testing.\n"
            "2. Verification: Check change management ticket in database.\n"
            "3. Closure: Close alert without triggering defensive blocking tools."
        )
    }
]
