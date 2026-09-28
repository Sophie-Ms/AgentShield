import re
import urllib.parse
import time
from typing import Dict, List, Tuple, Any


class PIIRedactor:
    """
    Redacts PII, secrets, and sensitive tokens from alert payloads
    before they reach downstream LLMs or agents.

    Handles:
      - Email addresses
      - API keys / secrets / tokens (key=value patterns)
      - JWT tokens
      - Credit card numbers
      - Phone numbers
      - Social Security Numbers
    """

    PATTERNS: Dict[str, re.Pattern] = {
        "EMAIL": re.compile(
            r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b"
        ),
        # Matches: api_key=abc123... / secret: 'xyz' / token= ...
        "API_KEY": re.compile(
            r"(?:api[_-]?key|secret|token|bearer|access_token|password)"
            r"[\s:=]+[\"']?([a-zA-Z0-9_\-\.]{16,})[\"']?",
            re.IGNORECASE,
        ),
        "JWT": re.compile(
            r"\beyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b"
        ),
        "CREDIT_CARD": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        # Phone: optional country code, then area code + 7 digits
        "PHONE": re.compile(
            r"(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{2,4}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b"
        ),
        "SSN": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    }

    def redact(self, text: str) -> Tuple[str, List[Dict[str, Any]]]:
        """
        Redacts sensitive entities from text.

        Returns:
            sanitized_text: Scrubbed text with placeholder tokens.
            redacted_entities: Metadata list of what was redacted.
        """
        if not text:
            return text, []

        sanitized = text
        redacted_entities: List[Dict[str, Any]] = []

        # 1. JWT Tokens (before API_KEY to avoid partial overlap)
        for m in self.PATTERNS["JWT"].finditer(sanitized):
            redacted_entities.append(
                {"type": "JWT_TOKEN", "preview": m.group(0)[:8] + "..."}
            )
        sanitized = self.PATTERNS["JWT"].sub("<REDACTED_JWT>", sanitized)

        # 2. API Keys & Secrets (capture group 1 = the value)
        def _replace_secret(match: re.Match) -> str:
            secret_val = match.group(1) if match.groups() else match.group(0)
            redacted_entities.append(
                {
                    "type": "API_KEY/SECRET",
                    "length": len(secret_val),
                    "preview": secret_val[:3] + "***" if len(secret_val) > 4 else "***",
                }
            )
            return match.group(0).replace(secret_val, "<REDACTED_SECRET>")

        sanitized = self.PATTERNS["API_KEY"].sub(_replace_secret, sanitized)

        # 3. Email addresses
        for m in self.PATTERNS["EMAIL"].finditer(sanitized):
            redacted_entities.append({"type": "EMAIL", "preview": m.group(0)})
        sanitized = self.PATTERNS["EMAIL"].sub("<REDACTED_EMAIL>", sanitized)

        # 4. Credit card numbers
        for m in self.PATTERNS["CREDIT_CARD"].finditer(sanitized):
            redacted_entities.append(
                {"type": "CREDIT_CARD", "preview": "****-****-****-" + m.group(0)[-4:]}
            )
        sanitized = self.PATTERNS["CREDIT_CARD"].sub("<REDACTED_CC>", sanitized)

        # 5. Phone numbers
        for m in self.PATTERNS["PHONE"].finditer(sanitized):
            redacted_entities.append({"type": "PHONE", "preview": m.group(0)})
        sanitized = self.PATTERNS["PHONE"].sub("<REDACTED_PHONE>", sanitized)

        # 6. Social Security Numbers
        for m in self.PATTERNS["SSN"].finditer(sanitized):
            redacted_entities.append(
                {"type": "SSN", "preview": "***-**-" + m.group(0)[-4:]}
            )
        sanitized = self.PATTERNS["SSN"].sub("<REDACTED_SSN>", sanitized)

        return sanitized, redacted_entities
