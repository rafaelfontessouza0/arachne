"""Secret / credential detection over response bodies (SecretFinder / mantra role).

Scans HTML, JavaScript and JSON text for high-signal secrets. Findings are
de-duplicated by (type, value) by the caller and written to `secrets.jsonl`.
"""
from __future__ import annotations

import re
from typing import List, Dict

# (name, confidence, regex) — group(1) is the secret if the pattern has a group,
# otherwise the whole match.
_PATTERNS = [
    ("aws_access_key_id", "high",
     re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ABIA)[0-9A-Z]{16})\b")),
    ("aws_secret_access_key", "medium",
     re.compile(r"(?i)aws.{0,20}(?:secret|sk).{0,20}['\"]([0-9a-zA-Z/+]{40})['\"]")),
    ("google_api_key", "high", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
    ("google_oauth_token", "high", re.compile(r"\b(ya29\.[0-9A-Za-z\-_]{20,})")),
    ("firebase_db", "low", re.compile(r"\b([a-z0-9][a-z0-9.-]*\.firebaseio\.com)\b")),
    ("slack_token", "high", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,48})\b")),
    ("slack_webhook", "high",
     re.compile(r"(https://hooks\.slack\.com/services/[A-Za-z0-9/_-]+)")),
    ("github_token", "high", re.compile(r"\b(gh[pousr]_[0-9A-Za-z]{36})\b")),
    ("github_pat_finegrained", "high", re.compile(r"\b(github_pat_[0-9A-Za-z_]{59,})\b")),
    ("stripe_secret_key", "high", re.compile(r"\b((?:sk|rk)_live_[0-9a-zA-Z]{24,})\b")),
    ("stripe_pub_key", "low", re.compile(r"\b(pk_live_[0-9a-zA-Z]{24,})\b")),
    ("twilio_account_sid", "medium", re.compile(r"\b(AC[0-9a-fA-F]{32})\b")),
    ("twilio_api_key", "medium", re.compile(r"\b(SK[0-9a-fA-F]{32})\b")),
    ("sendgrid_key", "high", re.compile(r"\b(SG\.[\w-]{22}\.[\w-]{43})\b")),
    ("mailgun_key", "medium", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b")),
    ("jwt", "medium",
     re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,})\b")),
    ("private_key", "high",
     re.compile(r"(-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----)")),
    ("basic_auth_url", "medium",
     re.compile(r"\b(https?://[^/\s:@'\"]+:[^/\s:@'\"]+@[^/\s'\"]+)")),
    ("authorization_bearer", "low",
     re.compile(r"(?i)authorization['\"]?\s*[:=]\s*['\"]?bearer\s+([A-Za-z0-9\-._~+/]{12,})")),
    ("generic_api_key", "low",
     re.compile(r"(?i)\b(?:api[_-]?key|apikey|client[_-]?secret|access[_-]?token|"
                r"secret[_-]?key|auth[_-]?token)\b\s*[:=]\s*['\"]([0-9a-zA-Z\-_=.]{12,64})['\"]")),
]

# obvious placeholders / dummy values to drop
_FALSE = re.compile(
    r"^(?:0+|x+|y+|a+|example.*|test.*|sample.*|your[_-]?.*|xxxx.*|placeholder|"
    r"dummy|none|null|false|true|undefined|changeme|<.*>|\$\{.*\})$", re.I)


def _redact(s: str) -> str:
    if len(s) <= 8:
        return s[0] + "*" * (len(s) - 1)
    return s[:4] + "*" * (len(s) - 8) + s[-4:]


def scan(text: str, redact: bool = True) -> List[Dict]:
    """Return a list of {type, confidence, match} findings for one body."""
    out: List[Dict] = []
    seen = set()
    for name, conf, rx in _PATTERNS:
        for m in rx.finditer(text):
            val = (m.group(1) if m.groups() else m.group(0)) or ""
            val = val.strip()
            if not val:
                continue
            if _FALSE.match(val.strip("'\"")):
                continue
            key = (name, val)
            if key in seen:
                continue
            seen.add(key)
            out.append({
                "type": name,
                "confidence": conf,
                "match": _redact(val) if redact else val,
            })
    return out
