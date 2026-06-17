"""UQL parser — entity-type detection + query normalization.

Auto-detect priority:
  1. explicit prefix (domain:, ip:, url:, email:, hash:, text:/keyword:)
  2. IP pattern        -> ip
  3. email pattern     -> email
  4. hash by length    -> hash   (32=MD5, 40=SHA1, 64=SHA256)
  5. URL pattern       -> url     (starts with http/https)
  6. has dots, no space-> domain  (subdomains preserved, still tagged domain)
  7. fallback          -> keyword
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_PREFIXES = {"domain", "ip", "url", "email", "hash", "text", "keyword"}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
_IPV6_RE = re.compile(r"^[0-9a-fA-F:]+:[0-9a-fA-F:]*$")
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
_URL_RE = re.compile(r"^https?://", re.IGNORECASE)
_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}$")

_HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


@dataclass
class UQLQuery:
    type: str    # domain | ip | url | email | hash | keyword
    value: str
    raw: str


def _is_ip(v: str) -> bool:
    if _IPV4_RE.match(v):
        return all(0 <= int(p) <= 255 for p in v.split("."))
    return bool(_IPV6_RE.match(v) and v.count(":") >= 2)


def detect_type(value: str) -> str:
    v = value.strip()
    if not v:
        return "keyword"
    if _is_ip(v):
        return "ip"
    if _EMAIL_RE.match(v):
        return "email"
    if _HEX_RE.match(v) and len(v) in _HASH_LENGTHS:
        return "hash"
    if _URL_RE.match(v):
        return "url"
    if "." in v and " " not in v and _DOMAIN_RE.match(v):
        return "domain"
    return "keyword"


def parse(query: str) -> UQLQuery:
    raw = (query or "").strip()
    if not raw:
        return UQLQuery(type="keyword", value="", raw=raw)

    # 1. Explicit prefix. Split only on the FIRST colon, and only treat it as a
    # prefix if the head is a known UQL keyword (so 'http://x' and IPv6 aren't
    # mistaken for prefixed queries).
    head, sep, rest = raw.partition(":")
    if sep and head.lower() in _PREFIXES and rest.strip():
        t = head.lower()
        if t in ("text", "keyword"):
            t = "keyword"
        return UQLQuery(type=t, value=rest.strip(), raw=raw)

    return UQLQuery(type=detect_type(raw), value=raw, raw=raw)
