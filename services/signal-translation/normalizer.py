"""Field-name normalization across SIEM dialects.

The YAML detections are written using a canonical name set
(src_ip, dst_ip, hostname, username, process). The compiler rewrites these
into each backend's preferred field name before emitting the artifact.

We use whole-word substitution to avoid corrupting unrelated identifiers
that share the same prefix.
"""

from __future__ import annotations

import re
from typing import Mapping

# Canonical name → backend-specific name.
SPLUNK_MAP: Mapping[str, str] = {
    "src_ip": "src",
    "dst_ip": "dest",
    "hostname": "host",
    "username": "user",
    "process": "process",
}

SENTINEL_MAP: Mapping[str, str] = {
    "src_ip": "SourceIP",
    "dst_ip": "DestinationIP",
    "hostname": "DeviceName",
    "username": "AccountName",
    "process": "InitiatingProcessFileName",
}

ELASTIC_MAP: Mapping[str, str] = {
    "src_ip": "source.ip",
    "dst_ip": "destination.ip",
    "hostname": "host.hostname",
    "username": "user.name",
    "process": "process.name",
}


def _apply(query: str, mapping: Mapping[str, str]) -> str:
    out = query
    # Sort longer names first so dst_ip is replaced before src_ip etc. — even
    # though they don't conflict, deterministic ordering helps idempotency.
    for canonical in sorted(mapping.keys(), key=len, reverse=True):
        replacement = mapping[canonical]
        if canonical == replacement:
            continue
        # \b doesn't treat '.' as a word boundary; use a custom lookaround so
        # we only match when the canonical name appears as a standalone token.
        pattern = re.compile(rf"(?<![A-Za-z0-9_]){re.escape(canonical)}(?![A-Za-z0-9_])")
        out = pattern.sub(replacement, out)
    return out


def for_splunk(query: str) -> str:
    return _apply(query, SPLUNK_MAP)


def for_sentinel(query: str) -> str:
    return _apply(query, SENTINEL_MAP)


def for_elastic(query: str) -> str:
    return _apply(query, ELASTIC_MAP)
