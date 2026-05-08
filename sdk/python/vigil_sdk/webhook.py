"""Webhook signature verification.

VIGIL signs every webhook delivery with HMAC-SHA256 over the raw request
body using the secret you supplied at registration. Use this helper to
verify before processing — drop the request if it returns False.
"""

from __future__ import annotations
import hashlib
import hmac


def verify_webhook_signature(
    payload_bytes: bytes, signature_header: str, secret: str
) -> bool:
    """Constant-time compare incoming X-VIGIL-Signature against the local
    HMAC. Tolerates both ``sha256=<hex>`` and bare ``<hex>`` forms."""
    if not payload_bytes or not signature_header or not secret:
        return False

    presented = signature_header.split("=", 1)[1] if "=" in signature_header else signature_header
    expected = hmac.new(secret.encode("utf-8"), payload_bytes, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, presented)
