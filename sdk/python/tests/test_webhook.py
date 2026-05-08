"""Tests for vigil_sdk.webhook.verify_webhook_signature."""

from __future__ import annotations
import hashlib
import hmac

from vigil_sdk import verify_webhook_signature


def _sign(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()


def test_verify_passes_with_correct_secret():
    secret = "topsecret"
    payload = b'{"event":"attack.created","tenant_id":"t-1"}'
    sig = _sign(secret, payload)
    assert verify_webhook_signature(payload, sig, secret) is True
    assert verify_webhook_signature(payload, f"sha256={sig}", secret) is True


def test_verify_fails_with_wrong_secret():
    secret = "topsecret"
    other = "other"
    payload = b"payload"
    sig = _sign(secret, payload)
    assert verify_webhook_signature(payload, sig, other) is False


def test_verify_fails_with_tampered_payload():
    secret = "s"
    sig = _sign(secret, b"original")
    assert verify_webhook_signature(b"tampered", sig, secret) is False


def test_verify_handles_empty_inputs():
    assert verify_webhook_signature(b"", "anything", "s") is False
    assert verify_webhook_signature(b"x", "", "s") is False
    assert verify_webhook_signature(b"x", "y", "") is False


def test_verify_constant_time_against_truncated_signature():
    """Sanity check: a too-short signature still returns False, doesn't raise."""
    assert verify_webhook_signature(b"x", "abc", "s") is False
