"""Tests for the inbound POST /signals webhook and its API-key auth."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import bcrypt
import pytest
from fastapi import HTTPException

from .. import auth, main
from ..models.cdm import CDMEvent


def _hash(raw: str) -> str:
    digest = hashlib.sha256(raw.encode()).digest()
    return bcrypt.hashpw(digest, bcrypt.gensalt(rounds=4)).decode()


def test_verify_roundtrip():
    raw = "vgl_" + "a" * 48
    h = _hash(raw)
    assert auth._verify(raw, h) is True
    assert auth._verify("vgl_" + "b" * 48, h) is False
    assert auth._verify("", h) is False
    assert auth._verify(raw, "") is False


class _FakeProducer:
    def __init__(self, connected=True):
        self._connected = connected
        self.published: list[CDMEvent] = []

    def is_connected(self) -> bool:
        return self._connected

    async def publish_signal(self, event: CDMEvent) -> bool:
        self.published.append(event)
        return True

    async def publish_signals_batch(self, events: list[CDMEvent]) -> int:
        self.published.extend(events)
        return len(events)


class _FakeEngine:
    def __init__(self, connected=True):
        self.producer = _FakeProducer(connected)


def _event(tenant="spoofed-tenant") -> CDMEvent:
    return CDMEvent(
        tenant_id=tenant,
        source_event_id="evt-1",
        timestamp=datetime.now(timezone.utc),
        title="Suspicious LSASS access",
        detection_id="D1-LSASS-MEMORY-ACCESS",
    )


def _raw_event() -> CDMEvent:
    """A raw event with NO detection_id, but process fields that match a rule."""
    from ..models.cdm import ProcessEntity

    return CDMEvent(
        tenant_id="spoofed",
        source_event_id="raw-1",
        timestamp=datetime.now(timezone.utc),
        title="raw telemetry",
        process=ProcessEntity(process_name="fodhelper.exe"),
    )


@pytest.mark.asyncio
async def test_signals_publishes_with_tenant_from_key(monkeypatch):
    async def fake_auth(_authorization):
        return "real-tenant-123"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine(connected=True))

    out = await main.ingest_signal(_event(tenant="spoofed-tenant"), authorization="Bearer vgl_x")

    assert out["published"] is True
    assert out["tenant_id"] == "real-tenant-123"
    # tenant_id is taken from the key, NOT the request body
    published = main.engine.producer.published
    assert len(published) == 1
    assert published[0].tenant_id == "real-tenant-123"


@pytest.mark.asyncio
async def test_signals_enriches_raw_event_with_detection(monkeypatch):
    async def fake_auth(_authorization):
        return "real-tenant-123"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine(connected=True))

    out = await main.ingest_signal(_raw_event(), authorization="Bearer vgl_x")

    # the in-transit evaluator tagged the raw event with a detection
    assert out["matched_rule"] == "D7-UAC-BYPASS-FODHELPER"
    assert out["detection_id"] == "D7-UAC-BYPASS-FODHELPER"
    published = main.engine.producer.published[0]
    assert published.detection_id == "D7-UAC-BYPASS-FODHELPER"
    assert published.state_impact["phase"] == "privilege-escalation"


@pytest.mark.asyncio
async def test_signals_preserves_existing_detection_id(monkeypatch):
    async def fake_auth(_authorization):
        return "t"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine(connected=True))

    # event already carries a detection_id -> evaluator must not overwrite it
    out = await main.ingest_signal(_event(), authorization="Bearer vgl_x")
    assert out["detection_id"] == "D1-LSASS-MEMORY-ACCESS"
    assert out["matched_rule"] is None


@pytest.mark.asyncio
async def test_signals_503_when_pipeline_down(monkeypatch):
    async def fake_auth(_authorization):
        return "t"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine(connected=False))

    with pytest.raises(HTTPException) as ei:
        await main.ingest_signal(_event(), authorization="Bearer vgl_x")
    assert ei.value.status_code == 503


@pytest.mark.asyncio
async def test_detect_evaluate_dry_run(monkeypatch):
    async def fake_auth(_a):
        return "t"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    out = await main.detect_evaluate(_raw_event(), authorization="Bearer vgl_x")
    assert out["best"] == "D7-UAC-BYPASS-FODHELPER"
    assert any(m["detection_id"] == "D7-UAC-BYPASS-FODHELPER" for m in out["matched"])
    assert out["rule_count"] >= 1


@pytest.mark.asyncio
async def test_signals_batch_publishes_and_enriches(monkeypatch):
    async def fake_auth(_a):
        return "real-tenant"

    monkeypatch.setattr(main, "authenticate", fake_auth)
    monkeypatch.setattr(main, "engine", _FakeEngine(connected=True))

    out = await main.ingest_signals_batch(
        [_event(), _raw_event()], authorization="Bearer vgl_x"
    )
    assert out["received"] == 2
    assert out["published"] == 2
    assert out["enriched"] == 1  # the raw event got a detection_id
    assert all(e.tenant_id == "real-tenant" for e in main.engine.producer.published)


@pytest.mark.asyncio
async def test_signals_rejects_bad_auth(monkeypatch):
    # real authenticate path: no/invalid header -> 401 before any DB call
    with pytest.raises(HTTPException) as ei:
        await auth.authenticate(None)
    assert ei.value.status_code == 401

    with pytest.raises(HTTPException) as ei:
        await auth.authenticate("Bearer not-a-vgl-key")
    assert ei.value.status_code == 401
