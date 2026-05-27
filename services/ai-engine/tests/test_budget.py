"""Tests for the hard daily Claude-call budget."""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from ai_engine.budget import CallBudget


@pytest.mark.asyncio
async def test_consume_under_limit_returns_allowed():
    client = MagicMock()
    client.incr = AsyncMock(return_value=1)
    client.expire = AsyncMock()
    budget = CallBudget(client=client, daily_limit=5)

    allowed, count = await budget.try_consume()
    assert allowed is True
    assert count == 1
    client.expire.assert_awaited_once()


@pytest.mark.asyncio
async def test_consume_at_limit_still_allowed():
    client = MagicMock()
    client.incr = AsyncMock(return_value=5)
    client.expire = AsyncMock()
    budget = CallBudget(client=client, daily_limit=5)

    allowed, count = await budget.try_consume()
    assert allowed is True
    assert count == 5


@pytest.mark.asyncio
async def test_consume_over_limit_denied():
    client = MagicMock()
    client.incr = AsyncMock(return_value=6)
    client.expire = AsyncMock()
    budget = CallBudget(client=client, daily_limit=5)

    allowed, count = await budget.try_consume()
    assert allowed is False
    assert count == 6


@pytest.mark.asyncio
async def test_zero_limit_blocks_all_calls():
    """ANTHROPIC_DAILY_CALL_BUDGET=0 is the operator's emergency stop."""
    client = MagicMock()
    client.incr = AsyncMock()
    budget = CallBudget(client=client, daily_limit=0)

    allowed, count = await budget.try_consume()
    assert allowed is False
    assert count == 0
    client.incr.assert_not_called()


@pytest.mark.asyncio
async def test_redis_failure_fails_closed():
    """If Redis is unreachable we MUST refuse to call Claude — uptime is
    worth less than runaway-cost protection.
    """
    client = MagicMock()
    client.incr = AsyncMock(side_effect=RuntimeError("redis down"))
    budget = CallBudget(client=client, daily_limit=100)

    allowed, count = await budget.try_consume()
    assert allowed is False
    assert count == -1


@pytest.mark.asyncio
async def test_expire_set_only_on_first_increment():
    """The TTL is only pinned when the daily counter rolls over (count == 1).
    Subsequent calls in the same day must not reset the TTL.
    """
    client = MagicMock()
    client.expire = AsyncMock()
    budget = CallBudget(client=client, daily_limit=10)

    client.incr = AsyncMock(return_value=1)
    await budget.try_consume()
    assert client.expire.await_count == 1

    client.incr = AsyncMock(return_value=2)
    await budget.try_consume()
    assert client.expire.await_count == 1  # unchanged


def test_key_includes_utc_date():
    """The day key must be UTC, not local — Railway containers are UTC but
    local dev may not be, and we want one global reset moment.
    """
    fixed = datetime(2026, 5, 27, 23, 59, 59, tzinfo=timezone.utc)
    key = CallBudget._key(fixed)
    assert key == "ai_engine:budget:claude_calls:2026-05-27"
