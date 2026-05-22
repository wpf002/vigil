"""Launcher for the playbook-engine.

Runs three coroutines under asyncio.gather():
  1. uvicorn (FastAPI app)
  2. Temporal worker (hosts ResponseWorkflow + activities)
  3. Kafka escalation consumer (starts workflows on attacks.escalated)
"""

from __future__ import annotations

import asyncio
import importlib.util
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def _register(alias: str, pkg_path: Path) -> None:
    if alias in sys.modules:
        return
    spec = importlib.util.spec_from_file_location(
        alias,
        pkg_path / "__init__.py",
        submodule_search_locations=[str(pkg_path)],
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot register {alias}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[alias] = mod
    spec.loader.exec_module(mod)


_register("playbook_engine", _HERE)


async def _main() -> None:
    import socket

    import uvicorn  # noqa: E402

    from playbook_engine.config import get_config  # noqa: E402
    from playbook_engine.consumer import EscalationConsumer  # noqa: E402
    from playbook_engine.store import PlaybookStore  # noqa: E402
    from playbook_engine.worker import build_temporal_client, run_worker  # noqa: E402

    cfg = get_config()

    # API server. Railway: the public edge reaches us over IPv4 while
    # *.railway.internal private DNS is IPv6, so bind a single dual-stack
    # socket (IPV6_V6ONLY=0) that serves both families on cfg.port.
    _sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    _sock.bind(("::", cfg.port))
    api_config = uvicorn.Config(
        "playbook_engine.main:app",
        reload=False,
        log_level=cfg.log_level.lower(),
    )
    api_server = uvicorn.Server(api_config)

    async def consumer_task() -> None:
        # Best-effort: keep retrying until Temporal + Kafka are reachable.
        store = await PlaybookStore.from_dsn(cfg.database_url)
        try:
            client = await build_temporal_client(cfg)
            while client is None:
                await asyncio.sleep(15)
                client = await build_temporal_client(cfg)
            consumer = EscalationConsumer(cfg=cfg, store=store, temporal_client=client)
            try:
                consumer.connect()
            except Exception:
                # Kafka not up yet — retry forever.
                while True:
                    await asyncio.sleep(15)
                    try:
                        consumer.connect()
                        break
                    except Exception:
                        pass
            await consumer.run()
        finally:
            await store.close()

    await asyncio.gather(
        api_server.serve(sockets=[_sock]),
        run_worker(cfg),
        consumer_task(),
        return_exceptions=False,
    )


if __name__ == "__main__":
    asyncio.run(_main())
