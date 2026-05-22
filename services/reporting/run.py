"""Launcher for the reporting service."""

from __future__ import annotations

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


_register("reporting", _HERE)


if __name__ == "__main__":
    import uvicorn

    from reporting.config import get_config

    cfg = get_config()
    import socket

    # Railway: the public edge reaches us over IPv4 while *.railway.internal
    # private DNS is IPv6, so bind a single dual-stack socket (IPV6_V6ONLY=0)
    # that serves both families on cfg.port.
    _sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    _sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    _sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    _sock.bind(("::", cfg.port))
    _server = uvicorn.Server(
        uvicorn.Config(
            "reporting.main:app",
            reload=False,
            log_level=cfg.log_level.lower(),
        )
    )
    _server.run(sockets=[_sock])
