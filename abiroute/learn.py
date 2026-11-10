# -*- coding: utf-8 -*-
"""Автопоиск серверов игры: слушаем сетевые подключения процессов игры."""
import socket

from .netping import is_public_v4

try:
    import psutil
except ImportError:  # pragma: no cover — ядро тестируется и без psutil
    psutil = None


def game_remote_endpoints(names):
    """{ip: tcp_port | None} для публичных IPv4-подключений процессов игры."""
    if psutil is None:
        return {}
    wanted = {n.strip().lower() for n in names if n.strip()}
    pids = set()
    for p in psutil.process_iter(["name"]):
        if (p.info.get("name") or "").lower() in wanted:
            pids.add(p.pid)
    if not pids:
        return {}
    out = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        conns = []
    for c in conns:
        if c.pid in pids and c.raddr and is_public_v4(c.raddr.ip):
            port = c.raddr.port if c.type == socket.SOCK_STREAM else None
            if out.get(c.raddr.ip) is None:
                out[c.raddr.ip] = port
    return out


def game_remote_ips(names):
    return set(game_remote_endpoints(names))
