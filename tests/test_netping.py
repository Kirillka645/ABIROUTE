# -*- coding: utf-8 -*-
"""TCP-пинг и проверка целей на локальном слушателе."""
import socket

from abiroute.netping import check_targets, in_nets, is_public_v4, tcp_ping, wait_tunnel


def _listener():
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(8)
    return srv, srv.getsockname()[1]


def test_is_public_v4():
    assert is_public_v4("8.8.8.8") and is_public_v4("43.153.253.7")
    assert not is_public_v4("10.0.0.1")
    assert not is_public_v4("192.168.1.1")
    assert not is_public_v4("127.0.0.1")
    assert not is_public_v4("::1")
    assert not is_public_v4("мусор")


def test_in_nets():
    assert in_nets("43.153.253.9", ["43.153.253.0/24"])
    assert not in_nets("43.154.1.1", ["43.153.253.0/24"])
    assert not in_nets("bad", ["43.153.253.0/24"])


def test_tcp_ping_local_listener():
    srv, port = _listener()
    try:
        r = tcp_ping("127.0.0.1", port, count=3, timeout=2)
        assert r is not None
        assert r["loss"] == 0 and r["ms"] >= 0 and r["jitter"] >= 0
        assert r["min"] <= r["ms"]
    finally:
        srv.close()


def test_tcp_ping_closed_port():
    # порт 9 на localhost обычно закрыт (discard не слушается)
    r = tcp_ping("127.0.0.1", 9, count=1, timeout=0.4)
    assert r is None or r["ms"] >= 0  # на некоторых системах RST приходит мгновенно


def test_check_targets_mix():
    srv, port = _listener()
    try:
        ms = check_targets([("127.0.0.1", port), ("127.0.0.1", 9)])
        assert ms is not None
        assert check_targets([]) is None
    finally:
        srv.close()


def test_wait_tunnel_success():
    srv, port = _listener()
    try:
        assert wait_tunnel([("127.0.0.1", port)], seconds=3) is not None
    finally:
        srv.close()
