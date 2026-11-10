# -*- coding: utf-8 -*-
"""Конфиг туннеля и нормализация диапазонов."""
import ipaddress

import pytest

from abiroute.util import b64
from abiroute.tunnel import build_conf, normalize_ranges, service_name


def make_st(ranges=("162.159.192.0/24",)):
    return {
        "warp": {"private_key": b64(b"\x01" * 32), "v4": "172.16.0.2",
                 "peer_public_key": b64(b"\x02" * 32)},
        "endpoint": "162.159.192.1:2408",
        "ranges": list(ranges),
        "mtu": 1280,
        "awg": {"Jc": 4, "Jmin": 40, "Jmax": 70},
    }


def test_normalize_collapse():
    assert normalize_ranges(["10.0.0.0/24", "10.0.1.0/24"]) == ["10.0.0.0/23"]


def test_normalize_filters_ipv6_and_empty():
    assert normalize_ranges(["::1/128", "", "  "]) == []


def test_normalize_exclude_endpoint():
    out = normalize_ranges(["10.0.0.0/24"], exclude_ip="10.0.0.5")
    nets = [ipaddress.ip_network(n) for n in out]
    total = sum(n.num_addresses for n in nets)
    assert total == ipaddress.ip_network("10.0.0.0/24").num_addresses - 1  # один адрес вырезан
    assert all(ipaddress.ip_address("10.0.0.5") not in n for n in nets)


def test_normalize_invalid_raises():
    with pytest.raises(ValueError):
        normalize_ranges(["not-a-network"])


def test_build_conf_wireguard():
    conf = build_conf(make_st(), "wg")
    assert conf.startswith("[Interface]")
    assert "PrivateKey = " in conf and "Address = 172.16.0.2/32" in conf
    assert "MTU = 1280" in conf
    assert "[Peer]" in conf and "PublicKey = " in conf
    assert "Endpoint = 162.159.192.1:2408" in conf
    assert "PersistentKeepalive = 25" in conf
    ips = next(l for l in conf.splitlines() if l.startswith("AllowedIPs")).split("= ")[1].split(", ")
    for n in ips:
        assert ipaddress.ip_address("162.159.192.1") not in ipaddress.ip_network(n)


def test_build_conf_awg_obfuscation():
    conf = build_conf(make_st(), "awg")
    for line in ("Jc = 4", "Jmin = 40", "Jmax = 70", "S1 = 0", "S2 = 0",
                 "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"):
        assert line in conf


def test_build_conf_no_ranges_raises():
    with pytest.raises(ValueError):
        build_conf(make_st(ranges=[]), "wg")


def test_service_name():
    assert service_name("awg") == "AmneziaWGTunnel$ABIRoute"
    assert service_name("wg") == "WireGuardTunnel$ABIRoute"
