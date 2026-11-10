# -*- coding: utf-8 -*-
"""Настройки в %APPDATA%/ABIRoute/settings.json: атомарная запись + санитизация."""
import ipaddress
import json
import os

from . import DATA_DIR, SETTINGS_PATH
from .util import split_endpoint

DEFAULTS = {
    "warp": None,
    "endpoint": "162.159.192.1:2408",
    "game_processes": ["UAGame.exe", "ArenaBreakoutInfinite.exe", "ArenaBreakoutInfiniteLauncher.exe"],
    "ranges": [],
    "seen_ips": [],
    "auto_learn": True,
    "prefix": 24,
    "awg": {"Jc": 4, "Jmin": 40, "Jmax": 70},
    "mtu": 1280,
    "failover": True,
    "endpoint_ms": None,
    "endpoint_list": [],
    "ignore_ranges": ["92.122.0.0/15"],
    "tcp_ports": {},
    "ping": {},
    "verify_targets": [],
}


def load_settings():
    st = json.loads(json.dumps(DEFAULTS))
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            st.update(json.load(f))
    except (OSError, ValueError):
        pass
    return sanitize_settings(st)


def save_settings(st):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_PATH)


def _clean_nets(lst):
    """Только корректные IPv4-сети; мусор из рук / битых версий молча отбрасывается."""
    out = []
    for r in lst or []:
        try:
            n = ipaddress.ip_network(str(r).strip(), strict=False)
        except (ValueError, AttributeError):
            continue
        if n.version == 4:
            out.append(str(n))
    return out


def sanitize_settings(st):
    """Чинит настройки от битого/старого settings.json, чтобы GUI не упал на старте."""
    try:
        host, port = split_endpoint(str(st.get("endpoint") or ""))
        ipaddress.ip_address(host)
        assert 1 <= port <= 65535
    except (ValueError, AssertionError):
        st["endpoint"] = DEFAULTS["endpoint"]

    st["ranges"] = _clean_nets(st.get("ranges"))
    st["ignore_ranges"] = _clean_nets(st.get("ignore_ranges"))

    procs = [str(p).strip() for p in (st.get("game_processes") or []) if str(p).strip()]
    st["game_processes"] = procs or list(DEFAULTS["game_processes"])

    if st.get("prefix") not in (16, 20, 24):
        st["prefix"] = 24
    try:
        st["mtu"] = max(1000, min(1500, int(st.get("mtu", 1280))))
    except (TypeError, ValueError):
        st["mtu"] = 1280

    awg = dict(st.get("awg") or {})
    for key, dflt in (("Jc", 4), ("Jmin", 40), ("Jmax", 70)):
        try:
            awg[key] = max(0, int(awg.get(key, dflt)))
        except (TypeError, ValueError):
            awg[key] = dflt
    st["awg"] = awg

    vt = []
    for t in st.get("verify_targets") or []:
        try:
            ip, port = t[0], int(t[1])
            ipaddress.ip_address(ip)
            if 0 <= port <= 65535:
                vt.append([ip, port])
        except (ValueError, TypeError, IndexError, KeyError):
            pass
    st["verify_targets"] = vt
    return st
