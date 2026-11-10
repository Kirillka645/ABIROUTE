# -*- coding: utf-8 -*-
"""Настройки ABI Route: %APPDATA%\\ABIRoute\\settings.json."""
import copy
import json
import os

DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ABIRoute")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
CONF_PATH = os.path.join(DATA_DIR, "ABIRoute.conf")

DEFAULTS = {
    "warp": None,
    "endpoint": "162.159.192.1:2408",
    "endpoint_list": [],          # [[endpoint, мс до узла, код узла]]
    "obf_id": "light",
    "obf": {"Jc": 4, "Jmin": 40, "Jmax": 70},
    "colo": None,
    "game_processes": ["UAGame.exe", "ArenaBreakoutInfinite.exe", "ArenaBreakoutInfiniteLauncher.exe"],
    "ranges": [],
    "seen_ips": [],
    "auto_learn": True,
    "prefix": 24,
    "mtu": 1280,
    "failover": True,
    "ignore_ranges": ["92.122.0.0/15"],
    "tcp_ports": {},
    "verify_targets": [],
    "compare": {},                # ip -> {"direct": сводка|None, "warp": сводка|None}
}

# Готовые списки. Собраны из реальных подключений игры (журнал ABI Route, ноябрь 2026).
GAME_PRESETS = {
    "Найденные серверы ABI (/24)": [
        "43.153.253.0/24", "43.163.53.0/24", "43.163.63.0/24", "43.168.141.0/24",
        "43.174.218.0/24", "43.174.250.0/24", "43.174.251.0/24", "101.32.107.0/24",
        "101.32.113.0/24", "101.32.171.0/24", "101.33.43.0/24", "101.33.48.0/24",
        "129.226.1.0/24", "129.226.2.0/24", "188.43.72.0/24"],
    "Широкий охват ABI (/16)": [
        "43.153.0.0/16", "43.163.0.0/16", "43.168.0.0/16", "43.174.0.0/16",
        "101.32.0.0/16", "101.33.0.0/16", "129.226.0.0/16", "188.43.72.0/24"],
}


def load_settings(path=SETTINGS_PATH):
    st = copy.deepcopy(DEFAULTS)
    try:
        with open(path, "r", encoding="utf-8") as f:
            user = json.load(f)
    except (OSError, ValueError):
        user = {}
    if isinstance(user, dict):
        st.update(user)
    # 2.x: маскировка лежала в "awg", у списка серверов не было кода узла
    old = st.pop("awg", None)
    if isinstance(old, dict) and "obf" not in user:
        st["obf"] = {k: int(old[k]) for k in ("Jc", "Jmin", "Jmax") if k in old}
        st["obf_id"] = "strong" if st["obf"].get("Jc", 0) >= 100 else "light"
    st["endpoint_list"] = [(list(e) + [None, None])[:3] for e in st.get("endpoint_list") or [] if e]
    for k in ("endpoint_ms", "ping"):
        st.pop(k, None)
    return st


def save_settings(st, path=SETTINGS_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)
