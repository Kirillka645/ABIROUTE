# -*- coding: utf-8 -*-
"""Системный туннель: AmneziaWG или WireGuard, работающий как служба Windows."""
import ctypes
import os
import struct
import subprocess
import time

TUNNEL = "ABIRoute"
NOWIN = 0x08000000 if os.name == "nt" else 0
CPS_MIN_VERSION = (2, 0, 0)  # с AmneziaWG 2.0 для Windows клиент понимает I1–I5


def _run(cmd, timeout=30):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          creationflags=NOWIN, errors="ignore")


def pe_version(path):
    """Версия файла из ресурса VS_VERSION_INFO исполняемого файла -> (a, b, c) или None."""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None
    i = data.find(struct.pack("<I", 0xFEEF04BD))
    if i < 0 or len(data) < i + 16:
        return None
    ms, ls = struct.unpack_from("<II", data, i + 8)
    ver = (ms >> 16, ms & 0xFFFF, ls >> 16)
    return ver if any(ver) else None


def find_client():
    """-> {"exe", "kind": "awg"|"wg", "version", "cps", "tool"} или None, если клиента нет."""
    roots = []
    for var in ("ProgramW6432", "ProgramFiles", "ProgramFiles(x86)"):
        p = os.environ.get(var)
        if p and p not in roots:
            roots.append(p)
    if not roots:
        roots = [r"C:\Program Files"]
    for folder, exe, tool, kind in (("AmneziaWG", "amneziawg.exe", "awg.exe", "awg"),
                                    ("WireGuard", "wireguard.exe", "wg.exe", "wg")):
        for root in roots:
            path = os.path.join(root, folder, exe)
            if os.path.exists(path):
                ver = pe_version(path)
                return {"exe": path, "kind": kind, "version": ver,
                        "cps": kind == "awg" and bool(ver) and ver >= CPS_MIN_VERSION,
                        "tool": os.path.join(root, folder, tool)}
    return None


def version_str(ver):
    return ".".join(str(x) for x in ver) if ver else "?"


def service_name(kind):
    return ("AmneziaWGTunnel$" if kind == "awg" else "WireGuardTunnel$") + TUNNEL


def tunnel_running(kind):
    if os.name != "nt" or not kind:
        return False
    try:
        return "RUNNING" in _run(["sc", "query", service_name(kind)], timeout=10).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def tunnel_down(exe):
    if exe:
        try:
            _run([exe, "/uninstalltunnelservice", TUNNEL])
        except (OSError, subprocess.TimeoutExpired):
            pass


def tunnel_up(exe, kind, conf_text, conf_path):
    """Ставит туннель службой. -> (True, "") или (False, текст ошибки клиента)."""
    os.makedirs(os.path.dirname(conf_path), exist_ok=True)
    with open(conf_path, "w", encoding="utf-8") as f:
        f.write(conf_text)
    tunnel_down(exe)
    time.sleep(0.8)
    try:
        r = _run([exe, "/installtunnelservice", conf_path])
    except (OSError, subprocess.TimeoutExpired) as e:
        return False, str(e)
    for _ in range(16):
        time.sleep(0.5)
        if tunnel_running(kind):
            return True, ""
    err = (r.stderr or r.stdout or "").strip()
    return False, err.removeprefix("Error: ").strip() or "служба туннеля не запустилась"


def tunnel_stats(client, peer_key=None):
    """Рукопожатие и трафик работающего туннеля (awg.exe / wg.exe show dump) или None."""
    if not client or not os.path.exists(client.get("tool") or ""):
        return None
    try:
        lines = _run([client["tool"], "show", TUNNEL, "dump"], timeout=5).stdout.strip().splitlines()
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in lines[1:]:
        f = line.split("\t")
        if len(f) >= 8 and (not peer_key or f[0] == peer_key):
            try:
                return {"handshake": int(f[4]), "rx": int(f[5]), "tx": int(f[6]), "endpoint": f[2]}
            except ValueError:
                return None
    return None


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return os.name != "nt"
