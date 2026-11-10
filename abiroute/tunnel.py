# -*- coding: utf-8 -*-
"""Split-tunnel конфиг и управление службой туннеля AmneziaWG / WireGuard."""
import ipaddress
import os
import time

from . import CONF_PATH, DATA_DIR, TUNNEL
from .util import _run, split_endpoint

# ----------------------------------------------------------------- конфиг


def normalize_ranges(ranges, exclude_ip=None):
    """Схлопывает пересечения, оставляет только IPv4, вырезает адрес сервера WARP из маршрутов."""
    nets = []
    for r in ranges:
        r = str(r).strip()
        if not r:
            continue
        n = ipaddress.ip_network(r, strict=False)
        if n.version == 4:
            nets.append(n)
    nets = list(ipaddress.collapse_addresses(nets))
    if exclude_ip:
        ex = ipaddress.ip_network(exclude_ip + "/32")
        out = []
        for n in nets:
            out.extend(n.address_exclude(ex) if ex.subnet_of(n) else [n])
        nets = list(ipaddress.collapse_addresses(out))
    return [str(n) for n in nets]


def build_conf(st, kind):
    """Текст .conf: через туннель идут только диапазоны игры, остальное — напрямую."""
    w = st["warp"]
    host, port = split_endpoint(st["endpoint"])
    ranges = normalize_ranges(st["ranges"], exclude_ip=host)
    if not ranges:
        raise ValueError("Нет IP-диапазонов игры")
    lines = ["[Interface]", f"PrivateKey = {w['private_key']}", f"Address = {w['v4']}/32",
             f"MTU = {int(st.get('mtu', 1280))}"]
    if kind == "awg":
        a = st["awg"]
        lines += [f"Jc = {a['Jc']}", f"Jmin = {a['Jmin']}", f"Jmax = {a['Jmax']}",
                  "S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"]
    lines += ["", "[Peer]", f"PublicKey = {w['peer_public_key']}",
              f"AllowedIPs = {', '.join(ranges)}", f"Endpoint = {host}:{port}",
              "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


# ----------------------------------------------------------------- служба туннеля


def find_client():
    """Установленный клиент: сначала AmneziaWG (с обфускацией), потом обычный WireGuard."""
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    for path, kind in ((os.path.join(pf, "AmneziaWG", "amneziawg.exe"), "awg"),
                       (os.path.join(pf, "WireGuard", "wireguard.exe"), "wg")):
        if os.path.exists(path):
            return path, kind
    return None, None


def service_name(kind):
    return ("AmneziaWGTunnel$" if kind == "awg" else "WireGuardTunnel$") + TUNNEL


def tunnel_running(kind):
    if os.name != "nt" or not kind:
        return False
    try:
        return "RUNNING" in _run(["sc", "query", service_name(kind)]).stdout
    except (OSError, TimeoutError):
        return False


def tunnel_down(exe):
    if exe:
        _run([exe, "/uninstalltunnelservice", TUNNEL])


def tunnel_up(exe, kind, conf_text):
    """Ставит туннель как службу Windows. -> (успех, текст ошибки)."""
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CONF_PATH, "w", encoding="utf-8") as f:
        f.write(conf_text)
    tunnel_down(exe)
    time.sleep(1.0)
    r = _run([exe, "/installtunnelservice", CONF_PATH])
    for _ in range(10):
        time.sleep(0.5)
        if tunnel_running(kind):
            return True, ""
    return False, (r.stderr or r.stdout or "служба не запустилась").strip()


def tunnel_stats(exe, kind):
    """Последнее рукопожатие и трафик туннеля через awg.exe / wg.exe (если есть)."""
    if not exe:
        return None
    tool = os.path.join(os.path.dirname(exe), "awg.exe" if kind == "awg" else "wg.exe")
    if not os.path.exists(tool):
        return None
    try:
        lines = _run([tool, "show", TUNNEL, "dump"], timeout=5).stdout.strip().splitlines()
        f = lines[1].split("\t")
        return {"handshake": int(f[4]), "rx": int(f[5]), "tx": int(f[6])}
    except (OSError, TimeoutError, IndexError, ValueError):
        return None
