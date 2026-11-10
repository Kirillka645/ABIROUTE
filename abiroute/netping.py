# -*- coding: utf-8 -*-
"""Пинг до серверов игры: точный TCP-замер, ICMP как запасной, проверка доступности туннеля."""
import ipaddress
import os
import re
import socket
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor

from .util import NOWIN


def is_public_v4(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def icmp_ping(ip, count=3):
    flag = "-n" if os.name == "nt" else "-c"
    cmd = ["ping", flag, str(count), "-w" if os.name == "nt" else "-W", "1000" if os.name == "nt" else "1", ip]
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=count * 2 + 3, creationflags=NOWIN).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = out.decode("oem" if os.name == "nt" else "utf-8", errors="ignore")
    vals = [float(v) for v in re.findall(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)", text.replace(",", "."))]
    return round(sum(vals) / len(vals)) if vals else None


def tcp_ping(ip, port, count=4, timeout=1.5):
    """Точный пинг по времени TCP-рукопожатия (работает, даже когда ICMP закрыт)."""
    vals = []
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            s.connect((ip, int(port)))
            vals.append((time.perf_counter() - t0) * 1000)
        except ConnectionRefusedError:
            # RST тоже даёт честный RTT, но Windows повторяет SYN после RST — там не считаем
            if os.name != "nt":
                vals.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
        finally:
            s.close()
        if i + 1 < count:
            time.sleep(0.12)
    if not vals:
        return None
    return {"ms": round(statistics.median(vals)), "min": round(min(vals)),
            "jitter": round(statistics.pstdev(vals)) if len(vals) > 1 else 0,
            "loss": round(100 * (count - len(vals)) / count)}


def best_ping(ip, port=None, count=4):
    """TCP-пинг по порту игры (или 443/80/8080), если не вышло — ICMP."""
    for p in ([port] if port else []) + [443, 80, 8080]:
        if tcp_ping(ip, p, 1, timeout=1.2):
            r = tcp_ping(ip, p, count)
            if r:
                r.update(how=f"TCP {p}", port=p)
                return r
    ms = icmp_ping(ip, count)
    if ms is not None:
        return {"ms": ms, "min": ms, "jitter": 0, "loss": 0, "how": "ICMP", "port": 0}
    return None


def in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in ipaddress.ip_network(n, strict=False) for n in nets)


def check_targets(targets, timeout=1.5):
    """Отвечает ли хоть один сервер игры. targets = [(ip, tcp_port или 0 для ICMP)] -> мс или None."""
    if not targets:
        return None

    def one(t):
        ip, port = t
        if port:
            r = tcp_ping(ip, port, 1, timeout=timeout)
            return r["ms"] if r else None
        return icmp_ping(ip, 1)

    with ThreadPoolExecutor(max_workers=min(len(targets), 32)) as ex:
        vals = [v for v in ex.map(one, targets) if v is not None]
    return min(vals) if vals else None


def wait_tunnel(targets, seconds=8.0):
    """Ждёт, пока через поднятый туннель начнут отвечать серверы игры. -> мс или None."""
    end = time.time() + seconds
    time.sleep(1.0)
    while True:
        ms = check_targets(targets)
        if ms is not None or time.time() >= end:
            return ms
        time.sleep(0.5)
