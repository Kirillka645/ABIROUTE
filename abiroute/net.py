# -*- coding: utf-8 -*-
"""Пинг напрямую (ICMP, запасной вариант — TCP) и поиск подключений игры.

Пока туннель работает, адреса игры маршрутизируются в него. Чтобы померить путь «напрямую»
без остановки туннеля, запросы отправляются с адреса физического адаптера (source):
Windows по модели strong host выбирает маршрут только среди маршрутов этого адаптера.
"""
import ctypes
import os
import re
import socket
import struct
import subprocess
import time

from .common import is_public_v4, summarize

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

NOWIN = 0x08000000 if os.name == "nt" else 0


def local_ip_for(dest_ip):
    """Адрес этого компьютера, с которого Windows отправит пакет на dest_ip (без отправки)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((dest_ip, 9))
        ip = s.getsockname()[0]
        return None if ip.startswith("0.") else ip
    except OSError:
        return None
    finally:
        s.close()

# ----------------------------------------------------------------- ICMP


if os.name == "nt":
    class _IpOptions(ctypes.Structure):
        _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                    ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]

    class _EchoReply(ctypes.Structure):
        _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong),
                    ("RoundTripTime", ctypes.c_ulong), ("DataSize", ctypes.c_ushort),
                    ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p), ("Options", _IpOptions)]

    _ICMP = None

    def _icmp_api():
        global _ICMP
        if _ICMP is None:
            dll = ctypes.WinDLL("iphlpapi.dll")
            dll.IcmpCreateFile.restype = ctypes.c_void_p
            dll.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
            dll.IcmpSendEcho2Ex.restype = ctypes.c_ulong
            dll.IcmpSendEcho2Ex.argtypes = [
                ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p,  # handle, event, apc, ctx
                ctypes.c_ulong, ctypes.c_ulong,                                      # source, destination
                ctypes.c_void_p, ctypes.c_ushort, ctypes.POINTER(_IpOptions),        # data, size, options
                ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]                     # reply, size, timeout
            _ICMP = dll
        return _ICMP

    def _ipaddr(ip):
        return struct.unpack("<I", socket.inet_aton(ip))[0] if ip else 0

    def _icmp_series(ip, count, timeout_ms, source, interval):
        dll = _icmp_api()
        h = dll.IcmpCreateFile()
        if not h or h == ctypes.c_void_p(-1).value:
            raise OSError("IcmpCreateFile")
        try:
            data = b"ABIRoute ping...."
            req = ctypes.create_string_buffer(data, len(data))
            reply = ctypes.create_string_buffer(ctypes.sizeof(_EchoReply) + len(data) + 8 + 128)
            opts = _IpOptions(Ttl=128)
            out = []
            for i in range(count):
                n = dll.IcmpSendEcho2Ex(h, None, None, None, _ipaddr(source), _ipaddr(ip), req, len(data),
                                        ctypes.byref(opts), reply, len(reply), timeout_ms)
                r = _EchoReply.from_buffer(reply)
                if n and r.Status == 0:
                    out.append(float(r.RoundTripTime) or 0.5)  # 0 у Windows значит «меньше 1 мс»
                if i + 1 < count:
                    time.sleep(interval)
            return out
        finally:
            dll.IcmpCloseHandle(h)


def _ping_exe_series(ip, count, timeout_ms, source, interval):
    """Запасной путь — системный ping (по одному запросу, чтобы мерить каждый ответ)."""
    out = []
    for i in range(count):
        if os.name == "nt":
            cmd = ["ping", "-n", "1", "-w", str(timeout_ms)] + (["-S", source] if source else []) + [ip]
        else:
            cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000))] + (["-I", source] if source else []) + [ip]
        try:
            raw = subprocess.run(cmd, capture_output=True, timeout=timeout_ms / 1000 + 3,
                                 creationflags=NOWIN).stdout
        except (OSError, subprocess.TimeoutExpired):
            return out
        text = raw.decode("oem" if os.name == "nt" else "utf-8", errors="ignore").replace(",", ".")
        m = re.search(r"[=<]\s*(\d+(?:\.\d+)?)\s*(?:ms|мс)", text)
        if m:
            out.append(max(float(m.group(1)), 0.5))
        if i + 1 < count:
            time.sleep(interval)
    return out


def icmp_ping(ip, count=5, timeout_ms=1000, source=None, interval=0.15):
    """ICMP-пинг: сводка (мс, разброс, потери) или None, если ответов нет."""
    vals = None
    if os.name == "nt":
        try:
            vals = _icmp_series(ip, count, timeout_ms, source, interval)
        except (OSError, AttributeError, ValueError):
            vals = None
    if vals is None:
        vals = _ping_exe_series(ip, count, timeout_ms, source, interval)
    return summarize(vals, count, "ICMP")

# ----------------------------------------------------------------- TCP


def tcp_ping(ip, port, count=4, timeout=1.2, source=None, interval=0.12):
    """Время TCP-рукопожатия. Только для пути напрямую: через WARP TCP отвечает сам Cloudflare."""
    vals = []
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.perf_counter()
        try:
            if source:
                s.bind((source, 0))
                t0 = time.perf_counter()
            s.connect((ip, int(port)))
            vals.append((time.perf_counter() - t0) * 1000)
        except ConnectionRefusedError:
            # RST — тоже честный RTT, но Windows повторяет SYN после RST, там не считаем
            if os.name != "nt":
                vals.append((time.perf_counter() - t0) * 1000)
        except OSError:
            pass
        finally:
            s.close()
        if i + 1 < count:
            time.sleep(interval)
    return summarize(vals, count, f"TCP {port}")


def direct_ping(ip, port=None, count=5, source=None):
    """Пинг напрямую: ICMP (как и через WARP — сравнение честное), если закрыт — TCP."""
    r = icmp_ping(ip, count, source=source)
    if r:
        return r
    for p in ([port] if port else []) + [443, 80]:
        if tcp_ping(ip, p, 1, timeout=1.0, source=source):
            r = tcp_ping(ip, p, count, source=source)
            if r:
                return r
    return None

# ----------------------------------------------------------------- подключения игры


def game_remote_endpoints(names):
    """{ip: tcp_порт | None} для текущих подключений процессов игры."""
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
        conns = psutil.net_connections(kind="inet4")
    except (psutil.AccessDenied, OSError):
        conns = []
    for c in conns:
        if c.pid in pids and c.raddr and is_public_v4(c.raddr.ip):
            port = c.raddr.port if c.type == socket.SOCK_STREAM else None
            if out.get(c.raddr.ip) is None:
                out[c.raddr.ip] = port
    return out


def game_running(names):
    if psutil is None:
        return False
    wanted = {n.strip().lower() for n in names if n.strip()}
    try:
        return any((p.info.get("name") or "").lower() in wanted for p in psutil.process_iter(["name"]))
    except Exception:  # noqa: BLE001
        return False
