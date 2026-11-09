# -*- coding: utf-8 -*-
"""
ABI Route — WARP-туннель только для Arena Breakout Infinite.

* Регистрирует бесплатный профиль Cloudflare WARP (аналог "warp generator").
* Ищет лучший эндпоинт WARP реальным WireGuard-рукопожатием (UDP), а не ICMP.
* Генерирует split-tunnel конфиг: через WARP идут ТОЛЬКО IP-адреса серверов игры.
* Сам находит IP серверов игры по подключениям процесса игры и дописывает маршруты.
* Туннель работает как служба Windows (AmneziaWG или WireGuard) — в фоне.
* v2: автосмена сервера WARP при сбое, точный TCP-пинг с таблицей сравнения,
  готовые списки серверов игры, новый интерфейс.
"""
import base64
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import socket
import statistics
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import messagebox, ttk
except ImportError:  # позволяет тестировать ядро без GUI
    tk = None

APP_NAME = "ABI Route"
TUNNEL = "ABIRoute"
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ABIRoute")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
CONF_PATH = os.path.join(DATA_DIR, TUNNEL + ".conf")
NOWIN = 0x08000000 if os.name == "nt" else 0

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
VERSION = "2.1"

# ----------------------------------------------------------------- settings

def load_settings():
    st = json.loads(json.dumps(DEFAULTS))
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            st.update(json.load(f))
    except (OSError, ValueError):
        pass
    return st


def save_settings(st):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_PATH)

# ----------------------------------------------------------------- keys / WARP API

def b64(b):
    return base64.b64encode(b).decode()


def gen_keypair():
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


WARP_API = "https://api.cloudflareclient.com/v0a2158"
WARP_HEADERS = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.10-2158",
    "Content-Type": "application/json; charset=UTF-8",
}


def warp_register():
    """Регистрирует новый бесплатный аккаунт WARP и возвращает данные для конфига."""
    priv, pub = gen_keypair()
    body = {
        "key": b64(pub), "install_id": "", "fcm_token": "",
        "tos": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": True,
    }
    req = urllib.request.Request(WARP_API + "/reg", data=json.dumps(body).encode(),
                                 headers=WARP_HEADERS, method="POST")
    with urllib.request.urlopen(req, timeout=20) as r:
        j = json.loads(r.read().decode())
    d = j.get("result", j)
    cfg = d["config"]
    peer = cfg["peers"][0]
    addr = cfg["interface"]["addresses"]
    return {
        "private_key": b64(priv), "public_key": b64(pub),
        "peer_public_key": peer["public_key"],
        "v4": addr["v4"], "v6": addr.get("v6", ""),
        "id": d.get("id"), "token": d.get("token"),
        "created": datetime.now().strftime("%d.%m.%Y %H:%M"),
    }

# ----------------------------------------------------------------- WireGuard handshake ping

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"


def _hash(*parts):
    h = hashlib.blake2s()
    for p in parts:
        h.update(p)
    return h.digest()


def _hmac(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def _kdf(key, data, n):
    t0 = _hmac(key, data)
    out, prev = [], b""
    for i in range(1, n + 1):
        prev = _hmac(t0, prev + bytes([i]))
        out.append(prev)
    return out


def _aead(key, counter, pt, ad):
    return ChaCha20Poly1305(key).encrypt(b"\0" * 4 + struct.pack("<Q", counter), pt, ad)


def _dh(priv, pub):
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


def _tai64n():
    t = time.time()
    s = int(t)
    return struct.pack(">QI", 0x400000000000000A + s, int((t - s) * 1e9))


def build_initiation(s_priv, s_pub, r_pub, sender=None):
    """Сообщение Handshake Initiation (148 байт) по протоколу WireGuard."""
    c = _hash(CONSTRUCTION)
    h = _hash(c, IDENTIFIER)
    h = _hash(h, r_pub)
    e_priv, e_pub = gen_keypair()
    c = _kdf(c, e_pub, 1)[0]
    h = _hash(h, e_pub)
    c, k = _kdf(c, _dh(e_priv, r_pub), 2)
    enc_static = _aead(k, 0, s_pub, h)
    h = _hash(h, enc_static)
    c, k = _kdf(c, _dh(s_priv, r_pub), 2)
    enc_ts = _aead(k, 0, _tai64n(), h)
    sender = secrets.randbits(32) if sender is None else sender
    msg = struct.pack("<II", 1, sender) + e_pub + enc_static + enc_ts
    mac1 = hashlib.blake2s(msg, key=_hash(LABEL_MAC1, r_pub), digest_size=16).digest()
    return msg + mac1 + b"\0" * 16, sender


def handshake_ping(host, port, warp, awg=None, timeout=1.2):
    """RTT (мс) реального рукопожатия с сервером WARP или None, если ответа нет."""
    s_priv = base64.b64decode(warp["private_key"])
    s_pub = base64.b64decode(warp["public_key"])
    r_pub = base64.b64decode(warp["peer_public_key"])
    pkt, sender = build_initiation(s_priv, s_pub, r_pub)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        addr = (host, port)
        if awg:  # мусорные пакеты, как у AmneziaWG — помогают пройти DPI
            for _ in range(int(awg.get("Jc", 0))):
                sock.sendto(os.urandom(random.randint(int(awg["Jmin"]), int(awg["Jmax"]))), addr)
        t0 = time.perf_counter()
        sock.sendto(pkt, addr)
        deadline = t0 + timeout
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return None
            sock.settimeout(left)
            data, _ = sock.recvfrom(2048)
            if len(data) >= 92 and data[0] == 2 and struct.unpack("<I", data[8:12])[0] == sender:
                return (time.perf_counter() - t0) * 1000
    except OSError:
        return None
    finally:
        sock.close()


WARP_IPS = (["162.159.192.%d" % i for i in (1, 2, 5, 7, 9, 10)]
            + ["162.159.193.%d" % i for i in (1, 3, 5, 10)]
            + ["162.159.195.%d" % i for i in (1, 4, 8)]
            + ["188.114.96.1", "188.114.96.3", "188.114.97.1", "188.114.97.4",
               "188.114.98.1", "188.114.99.1"])
WARP_PORTS = [2408, 500, 1701, 4500, 878, 894, 854, 939, 7559]


def scan_endpoints(warp, awg, progress=None, tries=2):
    return probe_endpoints([f"{ip}:{p}" for ip in WARP_IPS for p in WARP_PORTS], warp, awg, progress, tries)


def probe_endpoints(eps, warp, awg, progress=None, tries=2):
    cands = [split_endpoint(e) for e in eps]
    done = [0]
    lock = threading.Lock()

    def test(c):
        best = None
        for _ in range(tries):
            ms = handshake_ping(c[0], c[1], warp, awg)
            if ms is not None and (best is None or ms < best):
                best = ms
        with lock:
            done[0] += 1
            if progress:
                progress(done[0], len(cands))
        return c, best

    with ThreadPoolExecutor(max_workers=40) as ex:
        res = list(ex.map(test, cands))
    ok = sorted([(f"{ip}:{p}", ms) for (ip, p), ms in res if ms is not None], key=lambda x: x[1])
    return ok, len(cands)

# ----------------------------------------------------------------- game detection / ping

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

# ----------------------------------------------------------------- config / tunnel

def split_endpoint(ep):
    host, _, port = ep.rpartition(":")
    return host, int(port)


def normalize_ranges(ranges, exclude_ip=None):
    nets = []
    for r in ranges:
        r = r.strip()
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


def find_client():
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    for path, kind in ((os.path.join(pf, "AmneziaWG", "amneziawg.exe"), "awg"),
                       (os.path.join(pf, "WireGuard", "wireguard.exe"), "wg")):
        if os.path.exists(path):
            return path, kind
    return None, None


def _run(cmd, timeout=30):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          creationflags=NOWIN, errors="ignore")


def service_name(kind):
    return ("AmneziaWGTunnel$" if kind == "awg" else "WireGuardTunnel$") + TUNNEL


def tunnel_running(kind):
    if os.name != "nt" or not kind:
        return False
    try:
        return "RUNNING" in _run(["sc", "query", service_name(kind)]).stdout
    except (OSError, subprocess.TimeoutExpired):
        return False


def tunnel_down(exe):
    _run([exe, "/uninstalltunnelservice", TUNNEL])


def tunnel_up(exe, kind, conf_text):
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


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resource(name):
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), name)

# ----------------------------------------------------------------- game / ping / stats v2

def game_remote_endpoints(names):
    """{ip: tcp_port | None} для подключений процесса игры."""
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
    except (OSError, subprocess.TimeoutExpired, IndexError, ValueError):
        return None


# Готовые списки. Собраны из реальных подключений игры (журнал ABI Route, ноябрь 2026).
PRESETS = {
    "ABI — найденные серверы (/24)": [
        "43.153.253.0/24", "43.163.53.0/24", "43.163.63.0/24", "43.168.141.0/24",
        "43.174.218.0/24", "43.174.250.0/24", "43.174.251.0/24", "101.32.107.0/24",
        "101.32.113.0/24", "101.32.171.0/24", "101.33.43.0/24", "101.33.48.0/24",
        "129.226.1.0/24", "129.226.2.0/24", "188.43.72.0/24"],
    "ABI — широкий охват (/16)": [
        "43.153.0.0/16", "43.163.0.0/16", "43.168.0.0/16", "43.174.0.0/16",
        "101.32.0.0/16", "101.33.0.0/16", "129.226.0.0/16", "188.43.72.0/24"],
}

JUNK_PROFILES = [
    {"Jc": 4, "Jmin": 40, "Jmax": 70},     # лёгкая маскировка
    {"Jc": 120, "Jmin": 23, "Jmax": 911},  # сильная (как в популярных генераторах WARP для РФ)
]


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

    with ThreadPoolExecutor(max_workers=len(targets)) as ex:
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


# ----------------------------------------------------------------- GUI

BG, SURF, RAISED, EDGE = "#191919", "#202020", "#2c2c2b", "#383836"
FG, MUTED = "#ffffff", "#a5a5a3"
ACC, ACC_H = "#5e9fe8", "#7db3ef"
OK, WAIT, BAD = "#72bc8f", "#de9255", "#e97366"
TINT = {OK: "#1f2a24", WAIT: "#2f261d", BAD: "#30201e", ACC: "#1c2634"}
FONT = "Segoe UI"
MONO = "Consolas"


def fmt_bytes(n):
    n = float(n)
    for u in ("Б", "КБ", "МБ"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.2f} ГБ"


class App:
    def __init__(self):
        self.st = load_settings()
        self.lock = threading.RLock()
        self.q = queue.Queue()
        self.exe, self.kind = find_client()
        self.running = False
        self.armed = False
        self.pending = False
        self.busy = False
        self.last_restart = 0.0
        self.last_failover = 0.0
        self.started_at = 0.0
        self.fails = 0
        self.verify = [tuple(t) for t in self.st.get("verify_targets", [])]
        self.last_why = ""
        self.results = {}  # ip -> {"direct": {...}|None, "warp": {...}|None}

        r = self.root = tk.Tk()
        global FONT
        try:
            if FONT not in tkfont.families(r):
                FONT = "Arial"
        except Exception:
            FONT = "Arial"
        r.title(f"{APP_NAME} — Arena Breakout Infinite")
        r.geometry("940x740")
        r.minsize(860, 660)
        r.configure(bg=BG)
        try:
            r.iconbitmap(resource("icon.ico"))
        except Exception:
            pass
        self._style()
        self._build()
        r.protocol("WM_DELETE_WINDOW", self.on_close)
        r.after(100, self._pump)
        threading.Thread(target=self._watcher, daemon=True).start()
        self._startup_checks()

    # ---------- helpers
    def log(self, msg):
        self.q.put(("log", f"[{time.strftime('%H:%M:%S')}] {msg}"))

    def ui(self, fn):
        self.q.put(("call", fn))

    def bg(self, fn):
        def wrap():
            try:
                fn()
            except Exception as e:  # noqa
                self.log(f"Ошибка: {e}")
            finally:
                self.busy = False
        if self.busy:
            self.log("Подождите, предыдущая операция ещё выполняется…")
            return
        self.busy = True
        threading.Thread(target=wrap, daemon=True).start()

    def _pump(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "log":
                    for w in (self.log_txt, self.mini_log):
                        w.configure(state="normal")
                        w.insert("end", val + "\n")
                        w.see("end")
                        w.configure(state="disabled")
                else:
                    val()
        except queue.Empty:
            pass
        self.root.after(100, self._pump)

    def _awg(self):
        """Маскировка для сканирования: не больше 8 мусорных пакетов на проверку."""
        if self.kind == "wg":
            return None
        a = dict(self.st["awg"])
        a["Jc"] = min(int(a["Jc"]), 8)
        return a

    # ---------- widgets
    def _style(self):
        s = ttk.Style(self.root)
        s.theme_use("clam")
        s.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        s.configure("TNotebook.Tab", background=BG, foreground=MUTED, padding=(18, 9), borderwidth=0,
                    font=(FONT, 10, "bold"), lightcolor=BG, bordercolor=BG, focuscolor=BG)
        s.map("TNotebook.Tab", background=[("selected", SURF), ("active", RAISED)],
              foreground=[("selected", FG), ("active", FG)])
        s.configure("Treeview", background=SURF, fieldbackground=SURF, foreground=FG, rowheight=28,
                    borderwidth=0, font=(FONT, 10))
        s.configure("Treeview.Heading", background=RAISED, foreground=MUTED, relief="flat",
                    font=(FONT, 9, "bold"), borderwidth=0)
        s.map("Treeview.Heading", background=[("active", EDGE)])
        s.map("Treeview", background=[("selected", TINT[ACC])], foreground=[("selected", ACC)])
        s.configure("TCombobox", fieldbackground=RAISED, background=RAISED, foreground=FG, arrowcolor=FG,
                    bordercolor=EDGE, lightcolor=RAISED, darkcolor=RAISED)
        s.map("TCombobox", fieldbackground=[("readonly", RAISED)], foreground=[("readonly", FG)])
        s.configure("Horizontal.TProgressbar", troughcolor=RAISED, background=ACC, borderwidth=0,
                    lightcolor=ACC, darkcolor=ACC, thickness=6)
        self.root.option_add("*TCombobox*Listbox.background", RAISED)
        self.root.option_add("*TCombobox*Listbox.foreground", FG)

    def _btn(self, parent, text, cmd, primary=False, big=False):
        b = tk.Button(parent, text=text, command=cmd, relief="flat", bd=0, cursor="hand2",
                      highlightthickness=0, padx=20 if big else 14, pady=12 if big else 6,
                      font=(FONT, 12 if big else 10, "bold"))
        self._paint(b, primary)
        b.bind("<Enter>", lambda e: b.configure(bg=b._hover))
        b.bind("<Leave>", lambda e: b.configure(bg=b._base))
        return b

    @staticmethod
    def _paint(b, primary):
        b._base, b._hover = (ACC, ACC_H) if primary else (RAISED, EDGE)
        fg = "#0d1622" if primary else FG
        b.configure(bg=b._base, fg=fg, activebackground=b._hover, activeforeground=fg)

    def _card(self, parent, title=None, sub=None):
        f = tk.Frame(parent, bg=SURF, highlightbackground=EDGE, highlightthickness=1)
        if title:
            tk.Label(f, text=title, bg=SURF, fg=FG, font=(FONT, 11, "bold")).pack(anchor="w", padx=16, pady=(12, 0))
        if sub:
            tk.Label(f, text=sub, bg=SURF, fg=MUTED, font=(FONT, 9), justify="left",
                     wraplength=760).pack(anchor="w", padx=16, pady=(2, 0))
        inner = tk.Frame(f, bg=SURF)
        inner.pack(fill="both", expand=True, padx=16, pady=(8, 14))
        return f, inner

    def _lbl(self, parent, text="", muted=False, size=9, bold=False, **kw):
        return tk.Label(parent, text=text, bg=parent["bg"], fg=MUTED if muted else FG,
                        font=(FONT, size, "bold" if bold else "normal"), justify="left", anchor="w", **kw)

    def _check(self, parent, text, var, cmd):
        return tk.Checkbutton(parent, text=text, variable=var, command=cmd, bg=parent["bg"], fg=FG,
                              selectcolor=RAISED, activebackground=parent["bg"], activeforeground=FG,
                              highlightthickness=0, bd=0, font=(FONT, 10), cursor="hand2")

    def _text(self, parent, height, mono=True, log=False):
        t = tk.Text(parent, height=height, bg="#151515" if log else RAISED, fg=MUTED if log else FG,
                    insertbackground=FG, relief="flat", bd=0, padx=10, pady=8, wrap="word",
                    font=(MONO if mono else FONT, 9 if log else 10), highlightthickness=1,
                    highlightbackground=EDGE, highlightcolor=ACC)
        if log:
            t.configure(state="disabled")
        return t

    def _tile(self, parent, col, title):
        f = tk.Frame(parent, bg=SURF, highlightbackground=EDGE, highlightthickness=1)
        f.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 6, 0 if col == 2 else 6))
        tk.Label(f, text=title, bg=SURF, fg=MUTED, font=(FONT, 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        v = tk.Label(f, text="—", bg=SURF, fg=FG, font=(FONT, 16, "bold"), anchor="w")
        v.pack(anchor="w", padx=16)
        s = tk.Label(f, text="", bg=SURF, fg=MUTED, font=(FONT, 9), anchor="w")
        s.pack(anchor="w", padx=16, pady=(0, 12))
        return v, s

    # ---------- layout
    def _build(self):
        root = self.root
        head = tk.Frame(root, bg=BG)
        head.pack(fill="x", padx=24, pady=(16, 10))
        tk.Label(head, text="ABI Route", bg=BG, fg=FG, font=(FONT, 18, "bold")).pack(side="left")
        tk.Label(head, text=f"  v{VERSION} · WARP только для Arena Breakout Infinite", bg=BG, fg=MUTED,
                 font=(FONT, 10)).pack(side="left", pady=(6, 0))
        self.pill = tk.Label(head, text="", font=(FONT, 10, "bold"), padx=12, pady=4)
        self.pill.pack(side="right")

        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=24, pady=(0, 18))
        tabs = {}
        for key, name in (("main", "Главная"), ("ping", "Пинг"), ("routes", "Серверы игры"), ("log", "Журнал")):
            f = tk.Frame(nb, bg=BG)
            nb.add(f, text=name)
            tabs[key] = f
        self._build_main(tabs["main"])
        self._build_ping(tabs["ping"])
        self._build_routes(tabs["routes"])
        self.log_txt = self._text(tabs["log"], 20, log=True)
        self.log_txt.pack(fill="both", expand=True, pady=(14, 0))
        self.set_state("off")
        self._refresh()

    def _build_main(self, tab):
        hero, hi = self._card(tab)
        hero.pack(fill="x", pady=(14, 12))
        left = tk.Frame(hi, bg=SURF)
        left.pack(side="left", fill="x", expand=True)
        self.hero_title = tk.Label(left, text="", bg=SURF, fg=FG, font=(FONT, 20, "bold"), anchor="w")
        self.hero_title.pack(anchor="w")
        self.hero_sub = tk.Label(left, text="", bg=SURF, fg=MUTED, font=(FONT, 10), anchor="w",
                                 justify="left", wraplength=560)
        self.hero_sub.pack(anchor="w", pady=(2, 0))
        self.start_btn = self._btn(hi, "", self.toggle, primary=True, big=True)
        self.start_btn.configure(width=14)
        self.start_btn.pack(side="right", padx=(12, 0))

        tiles = tk.Frame(tab, bg=BG)
        tiles.pack(fill="x", pady=(0, 12))
        for c in range(3):
            tiles.columnconfigure(c, weight=1, uniform="t")
        self.t_ep, self.t_ep_sub = self._tile(tiles, 0, "СЕРВЕР WARP")
        self.t_ping, self.t_ping_sub = self._tile(tiles, 1, "ПИНГ ДО ИГРЫ")
        self.t_conn, self.t_conn_sub = self._tile(tiles, 2, "СОЕДИНЕНИЕ")
        self.t_ping_sub.configure(text="откройте вкладку «Пинг»")
        self.t_conn_sub.configure(text="туннель выключен")

        setup = tk.Frame(tab, bg=BG)
        setup.pack(fill="x", pady=(0, 12))
        setup.columnconfigure(0, weight=1, uniform="s")
        setup.columnconfigure(1, weight=1, uniform="s")
        c1, i1 = self._card(setup, "Профиль WARP")
        c1.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.warp_lbl = self._lbl(i1, muted=True, wraplength=360)
        self.warp_lbl.pack(fill="x", pady=(0, 10))
        self._btn(i1, "Сгенерировать новый", self.do_generate).pack(anchor="w")

        c2, i2 = self._card(setup, "Сервер WARP")
        c2.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        row = tk.Frame(i2, bg=SURF)
        row.pack(fill="x")
        self._btn(row, "Найти лучший", self.do_scan, primary=True).pack(side="left")
        self._btn(row, "Автоподбор", self.do_autotune).pack(side="left", padx=(8, 0))
        self.fo_var = tk.BooleanVar(value=self.st.get("failover", True))
        self._check(i2, "Автосмена при сбое", self.fo_var, self.collect_ui).pack(anchor="w", pady=(10, 0))
        self.prog = ttk.Progressbar(i2, mode="determinate", style="Horizontal.TProgressbar")
        self.prog.pack(fill="x", pady=(12, 4))
        self._lbl(i2, "Список серверов — на вкладке «Пинг».", muted=True).pack(anchor="w")

        self._lbl(tab, "ПОСЛЕДНИЕ СОБЫТИЯ", muted=True, bold=True).pack(anchor="w", pady=(0, 4))
        self.mini_log = self._text(tab, 6, log=True)
        self.mini_log.pack(fill="both", expand=True)

    def _build_ping(self, tab):
        c, i = self._card(tab, "Пинг до серверов игры",
                          "Точный замер по TCP (как игровой трафик), а если нельзя — ICMP. «Сравнить» меряет "
                          "напрямую и через WARP (туннель на пару секунд переключится — не делайте это во время матча).")
        c.pack(fill="both", expand=True, pady=(14, 12))
        row = tk.Frame(i, bg=SURF)
        row.pack(fill="x", pady=(0, 10))
        self._btn(row, "Сравнить: напрямую vs WARP", lambda: self.do_measure(True), primary=True).pack(side="left")
        self._btn(row, "Замерить сейчас", lambda: self.do_measure(False)).pack(side="left", padx=8)
        self._btn(row, "Автоподбор WARP", self.do_autotune).pack(side="left")
        cols = (("ip", "Сервер", 140), ("how", "Метод", 90), ("d", "Напрямую", 100),
                ("w", "Через WARP", 100), ("diff", "Разница", 90), ("j", "Стабильность", 190))
        t = self.ping_tree = ttk.Treeview(i, columns=[x[0] for x in cols], show="headings", height=7)
        for key, name, w in cols:
            t.heading(key, text=name)
            t.column(key, width=w, anchor="w" if key == "ip" else "center")
        t.tag_configure("better", foreground=OK)
        t.tag_configure("worse", foreground=WAIT)
        t.pack(fill="both", expand=True)
        self.ping_sum = self._lbl(i, "Нажмите «Сравнить», чтобы увидеть, даёт ли WARP выигрыш.", size=10,
                                  wraplength=800)
        self.ping_sum.pack(anchor="w", pady=(10, 0))

        c2, i2 = self._card(tab, "Серверы WARP", "Результат последнего поиска. Двойной клик — выбрать вручную. "
                                                "Остальные серверы — запас ��ля автосмены.")
        c2.pack(fill="both", expand=True)
        t2 = self.ep_tree = ttk.Treeview(i2, columns=("ep", "ms", "st"), show="headings", height=5)
        for key, name, w in (("ep", "Сервер", 220), ("ms", "Рукопожатие", 120), ("st", "", 140)):
            t2.heading(key, text=name)
            t2.column(key, width=w, anchor="w" if key == "ep" else "center")
        t2.tag_configure("cur", foreground=ACC)
        t2.pack(fill="both", expand=True)
        t2.bind("<Double-1>", self.on_pick_endpoint)

    def _build_routes(self, tab):
        c, i = self._card(tab, "Что идёт через WARP",
                          "Только эти IP-диапазоны. Весь остальной трафик (браузер, Discord, загрузки) идёт напрямую.")
        c.pack(fill="both", expand=True, pady=(14, 12))
        pr = tk.Frame(i, bg=SURF)
        pr.pack(fill="x", pady=(0, 10))
        self._lbl(pr, "Готовый список:", muted=True).pack(side="left")
        self.preset_var = tk.StringVar(value=list(PRESETS)[0])
        ttk.Combobox(pr, textvariable=self.preset_var, values=list(PRESETS), width=36,
                     state="readonly").pack(side="left", padx=8)
        self._btn(pr, "Добавить", self.do_preset, primary=True).pack(side="left")
        self._btn(pr, "Очистить", self.do_clear_ranges).pack(side="right")

        self.ranges_txt = self._text(i, 8)
        self.ranges_txt.pack(fill="both", expand=True)
        self.ranges_txt.insert("1.0", "\n".join(self.st["ranges"]))
        row = tk.Frame(i, bg=SURF)
        row.pack(fill="x", pady=(10, 0))
        self.auto_var = tk.BooleanVar(value=self.st["auto_learn"])
        self._check(row, "Автопоиск серверов игры", self.auto_var, self.collect_ui).pack(side="left")
        self._lbl(row, "     Охват:", muted=True).pack(side="left")
        self.prefix_var = tk.StringVar(value=f"/{self.st['prefix']}")
        cb = ttk.Combobox(row, textvariable=self.prefix_var, values=["/24", "/20", "/16"], width=5,
                          state="readonly")
        cb.pack(side="left", padx=6)
        cb.bind("<<ComboboxSelected>>", lambda e: self.on_prefix())
        self._btn(row, "Применить", self.do_apply_routes).pack(side="right")

        bottom = tk.Frame(tab, bg=BG)
        bottom.pack(fill="x")
        bottom.columnconfigure(0, weight=1, uniform="b")
        bottom.columnconfigure(1, weight=1, uniform="b")
        c2, i2 = self._card(bottom, "Процессы игры")
        c2.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        self.proc_var = tk.StringVar(value=", ".join(self.st["game_processes"]))
        tk.Entry(i2, textvariable=self.proc_var, bg=RAISED, fg=FG, insertbackground=FG, relief="flat",
                 highlightthickness=1, highlightbackground=EDGE, highlightcolor=ACC,
                 font=(FONT, 10)).pack(fill="x", ipady=6)
        self._lbl(i2, "Через запятую. По ним ищутся серверы игры.", muted=True).pack(anchor="w", pady=(6, 0))
        c3, i3 = self._card(bottom, "Не пускать через WARP")
        c3.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        self.ignore_txt = self._text(i3, 2)
        self.ignore_txt.pack(fill="x")
        self.ignore_txt.insert("1.0", "\n".join(self.st.get("ignore_ranges", [])))
        self._lbl(i3, "Серверы обновлений/CDN — автопоиск их пропустит.", muted=True).pack(anchor="w", pady=(6, 0))

    # ---------- state
    def _refresh(self):
        w = self.st.get("warp")
        if w:
            self.warp_lbl.configure(text=f"Профиль создан {w.get('created', '')}\nАдрес в WARP: {w['v4']}", fg=OK)
        else:
            self.warp_lbl.configure(text="Профиля нет. Нажмите кнопку — программа зарегистрирует "
                                         "бесплатный ключ Cloudflare WARP.", fg=MUTED)
        self.t_ep.configure(text=self.st["endpoint"])
        ms = self.st.get("endpoint_ms")
        self.t_ep_sub.configure(text=f"рукопожатие {ms} мс" if ms else "нажмите «Найти лучший»")
        self._fill_eps()

    def _fill_eps(self):
        t = self.ep_tree
        t.delete(*t.get_children())
        cur = self.st["endpoint"]
        for item in self.st.get("endpoint_list", []):
            ep, ms = item
            t.insert("", "end", values=(ep, f"{ms} мс", "● текущий" if ep == cur else ""),
                     tags=("cur",) if ep == cur else ())

    def set_state(self, state):
        title, sub, color, pill, btn, primary = {
            "off": ("Туннель выключен", "Игра идёт напрямую. Нажмите «Запустить», чтобы пустить её через WARP.",
                    BAD, "ВЫКЛЮЧЕН", "Запустить", True),
            "wait": ("Ждём игру…", "Запустите Arena Breakout Infinite — туннель включится сам, как только появятся её серверы.",
                     WAIT, "ОЖИДАНИЕ", "Отмена", False),
            "on": ("Туннель работает", "Серверы игры идут через WARP, остальной трафик — напрямую. Окно можно свернуть.",
                   OK, "РАБОТАЕТ", "Остановить", False),
        }[state]
        self.hero_title.configure(text=title, fg=color if state != "off" else FG)
        self.hero_sub.configure(text=sub)
        self.pill.configure(text="●  " + pill, fg=color, bg=TINT[color])
        self.start_btn.configure(text=btn)
        self._paint(self.start_btn, primary)
        if state != "on":
            self.t_conn.configure(text="—")
            self.t_conn_sub.configure(text="туннель выключен" if state == "off" else "ждём игру")

    def _show_stats(self, s):
        self.t_conn.configure(text=f"↓ {fmt_bytes(s['rx'])}   ↑ {fmt_bytes(s['tx'])}")
        if s["handshake"]:
            age = int(time.time() - s["handshake"])
            self.t_conn_sub.configure(text=f"рукопожатие {age} с назад", fg=OK if age < 180 else WAIT)
        else:
            self.t_conn_sub.configure(text="ждём рукопожатие…", fg=WAIT)

    def _startup_checks(self):
        self.log(f"ABI Route {VERSION} запущен.")
        if os.name == "nt" and not is_admin():
            self.log("⚠ Нет прав администратора — запуск туннеля не сработает. Запустите от имени администратора.")
        if not self.exe:
            self.log("⚠ Не найден AmneziaWG/WireGuard. Установите AmneziaWG (рекомендуется для РФ): "
                     "github.com/amnezia-vpn/amneziawg-windows-client/releases")
        else:
            self.log(f"Клиент туннеля: {'AmneziaWG (с обфускацией)' if self.kind == 'awg' else 'WireGuard'}")
            if tunnel_running(self.kind):
                self.running = True
                self.started_at = time.time()
                self.set_state("on")
                self.log("Туннель уже работает в фоне.")
        if psutil is None:
            self.log("⚠ psutil не установлен — автопоиск IP игры недоступен.")

    # ---------- ui -> settings
    def _read_nets(self, widget):
        good = []
        for line in widget.get("1.0", "end").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ipaddress.ip_network(line, strict=False)
                good.append(line)
            except ValueError:
                self.log(f"Пропущена некорректная строка: {line}")
        return good

    def collect_ui(self):
        with self.lock:
            self.st["game_processes"] = [p.strip() for p in self.proc_var.get().split(",") if p.strip()]
            self.st["ranges"] = self._read_nets(self.ranges_txt)
            self.st["ignore_ranges"] = self._read_nets(self.ignore_txt)
            self.st["auto_learn"] = bool(self.auto_var.get())
            self.st["failover"] = bool(self.fo_var.get())
            save_settings(self.st)

    def on_prefix(self):
        with self.lock:
            self.st["prefix"] = int(self.prefix_var.get().strip("/"))
            save_settings(self.st)

    def do_clear_ranges(self):
        self.ranges_txt.delete("1.0", "end")
        self.collect_ui()
        self.log("Список диапазонов очищен.")

    def do_preset(self):
        name = self.preset_var.get()
        cur = self._read_nets(self.ranges_txt)
        merged = normalize_ranges(cur + PRESETS.get(name, []))
        self.ranges_txt.delete("1.0", "end")
        self.ranges_txt.insert("1.0", "\n".join(merged))
        self.collect_ui()
        self.log(f"Добавлен список «{name}»: теперь {len(merged)} диапазон(ов).")
        self.do_apply_routes(quiet=True)

    def do_apply_routes(self, quiet=False):
        self.collect_ui()
        if self.running:
            self.log("Маршруты изменены — перезапускаю туннель…")
            self.pending = True
            self.last_restart = 0
        elif not quiet:
            self.log("Маршруты сохранены.")

    def on_pick_endpoint(self, _e):
        sel = self.ep_tree.selection()
        if not sel:
            return
        ep, ms = self.ep_tree.item(sel[0], "values")[:2]
        with self.lock:
            self.st["endpoint"] = ep
            self.st["endpoint_ms"] = int(str(ms).split()[0])
            save_settings(self.st)
        self._refresh()
        self.log(f"Выбран сервер WARP {ep}." + (" Перезапускаю туннель…" if self.running else ""))
        if self.running:
            self.pending = True
            self.last_restart = 0

    # ---------- actions
    def do_generate(self):
        if self.st.get("warp") and not messagebox.askyesno(
                APP_NAME, "Профиль уже есть. Создать новый?\nПолезно, если старый перестал работать."):
            return

        def job():
            self.log("Регистрирую профиль Cloudflare WARP…")
            w = warp_register()
            with self.lock:
                self.st["warp"] = w
                save_settings(self.st)
            self.ui(self._refresh)
            self.log(f"Готово! Адрес в WARP: {w['v4']}. Теперь нажмите «Найти лучший».")
            if self.running:
                self.pending = True
                self.last_restart = 0
        self.bg(job)

    def _save_scan(self, ok):
        with self.lock:
            self.st["endpoint_list"] = [[ep, round(ms)] for ep, ms in ok[:15]]
            self.st["endpoint"], self.st["endpoint_ms"] = ok[0][0], round(ok[0][1])
            save_settings(self.st)
        self.ui(self._refresh)

    def do_scan(self):
        if not self.st.get("warp"):
            self.log("Сначала сгенерируйте профиль WARP.")
            return

        def prog(d, t):
            self.ui(lambda: self.prog.configure(maximum=t, value=d))

        def job():
            self.log(f"Проверяю {len(WARP_IPS) * len(WARP_PORTS)} серверов WARP настоящим рукопожатием…")
            ok, total = scan_endpoints(self.st["warp"], self._awg(), prog)
            if not ok:
                self.log("Ни один сервер не ответил. Проверьте интернет; возможна блокировка UDP провайдером.")
                return
            self._save_scan(ok)
            self.log(f"Ответили {len(ok)} из {total}. Лучший: {ok[0][0]} — {ok[0][1]:.0f} мс (выбран). "
                     f"Ещё {min(len(ok), 15) - 1} в запасе для автосмены.")
            if self.running:
                self.pending = True
                self.last_restart = 0
        self.bg(job)

    # ---------- ping
    def _targets(self, n=8):
        with self.lock:
            ports = self.st.get("tcp_ports", {})
            ign = self.st.get("ignore_ranges", [])
            seen = [ip for ip in self.st.get("seen_ips", []) if not in_nets(ip, ign)]
            seen.sort(key=lambda ip: 0 if ports.get(ip) else 1)
            ips = seen[:n]
            if not ips:
                ips = [str(next(iter(ipaddress.ip_network(r, strict=False).hosts()), r.split("/")[0]))
                       for r in self.st["ranges"][:n]]
        return ips

    def _measure(self, ips, mode):
        label = "через WARP" if mode == "warp" else "напрямую"
        self.log(f"Меряю пинг {label} до {len(ips)} серверов…")
        ports = dict(self.st.get("tcp_ports", {}))
        with ThreadPoolExecutor(max_workers=8) as ex:
            res = list(ex.map(lambda ip: (ip, best_ping(ip, ports.get(ip))), ips))
        for ip, r in res:
            self.results.setdefault(ip, {})[mode] = r
        if mode == "direct":
            with self.lock:
                ranges = list(self.st["ranges"])
            good = sorted([(ip, r.get("port", 0)) for ip, r in res if r and in_nets(ip, ranges)],
                          key=lambda t: t[1] == 0)[:4]
            if good:
                self.verify = good
                with self.lock:
                    self.st["verify_targets"] = [list(t) for t in good]
                    save_settings(self.st)
        vals = [r["ms"] for _, r in res if r]
        self.ui(self._fill_ping)
        if vals:
            med = round(statistics.median(vals))
            self.ui(lambda: (self.t_ping.configure(text=f"{med} мс"),
                             self.t_ping_sub.configure(text=f"медиана, {label}")))
            self.log(f"Готово ({label}): ответили {len(vals)} из {len(ips)}, медиана {med} мс.")
        else:
            self.log(f"Готово ({label}): ни один сервер не ответил на пинг.")

    def _fill_ping(self):
        t = self.ping_tree
        t.delete(*t.get_children())
        diffs = []

        def cell(rr, key):
            if key not in rr:
                return "—"
            return f"{rr[key]['ms']} мс" if rr[key] else "нет ответа"

        for ip, rr in self.results.items():
            d, w = rr.get("direct"), rr.get("warp")
            src = w or d
            diff, tag = "—", ()
            if d and w:
                dv = w["ms"] - d["ms"]
                diffs.append(dv)
                diff = f"{dv:+d} мс"
                tag = ("better",) if dv < -2 else ("worse",) if dv > 2 else ()
            stab = f"±{src['jitter']} мс · потери {src['loss']}%" if src else "—"
            t.insert("", "end", values=(ip, src["how"] if src else "—", cell(rr, "direct"), cell(rr, "warp"),
                                         diff, stab), tags=tag)
        if not diffs:
            tested = [rr for rr in self.results.values() if "warp" in rr]
            if tested and not any(rr["warp"] for rr in tested):
                self.ping_sum.configure(fg=BAD, text=(
                    "Через WARP не ответил ни один сервер — туннель поднимается, но трафик не идёт. "
                    "Нажмите «Автоподбор WARP»: программа сама переберёт серверы WARP и маскировку "
                    "и оставит рабочий вариант."))
            return
        avg = round(statistics.mean(diffs))
        if avg < -2:
            msg, col = f"Через WARP быстрее в среднем на {-avg} мс — оставляйте туннель включённым.", OK
        elif avg > 2:
            msg, col = (f"Через WARP медленнее в среднем на {avg} мс. Попробуйте «Найти лучший» сервер WARP; "
                        "если игра заходит и без туннеля — его можно не включать."), WAIT
        else:
            msg, col = "Разницы почти нет — WARP не добавляет задержки.", OK
        self.ping_sum.configure(text=msg, fg=col)

    def do_measure(self, compare):
        def job():
            ips = self._targets()
            if not ips:
                self.log("Пока нет серверов игры. Запустите игру или добавьте готовый список.")
                return
            can = bool(self.exe and self.st.get("warp") and self.st["ranges"])
            if not compare or not can:
                if compare:
                    self.log("Для сравнения нужен профиль WARP, клиент туннеля и серверы игры — меряю только текущий режим.")
                self._measure(ips, "warp" if self.running else "direct")
                return
            was_on = self.running
            self._measure(ips, "warp" if was_on else "direct")
            if was_on:
                tunnel_down(self.exe)
                self.running = False
                self.ui(lambda: self.set_state("off"))
                time.sleep(2)
                self._measure(ips, "direct")
                self._apply()
            else:
                self._apply()
                if self.running:
                    wait_tunnel(self.verify or [(ip, 0) for ip in ips[:3]], 8)
                    self._measure(ips, "warp")
                self._stop()
        self.bg(job)

    # ---------- tunnel
    def toggle(self):
        if self.running or self.armed:
            self.bg(self._stop)
            return
        self.collect_ui()
        if not self.exe:
            messagebox.showerror(APP_NAME, "Не найден AmneziaWG или WireGuard.\nУстановите AmneziaWG и "
                                           "перезапустите программу.")
            return
        if not self.st.get("warp"):
            messagebox.showinfo(APP_NAME, "Сначала нажмите «Сгенерировать» в карточке «Профиль WARP».")
            return
        if not self.st["ranges"]:
            if not self.st["auto_learn"]:
                messagebox.showinfo(APP_NAME, "Добавьте серверы игры (вкладка «Серверы игры») или включите автопоиск.")
                return
            self.armed = True
            self.set_state("wait")
            self.log("Запустите Arena Breakout Infinite — как только появятся её подключения, туннель включится.")
            return
        self.bg(self._apply)

    def _apply(self):
        with self.lock:
            conf = build_conf(self.st, self.kind)
            n = len(normalize_ranges(self.st["ranges"]))
            ep = self.st["endpoint"]
        self.last_restart = time.time()
        ok, err = tunnel_up(self.exe, self.kind, conf)
        if ok:
            self.running, self.armed = True, False
            self.started_at = time.time()
            self.fails = 0
            self.ui(lambda: self.set_state("on"))
            self.log(f"Туннель работает: {n} диапазон(ов) игры → WARP {ep}. Остальной трафик идёт напрямую.")
        else:
            self.log(f"Не удалось запустить туннель: {err}")

    def _stop(self):
        self.armed = False
        if self.exe:
            tunnel_down(self.exe)
        self.running = False
        self.ui(lambda: self.set_state("off"))
        self.log("Туннель остановлен.")

    # ---------- failover
    def _health(self):
        """(сломан?, сколько неудач подряд нужно). сломан: True / False / None (неизвестно)."""
        stats = tunnel_stats(self.exe, self.kind)
        if stats:
            self.ui(lambda: self._show_stats(stats))
        if self.verify:
            return check_targets(self.verify) is None, 2
        if stats:
            if not stats["handshake"]:
                return (time.time() - self.started_at) > 45, 1
            return (time.time() - stats["handshake"]) > 200, 1
        return None, 3

    def _failover(self):
        self.last_failover = time.time()
        cur = self.st["endpoint"]
        if self.verify:
            self.log(f"⚠ Через WARP {cur} серверы игры перестали отвечать — переподключаюсь и ищу замену…")
            res = self._find_working(self._variants()[:6], self.verify, "Автосмена")
            if res:
                self._tuned(*res)
                return
            self.log("Рабочая замена не найдена — возвращаю прежние настройки. Позже нажмите «Автоподбор».")
            self._apply()
            return
        self.log(f"⚠ Сервер WARP {cur} перестал отвечать — ищу замену…")
        cands = [e for e, _ in self.st.get("endpoint_list", []) if e != cur]
        ok = probe_endpoints(cands, self.st["warp"], self._awg(), tries=1)[0] if cands else []
        if not ok:
            ok = [x for x in scan_endpoints(self.st["warp"], self._awg(), tries=1)[0] if x[0] != cur]
        if ok:
            best, ms = ok[0]
            with self.lock:
                self.st["endpoint"], self.st["endpoint_ms"] = best, round(ms)
                save_settings(self.st)
            self.ui(self._refresh)
            self.log(f"Переключаюсь на {best} ({ms:.0f} мс).")
        else:
            self.log("Замена не найдена — переподключаю текущий сервер.")
        self._apply()

    # ---------- autotune
    def _candidate_targets(self):
        """Серверы игры внутри маршрутов, по которым можно проверить туннель: [(ip, tcp_port или 0)]."""
        with self.lock:
            ranges = list(self.st["ranges"])
            ign = list(self.st.get("ignore_ranges", []))
            ports = dict(self.st.get("tcp_ports", {}))
            seen = list(self.st.get("seen_ips", []))
        out = []

        def add(ip, port):
            if in_nets(ip, ranges) and not in_nets(ip, ign) and (ip, port) not in out:
                out.append((ip, port))
        for ip, port in self.verify:
            add(ip, port)
        for ip, rr in list(self.results.items()):
            if rr.get("direct"):
                add(ip, rr["direct"].get("port", 0))
        for ip, port in reversed(list(ports.items())):
            if port:
                add(ip, port)
        for ip in seen[:8]:
            add(ip, 0)
        return out[:12]

    def _variants(self):
        """Варианты для перебора: (сервер WARP, маскировка). Первый — текущие настройки (переподключение)."""
        cur = self.st["endpoint"]
        lst = [e for e, _ in self.st.get("endpoint_list", [])]
        eps, ips = [cur], {split_endpoint(cur)[0]}
        for e in lst:  # сначала разные IP — на случай, если провайдер режет конкретный адрес
            if split_endpoint(e)[0] not in ips:
                eps.append(e)
                ips.add(split_endpoint(e)[0])
        eps += [e for e in lst if e not in eps]
        eps = eps[:5]
        if self.kind == "wg":
            return [(e, None) for e in eps]
        mine = {k: int(v) for k, v in self.st["awg"].items()}
        profs = [mine] + [p for p in JUNK_PROFILES if p != mine]
        out = []
        for i, e in enumerate(eps):
            for j, prof in enumerate(profs):
                if j == 0 or i < 3:  # сильную маскировку пробуем на трёх первых серверах
                    out.append((e, dict(prof)))
        return out[:9]

    def _find_working(self, variants, targets, label):
        """Поднимает туннель с каждым вариантом и проверяет серверы игры. -> (ep, awg, мс) или None."""
        orig_ep, orig_awg = self.st["endpoint"], dict(self.st["awg"])
        total = len(variants)
        self.last_why = ""
        for n, (ep, prof) in enumerate(variants, 1):
            self.ui(lambda n=n: self.prog.configure(maximum=total, value=n - 1))
            with self.lock:
                self.st["endpoint"] = ep
                if prof:
                    self.st["awg"] = dict(prof)
                conf = build_conf(self.st, self.kind)
            desc = ep + (f", маскировка Jc={prof['Jc']}" if prof else "")
            ok, err = tunnel_up(self.exe, self.kind, conf)
            if not ok:
                self.log(f"{label} {n}/{total}: {desc} — туннель не запустился: {err[:120]}")
                continue
            ms = wait_tunnel(targets, 8)
            if ms is not None:
                self.ui(lambda: self.prog.configure(maximum=total, value=total))
                with self.lock:
                    save_settings(self.st)
                return ep, prof, ms
            why = ""
            stats = tunnel_stats(self.exe, self.kind)
            if stats:
                self.last_why = "hs" if stats["handshake"] else "nohs"
                why = " (рукопожатие есть, но данные не проходят)" if stats["handshake"] else " (нет даже рукопожатия)"
            self.log(f"{label} {n}/{total}: {desc} — серверы игры через WARP не отвечают{why}")
        with self.lock:
            self.st["endpoint"], self.st["awg"] = orig_ep, orig_awg
            save_settings(self.st)
        tunnel_down(self.exe)
        self.running = False
        self.ui(lambda: (self.prog.configure(value=0), self.set_state("off"), self._refresh()))
        return None

    def _tuned(self, ep, prof, ms):
        self.running, self.armed = True, False
        self.started_at = time.time()
        self.fails = 0
        with self.lock:
            known = {e: m for e, m in self.st.get("endpoint_list", [])}
            if ep in known:
                self.st["endpoint_ms"] = known[ep]
            save_settings(self.st)
        self.ui(lambda: (self.set_state("on"), self._refresh(), self.t_ping.configure(text=f"{ms} мс"),
                         self.t_ping_sub.configure(text="через WARP, проверено")))
        self.log(f"✓ Работает: WARP {ep}" + (f", маскировка Jc={prof['Jc']}" if prof else "")
                 + f". Сервер игры отвечает через туннель за {ms} мс. Настройки сохранены, туннель включён.")

    def do_autotune(self):
        self.collect_ui()
        if not self.exe or not self.st.get("warp"):
            self.log("Для автоподбора нужны AmneziaWG и профиль WARP («Сгенерировать новый»).")
            return
        if not self.st["ranges"]:
            self.log("Сначала добавьте серверы игры: вкладка «Серверы игры» → «Готовый список» → «Добавить».")
            return
        self.bg(self._autotune)

    def _autotune(self):
        self.log("Автоподбор: ищу настройки, при которых серверы игры отвечают через WARP (до пары минут).")
        if self.running or tunnel_running(self.kind):
            tunnel_down(self.exe)
            self.running = False
            self.ui(lambda: self.set_state("off"))
            time.sleep(2)
        cands = self._candidate_targets()
        res = []
        if cands:
            with ThreadPoolExecutor(max_workers=8) as ex:
                res = list(ex.map(lambda t: (t, check_targets([t])), cands))
        direct = sorted([t for t, ms in res if ms is not None], key=lambda t: t[1] == 0)[:4]
        if not direct:
            self.log("Серверы игры не отвечают даже напрямую — проверять туннель не на чем. "
                     "Запустите игру (до главного меню) и повторите автоподбор.")
            return
        self.verify = direct
        with self.lock:
            self.st["verify_targets"] = [list(t) for t in direct]
            save_settings(self.st)
        self.log("Проверяю по серверам игры: " + ", ".join(f"{ip}:{p}" if p else ip for ip, p in direct))
        if not self.st.get("endpoint_list"):
            self.log("Сначала ищу серверы WARP…")
            ok, _ = scan_endpoints(self.st["warp"], self._awg(), tries=1)
            if ok:
                self._save_scan(ok)
        found = self._find_working(self._variants(), direct, "Автоподбор")
        if found:
            self._tuned(*found)
            return
        hint = {"hs": "Рукопожатие с WARP проходит, а данные блокируются — похоже на блокировку у провайдера.",
                "nohs": "Серверы WARP не принимают подключение туннеля — похоже, провайдер блокирует WARP."}.get(
            self.last_why, "Трафик через WARP не идёт ни на одном варианте.")
        self.log("✗ Рабочий вариант не найден. " + hint + " Что попробовать: 1) раздайте интернет с телефона "
                 "и повторите автоподбор — станет понятно, дело в провайдере или нет; 2) «Сгенерировать новый» профиль "
                 "WARP и снова «Автоподбор»; 3) если игра заходит без туннеля — играйте напрямую.")

    # ---------- background watcher
    def _watcher(self):
        tick = 0
        while True:
            time.sleep(4)
            tick += 1
            try:
                with self.lock:
                    auto = self.st.get("auto_learn")
                    names = list(self.st["game_processes"])
                    prefix = int(self.st.get("prefix", 24))
                    ep_ip = split_endpoint(self.st["endpoint"])[0]
                if auto:
                    eps = game_remote_endpoints(names)
                    eps.pop(ep_ip, None)
                    if eps:
                        self._learn(eps, prefix)
                if self.pending and not self.busy and time.time() - self.last_restart > 15:
                    self.pending = False
                    self.busy = True
                    try:
                        self._apply()
                    finally:
                        self.busy = False
                if self.running and not self.busy and tick % 5 == 0:
                    broken, need = self._health()
                    if broken:
                        self.fails += 1
                    elif broken is False:
                        self.fails = 0
                    if (self.fails >= need and self.st.get("failover") and not self.busy
                            and time.time() - self.last_failover > 60):
                        self.fails = 0
                        self.busy = True
                        try:
                            self._failover()
                        finally:
                            self.busy = False
            except Exception as e:  # noqa
                self.log(f"Фоновая ошибка: {e}")

    def _learn(self, eps, prefix):
        with self.lock:
            changed = False
            ports = self.st.setdefault("tcp_ports", {})
            for ip, port in eps.items():
                if port and ports.get(ip) != port:
                    ports.pop(ip, None)
                    ports[ip] = port
                    changed = True
            while len(ports) > 100:
                ports.pop(next(iter(ports)))
            ign = self.st.get("ignore_ranges", [])
            ips = {ip for ip in eps if not in_nets(ip, ign)}
            cur = [ipaddress.ip_network(r, strict=False) for r in self.st["ranges"]]
            new = []
            for ip in sorted(ips):
                a = ipaddress.ip_address(ip)
                if any(a in n for n in cur + new):
                    continue
                new.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            seen = [ip for ip in ips if ip not in self.st["seen_ips"]]
            if seen:
                self.st["seen_ips"] = (seen + self.st["seen_ips"])[:50]
                changed = True
            if new:
                self.st["ranges"] += [str(n) for n in new]
                changed = True
            if changed:
                save_settings(self.st)
        if not new:
            return
        lines = "\n".join(str(n) for n in new)

        def add():
            cur_text = self.ranges_txt.get("1.0", "end").strip()
            self.ranges_txt.insert("end", ("\n" if cur_text else "") + lines)
        self.ui(add)
        self.log(f"Найдены новые серверы игры: {', '.join(str(n) for n in new)}")
        if self.running or self.armed:
            self.pending = True
            if self.armed:
                self.last_restart = 0

    def on_close(self):
        if self.running:
            ans = messagebox.askyesnocancel(
                APP_NAME, "Туннель работает как служба Windows.\n\n"
                          "Да — свернуть окно (автопоиск и автосмена продолжат работать)\n"
                          "Нет — выключить туннель и выйти\nОтмена — вернуться")
            if ans is None:
                return
            if ans:
                self.root.iconify()
                return
            if self.exe:
                tunnel_down(self.exe)
        self.root.destroy()

    def run(self):
        self.root.mainloop()


if __name__ == "__main__":
    App().run()
