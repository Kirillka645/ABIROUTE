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
* v3: маскировка QUIC/DNS (AmneziaWG 2), радар UDP для серверов матчей, маршруты без
  перезапуска, сравнение пинга без отключения туннеля, импорт/экспорт конфигов.
"""
import base64
import ctypes
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import queue
import random
import re
import secrets
import socket
import ssl
import statistics
import string
import struct
import subprocess
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

try:
    import psutil
except ImportError:  # pragma: no cover
    psutil = None

try:
    import tkinter as tk
    from tkinter import font as tkfont
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # позволяет тестировать ядро без GUI
    tk = None

APP_NAME = "ABI Route"
TUNNEL = "ABIRoute"
DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ABIRoute")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
CONF_PATH = os.path.join(DATA_DIR, TUNNEL + ".conf")
LOG_PATH = os.path.join(DATA_DIR, "abiroute.log")
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
    "mimic": "off",  # маскировка I1 (AmneziaWG 2): off | quic | dns | import
    "mimic_sni": "www.google.com",
    "mimic_i1": "",
    "mimic_key": "",
    "mimic_import": {},
    "radar": True,  # искать серверы матчей по UDP-пакетам игры
}
VERSION = "3.0"

# ----------------------------------------------------------------- settings

def load_settings():
    st = json.loads(json.dumps(DEFAULTS))
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            st.update(data)
    except (OSError, ValueError):
        pass
    a = st.get("awg")
    if not (isinstance(a, dict) and all(isinstance(a.get(k), int) for k in ("Jc", "Jmin", "Jmax"))):
        st["awg"] = dict(DEFAULTS["awg"])
    for k in ("ranges", "seen_ips", "endpoint_list", "game_processes", "ignore_ranges", "verify_targets"):
        if not isinstance(st.get(k), list):
            st[k] = list(DEFAULTS[k])
    for k in ("tcp_ports", "ping", "mimic_import"):
        if not isinstance(st.get(k), dict):
            st[k] = {}
    return st


def save_settings(st):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = SETTINGS_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(st, f, ensure_ascii=False, indent=2)
    os.replace(tmp, SETTINGS_PATH)


_LOG_LOCK = threading.Lock()


def log_file(line):
    """Журнал abiroute.log рядом с настройками (до ~1 МБ, затем .1) — для разбора пр��блем."""
    try:
        with _LOG_LOCK:
            os.makedirs(DATA_DIR, exist_ok=True)
            if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 1_000_000:
                os.replace(LOG_PATH, LOG_PATH + ".1")
            with open(LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError:
        pass

# ----------------------------------------------------------------- keys / WARP API

def b64(b):
    return base64.b64encode(b).decode()


def gen_keypair():
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return priv, pub


def key32(text):
    """base64-ключ WireGuard -> 32 байта (ValueError, если это не ключ)."""
    try:
        raw = base64.b64decode(str(text).strip(), validate=True)
    except (ValueError, TypeError):
        raise ValueError("ключ не в формате base64") from None
    if len(raw) != 32:
        raise ValueError("ключ должен быть 32 байта")
    return raw


def pub_from_priv(priv_b64):
    k = X25519PrivateKey.from_private_bytes(key32(priv_b64))
    return b64(k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def is_ipv4(s):
    try:
        return ipaddress.ip_address(str(s)).version == 4
    except ValueError:
        return False


WARP_HOST = "api.cloudflareclient.com"
WARP_PEER_KEY = "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
# Версии API: если Cloudflare начнёт отклонять одну, пробуем следующую.
WARP_APIS = [("v0a2158", "a-6.10-2158"), ("v0a1922", "a-6.3-1922")]


class _PinnedHTTPS(http.client.HTTPSConnection):
    """HTTPS на заданный IP с правильным SNI — когда DNS провайдера не отдаёт адрес API."""

    def __init__(self, host, ip, timeout):
        super().__init__(host, 443, timeout=timeout, context=ssl.create_default_context())
        self._pin_ip = ip

    def connect(self):
        sock = socket.create_connection((self._pin_ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _https(method, host, path, headers, data, timeout, ip=None):
    conn = (_PinnedHTTPS(host, ip, timeout) if ip else
            http.client.HTTPSConnection(host, 443, timeout=timeout, context=ssl.create_default_context()))
    try:
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        return r.status, r.read()
    finally:
        conn.close()


def doh_resolve(host, timeout=6):
    """IPv4-адреса через DNS-over-HTTPS (Cloudflare, Google) — в обход DNS провайдера."""
    out = []
    for srv, path in (("1.1.1.1", "/dns-query"), ("8.8.8.8", "/resolve"), ("1.0.0.1", "/dns-query")):
        try:
            status, raw = _https("GET", srv, f"{path}?name={host}&type=A",
                                 {"Accept": "application/dns-json"}, None, timeout)
            if status != 200:
                continue
            for a in json.loads(raw.decode("utf-8", "ignore")).get("Answer", []):
                if a.get("type") == 1 and is_ipv4(a.get("data")) and a["data"] not in out:
                    out.append(a["data"])
        except (OSError, ValueError, http.client.HTTPException):
            continue
        if out:
            break
    return out


def warp_api(method, path, body=None, token=None, timeout=15):
    """Запрос к API WARP: две версии API, при сетевой ошибке — адрес через DNS-over-HTTPS."""
    data = None if body is None else json.dumps(body).encode()
    errors, routes, dead, doh = [], [None], set(), False
    for ver, client in WARP_APIS:
        headers = {"User-Agent": "okhttp/3.12.1", "CF-Client-Version": client,
                   "Content-Type": "application/json; charset=UTF-8"}
        if token:
            headers["Authorization"] = "Bearer " + token
        i = 0
        while i < len(routes):
            ip = routes[i]
            i += 1
            if ip in dead:
                continue
            try:
                status, raw = _https(method, WARP_HOST, f"/{ver}{path}", headers, data, timeout, ip)
            except (OSError, http.client.HTTPException) as e:
                dead.add(ip)
                errors.append(f"{ip or WARP_HOST}: {e}")
                if not doh:
                    doh = True
                    routes += [a for a in doh_resolve(WARP_HOST) if a not in routes][:3]
                continue
            text = raw.decode("utf-8", "ignore")
            if 200 <= status < 300:
                return json.loads(text or "{}")
            errors.append(f"HTTP {status}: {text[:120]}")
            if status == 429:  # слишком часто — Cloudflare просит подождать
                time.sleep(4)
            break
    raise RuntimeError("API WARP недоступен (" + "; ".join(errors[-3:] or ["нет ответа"]) + ")")


def warp_register():
    """Регистрирует новый бесплатный аккаунт WARP и возвращает данные для конфига."""
    priv, pub = gen_keypair()
    body = {
        "key": b64(pub), "install_id": "", "fcm_token": "",
        "tos": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": True,
    }
    j = warp_api("POST", "/reg", body)
    d = j.get("result", j)
    cfg = d["config"]
    peer = cfg["peers"][0]
    addr = cfg["interface"]["addresses"]
    return {
        "private_key": b64(priv), "public_key": b64(pub),
        "peer_public_key": peer["public_key"],
        "v4": addr["v4"], "v6": addr.get("v6", ""),
        "id": d.get("id"), "token": d.get("token"),
        "created": datetime.now().strftime("%d.%m.%Y %H:%M"), "source": "api",
    }


AWG_KEEP = ("S1", "S2", "S3", "S4", "H1", "H2", "H3", "H4")
AWG_DEFAULT_SH = (("S1", "0"), ("S2", "0"), ("H1", "1"), ("H2", "2"), ("H3", "3"), ("H4", "4"))


def _ep_is_ip(ep):
    host, _, port = str(ep).rpartition(":")
    return is_ipv4(host) and port.isdigit()


def parse_conf(text):
    """Импорт конфига WireGuard / AmneziaWG (из генератора WARP или своего сервера).
    -> {"warp": профиль, "awg": {Jc, Jmin, Jmax} | None, "mimic": {I1…I5}, "endpoint": "ip:port" | ""}"""
    sec, iface, peer, peers = None, {}, {}, 0
    for raw in str(text).replace("\r", "").split("\n"):
        line = raw.strip().lstrip("\ufeff")
        if not line or line[0] in "#;":
            continue
        if line.startswith("[") and line.endswith("]"):
            sec = line[1:-1].strip().lower()
            peers += sec == "peer"
            continue
        if "=" not in line:
            continue
        k, v = (x.strip() for x in line.split("=", 1))
        k = k.lower()
        if k not in ("i1", "i2", "i3", "i4", "i5"):
            v = v.split("#")[0].strip()
        if sec == "interface":
            iface[k] = v
        elif sec == "peer" and peers == 1:
            peer[k] = v
    if "privatekey" not in iface:
        raise ValueError("в файле нет PrivateKey — это не конфиг WireGuard/AmneziaWG")
    priv = iface["privatekey"]
    pub = pub_from_priv(priv)
    v4 = v6 = ""
    for a in re.split(r"[,\s]+", iface.get("address", "")):
        ip = a.split("/")[0]
        if not v4 and is_ipv4(ip):
            v4 = ip
        elif not v6 and ":" in ip:
            v6 = ip
    if not v4:
        raise ValueError("в конфиге нет IPv4-адреса (строка Address)")
    ppk = peer.get("publickey", "")
    try:
        key32(ppk)
    except ValueError:
        raise ValueError("в разделе [Peer] нет корректного PublicKey") from None
    ep = peer.get("endpoint", "")
    warp = {"private_key": priv, "public_key": pub, "peer_public_key": ppk, "v4": v4, "v6": v6,
            "id": None, "token": None, "created": datetime.now().strftime("%d.%m.%Y %H:%M"),
            "source": "import"}
    if peer.get("presharedkey"):
        key32(peer["presharedkey"])
        warp["psk"] = peer["presharedkey"]
    extra = {k: iface[k.lower()] for k in AWG_KEEP if k.lower() in iface}
    if any(str(extra.get(k, d)) != d for k, d in AWG_DEFAULT_SH) or "S3" in extra or "S4" in extra:
        warp["awg_extra"] = extra
    if ppk != WARP_PEER_KEY:  # свой сервер WireGuard/AmneziaWG
        if not ep:
            raise ValueError("в конфиге своего сервера нет Endpoint")
        warp["custom"] = True
        warp["endpoint"] = ep
    awg = None
    if "jc" in iface:
        try:
            awg = {"Jc": int(iface["jc"]), "Jmin": int(iface.get("jmin", 40)), "Jmax": int(iface.get("jmax", 70))}
        except ValueError:
            awg = None
    mimic = {k.upper(): iface[k] for k in ("i1", "i2", "i3", "i4", "i5") if iface.get(k)}
    endpoint = ep if (not warp.get("custom") and _ep_is_ip(ep)) else ""
    return {"warp": warp, "awg": awg, "mimic": mimic, "endpoint": endpoint}

# ----------------------------------------------------------------- маскировка первого пакета (AmneziaWG 2.0)
# AmneziaWG 2.0 перед каждым рукопожатием может слать «пакет-приманку» I1. Для DPI поток тогда
# начинается как обычный QUIC (HTTP/3) или DNS, а не как WireGuard. Сервер WARP такие пакеты игнорирует.

QUIC_V1_SALT = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")


def _varint(v):
    if v < 0x40:
        return bytes([v])
    if v < 0x4000:
        return struct.pack(">H", v | 0x4000)
    if v < 0x40000000:
        return struct.pack(">I", v | 0x80000000)
    return struct.pack(">Q", v | 0xC000000000000000)


def _hkdf_label(secret, label, length):
    """HKDF-Expand-Label из TLS 1.3 (SHA-256)."""
    full = b"tls13 " + label
    info = struct.pack(">HB", length, len(full)) + full + b"\x00"
    out, t, i = b"", b"", 1
    while len(out) < length:
        t = hmac.new(secret, t + info + bytes([i]), hashlib.sha256).digest()
        out += t
        i += 1
    return out[:length]


def quic_client_keys(dcid):
    """Ключи Initial-пакета клиента QUIC v1 (RFC 9001, 5.2) -> (key, iv, hp)."""
    initial = hmac.new(QUIC_V1_SALT, dcid, hashlib.sha256).digest()
    client = _hkdf_label(initial, b"client in", 32)
    return (_hkdf_label(client, b"quic key", 16), _hkdf_label(client, b"quic iv", 12),
            _hkdf_label(client, b"quic hp", 16))


def _tls_client_hello(sni, scid):
    host = sni.encode("ascii")

    def ext(t, data):
        return struct.pack(">HH", t, len(data)) + data

    def tp(pid, val):
        return _varint(pid) + _varint(len(val)) + val

    params = (tp(0x01, _varint(30000)) + tp(0x03, _varint(1472)) + tp(0x04, _varint(1048576))
              + tp(0x05, _varint(262144)) + tp(0x06, _varint(262144)) + tp(0x07, _varint(262144))
              + tp(0x08, _varint(100)) + tp(0x09, _varint(100)) + tp(0x0e, _varint(4)) + tp(0x0f, scid))
    key_share = gen_keypair()[1]
    exts = b"".join([
        ext(0x0000, struct.pack(">HBH", len(host) + 3, 0, len(host)) + host),           # server_name
        ext(0x000a, struct.pack(">H", 6) + bytes.fromhex("001d00170018")),             # supported_groups
        ext(0x0010, struct.pack(">HB", 3, 2) + b"h3"),                                   # ALPN h3
        ext(0x000d, struct.pack(">H", 16) + bytes.fromhex("04030804040105030805050108060601")),
        ext(0x0033, struct.pack(">HHH", 36, 0x001d, 32) + key_share),                   # key_share x25519
        ext(0x002d, b"\x01\x01"),                                                       # psk modes
        ext(0x002b, b"\x02\x03\x04"),                                                   # TLS 1.3
        ext(0x0039, params),                                                            # QUIC transport params
    ])
    body = (b"\x03\x03" + os.urandom(32) + b"\x00" + struct.pack(">H", 6) + bytes.fromhex("130113021303")
            + b"\x01\x00" + struct.pack(">H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def quic_initial(sni, dcid=None, scid=None):
    """Настоящий QUIC v1 Initial (TLS ClientHello с SNI), >= 1200 байт, как у браузера."""
    dcid = dcid or os.urandom(8)
    scid = scid or os.urandom(8)
    hello = _tls_client_hello(sni, scid)
    payload = b"\x06" + _varint(0) + _varint(len(hello)) + hello  # кадр CRYPTO
    pn_len = 2
    head = (bytes([0xC0 | (pn_len - 1)]) + b"\x00\x00\x00\x01" + bytes([len(dcid)]) + dcid
            + bytes([len(scid)]) + scid + _varint(0))
    pad = 1200 - (len(head) + 2 + pn_len + len(payload) + 16)
    if pad > 0:
        payload += b"\x00" * pad  # кадры PADDING
    head += struct.pack(">H", (pn_len + len(payload) + 16) | 0x4000) + b"\x00" * pn_len
    key, iv, hp = quic_client_keys(dcid)
    ct = AESGCM(key).encrypt(iv, payload, head)  # номер пакета 0 -> nonce = iv
    mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(ct[4 - pn_len:20 - pn_len])
    pn_off = len(head) - pn_len
    return (bytes([head[0] ^ (mask[0] & 0x0F)]) + head[1:pn_off]
            + bytes(b ^ m for b, m in zip(head[pn_off:], mask[1:1 + pn_len])) + ct)


def dns_query(name):
    """Обычный DNS-запрос A с EDNS0."""
    q = b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.strip(".").split(".") if p)
    return (struct.pack(">HHHHHH", secrets.randbits(16), 0x0100, 1, 0, 0, 1) + q + b"\x00"
            + struct.pack(">HH", 1, 1) + b"\x00" + struct.pack(">HHIH", 41, 1232, 0, 0))


def to_cps(data):
    """Байты -> строка для I1 в конфиге AmneziaWG."""
    return f"<b 0x{data.hex()}>"


_CPS_TAG = re.compile(r"<\s*(b|rc|rd|r|c|t)(?:\s+([^>]*))?>", re.I)


def render_cps(spec):
    """Строка I1…I5 (теги <b 0x..>, <r N>, <rc N>, <rd N>, <c>, <t>) -> байты пакета."""
    out = b""
    for m in _CPS_TAG.finditer(spec or ""):
        tag, arg = m.group(1).lower(), (m.group(2) or "").strip()
        if tag == "b":
            out += bytes.fromhex(arg[2:] if arg.lower().startswith("0x") else arg)
        elif tag in ("r", "rc", "rd"):
            n = max(0, min(int(arg or 0), 1500))
            if tag == "r":
                out += os.urandom(n)
            else:
                abc = string.ascii_letters if tag == "rc" else string.digits
                out += "".join(random.choice(abc) for _ in range(n)).encode()
        elif tag == "c":
            out += struct.pack(">I", 1)
        else:
            out += struct.pack(">I", int(time.time()))
    return out

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


def handshake_ping(host, port, warp, awg=None, timeout=1.2, pre=None):
    """RTT (мс) реального рукопожатия с сервером WARP или None, если ответа нет.
    pre — пакеты маскировки (I1…), которые AmneziaWG шлёт перед рукопожатием."""
    s_priv = base64.b64decode(warp["private_key"])
    s_pub = base64.b64decode(warp["public_key"])
    r_pub = base64.b64decode(warp["peer_public_key"])
    pkt, sender = build_initiation(s_priv, s_pub, r_pub)
    want = struct.pack("<I", sender)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        addr = (host, port)
        for p in pre or ():
            if p:
                sock.sendto(p, addr)
        if awg:  # мусорные пакеты, как у AmneziaWG — помогают пройти DPI
            lo, hi = sorted((int(awg.get("Jmin", 40)), int(awg.get("Jmax", 70))))
            for _ in range(int(awg.get("Jc", 0))):
                sock.sendto(os.urandom(random.randint(max(1, lo), max(1, hi))), addr)
        t0 = time.perf_counter()
        sock.sendto(pkt, addr)
        deadline = t0 + timeout
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return None
            sock.settimeout(left)
            data, _ = sock.recvfrom(2048)
            # 2 — ответ на рукопожатие; 3 — cookie: сервер жив, но под нагрузкой просит подтвердить адрес
            if len(data) >= 92 and data[:4] == b"\x02\0\0\0" and data[8:12] == want:
                return (time.perf_counter() - t0) * 1000
            if len(data) == 64 and data[:4] == b"\x03\0\0\0" and data[4:8] == want:
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
# редкие порты WARP — для «глубокого» поиска, когда провайдер закрыл основные
WARP_PORTS_EXTRA = [859, 864, 880, 890, 891, 903, 908, 928, 934, 942, 943, 945, 946, 955, 968, 987,
                    988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371, 2506, 3138, 3476,
                    3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 8319, 8742, 8854, 8886]
WARP_DEEP_IPS = ["162.159.192.1", "162.159.193.1", "162.159.195.1",
                 "188.114.96.1", "188.114.97.1", "188.114.98.1"]


def scan_endpoints(warp, awg, progress=None, tries=2, pre=None, deep=False, cancel=None):
    eps = [f"{ip}:{p}" for ip in WARP_IPS for p in WARP_PORTS]
    if deep:
        eps += [f"{ip}:{p}" for ip in WARP_DEEP_IPS for p in WARP_PORTS_EXTRA]
    return probe_endpoints(eps, warp, awg, progress, tries, pre=pre, cancel=cancel)


def probe_endpoints(eps, warp, awg, progress=None, tries=2, pre=None, cancel=None):
    cands = [split_endpoint(e) for e in eps]
    done = [0]
    lock = threading.Lock()

    def test(c):
        best = None
        for _ in range(tries):
            if cancel is not None and cancel.is_set():
                break
            ms = handshake_ping(c[0], c[1], warp, awg, pre=pre)
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


def ep_score(ms, jitter=0, loss=0):
    """Чем меньше, тем лучше: пинг + разброс + штраф за потери."""
    return ms + 1.5 * jitter + 5 * loss


def refine_endpoints(eps, warp, awg, pre=None, n=5, cancel=None):
    """Повторные рукопожатия к лучшим серверам -> [(ep, медиана мс, разброс мс, потери %)]."""
    def test(ep):
        host, port = split_endpoint(ep)
        vals, sent = [], 0
        for _ in range(n):
            if cancel is not None and cancel.is_set():
                break
            sent += 1
            ms = handshake_ping(host, port, warp, awg, pre=pre)
            if ms is not None:
                vals.append(ms)
            time.sleep(0.05)
        if not vals:
            return None
        jit = statistics.pstdev(vals) if len(vals) > 1 else 0.0
        return ep, round(statistics.median(vals)), round(jit), round(100 * (sent - len(vals)) / sent)

    if not eps:
        return []
    with ThreadPoolExecutor(max_workers=min(16, len(eps))) as ex:
        res = [r for r in ex.map(test, eps) if r]
    res.sort(key=lambda r: ep_score(r[1], r[2], r[3]))
    return res

# ----------------------------------------------------------------- game detection / ping

def is_public_v4(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


_PING_RE = re.compile(r"[=<]\s*(\d+(?:\.\d+)?)\s*(?:ms|мс)", re.I)


def parse_ping_output(text):
    """Среднее время ответов из вывода ping (русская/английская Windows, Linux) -> мс или None."""
    text = (text or "").replace(",", ".")
    replies = [line for line in text.splitlines() if "ttl=" in line.lower()]
    vals = [float(m[0]) for m in (_PING_RE.findall(line) for line in replies) if m]
    if not vals:  # необычный формат — берём все числа с «мс»
        vals = [float(v) for v in _PING_RE.findall(text)]
    return round(sum(vals) / len(vals)) if vals else None


def icmp_ping(ip, count=3, src=None):
    nt = os.name == "nt"
    cmd = ["ping", "-n" if nt else "-c", str(count), "-w" if nt else "-W", "1000" if nt else "1"]
    if src:  # с адреса сетевой карты — мимо туннеля
        cmd += ["-S" if nt else "-I", src]
    cmd.append(ip)
    try:
        out = subprocess.run(cmd, capture_output=True, timeout=count * 2 + 3, creationflags=NOWIN).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_ping_output(out.decode("oem" if nt else "utf-8", errors="ignore"))

# ----------------------------------------------------------------- config / tunnel

def split_endpoint(ep):
    host, _, port = str(ep).strip().rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"неверный адрес сервера: {ep!r} (нужно IP:порт)")
    return host.strip("[]"), int(port)


def join_endpoint(host, port):
    return f"[{host}]:{port}" if ":" in host else f"{host}:{port}"


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
    if exclude_ip and is_ipv4(exclude_ip):  # адрес сервера туннеля не должен идти в сам туннель
        ex = ipaddress.ip_network(exclude_ip + "/32")
        out = []
        for n in nets:
            out.extend(n.address_exclude(ex) if ex.subnet_of(n) else [n])
        nets = list(ipaddress.collapse_addresses(out))
    return [str(n) for n in nets]


def mimic_specs(st):
    """Строки I1…I5 для конфига AmneziaWG по настройке «Маскировка» ({} — выключена)."""
    mode = st.get("mimic", "off")
    if mode == "import":
        return dict(st.get("mimic_import") or {})
    if mode not in ("quic", "dns"):
        return {}
    sni = str(st.get("mimic_sni") or "www.google.com").strip()
    key = f"{mode}:{sni}"
    if st.get("mimic_key") != key or not st.get("mimic_i1"):
        make = quic_initial if mode == "quic" else dns_query
        try:
            pkt = make(sni)
        except ValueError:
            pkt = make("www.google.com")
        st["mimic_i1"], st["mimic_key"] = to_cps(pkt), key  # один и тот же пакет между запусками
    return {"I1": st["mimic_i1"]}


def mimic_packets(st):
    """Те же пакеты в байтах — чтобы проверки серверов выглядели для DPI так же, как сам туннель."""
    out = []
    for _, spec in sorted(mimic_specs(st).items()):
        try:
            out.append(render_cps(spec))
        except ValueError:
            pass
    return out


def build_conf(st, kind):
    w = st["warp"]
    host, port = split_endpoint(w["endpoint"] if w.get("custom") else st["endpoint"])
    ranges = normalize_ranges(st["ranges"], exclude_ip=host)
    if not ranges:
        raise ValueError("Нет IP-диапазонов игры")
    lines = ["[Interface]", f"PrivateKey = {w['private_key']}", f"Address = {w['v4']}/32",
             f"MTU = {int(st.get('mtu', 1280))}"]
    if kind == "awg":
        a = st["awg"]
        sh = dict(AWG_DEFAULT_SH)
        sh.update(w.get("awg_extra") or {})
        lines += [f"Jc = {a['Jc']}", f"Jmin = {a['Jmin']}", f"Jmax = {a['Jmax']}"]
        lines += [f"{k} = {sh[k]}" for k in AWG_KEEP if k in sh]
        lines += [f"{k} = {v}" for k, v in sorted(mimic_specs(st).items())]
    lines += ["", "[Peer]", f"PublicKey = {w['peer_public_key']}"]
    if w.get("psk"):
        lines.append(f"PresharedKey = {w['psk']}")
    lines += [f"AllowedIPs = {', '.join(ranges)}", f"Endpoint = {join_endpoint(host, port)}",
              "PersistentKeepalive = 25", ""]
    return "\n".join(lines)


def find_client():
    pf = os.environ.get("ProgramFiles", r"C:\Program Files")
    for path, kind in ((os.path.join(pf, "AmneziaWG", "amneziawg.exe"), "awg"),
                       (os.path.join(pf, "WireGuard", "wireguard.exe"), "wg")):
        if os.path.exists(path):
            return path, kind
    return None, None


def cli_path(exe, kind):
    """awg.exe / wg.exe рядом с клиентом (статистика, маршруты на лету)."""
    if not exe:
        return None
    tool = os.path.join(os.path.dirname(exe), "awg.exe" if kind == "awg" else "wg.exe")
    return tool if os.path.exists(tool) else None


def _run(cmd, timeout=30):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          creationflags=NOWIN, errors="ignore")


def service_name(kind):
    return ("AmneziaWGTunnel$" if kind == "awg" else "WireGuardTunnel$") + TUNNEL


_SC_STATE = re.compile(r"\b\d+\s+(RUNNING|STOPPED|START_PENDING|STOP_PENDING|PAUSED|PAUSE_PENDING|CONTINUE_PENDING)\b")


def parse_sc_state(text, code=0):
    """Вывод `sc query` -> RUNNING / STOPPED / …, GONE (службы нет) или None. Не зависит от языка Windows."""
    m = _SC_STATE.search(text or "")
    if m:
        return m.group(1)
    if code == 1060 or "1060" in (text or ""):
        return "GONE"
    return None


def service_state(kind):
    if os.name != "nt" or not kind:
        return None
    try:
        r = _run(["sc", "query", service_name(kind)], timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return parse_sc_state((r.stdout or "") + (r.stderr or ""), r.returncode)


def tunnel_running(kind):
    return service_state(kind) == "RUNNING"


def tunnel_down(exe, kind=None, wait=6.0):
    """Удаляет службу туннеля; с kind — ждёт, пока Windows действительно её уберёт."""
    try:
        _run([exe, "/uninstalltunnelservice", TUNNEL])
    except (OSError, subprocess.TimeoutExpired):
        pass
    end = time.time() + wait
    while kind and os.name == "nt" and time.time() < end:
        if service_state(kind) in ("GONE", None):
            return
        time.sleep(0.3)


def pick_log_reason(text):
    """Самая свежая ошибка нашего туннеля из журнала клиента."""
    mine = [line.strip() for line in (text or "").splitlines() if f"[{TUNNEL}]" in line][-60:]
    bad = [line for line in mine if re.search(r"error|invalid|fail|unable|unknown|cannot|denied", line, re.I)]
    line = (bad or mine or [""])[-1]
    return re.sub(r"^.*?\[" + TUNNEL + r"\]\s*", "", line)[:220]


def tunnel_log_reason(exe):
    try:
        return pick_log_reason(_run([exe, "/dumplog"], timeout=8).stdout)
    except (OSError, subprocess.TimeoutExpired):
        return ""


def write_conf(conf_text):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(conf_text)
    os.replace(tmp, CONF_PATH)


def tunnel_up(exe, kind, conf_text):
    """(Пере)запускает службу туннеля. -> (True, "") или (False, причина)."""
    write_conf(conf_text)
    tunnel_down(exe, kind)
    err = ""
    for _attempt in range(2):
        try:
            r = _run([exe, "/installtunnelservice", CONF_PATH])
        except (OSError, subprocess.TimeoutExpired) as e:
            return False, str(e)
        err = (r.stderr or r.stdout or "").strip()
        t0 = time.time()
        while time.time() - t0 < 8:
            time.sleep(0.5)
            state = service_state(kind)
            if state == "RUNNING":
                return True, ""
            if state in ("STOPPED", "GONE") and time.time() - t0 > 2.5:
                break  # служба стартовала и упала — причину берём из журнала
        if r.returncode == 0:
            break
        tunnel_down(exe, kind)  # установка не удалась (старая служба ещё удалялась?) — ещё раз
        time.sleep(1.0)
    reason = tunnel_log_reason(exe)
    tunnel_down(exe, kind)
    return False, (reason or err or "служба не запустилась")


_ROUTE_RE = re.compile(r"(\d+\.\d+\.\d+\.\d+/\d+)\s+\d+\s+(\S.*?)\s*$")


def parse_netsh_routes(text, iface=TUNNEL):
    """Маршруты из `netsh interface ipv4 show route`, которые идут через наш туннель."""
    out = set()
    for line in (text or "").splitlines():
        m = _ROUTE_RE.search(line)
        if m and m.group(2) == iface:
            out.add(m.group(1))
    return out


def tunnel_routes():
    try:
        return parse_netsh_routes(_run(["netsh", "interface", "ipv4", "show", "route"], timeout=10).stdout)
    except (OSError, subprocess.TimeoutExpired):
        return set()


def hot_add_ranges(cli, peer_pub, allowed, new):
    """Новые диапазоны в работающий туннель без перезапуска: AllowedIPs пира + маршруты Windows.
    -> True, если всё получилось (иначе нужен обычный перезапуск)."""
    if os.name != "nt" or not cli or not new:
        return False
    try:
        r = _run([cli, "set", TUNNEL, "peer", peer_pub, "allowed-ips", ",".join(allowed)], timeout=10)
        if r.returncode != 0:
            return False
        for n in new:
            _run(["netsh", "interface", "ipv4", "add", "route", f"prefix={n}", f"interface={TUNNEL}",
                  "nexthop=0.0.0.0", "metric=0", "store=active"], timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        return False
    have = tunnel_routes()
    return all(n in have for n in new)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def resource(name):
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), name)


_MUTEX = None


def single_instance():
    """False, если ABI Route уже запущен: два окна мешали бы друг другу управлять туннелем."""
    global _MUTEX
    if os.name != "nt":
        return True
    try:
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        _MUTEX = k32.CreateMutexW(None, False, "Local\\ABIRouteSingleInstance")
        return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS
    except (OSError, AttributeError):
        return True


def default_local_ip():
    """IP сетевой карты, через которую идёт интернет (не туннеля)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("1.1.1.1", 53))  # пакет не отправляется — Windows только выбирает маршрут
        ip = s.getsockname()[0]
        return ip if is_ipv4(ip) and not ip.startswith("0.") else None
    except OSError:
        return None
    finally:
        s.close()

# ----------------------------------------------------------------- game / ping / stats

def game_scan(names):
    """Процессы игры -> ({ip: tcp_port | None}, {локальные UDP-порты игры}, запущена ли игра)."""
    if psutil is None:
        return {}, set(), False
    wanted = {n.strip().lower() for n in names if n.strip()}
    pids = set()
    for p in psutil.process_iter(["name"]):
        if (p.info.get("name") or "").lower() in wanted:
            pids.add(p.pid)
    if not pids:
        return {}, set(), False
    out, udp = {}, set()
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError):
        conns = []
    for c in conns:
        if c.pid not in pids:
            continue
        if c.type == socket.SOCK_DGRAM and c.laddr:
            udp.add(c.laddr.port)
        ip = c.raddr.ip if c.raddr else ""
        if ip.startswith("::ffff:"):
            ip = ip[7:]
        if ip and is_public_v4(ip):
            port = c.raddr.port if c.type == socket.SOCK_STREAM else None
            if out.get(ip) is None:
                out[ip] = port
    return out, udp, True


def game_remote_endpoints(names):
    """{ip: tcp_port | None} для подключений процесса игры."""
    return game_scan(names)[0]


def game_remote_ips(names):
    return set(game_remote_endpoints(names))


def tcp_ping(ip, port, count=4, timeout=1.5, src=None):
    """Точный пинг по времени TCP-рукопожатия (работает, даже когда ICMP закрыт).
    src — адрес сетевой карты: Windows отправит пакеты напрямую, мимо туннеля."""
    vals = []
    for i in range(count):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if src:
                s.bind((src, 0))
            t0 = time.perf_counter()
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


def best_ping(ip, port=None, count=4, src=None):
    """TCP-пинг по порту игры (или 443/80/8080), если не вышло — ICMP."""
    for p in ([port] if port else []) + [443, 80, 8080]:
        if tcp_ping(ip, p, 1, timeout=1.2, src=src):
            r = tcp_ping(ip, p, count, src=src)
            if r:
                r.update(how=f"TCP {p}", port=p)
                return r
    ms = icmp_ping(ip, count, src=src)
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
    tool = cli_path(exe, kind)
    if not tool:
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
        "35.228.24.0/24", "43.128.81.0/24", "43.128.85.0/24", "43.128.88.0/24",
        "43.128.102.0/24", "43.131.60.0/24", "43.134.108.0/24", "43.134.152.0/24",
        "43.134.153.0/24", "43.153.253.0/24", "43.156.147.0/24", "43.157.67.0/24",
        "43.163.53.0/24", "43.163.63.0/24", "43.168.141.0/24", "43.174.218.0/24",
        "43.174.250.0/24", "43.174.251.0/24", "92.123.135.0/24", "101.32.107.0/24",
        "101.32.110.0/24", "101.32.113.0/24", "101.32.143.0/24", "101.32.171.0/24",
        "101.33.43.0/24", "101.33.48.0/24", "119.28.109.0/24", "119.28.123.0/24",
        "129.226.1.0/24", "129.226.2.0/24", "129.226.155.0/24", "150.109.0.0/24",
        "150.109.27.0/24", "150.109.28.0/24", "161.120.165.0/24", "162.62.221.0/24",
        "184.24.77.0/24", "188.43.72.0/24"],
    "ABI — широкий охват (/16)": [
        "43.153.0.0/16", "43.163.0.0/16", "43.168.0.0/16", "43.174.0.0/16",
        "101.32.0.0/16", "101.33.0.0/16", "129.226.0.0/16", "188.43.72.0/24"],
}

JUNK_PROFILES = [
    {"Jc": 4, "Jmin": 40, "Jmax": 70},     # лёгкая маскировка
    {"Jc": 120, "Jmin": 23, "Jmax": 911},  # сильная (как в популярных генераторах WARP для РФ)
]

# Варианты «Маскировки» в интерфейсе: (название, профиль мусорных пакетов, режим I1)
MASKS = [("Лёгкая (мусор ×4)", 0, "off"), ("Сильная (мусор ×120)", 1, "off"),
         ("QUIC / HTTP3 — AmneziaWG 2", 0, "quic"), ("DNS-запрос — AmneziaWG 2", 0, "dns")]
MASK_IMPORT = "Из импортированного конфига"


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

# ----------------------------------------------------------------- радар UDP: серверы матчей

def parse_udp(pkt, local):
    """IPv4-пакет -> (локальный порт, удалённый IP, удалённый порт) для UDP нашего адреса."""
    if len(pkt) < 28 or pkt[0] >> 4 != 4 or pkt[9] != 17:
        return None
    if struct.unpack_from(">H", pkt, 6)[0] & 0x1FFF:  # не первый фрагмент — портов в нём нет
        return None
    ihl = (pkt[0] & 0x0F) * 4
    if ihl < 20 or len(pkt) < ihl + 8:
        return None
    sport, dport = struct.unpack_from(">HH", pkt, ihl)
    src, dst = bytes(pkt[12:16]), bytes(pkt[16:20])
    if src == local:
        return sport, socket.inet_ntoa(dst), dport
    if dst == local:
        return dport, socket.inet_ntoa(src), sport
    return None


class UdpRadar:
    """Видит, куда игра шлёт UDP. Серверы матчей работают по UDP без «подключения»,
    поэтому их нет в списке соединений Windows — адрес виден только в самих пакетах.
    Смотрим только заголовки и только трафик с UDP-портов процесса игры."""

    def __init__(self, log=None):
        self.log = log or (lambda m: None)
        self.ports = set()
        self.hits = {}  # ip -> [пакетов, время последнего, удалённый порт]
        self.reported = set()
        self.lock = threading.Lock()
        self.sock = None
        self.ok = None  # None — не запускался, True — работает, False — недоступен
        self.local = None
        self.local_ip = None
        self._stop = threading.Event()

    def start(self, local_ip):
        if self.sock is not None:
            return True
        if os.name != "nt" or not local_ip:
            return False
        s = None
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((local_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
            s.settimeout(1.0)
        except (OSError, AttributeError, ValueError) as e:
            if s is not None:
                s.close()
            if self.ok is not False:
                self.log(f"Радар UDP недоступен ({e}) — серверы матчей будут только из готовых списков.")
            self.ok = False
            return False
        self.sock, self.local, self.local_ip, self.ok = s, socket.inet_aton(local_ip), local_ip, True
        self._stop.clear()
        threading.Thread(target=self._loop, args=(s,), daemon=True).start()
        return True

    def stop(self):
        s, self.sock = self.sock, None
        self._stop.set()
        if s is not None:
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except (OSError, AttributeError, ValueError):
                pass
            s.close()

    def _loop(self, s):
        buf = bytearray(65535)
        view = memoryview(buf)
        while not self._stop.is_set():
            try:
                n = s.recv_into(buf)
            except socket.timeout:
                continue
            except OSError:
                break
            self.feed(view[:n])
        if self.sock is s:  # сеть пропала — наблюдатель запустит радар заново
            self.sock = None
            try:
                s.close()
            except OSError:
                pass

    def feed(self, pkt):
        r = parse_udp(pkt, self.local)
        if not r or r[0] not in self.ports:
            return
        now = time.time()
        with self.lock:
            h = self.hits.get(r[1])
            if h is not None:
                h[0] += 1
                h[1] = now
            elif is_public_v4(r[1]):
                if len(self.hits) > 5000:
                    self.hits.clear()
                self.hits[r[1]] = [1, now, r[2]]

    def take(self, min_pkts=5):
        """Новые адреса, куда игра реально шлёт UDP (не меньше min_pkts пакетов)."""
        with self.lock:
            new = [ip for ip, h in self.hits.items() if h[0] >= min_pkts and ip not in self.reported]
            self.reported.update(new)
        return new

    def active(self, nets, within=25):
        """Был ли UDP игры в эти сети за последние within секунд (идёт матч напрямую)."""
        cutoff = time.time() - within
        with self.lock:
            recent = [ip for ip, h in self.hits.items() if h[1] >= cutoff]
        return any(in_nets(ip, nets) for ip in recent)


# ----------------------------------------------------------------- GUI

BG, SURF, RAISED, EDGE = "#191919", "#202020", "#2c2c2b", "#383836"
FG, MUTED = "#ffffff", "#a5a5a3"
ACC, ACC_H = "#5e9fe8", "#7db3ef"
OK, WAIT, BAD = "#72bc8f", "#de9255", "#e97366"
TINT = {OK: "#1f2a24", WAIT: "#2f261d", BAD: "#30201e", ACC: "#1c2634"}
FONT = "Segoe UI"
MONO = "Consolas"


def plural(n, one, few, many):
    """Склонение по числу: 1 сервер, 2 сервера, 5 серверов."""
    n = abs(int(n)) % 100
    if 10 < n < 20:
        return many
    n %= 10
    return one if n == 1 else few if 2 <= n <= 4 else many


def fmt_bytes(n):
    n = float(n)
    for u in ("Б", "КБ", "МБ"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.2f} ГБ"


class Cancelled(Exception):
    """Пользователь прервал долгую операцию."""


class App:
    def __init__(self):
        self.st = load_settings()
        self.lock = threading.RLock()
        self.q = queue.Queue()
        self.exe, self.kind = find_client()
        self.running = False
        self.armed = False
        self.pending = False
        self.dirty_routes = False  # диапазоны изменились — применить к работающему туннелю
        self.stop_after = False  # «Остановить» нажата во время операции
        self.op_lock = threading.Lock()  # одна долгая операция за раз
        self.cancel = threading.Event()  # кнопка «Прервать»
        self.applied = []  # AllowedIPs работающего туннеля
        self.hist = deque(maxlen=60)  # пинг через туннель, раз в 10 с
        self.radar = UdpRadar(self.log)
        self.game_on = False
        self.deferred = False  # новые маршруты ждут конца матча
        self.svc_drops = deque(maxlen=3)  # остановки службы туннеля вне программы
        self.admin = is_admin()
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
        r.title(f"{APP_NAME} {VERSION} — Arena Breakout Infinite")
        r.geometry("980x800")
        r.minsize(900, 720)
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
        line = f"[{time.strftime('%H:%M:%S')}] {msg}"
        log_file(time.strftime("%Y-%m-%d ") + line)
        self.q.put(("log", line))

    def ui(self, fn):
        self.q.put(("call", fn))

    def bg(self, fn):
        """Долгая операция в фоне. Одновременно — только одна: туннель у программы один."""
        if not self.op_lock.acquire(blocking=False):
            self.log("Подождите, предыдущая операция ещё выполняется. Прервать — кнопка «Прервать».")
            return False
        threading.Thread(target=self._locked, args=(fn,), daemon=True).start()
        return True

    @property
    def busy(self):
        return self.op_lock.locked()

    def _locked(self, fn):
        """Выполняет fn при уже захваченном op_lock: прерывание, ошибки, «остановить после»."""
        self.cancel.clear()
        try:
            fn()
        except Cancelled:
            self.log("Операция прервана.")
        except Exception as e:  # noqa
            self.log(f"Ошибка: {e}")
        finally:
            if self.stop_after:
                self.stop_after = False
                try:
                    self._stop()
                except Exception as e:  # noqa
                    self.log(f"Ошибка: {e}")
            self.op_lock.release()
            self.ui(lambda: self.prog.configure(value=0))

    def _cp(self):
        """Точка прерывания долгой операции."""
        if self.cancel.is_set():
            raise Cancelled()

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

    def _pre(self):
        """Пакеты-приманки I1…I5 перед рукопожатием (только AmneziaWG) — чтобы проверка шла как туннель."""
        if self.kind != "awg":
            return None
        with self.lock:
            return mimic_packets(self.st) or None

    def _custom(self):
        return bool((self.st.get("warp") or {}).get("custom"))

    def _ep(self):
        """Адрес сервера туннеля: свой сервер из импорта или выбранный сервер WARP."""
        w = self.st.get("warp") or {}
        return w["endpoint"] if w.get("custom") else self.st["endpoint"]

    def _eps(self):
        """[(сервер, мс)] из последнего поиска; терпимо к старому формату настроек."""
        out = []
        for item in self.st.get("endpoint_list", []):
            if isinstance(item, (list, tuple)) and item and isinstance(item[0], str):
                out.append((item[0], item[1] if len(item) > 1 else None))
        return out

    def _allowed(self):
        """AllowedIPs туннеля: диапазоны игры без адреса самого сервера туннеля."""
        with self.lock:
            try:
                host = split_endpoint(self._ep())[0]
            except (ValueError, IndexError, TypeError):
                host = None
            return normalize_ranges(self.st["ranges"], exclude_ip=host if host and is_ipv4(host) else None)

    def _local_ip(self):
        """IP сетевой карты (не адрес внутри туннеля) — для замеров мимо туннеля и радара."""
        ip = default_local_ip()
        w = self.st.get("warp") or {}
        return ip if ip and ip != w.get("v4") else None

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
        prow = tk.Frame(i1, bg=SURF)
        prow.pack(fill="x")
        self._btn(prow, "Сгенерировать новый", self.do_generate).pack(side="left")
        self._btn(prow, "Импорт", self.do_import).pack(side="left", padx=(8, 0))
        self._btn(prow, "Экспорт", self.do_export).pack(side="left", padx=(8, 0))
        mrow = tk.Frame(i1, bg=SURF)
        mrow.pack(fill="x", pady=(10, 0))
        self._lbl(mrow, "Маскировка:", muted=True).pack(side="left")
        self.mask_var = tk.StringVar()
        self.mask_cb = ttk.Combobox(mrow, textvariable=self.mask_var, width=28, state="readonly")
        self.mask_cb.pack(side="left", padx=(8, 0))
        self.mask_cb.bind("<<ComboboxSelected>>", self.on_mask)
        self._refresh_mask()

        c2, i2 = self._card(setup, "Сервер WARP")
        c2.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        row = tk.Frame(i2, bg=SURF)
        row.pack(fill="x")
        self._btn(row, "Найти лучший", self.do_scan, primary=True).pack(side="left")
        self._btn(row, "Автоподбор", self.do_autotune).pack(side="left", padx=(8, 0))
        self._btn(row, "Прервать", self.do_cancel).pack(side="left", padx=(8, 0))
        self.fo_var = tk.BooleanVar(value=self.st.get("failover", True))
        self._check(i2, "Автосмена при сбое", self.fo_var, self.collect_ui).pack(anchor="w", pady=(10, 0))
        self.prog = ttk.Progressbar(i2, mode="determinate", style="Horizontal.TProgressbar")
        self.prog.pack(fill="x", pady=(12, 4))
        self._lbl(i2, "Список серверов — на вкладке «Пинг». График — пинг через туннель.",
                  muted=True).pack(anchor="w")
        self.spark = tk.Canvas(i2, height=34, bg=SURF, highlightthickness=0)
        self.spark.pack(fill="x", pady=(6, 0))
        self.spark.bind("<Configure>", lambda e: self._draw_hist())

        self._lbl(tab, "ПОСЛЕДНИЕ СОБЫТИЯ", muted=True, bold=True).pack(anchor="w", pady=(0, 4))
        self.mini_log = self._text(tab, 6, log=True)
        self.mini_log.pack(fill="both", expand=True)

    def _build_ping(self, tab):
        c, i = self._card(tab, "Пинг до серверов игры",
                          "Точный замер по TCP (как игровой трафик), а если нельзя — ICMP. «Сравнить» меряет "
                          "напрямую и через WARP. Если туннель включён, прямой пинг идёт мимо него и туннель не трогается; "
                          "если выключен — он включится на несколько секунд (не делайте этого во время матча).")
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
                                                "Остальные серверы — запас для автосмены.")
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
        self.radar_var = tk.BooleanVar(value=self.st.get("radar", True))
        self._check(row, "Радар UDP (серверы матчей)", self.radar_var, self.collect_ui).pack(
            side="left", padx=(12, 0))
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
        if w and w.get("custom"):
            self.warp_lbl.configure(text=f"Свой сервер {w.get('endpoint', '')}\n"
                                         f"Адрес в сети: {w['v4']} · импортирован {w.get('created', '')}", fg=OK)
        elif w:
            how = "импортирован" if w.get("source") == "import" else "создан"
            self.warp_lbl.configure(text=f"Профиль {how} {w.get('created', '')}\nАдрес в WARP: {w['v4']}", fg=OK)
        else:
            self.warp_lbl.configure(text="Профиля нет. «Сгенерировать новый» зарегистрирует бесплатный ключ "
                                         "Cloudflare WARP, «Импорт» — загрузит готовый конфиг.", fg=MUTED)
        self.t_ep.configure(text=self._ep())
        ms = self.st.get("endpoint_ms")
        if self._custom():
            self.t_ep_sub.configure(text="свой сервер из конфига")
        else:
            self.t_ep_sub.configure(text=f"рукопожатие {ms} мс" if ms else "нажмите «Найти лучший»")
        self._fill_eps()

    def _fill_eps(self):
        t = self.ep_tree
        t.delete(*t.get_children())
        cur = self._ep()
        for ep, ms in self._eps():
            t.insert("", "end", values=(ep, f"{ms} мс" if ms is not None else "—", "● текущий" if ep == cur else ""),
                     tags=("cur",) if ep == cur else ())

    def _draw_hist(self):
        """Мини-график пинга через туннель (проверка раз в 10 с); красные штрихи — нет ответа."""
        c = self.spark
        c.delete("all")
        vals = list(self.hist)
        if not vals:
            return
        w, h = max(c.winfo_width(), 60), int(c["height"])
        good = [v for v in vals if v is not None]
        lo = min(good) if good else 0
        span = max((max(good) - lo) if good else 0, 10)
        step = w / max(len(vals) - 1, 1)
        pts = []

        def flush():
            if len(pts) >= 4:
                c.create_line(*pts, fill=ACC, width=2)
            elif len(pts) == 2:
                c.create_oval(pts[0] - 2, pts[1] - 2, pts[0] + 2, pts[1] + 2, fill=ACC, outline="")
            pts.clear()

        for i, v in enumerate(vals):
            x = i * step
            if v is None:
                flush()
                c.create_line(x, 2, x, h - 2, fill=BAD, width=2)
                continue
            pts.extend([x, h - 3 - (v - lo) / span * (h - 6)])
        flush()

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
        self.log(f"ABI Route {VERSION} запущен. Журнал: {LOG_PATH}")
        if os.name == "nt" and not self.admin:
            self.log("⚠ Нет прав администратора �� запуск туннеля и радар UDP не сработают. "
                     "Запустите от имени администратора.")
        if not self.exe:
            self.log("⚠ Не найден AmneziaWG/WireGuard. Установите AmneziaWG (рекомендуется для РФ): "
                     "github.com/amnezia-vpn/amneziawg-windows-client/releases")
        else:
            self.log(f"Клиент туннеля: {'AmneziaWG (с обфускацией)' if self.kind == 'awg' else 'WireGuard'}")
            if self.kind == "wg" and self.st.get("mimic", "off") != "off":
                self.log("Маскировка QUIC/DNS работает только в AmneziaWG — с WireGuard она не используется.")
            if tunnel_running(self.kind):
                self.running = True
                self.started_at = time.time()
                self.applied = self._allowed()
                self.set_state("on")
                self.log("Туннель уже работает в фоне.")
        w = self.st.get("warp") or {}
        if w.get("custom"):
            self.log(f"Профиль: свой сервер {w.get('endpoint')}.")
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
            self.st["radar"] = bool(self.radar_var.get())
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
        self.log(f"Добавлен список «{name}»: теперь {len(merged)} {plural(len(merged), 'диапазон', 'диапазона', 'диапазонов')}.")
        self.do_apply_routes(quiet=True)

    def do_apply_routes(self, quiet=False):
        self.collect_ui()
        if self.running:
            self.log("Маршруты изменены — применяю…")
            self.dirty_routes = True
            self.last_restart = 0
        elif not quiet:
            self.log("Маршруты сохранены.")

    def on_pick_endpoint(self, _e):
        sel = self.ep_tree.selection()
        if not sel or self._custom():
            return
        ep = str(self.ep_tree.item(sel[0], "values")[0])
        with self.lock:
            self.st["endpoint"] = ep
            self.st["endpoint_ms"] = dict(self._eps()).get(ep)
            save_settings(self.st)
        self._refresh()
        self.log(f"Выбран сервер WARP {ep}." + (" Перезапускаю туннель…" if self.running else ""))
        if self.running:
            self.pending = True
            self.last_restart = 0

    def _mask_values(self):
        vals = [m[0] for m in MASKS]
        if self.st.get("mimic_import"):
            vals.append(MASK_IMPORT)
        return vals

    def _mask_current(self):
        mode = self.st.get("mimic", "off")
        if mode == "import" and self.st.get("mimic_import"):
            return MASK_IMPORT
        for name, _prof, m in MASKS:
            if m == mode and m != "off":
                return name
        return MASKS[1][0] if int(self.st["awg"].get("Jc", 4)) >= 60 else MASKS[0][0]

    def _refresh_mask(self):
        self.mask_cb.configure(values=self._mask_values())
        self.mask_var.set(self._mask_current())

    def on_mask(self, _e=None):
        name = self.mask_var.get()
        with self.lock:
            if name == MASK_IMPORT:
                self.st["mimic"] = "import"
            else:
                _, prof, mode = next(m for m in MASKS if m[0] == name)
                self.st["mimic"] = mode
                self.st["awg"] = dict(JUNK_PROFILES[prof])
            mode = self.st["mimic"]
            save_settings(self.st)
        note = " Нужен AmneziaWG 2.0 или новее." if mode != "off" else ""
        self.log(f"Маскировка: {name}.{note}" + (" Перезапускаю туннель…" if self.running else ""))
        if self.running:
            self.pending = True
            self.last_restart = 0

    def do_import(self):
        path = filedialog.askopenfilename(title="Импорт конфига WireGuard / AmneziaWG",
                                          filetypes=[("Конфиг WireGuard / AmneziaWG", "*.conf"),
                                                     ("Все файлы", "*.*")])
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as f:
                data = parse_conf(f.read())
        except (OSError, ValueError) as e:
            messagebox.showerror(APP_NAME, f"Не удалось импортировать конфиг:\n{e}")
            return
        if self.st.get("warp") and not messagebox.askyesno(APP_NAME, "Заменить текущий профиль импортированным?"):
            return
        w = data["warp"]
        with self.lock:
            self.st["warp"] = w
            if data["awg"]:
                self.st["awg"] = dict(data["awg"])
            self.st["mimic_import"] = dict(data["mimic"])
            if data["mimic"]:
                self.st["mimic"] = "import"
            elif self.st.get("mimic") == "import":
                self.st["mimic"] = "off"
            if data["endpoint"]:
                self.st["endpoint"], self.st["endpoint_ms"] = data["endpoint"], None
            save_settings(self.st)
        self._refresh_mask()
        self._refresh()
        if w.get("custom"):
            self.log(f"Импортирован свой сервер {w['endpoint']} (адрес в сети {w['v4']}). "
                     "Поиск серверов WARP для него не нужен.")
        else:
            self.log(f"Импортирован профиль WARP (адрес {w['v4']})."
                     + (" Маскировка взята из конфига." if data["mimic"] else "")
                     + " Нажмите «Найти лучший» или «Запустить».")
        if self.kind == "wg" and (data["awg"] or data["mimic"] or w.get("awg_extra")):
            self.log("⚠ В конфиге есть параметры AmneziaWG, а установлен обычный WireGuard — установите AmneziaWG.")
        if self.running:
            self.pending = True
            self.last_restart = 0

    def do_export(self):
        if not self.st.get("warp"):
            messagebox.showinfo(APP_NAME, "Сначала создайте или импортируйте профиль.")
            return
        self.collect_ui()
        try:
            with self.lock:
                conf = build_conf(self.st, self.kind or "awg")
        except ValueError as e:
            messagebox.showerror(APP_NAME, f"Не удалось собрать конфиг: {e}")
            return
        path = filedialog.asksaveasfilename(title="Экспорт конфига", defaultextension=".conf",
                                            initialfile=f"{TUNNEL}.conf",
                                            filetypes=[("Конфиг WireGuard / AmneziaWG", "*.conf")])
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(conf)
        except OSError as e:
            messagebox.showerror(APP_NAME, f"Не удалось сохранить файл:\n{e}")
            return
        self.log(f"Конфиг сохранён: {path}. В нём только маршруты игры — его можно открыть в AmneziaWG.")

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
            self.log("Сначала создайте профиль: «Сгенерировать новый» или «Импорт».")
            return
        if self._custom():
            self.log("Подключён свой сервер — поиск серверов WARP для него не нужен.")
            return

        def job():
            ok, total = self._scan()
            if not ok:
                tip = ""
                if self.kind == "awg" and self.st.get("mimic", "off") == "off":
                    tip = " Попробуйте маскировку «QUIC / HTTP3» (нужен AmneziaWG 2.0) и повторите поиск."
                self.log("Ни один сервер WARP не ответил — похоже, провайдер блокирует WARP по UDP." + tip
                         + " Проверить можно, раздав интернет с телефона.")
                return
            self._save_scan(ok)
            self.log(f"Ответили {len(ok)} из {total}. Лучший: {ok[0][0]} — {ok[0][1]:.0f} мс (выбран). "
                     f"Ещё {min(len(ok), 15) - 1} в запасе для автосмены.")
            if self.running:
                self.pending = True
                self.last_restart = 0
        self.bg(job)

    def _scan(self, deep=False, tries=2):
        """Поиск серверов WARP; если обычные молчат — расширенный список адресов и портов."""
        def prog(d, t):
            self.ui(lambda: self.prog.configure(maximum=t, value=d))

        n = len(WARP_IPS) * len(WARP_PORTS) + (len(WARP_DEEP_IPS) * len(WARP_PORTS_EXTRA) if deep else 0)
        pre = self._pre()
        self.log(f"Проверяю {n} {plural(n, 'сервер', 'сервера', 'серверов')} WARP настоящим рукопожатием" + (" (расширенный поиск)" if deep else "")
                 + (" с маскировкой" if pre else "") + "…")
        ok, total = scan_endpoints(self.st["warp"], self._awg(), prog, tries=tries, pre=pre, deep=deep,
                                   cancel=self.cancel)
        self._cp()
        if not ok and not deep:
            self.log("Обычные серверы не ответили — пробую расширенный список адресов и портов…")
            return self._scan(True, tries)
        return ok, total

    def do_cancel(self):
        if not self.busy:
            self.log("Сейчас нечего прерывать.")
            return
        self.cancel.set()
        self.log("Прерываю текущую операцию…")

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

    def _measure(self, ips, mode, src=None):
        label = ("через туннель" if self._custom() else "через WARP") if mode == "warp" else "напрямую"
        self.log(f"Меряю пинг {label} до {len(ips)} серверов…")
        ports = dict(self.st.get("tcp_ports", {}))
        with ThreadPoolExecutor(max_workers=8) as ex:
            res = list(ex.map(lambda ip: (ip, best_ping(ip, ports.get(ip), src=src)), ips))
        self._cp()
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
            return f"{round(rr[key]['ms'])} мс" if rr[key] else "нет ответа"

        for ip, rr in self.results.items():
            d, w = rr.get("direct"), rr.get("warp")
            src = w or d
            diff, tag = "—", ()
            if d and w:
                dv = round(w["ms"] - d["ms"])  # ICMP может дать дробные мс
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
            if self.running:
                if compare:
                    src = self._local_ip()
                    if src:  # мимо туннеля: пакеты с адреса сетевой карты идут через неё
                        self._measure(ips, "direct", src=src)
                    else:
                        self.log("Не удалось определить сетевую карту — замер «напрямую» пропущен.")
                self._measure(ips, "warp")
                return
            self._measure(ips, "direct")
            if not compare:
                return
            if not (self.exe and self.st.get("warp") and self.st["ranges"]):
                self.log("Для сравнения нужен профиль, клиент туннеля и серверы игры — замерен только прямой пинг.")
                return
            self.log("Временно включаю туннель для замера…")
            if not self._apply():
                return
            try:
                wait_tunnel(self.verify or [(ip, 0) for ip in ips[:3]], 8)
                self._measure(ips, "warp")
            finally:
                self._stop(quiet=True)
                self.log("Замер окончен, туннель снова выключен.")
        self.bg(job)

    # ---------- tunnel
    def toggle(self):
        if self.running or self.armed:
            if self.busy:
                self.stop_after = True
                self.cancel.set()
                self.log("Останавливаю: прерываю текущую операцию…")
                return
            self.bg(self._stop)
            return
        if self.busy:
            self.log("Подождите, идёт операция. Прервать её — кнопка «Прервать».")
            return
        self.collect_ui()
        if not self.exe:
            messagebox.showerror(APP_NAME, "Не найден AmneziaWG или WireGuard.\nУстановите AmneziaWG и "
                                           "перезапустите программу.")
            return
        if not self.st.get("warp"):
            messagebox.showinfo(APP_NAME, "Сначала создайте профиль: «Сгенерировать новый» или «Импорт» "
                                          "в карточке «Профиль WARP».")
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
            allowed = self._allowed()
            ep = self._ep()
            mimic = self.kind == "awg" and self.st.get("mimic", "off") != "off"
        self.last_restart = time.time()
        ok, err = tunnel_up(self.exe, self.kind, conf)
        if ok:
            self.running, self.armed = True, False
            self.applied, self.dirty_routes = allowed, False
            self.started_at = time.time()
            self.fails = 0
            self.ui(lambda: self.set_state("on"))
            self.log(f"Туннель работает: {n} {plural(n, 'диапазон', 'диапазона', 'диапазонов')} игры → {'сервер' if self._custom() else 'WARP'} {ep}. "
                     "Остальной трафик идёт напрямую.")
            return True
        self.running = self.armed = False
        self.applied = []
        self.ui(lambda: self.set_state("off"))
        self.log(f"Не удалось запустить туннель: {err}")
        if mimic and re.search(r"\bI[1-5]\b|unknown|invalid|parse|key", err or "", re.I):
            self.log("Похоже, установлен AmneziaWG 1.x: маскировке QUIC/DNS нужен AmneziaWG 2.0 или новее. "
                     "Обновите клиент или выберите маскировку «Лёгкая».")
        return False

    def _stop(self, quiet=False):
        self.armed = False
        if self.exe:
            tunnel_down(self.exe, self.kind)
        self.running = False
        self.applied = []
        self.ui(lambda: self.set_state("off"))
        if not quiet:
            self.log("Туннель остановлен.")

    def _sync_routes(self):
        """Диапазоны изменились при работающем туннеле: новые — на лету, удалённые — перезапуском."""
        self.dirty_routes = False
        with self.lock:
            allowed = self._allowed()
            peer = self.st["warp"]["peer_public_key"]
            conf = build_conf(self.st, self.kind) if allowed else None
        if allowed == self.applied:
            return
        if not allowed:
            self.log("Список диапазонов пуст — останавливаю туннель.")
            self._stop()
            return
        nets = [ipaddress.ip_network(n) for n in allowed]
        lost = [r for r in self.applied if not any(ipaddress.ip_network(r).subnet_of(n) for n in nets)]
        added = [n for n in allowed if n not in self.applied]
        if not lost and added and hot_add_ranges(cli_path(self.exe, self.kind), peer, allowed, added):
            write_conf(conf)
            self.applied = allowed
            self.log(f"Маршруты добавлены на лету, без перезапуска: {', '.join(added)}")
            return
        self.log("Маршруты изменены — перезапускаю туннель…")
        self.pending = True

    # ---------- failover
    def _health(self):
        """(сломан?, сколько неудач подряд нужно). сломан: True / False / None (неизвестно)."""
        stats = tunnel_stats(self.exe, self.kind)
        if stats:
            self.ui(lambda: self._show_stats(stats))
        if self.verify:
            ms = check_targets(self.verify)
            self.hist.append(ms)
            self.ui(self._draw_hist)
            if ms is not None:
                self.ui(lambda: (self.t_ping.configure(text=f"{ms:.0f} мс"),
                                 self.t_ping_sub.configure(text="через туннель, сейчас")))
            return ms is None, 2
        if stats:
            if not stats["handshake"]:
                return (time.time() - self.started_at) > 45, 1
            return (time.time() - stats["handshake"]) > 200, 1
        return None, 3

    def _check_health(self):
        """Раз в 10 с: жива ли служба туннеля и отвечают ли через него серверы игры."""
        state = service_state(self.kind)
        if not self.running or self.busy:  # пока проверяли, туннель могли остановить кнопкой
            return
        if state in ("STOPPED", "GONE"):
            now = time.time()
            self.svc_drops.append(now)
            self.hist.append(None)
            self.ui(self._draw_hist)
            if len(self.svc_drops) == self.svc_drops.maxlen and now - self.svc_drops[0] < 300:
                self.svc_drops.clear()
                self.log("⚠ Служба туннеля останавливается снова и снова — больше не перезапускаю. "
                         "Проверьте AmneziaWG и нажмите «Запустить».")
                self._try_op(lambda: self._stop(quiet=True))
                return
            self.log("⚠ Служба туннеля остановилась вне программы — запускаю заново. "
                     "Выключать туннель лучше кнопкой «Остановить» здесь.")
            self._try_op(lambda: self.running and self._apply())
            return
        broken, need = self._health()
        if broken:
            self.fails += 1
        elif broken is False:
            self.fails = 0
        if self.fails >= need and self.st.get("failover") and time.time() - self.last_failover > 60:
            self.fails = 0
            self._try_op(lambda: self.running and self._failover())

    def _failover(self):
        """Игра перестала проходить через туннель: переподключение, затем другие серверы и маскировки."""
        self.last_failover = time.time()
        cur = self._ep()
        if self._custom():
            self.log(f"⚠ Свой сервер {cur} перестал отвечать — переподключаю…")
            self._apply()
            return
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
        warp, awg, pre = self.st["warp"], self._awg(), self._pre()
        cands = [e for e, _ in self._eps() if e != cur]
        ok = probe_endpoints(cands, warp, awg, tries=1, pre=pre, cancel=self.cancel)[0] if cands else []
        self._cp()
        if not ok:
            ok = [x for x in scan_endpoints(warp, awg, tries=1, pre=pre, cancel=self.cancel)[0] if x[0] != cur]
            self._cp()
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
        """Варианты перебора: (сервер, мусор AmneziaWG, маскировка I1 или None). Первый — текущие настройки."""
        cur = self._ep()
        if self._custom():
            return [(cur, None, None)]
        lst = [e for e, _ in self._eps()]
        eps, ips = [cur], {split_endpoint(cur)[0]}
        for e in lst:  # сначала разные IP — на случай, если провайдер режет конкретный адрес
            if split_endpoint(e)[0] not in ips:
                eps.append(e)
                ips.add(split_endpoint(e)[0])
        eps += [e for e in lst if e not in eps]
        eps = eps[:5]
        if self.kind == "wg":
            return [(e, None, None) for e in eps]
        mine = {k: int(v) for k, v in self.st["awg"].items()}
        profs = [mine] + [p for p in JUNK_PROFILES if p != mine]
        out = []
        for i, e in enumerate(eps):
            for j, prof in enumerate(profs):
                if j == 0 or i < 3:  # сильный мусор пробуем на трёх первых серверах
                    out.append((e, dict(prof), None))
        out = out[:9]
        # AmneziaWG 2: пакеты-приманки QUIC/DNS перед рукопожатием — или, наоборот, без них
        alt = ["quic", "dns"] if self.st.get("mimic", "off") == "off" else ["off"]
        for k, m in enumerate(alt):
            out.append((eps[min(k, len(eps) - 1)], dict(JUNK_PROFILES[1]), m))
        return out

    def _vdesc(self, ep, prof, mimic):
        out = ("сервер " if self._custom() else "WARP ") + ep
        if prof:
            out += f", мусор ×{prof['Jc']}"
        if mimic == "off":
            out += ", без приманок I1"
        elif mimic:
            out += ", маскировка " + next((n for n, _p, m in MASKS if m == mimic), mimic)
        return out

    def _find_working(self, variants, targets, label):
        """Поднимает туннель с ��аждым вариантом и проверяет серверы игры. -> (ep, awg, маскировка, мс) или None."""
        with self.lock:
            orig = (self.st["endpoint"], dict(self.st["awg"]), self.st.get("mimic", "off"))
        total = len(variants)
        self.last_why = ""
        try:
            for n, (ep, prof, mimic) in enumerate(variants, 1):
                self._cp()
                self.ui(lambda n=n: self.prog.configure(maximum=total, value=n - 1))
                with self.lock:
                    if not self._custom():
                        self.st["endpoint"] = ep
                    if prof:
                        self.st["awg"] = dict(prof)
                    if mimic:
                        self.st["mimic"] = mimic
                    conf = build_conf(self.st, self.kind)
                desc = self._vdesc(ep, prof, mimic)
                ok, err = tunnel_up(self.exe, self.kind, conf)
                if not ok:
                    self.log(f"{label} {n}/{total}: {desc} — туннель не запустился: {(err or '')[:120]}")
                    continue
                ms = wait_tunnel(targets, 8)
                if ms is not None:
                    self.ui(lambda: self.prog.configure(maximum=total, value=total))
                    with self.lock:
                        save_settings(self.st)
                    return ep, prof, mimic, ms
                why = ""
                stats = tunnel_stats(self.exe, self.kind)
                if stats:
                    self.last_why = "hs" if stats["handshake"] else "nohs"
                    why = " (рукопожатие есть, но данные не проходят)" if stats["handshake"] else " (нет даже рукопожатия)"
                self.log(f"{label} {n}/{total}: {desc} — серверы игры через туннель не отвечают{why}")
        except Cancelled:
            self._restore(orig)
            raise
        self._restore(orig)
        return None

    def _restore(self, orig):
        """Вернуть прежние настройки после перебора и выключить пробный туннель."""
        with self.lock:
            self.st["endpoint"], self.st["awg"], self.st["mimic"] = orig
            save_settings(self.st)
        tunnel_down(self.exe, self.kind)
        self.running = False
        self.applied = []
        self.ui(lambda: (self.prog.configure(value=0), self.set_state("off"), self._refresh(), self._refresh_mask()))

    def _tuned(self, ep, prof, mimic, ms):
        self.running, self.armed = True, False
        self.started_at = self.last_restart = time.time()
        self.fails = 0
        with self.lock:
            self.applied, self.dirty_routes = self._allowed(), False
            known = dict(self._eps())
            if ep in known:
                self.st["endpoint_ms"] = known[ep]
            save_settings(self.st)
        self.hist.append(ms)
        self.ui(lambda: (self.set_state("on"), self._refresh(), self._refresh_mask(), self._draw_hist(),
                         self.t_ping.configure(text=f"{ms:.0f} мс"),
                         self.t_ping_sub.configure(text="через туннель, проверено")))
        self.log(f"✓ Работает: {self._vdesc(ep, prof, mimic)}. Сервер игры отвечает через туннель за {ms:.0f} мс. "
                 "Настройки сохранены, туннель включён.")

    def do_autotune(self):
        self.collect_ui()
        if not self.exe or not self.st.get("warp"):
            self.log("Для автоподбора нужны AmneziaWG и профиль («Сгенерировать новый» или «Импорт»).")
            return
        if not self.st["ranges"]:
            self.log("Сначала добавьте серверы игры: вкладка «Серверы игры» → «Готовый список» → «Добавить».")
            return
        self.bg(self._autotune)

    def _autotune(self):
        self.log("Автоподбор: ищу настройки, при которых серверы игры отвечают через туннель (до пары минут). "
                 "Прервать — кнопка «Прервать».")
        if self.running or tunnel_running(self.kind):
            tunnel_down(self.exe, self.kind)
            self.running = False
            self.applied = []
            self.ui(lambda: self.set_state("off"))
            time.sleep(2)
        cands = self._candidate_targets()
        res = []
        if cands:
            with ThreadPoolExecutor(max_workers=8) as ex:
                res = list(ex.map(lambda t: (t, check_targets([t])), cands))
        self._cp()
        direct = []
        for t in sorted([t for t, ms in res if ms is not None], key=lambda t: t[1] == 0):
            if all(t[0] != d[0] for d in direct):  # один сервер — одна проверка, TCP точнее ICMP
                direct.append(t)
        direct = direct[:4]
        if not direct:
            self.log("Серверы игры не отвечают даже напрямую — проверять туннель не на чем. "
                     "Запустите игру (до главного меню) и повторите автоподбор.")
            return
        self.verify = direct
        with self.lock:
            self.st["verify_targets"] = [list(t) for t in direct]
            save_settings(self.st)
        self.log("Проверяю по серверам игры: " + ", ".join(f"{ip}:{p}" if p else ip for ip, p in direct))
        if not self._custom() and not self._eps():
            self.log("Сначала ищу серверы WARP…")
            ok, _ = self._scan(tries=1)
            if ok:
                self._save_scan(ok)
        found = self._find_working(self._variants(), direct, "Автоподбор")
        if found:
            self._tuned(*found)
            return
        hint = {"hs": "Рукопожатие проходит, а данные блокируются — похоже на блокировку у провайдера.",
                "nohs": "Сервер не принимает подключение туннеля — похоже, провайдер блокирует WARP."}.get(
            self.last_why, "Трафик через туннель не идёт ни на одном варианте.")
        self.log("✗ Рабочий вариант не найден. " + hint + " Что попробовать: 1) раздайте интернет с телефона "
                 "и повторите автоподбор — станет понятно, дело в провайдере или нет; 2) «Сгенерировать новый» профиль "
                 "WARP и снова «Автоподбор»; 3) если игра заходит без туннеля — играйте напрямую.")

    # ---------- background watcher
    def _watcher(self):
        tick, last_err, last_t = 0, "", 0.0
        while True:
            time.sleep(2)
            tick += 1
            try:
                self._watch(tick)
            except Exception as e:  # noqa
                msg = str(e) or type(e).__name__
                if msg != last_err or time.time() - last_t > 60:
                    last_err, last_t = msg, time.time()
                    self.log(f"Фоновая ошибка: {msg}")

    def _watch(self, tick):
        """Шаг наблюдателя (раз в 2 с): игра и радар — раз в 4 с, отложенные изменения, здоровье — раз в 10 с."""
        if tick % 2 == 0:
            self._game_state()
        self._pending_apply()
        if self.running and not self.busy and tick % 5 == 0:
            self._check_health()

    def _game_state(self):
        """Процессы игры: новые серверы (соединения + радар UDP), запуск и остановка радара."""
        with self.lock:
            auto = self.st.get("auto_learn")
            radar_on = self.st.get("radar", True)
            names = list(self.st["game_processes"])
            prefix = int(self.st.get("prefix", 24))
        if not (auto or self.armed):
            if self.radar.sock is not None:
                self.radar.stop()
            return
        eps, udp, game = game_scan(names)
        if game != self.game_on:
            self.game_on = game
            self.log("Игра запущена — слежу за её серверами." if game else "Игра закрыта.")
        if game and radar_on and self.admin:
            self.radar.ports = set(udp)
            if self.radar.sock is None:
                src = self._local_ip()
                if src and self.radar.start(src):
                    self.log(f"Радар UDP включён ({src}): серверы матчей будут найдены по пакетам игры.")
            for ip in self.radar.take():
                eps.setdefault(ip, None)
        elif self.radar.sock is not None:
            self.radar.stop()
        try:
            eps.pop(split_endpoint(self._ep())[0], None)
        except (ValueError, IndexError, TypeError):
            pass
        if eps:
            self._learn(eps, prefix)

    def _pending_apply(self):
        """Отложенные изменения: новые маршруты на лету или перезапуск туннеля (не чаще раза в 15 с)."""
        if self.busy:
            return
        if not self.running:
            self.dirty_routes = False  # туннель выключен — новые диапазоны попадут в него при запуске
            if not self.armed:
                self.pending = False

        if self.dirty_routes and not self.pending:
            new = [n for n in self._allowed() if n not in self.applied]
            if new and self.radar.active(new):
                if not self.deferred:
                    self.deferred = True
                    self.log("Матч идёт напрямую через новый сервер — добавлю его в туннель после матча, "
                             "чтобы не оборвать игру.")
                return
            self.deferred = False
            self._try_op(self._sync_routes)
            return
        if self.pending and time.time() - self.last_restart > 15 and self.op_lock.acquire(blocking=False):
            self.pending = self.dirty_routes = False
            self._locked(self._apply)

    def _try_op(self, fn):
        """Действие наблюдателя под тем же замком, что и кнопки, — не пересекается с ними."""
        if not self.op_lock.acquire(blocking=False):
            return False
        self._locked(fn)
        return True

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
        if self.running:
            self.dirty_routes = True  # добавятся в работающий туннель на лету, без перезапуска
        elif self.armed:
            self.pending = True
            self.last_restart = 0

    def on_close(self):
        if self.running or self.busy:
            head = "Туннель работает как служба Windows.\n\n" if self.running else "Идёт операция с туннелем.\n\n"
            ans = messagebox.askyesnocancel(
                APP_NAME, head + "Да — свернуть окно (автопоиск и автосмена продолжат работать)\n"
                                 "Нет — выключить туннель и выйти\nОтмена — вернуться")
            if ans is None:
                return
            if ans:
                self.root.iconify()
                return
            self.cancel.set()
            if self.exe:
                tunnel_down(self.exe, self.kind)
        self.radar.stop()
        self.root.destroy()

    def run(self):
        self.root.mainloop()


def main():
    if not single_instance():
        try:
            r = tk.Tk()
            r.withdraw()
            messagebox.showinfo(APP_NAME, "ABI Route уже запущен — найдите его окно на панели задач.")
            r.destroy()
        except Exception:  # noqa
            pass
        return
    App().run()


if __name__ == "__main__":
    main()
