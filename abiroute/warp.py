# -*- coding: utf-8 -*-
"""Cloudflare WARP: регистрация профиля, поиск эндпоинтов настоящим WireGuard-рукопожатием."""
import base64
import hashlib
import hmac
import json
import os
import random
import secrets
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .util import b64

# ----------------------------------------------------------------- ключи / WARP API


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
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            j = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"Cloudflare отклонил регистрацию (HTTP {e.code}). "
                           f"Попробуйте позже или смените сеть.") from None
    except (urllib.error.URLError, OSError) as e:
        raise RuntimeError(f"Нет связи с api.cloudflareclient.com: {e}") from None
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


# Адреса WARP-эндпоинтов (162.159.192-195.x, 188.114.96-99.x) + актуальные из DNS.
WARP_IPS = (["162.159.192.%d" % i for i in (1, 2, 5, 7, 9, 10)]
            + ["162.159.193.%d" % i for i in (1, 3, 5, 10)]
            + ["162.159.195.%d" % i for i in (1, 4, 8)]
            + ["188.114.96.1", "188.114.96.3", "188.114.97.1", "188.114.97.4",
               "188.114.98.1", "188.114.99.1"])
WARP_PORTS = [2408, 500, 1701, 4500, 878, 894, 854, 939, 7559]


def warp_endpoint_ips():
    """Известные адреса + свежие из DNS (engage.cloudflareclient.com), без дублей, с лимитом."""
    merged = []
    try:
        infos = socket.getaddrinfo("engage.cloudflareclient.com", 2408,
                                   socket.AF_INET, socket.SOCK_DGRAM)
        for i in infos:
            ip = i[4][0]
            if ip not in merged:
                merged.append(ip)
    except OSError:
        pass
    for ip in WARP_IPS:
        if ip not in merged:
            merged.append(ip)
    return merged[:30]


def scan_endpoints(warp, awg, progress=None, tries=2):
    eps = [f"{ip}:{p}" for ip in warp_endpoint_ips() for p in WARP_PORTS]
    return probe_endpoints(eps, warp, awg, progress, tries)


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
