# -*- coding: utf-8 -*-
"""Свой мини-клиент WireGuard / AmneziaWG — без драйвера и прав администратора.

Зачем он нужен:

* TCP-соединения через WARP Cloudflare завершает на своём узле: SYN-ACK приходит от
  Cloudflare за пару миллисекунд, даже если порт на сервере закрыт. Поэтому TCP-пинг
  «через туннель» показывает задержку до Cloudflare, а не до сервера игры. Честную
  задержку даёт только ICMP — его WARP доносит до самого сервера и обратно.
* Модуль сам делает рукопожатие с WARP и гоняет ICMP-эхо внутри туннеля, поэтому пинг
  через WARP меряется без системного туннеля и без переключения маршрутов.
* Перед рукопожатием он шлёт те же пакеты маскировки, что и AmneziaWG (I1–I5, затем Jc
  мусорных), так что проверка честно показывает, пропустит ли провайдер настоящий туннель.
"""
import base64
import hashlib
import hmac
import os
import random
import secrets
import socket
import string
import struct
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from .common import split_endpoint, summarize

CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
IDENTIFIER = b"WireGuard v1 zx2c4 Jason@zx2c4.com"
LABEL_MAC1 = b"mac1----"
INNER_V4 = "172.16.0.2"   # адрес клиента внутри WARP (одинаковый у всех бесплатных профилей)
CHECK_IP = "1.1.1.1"      # сам Cloudflare: отвечает на ICMP всегда, если данные проходят


def b64(b):
    return base64.b64encode(b).decode()


def gen_keypair():
    k = X25519PrivateKey.generate()
    priv = k.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                           serialization.NoEncryption())
    return priv, k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_from_private(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


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


def _nonce(counter):
    return b"\0" * 4 + struct.pack("<Q", counter)


def _dh(priv, pub):
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(pub))


_ts_lock = threading.Lock()
_ts_last = [0]


def _tai64n():
    """Метка времени рукопожатия. Строго растёт даже при параллельных проверках:
    сервер отбрасывает рукопожатие со «старой» меткой как повтор."""
    with _ts_lock:
        ns = max(time.time_ns(), _ts_last[0] + 1)
        _ts_last[0] = ns
    s, rest = divmod(ns, 1_000_000_000)
    return struct.pack(">QI", 0x400000000000000A + s, rest)

# ----------------------------------------------------------------- маскировка AmneziaWG


def cps_packet(spec):
    """Пакет по описанию CPS из параметров I1–I5 AmneziaWG.

    Теги как в amneziawg-go: <b 0xHEX> байты, <r N> случайные байты, <rc N> латиница,
    <rd N> цифры, <t> время (4 байта). ValueError, если описание некорректно.
    """
    out = bytearray()
    rest = str(spec)
    while True:
        start = rest.find("<")
        if start < 0:
            break
        end = rest.find(">", start)
        if end < 0:
            raise ValueError("нет закрывающей >")
        parts = rest[start + 1:end].split()
        rest = rest[end + 1:]
        if not parts:
            raise ValueError("пустой тег")
        tag, val = parts[0], (parts[1] if len(parts) > 1 else "")
        if tag == "b":
            hx = val[2:] if val.startswith("0x") else val
            if not hx or len(hx) % 2:
                raise ValueError("неверные байты в <b>")
            out += bytes.fromhex(hx)
        elif tag == "t":
            out += struct.pack(">I", int(time.time()) & 0xFFFFFFFF)
        elif tag in ("r", "rc", "rd"):
            n = int(val)
            if not 0 < n <= 1000:
                raise ValueError("длина вне 1..1000")
            if tag == "r":
                out += os.urandom(n)
            else:
                abc = string.ascii_letters if tag == "rc" else string.digits
                out += "".join(secrets.choice(abc) for _ in range(n)).encode()
        elif tag in ("d", "ds", "dz"):
            continue  # данные пакета: у I-пакетов их нет
        else:
            raise ValueError(f"неизвестный тег <{tag}>")
    if not out:
        raise ValueError("пустой пакет")
    return bytes(out)


def obfuscation_packets(obf):
    """Пакеты перед рукопожатием в порядке AmneziaWG: I1…I5, затем Jc мусорных."""
    if not obf:
        return []
    pkts = []
    for i in range(1, 6):
        spec = obf.get(f"I{i}")
        if spec:
            try:
                pkts.append(cps_packet(spec))
            except ValueError:
                pass
    jc = int(obf.get("Jc", 0) or 0)
    lo, hi = int(obf.get("Jmin", 0) or 0), int(obf.get("Jmax", 0) or 0)
    if jc > 0 and hi > 0:
        lo = max(1, min(lo, hi))
        pkts += [os.urandom(random.randint(lo, hi)) for _ in range(jc)]
    return pkts

# ----------------------------------------------------------------- сессия


class Session:
    """Одно соединение WireGuard с сервером WARP: рукопожатие и обмен IP-пакетами."""

    def __init__(self, keys, endpoint, obf=None, src_ip=INNER_V4):
        self.s_priv = base64.b64decode(keys["private_key"])
        self.s_pub = public_from_private(self.s_priv)
        self.r_pub = base64.b64decode(keys["peer_public_key"])
        host, port = split_endpoint(endpoint) if isinstance(endpoint, str) else endpoint
        self.addr = (host, int(port))
        self.obf = obf
        self.src = src_ip
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.k_send = self.k_recv = None
        self.idx = self.peer_idx = 0
        self.counter = 0
        self.rtt = None

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def _initiation(self):
        c = _hash(CONSTRUCTION)
        h = _hash(_hash(c, IDENTIFIER), self.r_pub)
        e_priv, e_pub = gen_keypair()
        c = _kdf(c, e_pub, 1)[0]
        h = _hash(h, e_pub)
        c, k = _kdf(c, _dh(e_priv, self.r_pub), 2)
        enc_static = ChaCha20Poly1305(k).encrypt(_nonce(0), self.s_pub, h)
        h = _hash(h, enc_static)
        c, k = _kdf(c, _dh(self.s_priv, self.r_pub), 2)
        enc_ts = ChaCha20Poly1305(k).encrypt(_nonce(0), _tai64n(), h)
        h = _hash(h, enc_ts)
        self.idx = secrets.randbits(32)
        msg = struct.pack("<II", 1, self.idx) + e_pub + enc_static + enc_ts
        mac1 = hashlib.blake2s(msg, key=_hash(LABEL_MAC1, self.r_pub), digest_size=16).digest()
        self._hs = (c, h, e_priv)
        return msg + mac1 + b"\0" * 16

    def _consume_response(self, data):
        c, h, e_priv = self._hs
        er_pub = data[12:44]
        c = _kdf(c, er_pub, 1)[0]
        h = _hash(h, er_pub)
        c = _kdf(c, _dh(e_priv, er_pub), 1)[0]
        c = _kdf(c, _dh(self.s_priv, er_pub), 1)[0]
        c, tau, k = _kdf(c, b"\0" * 32, 3)
        h = _hash(h, tau)
        ChaCha20Poly1305(k).decrypt(_nonce(0), data[44:60], h)  # InvalidTag, если ответ чужой
        self.k_send, self.k_recv = _kdf(c, b"", 2)
        self.peer_idx = struct.unpack("<I", data[4:8])[0]
        self.counter = 0

    def handshake(self, timeout=1.5):
        """RTT рукопожатия в мс или None. После успеха можно слать IP-пакеты."""
        try:
            for p in obfuscation_packets(self.obf):
                self.sock.sendto(p, self.addr)
            pkt = self._initiation()
            t0 = time.perf_counter()
            self.sock.sendto(pkt, self.addr)
            deadline = t0 + timeout
            while True:
                left = deadline - time.perf_counter()
                if left <= 0:
                    return None
                self.sock.settimeout(left)
                data, _ = self.sock.recvfrom(2048)
                if (len(data) == 92 and data[0] == 2
                        and struct.unpack("<I", data[8:12])[0] == self.idx):
                    rtt = (time.perf_counter() - t0) * 1000
                    try:
                        self._consume_response(data)
                    except Exception:  # noqa: BLE001 — не наш ответ
                        continue
                    self.rtt = rtt
                    return rtt
        except OSError:
            return None

    def send_ip(self, packet):
        pad = (-len(packet)) % 16
        n = self.counter
        self.counter += 1
        ct = ChaCha20Poly1305(self.k_send).encrypt(_nonce(n), packet + b"\0" * pad, b"")
        self.sock.sendto(struct.pack("<II", 4, self.peer_idx) + struct.pack("<Q", n) + ct, self.addr)

    def recv_ip(self, timeout):
        """Следующий IP-пакет из туннеля или None по таймауту."""
        deadline = time.perf_counter() + timeout
        while True:
            left = deadline - time.perf_counter()
            if left <= 0:
                return None
            try:
                self.sock.settimeout(left)
                data, _ = self.sock.recvfrom(4096)
            except OSError:
                return None
            if len(data) < 32 or data[0] != 4 or struct.unpack("<I", data[4:8])[0] != self.idx:
                continue
            try:
                pt = ChaCha20Poly1305(self.k_recv).decrypt(b"\0" * 4 + data[8:16], data[16:], b"")
            except Exception:  # noqa: BLE001
                continue
            if pt:  # пустой — keepalive
                return pt

# ----------------------------------------------------------------- IP-пакеты


def _csum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF


def ipv4_packet(src, dst, proto, payload, ttl=64):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), random.getrandbits(16), 0x4000,
                      ttl, proto, 0, socket.inet_aton(src), socket.inet_aton(dst))
    return hdr[:10] + struct.pack("!H", _csum(hdr)) + hdr[12:] + payload


def icmp_echo(src, dst, ident, seq, payload=b"ABIRoute ping...."):
    body = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + payload
    return ipv4_packet(src, dst, 1, body[:2] + struct.pack("!H", _csum(body)) + body[4:])


def udp_packet(src, dst, sport, dport, payload):
    seg = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 17, len(seg))
    c = _csum(pseudo + seg) or 0xFFFF
    return ipv4_packet(src, dst, 17, seg[:6] + struct.pack("!H", c) + seg[8:])


def parse_ipv4(pkt):
    """(протокол, src, dst, полезная нагрузка) или None."""
    if len(pkt) < 20 or pkt[0] >> 4 != 4:
        return None
    ihl = (pkt[0] & 15) * 4
    total = struct.unpack("!H", pkt[2:4])[0]
    return pkt[9], socket.inet_ntoa(pkt[12:16]), socket.inet_ntoa(pkt[16:20]), pkt[ihl:total]

# ----------------------------------------------------------------- замеры через туннель


def ping_via(session, ips, count=5, interval=0.2, timeout=1.2):
    """ICMP-пинг до каждого адреса через туннель. -> {ip: сводка или None}.

    Все адреса пингуются одновременно, раунд за раундом; поздние ответы тоже засчитываются.
    """
    ips = list(dict.fromkeys(ips))
    ident = random.getrandbits(16)
    sent = {}
    got = {ip: [] for ip in ips}
    seq = random.getrandbits(15)
    for rnd in range(count):
        waiting = set()
        for ip in ips:
            seq = (seq + 1) & 0xFFFF
            sent[seq] = (ip, time.perf_counter())
            waiting.add(seq)
            try:
                session.send_ip(icmp_echo(session.src, ip, ident, seq))
            except OSError:
                pass
        deadline = time.perf_counter() + timeout
        while waiting:
            left = deadline - time.perf_counter()
            if left <= 0:
                break
            pkt = session.recv_ip(left)
            if pkt is None:
                break
            p = parse_ipv4(pkt)
            if not p or p[0] != 1 or len(p[3]) < 8:
                continue
            typ, _, _, rid, rseq = struct.unpack("!BBHHH", p[3][:8])
            if typ != 0 or rid != ident or rseq not in sent:
                continue
            ip, t0 = sent.pop(rseq)
            if ip == p[1]:
                got[ip].append((time.perf_counter() - t0) * 1000)
                waiting.discard(rseq)
        if rnd + 1 < count:
            time.sleep(interval)
    return {ip: summarize(got[ip], count, "ICMP") for ip in ips}


def warp_colo(session, timeout=1.2):
    """Код узла Cloudflare (FRA, AMS…), через который идёт WARP: DNS-запрос id.server CH TXT."""
    qid = random.getrandbits(16)
    sport = random.randint(20000, 60000)
    q = struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + b"\x02id\x06server\x00" + struct.pack("!HH", 16, 3)
    try:
        session.send_ip(udp_packet(session.src, CHECK_IP, sport, 53, q))
    except OSError:
        return None
    deadline = time.perf_counter() + timeout
    while True:
        left = deadline - time.perf_counter()
        if left <= 0:
            return None
        pkt = session.recv_ip(left)
        if pkt is None:
            return None
        p = parse_ipv4(pkt)
        if not p or p[0] != 17 or len(p[3]) < 8 + 12:
            continue
        sp, dp = struct.unpack("!HH", p[3][:4])
        dns = p[3][8:]
        if sp != 53 or dp != sport or struct.unpack("!H", dns[:2])[0] != qid:
            continue
        try:
            i = 12 + len(b"\x02id\x06server\x00") + 4
            i += 2 if dns[i] & 0xC0 == 0xC0 else dns.index(b"\0", i) + 1 - i
            rdlen = struct.unpack("!H", dns[i + 8:i + 10])[0]
            txt = dns[i + 10:i + 10 + rdlen]
            code = txt[1:1 + txt[0]].decode("ascii", "ignore").strip().upper()
        except (IndexError, ValueError, struct.error):
            return None
        return code[:3] if code[:3].isalpha() else None


def probe(keys, endpoint, obf=None, targets=(), count=4, hs_timeout=1.5):
    """Полная проверка пути через WARP с этого компьютера.

    -> {"endpoint", "handshake": мс|None, "data": мс|None (ICMP до 1.1.1.1), "colo": "FRA"|None,
        "targets": {ip: сводка|None}}
    """
    res = {"endpoint": endpoint, "handshake": None, "data": None, "colo": None, "targets": {}}
    with Session(keys, endpoint, obf) as s:
        res["handshake"] = s.handshake(hs_timeout)
        if res["handshake"] is None:
            return res
        ips = [CHECK_IP] + [t for t in targets if t != CHECK_IP]
        pings = ping_via(s, ips, count=max(1, count))
        chk = pings.pop(CHECK_IP)
        res["data"] = chk["ms"] if chk else None
        res["targets"] = pings
        if res["data"] is not None:
            res["colo"] = warp_colo(s)
    return res


def handshake_ping(keys, endpoint, obf=None, timeout=1.2):
    with Session(keys, endpoint, obf) as s:
        return s.handshake(timeout)


def scan(keys, endpoints, obf=None, workers=24, timeout=1.2, progress=None, stop=None):
    """Рукопожатие с каждым сервером. -> [(endpoint, мс)] по возрастанию задержки.

    stop — threading.Event для отмены.
    """
    endpoints = list(dict.fromkeys(endpoints))
    done = [0]
    lock = threading.Lock()

    def one(ep):
        ms = None
        if not (stop and stop.is_set()):
            ms = handshake_ping(keys, ep, obf, timeout)
        with lock:
            done[0] += 1
            if progress:
                progress(done[0], len(endpoints))
        return ep, ms

    with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        res = list(ex.map(one, endpoints))
    return sorted([(ep, ms) for ep, ms in res if ms is not None], key=lambda x: x[1])
