# -*- coding: utf-8 -*-
"""WireGuard-хендшейк: структура пакета, шифрование, пинг по локальному UDP-серверу."""
import base64
import hashlib
import os
import socket
import struct
import threading

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from abiroute.util import b64
from abiroute.warp import (LABEL_MAC1, WARP_IPS, _aead, _hash, _kdf, _tai64n,
                           build_initiation, gen_keypair, handshake_ping,
                           warp_endpoint_ips)


def fake_warp():
    return {"private_key": b64(os.urandom(32)), "public_key": b64(os.urandom(32)),
            "peer_public_key": b64(os.urandom(32))}


def test_build_initiation_structure():
    s_priv, s_pub = gen_keypair()
    r_pub = os.urandom(32)
    msg, sender = build_initiation(s_priv, s_pub, r_pub)
    assert len(msg) == 148                      # тип + индекс + eph + static + ts + mac1 + mac2
    assert struct.unpack("<II", msg[:8]) == (1, sender)
    assert msg[-16:] == b"\0" * 16              # mac2 пустой
    mac1 = msg[-32:-16]
    assert mac1 == hashlib.blake2s(msg[:-32], key=_hash(LABEL_MAC1, r_pub), digest_size=16).digest()
    # разные вызовы дают разные эфемерные ключи и индексы
    msg2, sender2 = build_initiation(s_priv, s_pub, r_pub)
    assert msg2[:8] != msg[:8] or msg2[8:40] != msg[8:40]
    assert sender2 != sender


def test_kdf_deterministic_lengths():
    key, data = os.urandom(32), b"chain"
    out1, out2 = _kdf(key, data, 3), _kdf(key, data, 3)
    assert out1 == out2 and len(out1) == 3 and all(len(x) == 32 for x in out1)


def test_aead_roundtrip():
    key = os.urandom(32)
    ct = _aead(key, 7, b"payload", b"ad")
    assert ct != b"payload"
    plain = ChaCha20Poly1305(key).decrypt(b"\0" * 4 + struct.pack("<Q", 7), ct, b"ad")
    assert plain == b"payload"


def test_tai64n():
    ts = _tai64n()
    assert len(ts) == 12  # 8 байт секунд + 4 байта наносекунд


def test_handshake_ping_local_responder():
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(0.2)
    port = srv.getsockname()[1]
    stop = threading.Event()

    def responder():
        srv.settimeout(0.2)
        while not stop.is_set():
            try:
                data, addr = srv.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                return
            if len(data) >= 12 and data[0] == 1:
                # В WireGuard Initiation индекс отправителя лежит на байтах 4:8,
                # в Response он же приходит как Receiver Index на 8:12.
                sender = struct.unpack("<I", data[4:8])[0]
                srv.sendto(struct.pack("<II", 2, 0) + struct.pack("<I", sender) + b"\0" * 84, addr)

    t = threading.Thread(target=responder, daemon=True)
    t.start()
    try:
        ms = handshake_ping("127.0.0.1", port, fake_warp(), timeout=2)
        assert ms is not None and ms >= 0
        # с мусорными пакетами AmneziaWG — должен дойти до настоящего пакета
        ms2 = handshake_ping("127.0.0.1", port, fake_warp(),
                             awg={"Jc": 3, "Jmin": 40, "Jmax": 70}, timeout=2)
        assert ms2 is not None
        # и молча вернуть None, если ответа нет
        assert handshake_ping("127.0.0.1", 1, fake_warp(), timeout=0.3) is None
    finally:
        stop.set()
        t.join(timeout=2)
        srv.close()


def test_warp_endpoint_ips_contains_static():
    ips = warp_endpoint_ips()
    assert set(WARP_IPS) <= set(ips)   # статический список включён целиком
    assert "162.159.192.1" in ips
    assert len(ips) <= 30              # лимит размера скана
    assert len(ips) == len(set(ips))   # без дублей


def test_bad_warp_dict_raises_keyerror():
    w = {"private_key": b64(os.urandom(32)), "public_key": b64(os.urandom(32))}  # нет peer_public_key
    with pytest.raises(KeyError):
        handshake_ping("127.0.0.1", 2408, w, timeout=0.2)


def test_base64_helper():
    assert b64(b"\x00" * 3) == base64.b64encode(b"\x00" * 3).decode()
