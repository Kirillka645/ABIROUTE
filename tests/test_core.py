# -*- coding: utf-8 -*-
"""Тесты ядра ABI Route без сети: python -m unittest discover -s tests -v"""
import base64
import json
import os
import socket
import struct
import sys
import tempfile
import time
import unittest
import zlib

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from abiroute import common, engine, net, settings, tunnel, warp, wg  # noqa: E402


def _keypair_b64():
    priv, pub = wg.gen_keypair()
    return wg.b64(priv), wg.b64(pub)


class ObfuscationTest(unittest.TestCase):
    def test_cps_tags(self):
        pkt = wg.cps_packet("<b 0xdeadbeef><r 4><rc 3><rd 2><t>")
        self.assertEqual(len(pkt), 4 + 4 + 3 + 2 + 4)
        self.assertEqual(pkt[:4], bytes.fromhex("deadbeef"))
        self.assertTrue(pkt[8:11].decode().isalpha())
        self.assertTrue(pkt[11:13].decode().isdigit())
        self.assertLessEqual(abs(struct.unpack(">I", pkt[13:])[0] - time.time()), 2)

    def test_cps_errors(self):
        for bad in ("", "<b 0xabc>", "<x 1>", "<r 2000>", "<b 0x00", "<>"):
            with self.assertRaises(ValueError, msg=bad):
                wg.cps_packet(bad)

    def test_packets_order_like_amneziawg(self):
        pkts = wg.obfuscation_packets({"I1": "<b 0x01>", "I2": "<b 0x02>", "Jc": 3, "Jmin": 10, "Jmax": 10})
        self.assertEqual(pkts[:2], [b"\x01", b"\x02"])
        self.assertEqual([len(p) for p in pkts[2:]], [10, 10, 10])
        self.assertEqual(wg.obfuscation_packets(None), [])

    def test_presets_are_valid(self):
        for p in warp.OBF_PRESETS:
            wg.obfuscation_packets(p["obf"])
            for i in range(1, 6):
                if p["obf"].get(f"I{i}"):
                    wg.cps_packet(p["obf"][f"I{i}"])
        quic = wg.cps_packet(warp.QUIC_I1)
        self.assertEqual((len(quic), quic[0]), (1252, 0xC2))  # QUIC Initial дополняется до 1200+ байт
        self.assertTrue(wg.cps_packet(warp.SIP_I1).startswith(b"INVITE sip:"))


class ConfigTest(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = _keypair_b64()
        self.peer = _keypair_b64()[1]
        self.text = (f"[Interface]\nPrivateKey = {self.priv}\nS1 = 0\nS2 = 0\nJc = 120\nJmin = 23\nJmax = 911\n"
                     f"H1 = 1\nH2 = 2\nH3 = 3\nH4 = 4\nMTU = 1280\nI1 = <b 0xc200000001>\n"
                     f"Address = 172.16.0.2, 2606:4700:110:8aed::1\nDNS = 1.1.1.1\n\n"
                     f"[Peer]\nPublicKey = {self.peer}\nAllowedIPs = 0.0.0.0/0, ::/0\n"
                     f"Endpoint = 162.159.192.1:500\n")

    def test_import_amneziawg_conf(self):
        prof, extra = warp.parse_conf(self.text)
        self.assertEqual((prof["private_key"], prof["public_key"]), (self.priv, self.pub))
        self.assertEqual((prof["peer_public_key"], prof["v4"]), (self.peer, "172.16.0.2"))
        self.assertEqual(extra["endpoint"], "162.159.192.1:500")
        self.assertEqual(extra["obf"], {"Jc": 120, "Jmin": 23, "Jmax": 911, "I1": "<b 0xc200000001>"})
        self.assertEqual(extra["mtu"], 1280)

    def test_import_vpn_links(self):
        inner = json.dumps({"config": self.text.replace("\n", "\r\n")})
        doc = json.dumps({"containers": [{"container": "amnezia-awg", "awg": {"last_config": inner}}]}).encode()
        plain = "vpn://" + base64.b64encode(doc).decode()  # как у генераторов WARP
        packed = "vpn://" + base64.urlsafe_b64encode(struct.pack(">I", len(doc)) + zlib.compress(doc)).decode()
        for link in (plain, packed):
            prof, extra = warp.parse_conf(link)
            self.assertEqual(prof["peer_public_key"], self.peer)
            self.assertEqual(extra["endpoint"], "162.159.192.1:500")

    def test_import_rejects_garbage(self):
        for bad in ("", "[Interface]\nPrivateKey = abc\n", "vpn://!!!"):
            with self.assertRaises(ValueError):
                warp.parse_conf(bad)

    def test_import_inline_comments(self):
        text = self.text.replace("Endpoint = 162.159.192.1:500", "Endpoint = 162.159.192.1:500  # WARP")
        self.assertEqual(warp.parse_conf(text)[1]["endpoint"], "162.159.192.1:500")

    def test_split_tunnel_conf(self):
        prof, _ = warp.parse_conf(self.text)
        obf = {"Jc": 4, "Jmin": 40, "Jmax": 70, "I1": "<b 0xc2>"}
        ranges = ["43.174.251.0/24", "162.159.192.0/24", "43.174.250.0/24", "2001:db8::/32", ""]
        conf = warp.build_conf(prof, "162.159.192.1:2408", ranges, obf, "awg", cps_ok=True)
        allowed = next(ln for ln in conf.splitlines() if ln.startswith("AllowedIPs"))
        self.assertIn("43.174.250.0/23", allowed)            # соседние диапазоны схлопнуты
        self.assertNotIn("162.159.192.0/24", allowed)        # сервер WARP не уходит в туннель
        self.assertIn("162.159.192.0/32", allowed)
        self.assertNotIn("2001:db8", allowed)
        self.assertIn("I1 = <b 0xc2>", conf)
        self.assertNotIn("I1", warp.build_conf(prof, "162.159.192.1:2408", ranges, obf, "awg", cps_ok=False))
        self.assertNotIn("Jc", warp.build_conf(prof, "162.159.192.1:2408", ranges, obf, "wg", cps_ok=False))
        with self.assertRaises(ValueError):
            warp.build_conf(prof, "162.159.192.1:2408", [], obf, "awg", cps_ok=True)

    def test_candidate_endpoints(self):
        eps = warp.candidate_endpoints()
        self.assertEqual(len(eps), len(set(eps)))
        self.assertGreaterEqual(len(eps), 400)
        picked = warp.spread(["1.1.1.1:1", "1.1.1.2:1", "2.2.2.2:1", "3.3.3.3:1"], 3)
        self.assertEqual(picked, ["1.1.1.1:1", "2.2.2.2:1", "3.3.3.3:1"])


class PacketTest(unittest.TestCase):
    def test_icmp_echo_checksums(self):
        pkt = wg.icmp_echo("172.16.0.2", "1.1.1.1", 0x1234, 7)
        self.assertEqual(wg._csum(pkt[:20]), 0)
        self.assertEqual(wg._csum(pkt[20:]), 0)
        proto, src, dst, payload = wg.parse_ipv4(pkt)
        self.assertEqual((proto, src, dst, payload[0]), (1, "172.16.0.2", "1.1.1.1", 8))

    def test_udp_checksum(self):
        pkt = wg.udp_packet("172.16.0.2", "1.1.1.1", 40000, 53, b"\x12\x34hello")
        seg = pkt[20:]
        pseudo = socket.inet_aton("172.16.0.2") + socket.inet_aton("1.1.1.1") + struct.pack("!BBH", 0, 17, len(seg))
        self.assertEqual(wg._csum(pseudo + seg), 0)

    def test_summary(self):
        s = common.summarize([10, 12, 11], 4, "ICMP")
        self.assertEqual((s["ms"], s["min"], s["jitter"], s["loss"]), (11, 10, 2, 25))
        self.assertIsNone(common.summarize([], 4, "ICMP"))


class SystemTest(unittest.TestCase):
    def test_settings_migration_from_2x(self):
        old = {"awg": {"Jc": 120, "Jmin": 23, "Jmax": 911}, "endpoint_list": [["162.159.192.1:2408", 31]],
               "endpoint_ms": 31, "ping": {}, "ranges": ["43.174.251.0/24"]}
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "settings.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump(old, f)
            st = settings.load_settings(path)
        self.assertEqual((st["obf_id"], st["obf"]["Jc"]), ("strong", 120))
        self.assertEqual(st["endpoint_list"], [["162.159.192.1:2408", 31, None]])
        self.assertEqual(st["ranges"], ["43.174.251.0/24"])
        for gone in ("awg", "endpoint_ms", "ping"):
            self.assertNotIn(gone, st)

    def test_client_error_text(self):
        self.assertEqual(tunnel.client_error("2026/11/10 00:00:00 Error: Tunnel already installed and running\n"),
                         "Tunnel already installed and running")
        self.assertEqual(tunnel.client_error(""), "")

    def test_pe_version(self):
        blob = b"MZ" + bytes(40) + struct.pack("<IIII", 0xFEEF04BD, 0x10000, (3 << 16) | 1, 0) + bytes(16)
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(blob)
        try:
            self.assertEqual(tunnel.pe_version(f.name), (3, 1, 0))
        finally:
            os.unlink(f.name)


class AutotuneTest(unittest.TestCase):
    """Автоподбор на имитации ТСПУ: рукопожатие проходит, только если первым идёт QUIC (I1)."""

    def setUp(self):
        self.saved = (wg.probe, wg.scan, net.icmp_ping)
        wg.scan = lambda *a, **k: []
        net.icmp_ping = lambda *a, **k: None

        def dpi(keys, ep, obf=None, targets=(), count=4, hs_timeout=1.5):
            r = {"endpoint": ep, "handshake": None, "data": None, "colo": None, "targets": {}}
            if (obf or {}).get("I1", "").startswith("<b 0xc2"):
                r.update(handshake=30.0, data=21, colo="WAW", targets={t: None for t in targets})
            return r
        wg.probe = dpi

    def tearDown(self):
        wg.probe, wg.scan, net.icmp_ping = self.saved

    def make(self, cps):
        st = json.loads(json.dumps(settings.DEFAULTS))
        priv, pub = _keypair_b64()
        st.update(warp={"private_key": priv, "public_key": pub, "peer_public_key": pub, "v4": "172.16.0.2"},
                  ranges=["43.174.251.0/24"])
        logs = []
        eng = engine.Engine(lambda kind, **d: logs.append(d.get("text", "")) if kind == "log" else None,
                            settings=st, client={"exe": "x", "kind": "awg", "version": (3, 1, 0) if cps else (1, 0, 2),
                                                 "cps": cps, "tool": ""})
        eng.save = lambda: None
        return eng, logs

    def test_finds_quic_when_plain_is_blocked(self):
        eng, logs = self.make(cps=True)
        eng._autotune()
        self.assertEqual(eng.st["obf_id"], "quic")
        self.assertEqual(eng.st["colo"], "WAW")
        self.assertTrue(any(s.startswith("Работает:") for s in logs))

    def test_old_client_explains_update(self):
        eng, logs = self.make(cps=False)
        eng._autotune()
        self.assertEqual(eng.st["obf_id"], "light")
        self.assertTrue(any("2.0+" in s for s in logs))


class EffectiveObfuscationTest(unittest.TestCase):
    """Проба шлёт ровно ту маскировку, которую применит установленный клиент туннеля."""

    AWG3 = {"exe": "x", "kind": "awg", "version": (3, 1, 0), "cps": True, "tool": ""}
    AWG1 = dict(AWG3, version=(1, 0, 2), cps=False)
    WG = {"exe": "x", "kind": "wg", "version": (0, 5, 3), "cps": False, "tool": ""}

    def make(self, client):
        st = json.loads(json.dumps(settings.DEFAULTS))
        st.update(obf_id="quic", obf=dict(warp.PRESET_BY_ID["quic"]["obf"]))
        return engine.Engine(lambda *a, **k: None, settings=st, client=client)

    def test_cps_client_keeps_i1(self):
        self.assertIn("I1", self.make(self.AWG3).obf)

    def test_old_amneziawg_drops_i1(self):
        eng = self.make(self.AWG1)
        self.assertEqual(eng.obf, warp.PRESET_BY_ID["light"]["obf"])
        self.assertEqual(eng.preset_name(), "Лёгкая")
        _, presets = eng._variants()
        self.assertEqual(presets[0]["id"], "light")
        self.assertFalse(any(warp.needs_cps(p["obf"]) for p in presets))

    def test_wireguard_has_no_obfuscation(self):
        eng = self.make(self.WG)
        self.assertEqual(wg.obfuscation_packets(eng.obf), [])
        self.assertEqual([p["id"] for p in eng._variants()[1]], ["none"])


if __name__ == "__main__":
    unittest.main()
