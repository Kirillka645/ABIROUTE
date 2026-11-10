# -*- coding: utf-8 -*-
"""Профиль Cloudflare WARP: регистрация, импорт готового конфига, маскировка и конфиг туннеля."""
import base64
import binascii
import ipaddress
import json
import random
import socket
import urllib.error
import urllib.request
import zlib
from datetime import datetime, timezone

from .common import normalize_ranges, split_endpoint
from .wg import b64, cps_packet, gen_keypair, public_from_private

WARP_API = "https://api.cloudflareclient.com/v0a2158"
WARP_HEADERS = {
    "User-Agent": "okhttp/3.12.1",
    "CF-Client-Version": "a-6.10-2158",
    "Content-Type": "application/json; charset=UTF-8",
}


class WarpError(Exception):
    pass


def register(timeout=20):
    """Регистрирует бесплатное устройство WARP. -> профиль; WarpError с понятной причиной."""
    priv, pub = gen_keypair()
    body = {"key": b64(pub), "install_id": "", "fcm_token": "",
            "tos": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "type": "Android", "model": "PC", "locale": "en_US", "warp_enabled": True}
    req = urllib.request.Request(WARP_API + "/reg", data=json.dumps(body).encode(),
                                 headers=WARP_HEADERS, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            j = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise WarpError("Cloudflare временно ограничил регистрацию с вашего адреса. "
                            "Подождите минут десять или импортируйте готовый конфиг.") from e
        raise WarpError(f"Cloudflare ответил ошибкой {e.code}. Попробуйте позже или импортируйте конфиг.") from e
    except (urllib.error.URLError, OSError, ValueError) as e:
        raise WarpError("Сервер регистрации WARP недоступен — в России его часто блокирует провайдер. "
                        "Сгенерируйте конфиг WARP в другом месте (например, генератором на Replit) "
                        "и нажмите «Импорт конфига».") from e
    d = j.get("result", j)
    try:
        cfg = d["config"]
        addr = cfg["interface"]["addresses"]
        return {"private_key": b64(priv), "public_key": b64(pub),
                "peer_public_key": cfg["peers"][0]["public_key"],
                "v4": addr["v4"], "v6": addr.get("v6", ""), "id": d.get("id"), "token": d.get("token"),
                "created": datetime.now().strftime("%d.%m.%Y %H:%M"), "source": "api"}
    except (KeyError, IndexError, TypeError) as e:
        raise WarpError("Cloudflare прислал неожиданный ответ. Попробуйте ещё раз.") from e

# ----------------------------------------------------------------- импорт конфига


def _from_vpn_key(text):
    """Строка vpn://… из AmneziaVPN -> текст конфига (или None)."""
    raw = text.strip()[6:]
    raw += "=" * (-len(raw) % 4)
    try:
        data = base64.urlsafe_b64decode(raw)
    except (binascii.Error, ValueError):
        return None
    for blob in (data, data[4:]):
        try:
            j = json.loads(blob if blob[:1] == b"{" else zlib.decompress(blob))
            break
        except (ValueError, zlib.error):
            continue
    else:
        return None
    for c in j.get("containers", []):
        for proto in c.values():
            if isinstance(proto, dict) and proto.get("last_config"):
                try:
                    return json.loads(proto["last_config"]).get("config")
                except ValueError:
                    return proto["last_config"]
    return None


def parse_conf(text):
    """Импорт готового конфига WARP (AmneziaWG/WireGuard или vpn://).

    -> (профиль, {"endpoint": "ip:port"|None, "obf": {...}|None, "mtu": int|None}); ValueError.
    """
    if text.strip().startswith("vpn://"):
        text = _from_vpn_key(text) or ""
    sect, iface, peer = None, {}, {}
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()  # как в AmneziaWG: после # — комментарий
        if not line or line[0] == ";":
            continue
        if line.startswith("["):
            sect = line.strip("[]").strip().lower()
            continue
        if "=" in line and sect in ("interface", "peer"):
            k, v = line.split("=", 1)
            (iface if sect == "interface" else peer).setdefault(k.strip().lower(), v.strip())
    try:
        priv = base64.b64decode(iface["privatekey"], validate=True)
        peer_pub = base64.b64decode(peer["publickey"], validate=True)
        if len(priv) != 32 or len(peer_pub) != 32:
            raise ValueError
    except (KeyError, ValueError, binascii.Error):
        raise ValueError("В конфиге нет корректных PrivateKey и PublicKey.") from None
    v4 = v6 = ""
    for a in iface.get("address", "").split(","):
        try:
            ip = ipaddress.ip_interface(a.strip()).ip
        except ValueError:
            continue
        if ip.version == 4 and not v4:
            v4 = str(ip)
        elif ip.version == 6 and not v6:
            v6 = str(ip)
    if not v4:
        raise ValueError("В конфиге нет IPv4-адреса (Address).")
    profile = {"private_key": b64(priv), "public_key": b64(public_from_private(priv)),
               "peer_public_key": b64(peer_pub), "v4": v4, "v6": v6, "id": None, "token": None,
               "created": datetime.now().strftime("%d.%m.%Y %H:%M"), "source": "import"}
    endpoint = None
    if peer.get("endpoint"):
        try:
            host, port = split_endpoint(peer["endpoint"])
            endpoint = f"{socket.gethostbyname(host)}:{port}"
        except (OSError, ValueError):
            endpoint = None
    obf = {}
    for k in ("jc", "jmin", "jmax"):
        if iface.get(k, "").isdigit():
            obf[k.capitalize() if k == "jc" else "J" + k[1:]] = int(iface[k])
    for i in range(1, 6):
        spec = iface.get(f"i{i}")
        if spec:
            try:
                cps_packet(spec)
            except ValueError:
                continue
            obf[f"I{i}"] = spec
    mtu = int(iface["mtu"]) if iface.get("mtu", "").isdigit() else None
    return profile, {"endpoint": endpoint, "obf": obf or None, "mtu": mtu}

# ----------------------------------------------------------------- маскировка


def _b(data):
    return "<b 0x" + data.hex() + ">"


# Снимок настоящего QUIC Initial — I1 из генератора ImMALWARE/bash-warp-generator (MIT, см. THIRD_PARTY_NOTICES.md).
QUIC_I1 = "<b 0x" + (
    "c2000000011419fa4bb3599f336777de79f81ca9a8d80d91eeec000044c635cef024a885dcb66d1420a91a8c427e87d6"
    "cf8e08b563932f449412cddf77d3e2594ea1c7a183c238a89e9adb7ffa57c133e55c59bec101634db90afb83f75b19fe"
    "703179e26a31902324c73f82d9354e1ed8da39af610afcb27e6590a44341a0828e5a3d2f0e0f7b0945d7bf3402feea0e"
    "e6332e19bdf48ffc387a97227aa97b205a485d282cd66d1c384bafd63dc42f822c4df2109db5b5646c458236ddcc01ae"
    "1c493482128bc0830c9e1233f0027a0d262f92b49d9d8abd9a9e0341f6e1214761043c021d7aa8c464b9d865f5fbe234"
    "e49626e00712031703a3e23ef82975f014ee1e1dc428521dc23ce7c6c13663b19906240b3efe403cf30559d798871557"
    "e4e60e86c29ea4504ed4d9bb8b549d0e8acd6c334c39bb8fb42ede68fb2aadf00cfc8bcc12df03602bbd4fe701d64a39"
    "f7ced112951a83b1dbbe6cd696dd3f15985c1b9fef72fa8d0319708b633cc4681910843ce753fac596ed9945d8b839ae"
    "ff8d3bf0449197bd0bb22ab8efd5d63eb4a95db8d3ffc796ed5bcf2f4a136a8a36c7a0c65270d511aebac733e61d4140"
    "50088a1c3d868fb52bc7e57d3d9fd132d78b740a6ecdc6c24936e92c28672dbe00928d89b891865f885aeb4c4996d50c"
    "2bbbb7a99ab5de02ac89b3308e57bcecf13f2da0333d1420e18b66b4c23d625d836b538fc0c221d6bd7f566a31fa292b"
    "85be96041d8e0bfe655d5dc1afed23eb8f2b3446561bbee7644325cc98d31cea38b865bdcc507e48c6ebdc7553be7bd6"
    "ab963d5a14615c4b81da7081c127c791224853e2d19bafdc0d9f3f3a6de898d14abb0e2bc849917e0a599ed4a541268a"
    "d0e60ea4d147dc33d17fa82f22aa505ccb53803a31d10a7ca2fea0b290a52ee92c7bf4aab7cea4e3c07b1989364eed87"
    "a3c6ba65188cd349d37ce4eefde9ec43bab4b4dc79e03469c2ad6b902e28e0bbbbf696781ad4edf424ffb35ce0236d37"
    "3629008f142d04b5e08a124237e03e3149f4cdde92d7fae581a1ac332e26b2c9c1a6bdec5b3a9c7a2a870f7a0c25fc6c"
    "e245e029b686e346c6d862ad8df6d9b62474fbc31dbb914711f78074d4441f4e6e9edca3c52315a5c0653856e23f6815"
    "58d669f4a4e6915bcf42b56ce36cb7dd3983b0b1d6fdf0f8efddb68e7ca0ae9dd4570fe6978fbb524109f6ec957ca61f"
    "1767ef74eb803b0f16abd0087cf2d01bc1db1c01d97ac81b3196c934586963fe7cf2d310e0739621e8bd00dc23fded18"
    "576d8c8f285d7bb5f43b547af3c76235de8b6f757f817683b2151600b11721219212bf27558edd439e73fce951f61d58"
    "2320e5f4d6c315c71129b719277fc144bbe8ded25ab6d29b6e189c9bd9b16538faf60cc2aab3c3bb81fc2213657f2dd0"
    "ceb9b3b871e1423d8d3e8cc008721ef03b28e0ee7bb66b8f2a2ac01ef88df1f21ed49bf1ce435df31ac3448593617256"
    "7488812429c269b49ee9e3d99652b51a7a614b7c460bf0d2d64d8349ded7345bedab1ea0a766a8470b1242f38d09f785"
    "5a32db39516c2bd4bcc538c52fa3a90c8714d4b006a15d9c7a7d04919a1cab48da7cce0d5de1f9e5f8936cffe4691329"
    "91c6eb84c5191d1bcf69f70c58d9a7b66846440a9f0eef25ee6ab62715b50ca7bef0bc3013d4b62e1639b5028bdf7574"
    "54356e9326a4c76dabfb497d451a3a1d2dbd46ec283d255799f72dfe878ae25892e25a2542d3ca9018394d8ca35b53cc"
    "d94947a8") + ">"

# Пример звонка из RFC 3261 (SIP по UDP): такие пакеты провайдеры обычно не трогают.
_SIP_HEAD = ("Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
             "{mf}To: Bob <sip:bob@biloxi.com>\r\nFrom: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
             "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\nCSeq: 314159 INVITE\r\n")
SIP_I1 = _b(("INVITE sip:bob@biloxi.com SIP/2.0\r\n" + _SIP_HEAD.format(mf="Max-Forwards: 70\r\n")
             + "Contact: <sip:alice@pc33.atlanta.com>\r\nContent-Type: application/sdp\r\n"
             "Content-Length: 0\r\n\r\n").encode())
SIP_I2 = _b(("SIP/2.0 100 Trying\r\n" + _SIP_HEAD.format(mf="") + "Content-Length: 0\r\n\r\n").encode())
# DNS-запрос A yandex.ru со случайным идентификатором.
DNS_I1 = "<r 2>" + _b(bytes.fromhex("01000001000000000000") + b"\x06yandex\x02ru\x00" + bytes.fromhex("00010001"))

_LIGHT = {"Jc": 4, "Jmin": 40, "Jmax": 70}
_STRONG = {"Jc": 120, "Jmin": 23, "Jmax": 911}
OBF_PRESETS = [
    {"id": "light", "name": "Лёгкая", "obf": dict(_LIGHT),
     "hint": "4 мусорных пакета перед рукопожатием. Хватает у большинства провайдеров."},
    {"id": "quic", "name": "QUIC", "obf": dict(_LIGHT, I1=QUIC_I1),
     "hint": "Первым пакетом идёт снимок QUIC — для провайдера соединение похоже на HTTP/3."},
    {"id": "sip", "name": "SIP", "obf": dict(_LIGHT, I1=SIP_I1, I2=SIP_I2),
     "hint": "Начало соединения похоже на интернет-звонок (SIP)."},
    {"id": "dns", "name": "DNS", "obf": dict(_LIGHT, I1=DNS_I1),
     "hint": "Начало соединения похоже на DNS-запрос."},
    {"id": "quic_strong", "name": "QUIC + сильная", "obf": dict(_STRONG, I1=QUIC_I1),
     "hint": "QUIC плюс 120 мусорных пакетов — как в популярных генераторах WARP для России."},
    {"id": "strong", "name": "Сильная", "obf": dict(_STRONG),
     "hint": "120 мусорных пакетов до 911 байт перед каждым рукопожатием."},
    {"id": "none", "name": "Без маскировки", "obf": {"Jc": 0, "Jmin": 0, "Jmax": 0},
     "hint": "Обычный WireGuard. Подходит, если провайдер ничего не блокирует."},
]
PRESET_BY_ID = {p["id"]: p for p in OBF_PRESETS}


def needs_cps(obf):
    return any((obf or {}).get(f"I{i}") for i in range(1, 6))


def presets_for(client_cps):
    """Варианты маскировки, которые поймёт установленный клиент."""
    return [p for p in OBF_PRESETS if client_cps or not needs_cps(p["obf"])]

# ----------------------------------------------------------------- серверы WARP


WARP_NETS = ["162.159.192", "162.159.193", "162.159.195", "188.114.96", "188.114.97", "188.114.98",
             "188.114.99"]
WARP_PORTS = [2408, 500, 1701, 4500, 854, 859, 864, 878, 880, 890, 891, 894, 903, 908, 928, 934, 939, 942,
              943, 945, 946, 955, 968, 987, 988, 1002, 1010, 1014, 1018, 1070, 1074, 1180, 1387, 1843, 2371,
              2506, 3138, 3476, 3581, 3854, 4177, 4198, 4233, 5279, 5956, 7103, 7152, 7156, 7281, 7559,
              8319, 8742, 8854, 8886]


def candidate_endpoints(rnd=random):
    """Около 400 вариантов: во всех подсетях WARP по 6 адресов, у каждого 10 портов."""
    out = []
    for net in WARP_NETS:
        for host in [1] + rnd.sample(range(2, 255), 5):
            ports = WARP_PORTS[:4] + rnd.sample(WARP_PORTS[4:], 6)
            out += [f"{net}.{host}:{p}" for p in ports]
    rnd.shuffle(out)
    return out


def spread(endpoints, n):
    """До n серверов из списка, сначала по одному на подсеть /24 (если провайдер режет подсеть)."""
    out, nets = [], set()
    for ep in endpoints:
        net = split_endpoint(ep)[0].rsplit(".", 1)[0]
        if net not in nets:
            nets.add(net)
            out.append(ep)
    out += [ep for ep in endpoints if ep not in out]
    return out[:n]

# ----------------------------------------------------------------- конфиг туннеля


def build_conf(profile, endpoint, ranges, obf, kind, cps_ok, mtu=1280):
    """Split-tunnel конфиг: в туннель идут только диапазоны игры."""
    host, port = split_endpoint(endpoint)
    allowed = normalize_ranges(ranges, exclude_ip=host)
    if not allowed:
        raise ValueError("Нет IP-диапазонов игры")
    lines = ["[Interface]", f"PrivateKey = {profile['private_key']}", f"Address = {profile['v4']}/32",
             f"MTU = {int(mtu)}"]
    if kind == "awg":
        o = obf or {}
        lines += [f"Jc = {int(o.get('Jc', 0))}", f"Jmin = {int(o.get('Jmin', 0))}",
                  f"Jmax = {int(o.get('Jmax', 0))}", "S1 = 0", "S2 = 0", "H1 = 1", "H2 = 2", "H3 = 3", "H4 = 4"]
        if cps_ok:
            lines += [f"I{i} = {o[f'I{i}']}" for i in range(1, 6) if o.get(f"I{i}")]
    lines += ["", "[Peer]", f"PublicKey = {profile['peer_public_key']}", f"AllowedIPs = {', '.join(allowed)}",
              f"Endpoint = {host}:{port}", "PersistentKeepalive = 25", ""]
    return "\n".join(lines)
