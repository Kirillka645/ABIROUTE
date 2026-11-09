# -*- coding: utf-8 -*-
"""Общие мелочи: адреса, диапазоны, сводка замеров."""
import ipaddress
import statistics


def split_endpoint(ep):
    host, _, port = str(ep).strip().rpartition(":")
    return host.strip("[]"), int(port)


def is_public_v4(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a.is_global


def in_nets(ip, nets):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in nets:
        try:
            if a in ipaddress.ip_network(n, strict=False):
                return True
        except ValueError:
            continue
    return False


def normalize_ranges(ranges, exclude_ip=None):
    """Схлопывает IPv4-диапазоны; exclude_ip (адрес сервера WARP) вырезается из них."""
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


def summarize(samples, sent, how):
    """Сводка серии замеров (мс, в порядке отправки) -> dict или None, если ответов нет.

    jitter — средняя разница между соседними замерами (так его считают игры и RFC 3550).
    """
    if not samples or not sent:
        return None
    jit = statistics.mean(abs(a - b) for a, b in zip(samples, samples[1:])) if len(samples) > 1 else 0.0
    return {"ms": round(statistics.median(samples)), "min": round(min(samples)), "jitter": round(jit),
            "loss": round(100 * (sent - len(samples)) / sent), "how": how}
