# -*- coding: utf-8 -*-
"""Мелкие общие помощники: subprocess, base64, формат, права администратора."""
import ctypes
import os
import subprocess
import sys

NOWIN = 0x08000000 if os.name == "nt" else 0


def b64(b):
    """bytes -> base64-строка (как в конфигах WireGuard)."""
    import base64
    return base64.b64encode(b).decode()


def split_endpoint(ep):
    """'162.159.192.1:2408' -> ('162.159.192.1', 2408). Некорректное — ValueError."""
    host, _, port = ep.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError(f"Некорректный адрес: {ep!r}")
    return host, int(port)


def _run(cmd, timeout=30):
    """Запуск внешней команды со скрытым окном; не падает на таймауте (его ловит вызывающий)."""
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                          creationflags=NOWIN, errors="ignore")


def is_admin():
    """Запущено ли с правами администратора (нужны для установки службы туннеля)."""
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001 — любая ошибка = прав нет
        return False


def resource(name):
    """Путь к ресурсу рядом со скриптом или в распакованном PyInstaller-бандле."""
    return os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__))), name)


def fmt_bytes(n):
    """Человекочитаемый размер: 512 Б / 12.3 КБ / 4.5 МБ / 1.20 ГБ."""
    n = float(n)
    for u in ("Б", "КБ", "МБ"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.2f} ГБ"
