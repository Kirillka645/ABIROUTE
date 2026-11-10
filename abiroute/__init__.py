# -*- coding: utf-8 -*-
"""ABI Route — WARP-туннель только для Arena Breakout Infinite.

Пакет: ядро (warp, tunnel, netping, learn, settings, util) отделено от GUI,
чтобы его можно было тестировать без интерфейса.
"""
import os

__version__ = "2.2"

APP_NAME = "ABI Route"
TUNNEL = "ABIRoute"
REPO_URL = "https://github.com/Kirillka645/ABIROUTE"

DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "ABIRoute")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
CONF_PATH = os.path.join(DATA_DIR, TUNNEL + ".conf")
