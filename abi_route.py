# -*- coding: utf-8 -*-
"""ABI Route — WARP только для Arena Breakout Infinite. Точка входа для запуска и сборки PyInstaller.

    python abi_route.py                      — обычный запуск
    python abi_route.py --demo               — интерфейс на образце данных, без сети и туннеля
    python abi_route.py --screenshot папка   — снимки всех страниц (нужен Pillow)
    ABIRoute.exe --selftest файл             — самопроверка собранного exe (результат в файле)
"""
import sys

from abiroute.app import main

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
