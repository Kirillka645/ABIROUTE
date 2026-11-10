# -*- coding: utf-8 -*-
"""Точка входа: чёткость на HiDPI-экранах, один экземпляр программы, лог в файл."""
import ctypes
import logging
import os

from . import APP_NAME, DATA_DIR

LOG = logging.getLogger("abiroute")
LOG_PATH = os.path.join(DATA_DIR, "abiroute.log")


def _dpi_aware():
    """Иначе tkinter мылится на экранах с масштабом 125–150%."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 — старые Windows
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001
            pass


def _single_instance():
    """Второй экземпляр ломал бы службу туннеля: конфликт за один конфиг."""
    if os.name != "nt":
        return True
    try:
        ctypes.windll.kernel32.CreateMutexW(None, 0, "Global\\ABIRoute.SingleInstance")
        if ctypes.windll.kernel32.GetLastError() == 183:  # ERROR_ALREADY_EXISTS
            ctypes.windll.user32.MessageBoxW(0, f"{APP_NAME} уже запущена — посмотрите в трей "
                                                f"или свернутые окна.", APP_NAME, 0x30)
            return False
    except Exception:  # noqa: BLE001 — лучше запуститься дважды, чем не запуститься вовсе
        pass
    return True


def _setup_logging():
    """Журнал в файл — можно прислать вместо скриншотов, если что-то сломалось."""
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(LOG_PATH) and os.path.getsize(LOG_PATH) > 512 * 1024:
            os.remove(LOG_PATH)
        h = logging.FileHandler(LOG_PATH, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
        LOG.addHandler(h)
        LOG.setLevel(logging.INFO)
    except OSError:
        pass


def main():
    _dpi_aware()
    _setup_logging()
    if not _single_instance():
        return
    try:
        from .gui import App
    except ImportError as e:
        msg = f"Не найден tkinter ({e}).\nУстановите Python с компонентом «tcl/tk and IDLE»."
        try:
            ctypes.windll.user32.MessageBoxW(0, msg, APP_NAME, 0x10)
        except Exception:  # noqa: BLE001
            print(msg)
        return
    App().run()


if __name__ == "__main__":
    main()
