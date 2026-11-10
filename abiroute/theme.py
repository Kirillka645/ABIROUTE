# -*- coding: utf-8 -*-
"""Визуальный язык ABI Route: палитра «ночная карта», шрифты, масштаб под DPI, рамка окна Windows."""
import ctypes
import os
import tkinter as tk
from tkinter import font as tkfont

INK = "#0E1316"         # фон окна
BOARD = "#141B1F"       # планшет: панели и карта маршрута
RAISE = "#1C262C"       # кнопки, поля, наведение
LINE = "#27333A"        # тонкие линии и рамки
CONTOUR = "#1B272E"     # горизонтали рельефа на карте
TEXT = "#E8E3D6"        # основной текст — цвет бумаги карты
MUTED = "#95A2A6"       # вторичный текст
FAINT = "#62717A"       # подписи и неактивное
SIGNAL = "#F2A93B"      # маршрут через WARP и главная кнопка — больше нигде
SIGNAL_HI = "#F8C066"
SIGNAL_INK = "#1B1307"  # текст на янтарной кнопке
SIGNAL_DIM = "#5E4520"  # маршрут через WARP, пока туннель выключен
DIRECT = "#7FA0AB"      # прямой маршрут
GOOD = "#7DCB94"
BAD = "#F07164"
CAUTION = "#D9B36F"

SCALE = 1.0
REDUCED_MOTION = False
F = {}  # имя -> tkfont.Font


def px(v):
    return int(round(v * SCALE))


def init_dpi():
    """До создания окна: чёткий текст на мониторах с масштабом 125–200%."""
    if os.name != "nt":
        return
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:  # noqa: BLE001 — Windows 7/8
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:  # noqa: BLE001
            pass


def setup(root):
    global SCALE, REDUCED_MOTION
    SCALE = max(1.0, root.winfo_fpixels("1i") / 96.0)
    if os.name != "nt":  # для предпросмотра вне Windows — как Windows при 100%
        root.tk.call("tk", "scaling", 96 / 72 * SCALE)
    REDUCED_MOTION = not _animations_enabled()
    fams = set(tkfont.families(root))

    def pick(*names):
        return next((n for n in names if n in fams), None)

    # Bahnschrift — DIN из Windows 10/11 (есть кириллица). Roboto/Barlow — только для предпросмотра вне Windows.
    body = pick("Segoe UI", "Inter", "Noto Sans", "DejaVu Sans") or "TkDefaultFont"
    din_bold = pick("Bahnschrift SemiBold", "Roboto Medium", "Barlow SemiBold")
    din = pick("Bahnschrift", "Roboto", "Barlow") or body
    din_light = pick("Bahnschrift Light", "Bahnschrift SemiLight", "Roboto Light", "Barlow Light") or din

    def disp(size, weight="normal"):
        if weight == "bold" and din_bold:
            return tkfont.Font(root, family=din_bold, size=size)
        return tkfont.Font(root, family=din, size=size, weight=weight)

    F.update(
        brand=disp(14, "bold"),
        hero=disp(23, "bold"),
        title=disp(17, "bold"),
        section=disp(12, "bold"),
        num=disp(13, "bold"),
        num_lg=tkfont.Font(root, family=din_light, size=20),
        map_title=disp(11, "bold"),
        body=tkfont.Font(root, family=body, size=10),
        body_b=tkfont.Font(root, family=body, size=10, weight="bold"),
        small=tkfont.Font(root, family=body, size=9),
        nav=tkfont.Font(root, family=body, size=10),
        button=tkfont.Font(root, family=body, size=10, weight="bold"),
        button_lg=disp(13, "bold"),
        mono=tkfont.Font(root, family=pick("Cascadia Mono", "Consolas", "DejaVu Sans Mono") or body, size=9),
    )
    root.option_add("*Font", F["body"])


def _animations_enabled():
    if os.name != "nt":
        return True
    try:
        val = ctypes.c_int(1)
        ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(val), 0)  # SPI_GETCLIENTAREAANIMATION
        return bool(val.value)
    except Exception:  # noqa: BLE001
        return True


def window_handle(win):
    """HWND внешней рамки окна Tk (после того как окно показано)."""
    try:
        return int(win.wm_frame(), 16)
    except (tk.TclError, ValueError):
        return ctypes.windll.user32.GetParent(win.winfo_id())


def dark_frame(win):
    """Тёмный заголовок окна (Windows 10 20H1+) и рамка в тон фона (Windows 11). Звать после показа окна."""
    if os.name != "nt":
        return
    try:
        hwnd = window_handle(win)
        set_attr = ctypes.windll.dwmapi.DwmSetWindowAttribute
        on = ctypes.c_int(1)
        if set_attr(hwnd, 20, ctypes.byref(on), 4) != 0:  # DWMWA_USE_IMMERSIVE_DARK_MODE
            set_attr(hwnd, 19, ctypes.byref(on), 4)       # то же до Windows 10 20H1
        for attr, color in ((35, INK), (36, TEXT), (34, LINE)):  # caption, text, border — только Windows 11
            c = ctypes.c_int(int(color[5:7] + color[3:5] + color[1:3], 16))
            set_attr(hwnd, attr, ctypes.byref(c), 4)
        # SWP_FRAMECHANGED: Windows 10 иначе перерисует заголовок только при следующей активации окна
        ctypes.windll.user32.SetWindowPos(hwnd, 0, 0, 0, 0, 0, 0x0020 | 0x0001 | 0x0002 | 0x0004 | 0x0010)
    except Exception:  # noqa: BLE001
        pass


def show_dark(win):
    """Показывает окно сразу с тёмной рамкой: пока рамка светлая, окно прозрачно."""
    transparent = os.name == "nt"
    if transparent:
        win.attributes("-alpha", 0.0)
    win.deiconify()
    win.update_idletasks()
    dark_frame(win)
    if transparent:
        win.attributes("-alpha", 1.0)


def mix(c1, c2, t):
    """Цвет между c1 и c2 (t=0 — c1, t=1 — c2)."""
    a = [int(c1[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(c2[i:i + 2], 16) for i in (1, 3, 5)]
    return "#" + "".join(f"{round(x + (y - x) * t):02x}" for x, y in zip(a, b))


def text_widget(parent, height, mono=False, **kw):
    t = tk.Text(parent, height=height, bg=RAISE, fg=TEXT, insertbackground=TEXT, relief="flat", bd=0,
                padx=px(10), pady=px(8), wrap="word", font=F["mono" if mono else "body"], highlightthickness=1,
                highlightbackground=LINE, highlightcolor=FAINT, selectbackground=LINE, selectforeground=TEXT,
                **kw)
    return t


def entry_widget(parent, var, width=None):
    e = tk.Entry(parent, textvariable=var, bg=RAISE, fg=TEXT, insertbackground=TEXT, relief="flat",
                 highlightthickness=1, highlightbackground=LINE, highlightcolor=FAINT, font=F["body"],
                 selectbackground=LINE, selectforeground=TEXT, disabledbackground=BOARD)
    if width:
        e.configure(width=width)
    return e
