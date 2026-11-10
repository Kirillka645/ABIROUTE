# -*- coding: utf-8 -*-
"""Окно ABI Route: боковая навигация и пять страниц поверх движка (engine.py)."""
import copy
import os
import queue
import statistics
import subprocess
import sys
import time
import tkinter as tk
import webbrowser
from tkinter import filedialog, messagebox, ttk

from . import APP_NAME, VERSION, theme as T, tunnel, warp, wg
from .engine import Engine, colo_name, demo_seed
from .settings import DEFAULTS, GAME_PRESETS
from .theme import px
from .widgets import (Button, Check, Progress, RadioList, RouteMap, ScrollPage, StatusGlyph, Table,
                      style_scrollbar)

AWG_URL = "https://github.com/amnezia-vpn/amneziawg-windows-client/releases"

STATES = {  # заголовок, пояснение, кнопка, вид кнопки
    "off": ("Туннель выключен",
            "Игра идёт напрямую. Запустите туннель — через WARP пойдут только серверы игры, остальное "
            "останется как есть.", "Запустить", "primary"),
    "wait": ("Ждём игру",
             "Запустите Arena Breakout Infinite — туннель включится сам, когда игра подключится к своим "
             "серверам.", "Отменить", "secondary"),
    "starting": ("Запускаю туннель…", "Поднимаю службу AmneziaWG и проверяю, что серверы игры отвечают.",
                 "Подождите", "secondary"),
    "on": ("Туннель работает",
           "Серверы игры идут через WARP, остальной трафик — напрямую. Окно можно свернуть: туннель "
           "работает как служба Windows.", "Остановить", "secondary"),
}
NAV = [("route", "Маршрут"), ("ping", "Пинг"), ("warp", "WARP"), ("servers", "Серверы игры"),
       ("log", "Журнал")]
LEVEL_COLOR = {"ok": T.GOOD, "warn": T.CAUTION, "bad": T.BAD, "info": T.TEXT}


def resource(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, name)


def fmt_bytes(n):
    n = float(n)
    for u in ("Б", "КБ", "МБ"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "Б" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.2f} ГБ"


def signed(v):
    return f"−{-v}" if v < 0 else f"+{v}"


def verdict(results):
    """Одна фраза-итог по таблице сравнения -> (текст, цвет)."""
    pairs = [(rr["direct"]["ms"], rr["warp"]["ms"]) for rr in results.values()
             if rr.get("direct") and rr.get("warp")]
    if pairs:
        diff = round(statistics.median([w - d for d, w in pairs]))
        if diff < -2:
            return f"Через WARP быстрее на {-diff} мс — оставляйте туннель включённым.", T.GOOD
        if diff > 2:
            return (f"Через WARP медленнее на {diff} мс. Если игра работает и напрямую, туннель можно не "
                    "включать; или нажмите «Найти сервер» на вкладке WARP."), T.CAUTION
        return "Разницы почти нет: WARP не добавляет задержки.", T.GOOD
    tested = [rr for rr in results.values() if rr.get("warp_tested")]
    if tested:
        if any(rr.get("direct") and rr["direct"]["how"] == "ICMP" for rr in tested):
            return ("Через WARP серверы игры не ответили. Откройте «Журнал» → «Проверить всё»: там видно, "
                    "на каком шаге обрывается путь, а «Автоподбор» подберёт рабочую маскировку."), T.BAD
        return ("Серверы игры не отвечают на ICMP, поэтому пинг через WARP не сравнить. Игре это не мешает."), \
            T.MUTED
    return "", T.MUTED


class NavItem(tk.Frame):
    def __init__(self, parent, text, command):
        super().__init__(parent, bg=T.INK, cursor="hand2")
        self.command, self.active = command, False
        self.bar = tk.Frame(self, bg=T.INK, width=px(3))
        self.bar.pack(side="left", fill="y")
        self.lbl = tk.Label(self, text=text, bg=T.INK, fg=T.MUTED, font=T.F["nav"], anchor="w",
                            padx=px(16), pady=px(9))
        self.lbl.pack(side="left", fill="x", expand=True)
        for w in (self, self.lbl):
            w.bind("<Button-1>", lambda e: command())
            w.bind("<Enter>", lambda e: self._paint(True))
            w.bind("<Leave>", lambda e: self._paint(False))
        self._paint(False)

    def _paint(self, hover):
        bg = T.RAISE if self.active else (T.mix(T.INK, T.RAISE, .55) if hover else T.INK)
        self.configure(bg=bg)
        self.lbl.configure(bg=bg, fg=T.TEXT if self.active or hover else T.MUTED)
        self.bar.configure(bg=T.TEXT if self.active else bg)

    def set_active(self, on):
        self.active = on
        self._paint(False)


class App:
    def __init__(self, demo=False):
        T.init_dpi()
        self.root = root = tk.Tk()
        root.withdraw()
        T.setup(root)
        style_scrollbar(root)
        root.title(f"{APP_NAME} — Arena Breakout Infinite")
        root.configure(bg=T.INK)
        root.geometry(f"{px(1100)}x{px(760)}")
        root.minsize(px(980), px(680))
        try:
            root.iconbitmap(default=resource("icon.ico"))
        except tk.TclError:
            pass
        self.q = queue.Queue()
        self.demo = demo
        self.state, self.busy, self.game_on, self.page = "off", None, False, None
        self.engine = self._make_engine()
        self._build()
        root.protocol("WM_DELETE_WINDOW", self.on_close)
        for i, (key, _) in enumerate(NAV, 1):
            root.bind(f"<Control-Key-{i}>", lambda e, k=key: self.show(k))
        root.update_idletasks()
        T.dark_frame(root)
        root.deiconify()
        root.after(50, self._pump)
        if demo:
            self._demo_start()
        else:
            self.engine.startup()
        self.refresh()

    # ---------------------------------------------------------------- движок и события
    def _make_engine(self):
        if not self.demo:
            return Engine(self._emit)
        priv, pub = wg.gen_keypair()
        st = copy.deepcopy(DEFAULTS)
        st.update(warp={"private_key": wg.b64(priv), "public_key": wg.b64(pub),
                        "peer_public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=", "v4": "172.16.0.2",
                        "created": "09.11.2026 23:27", "source": "api"},
                  endpoint="162.159.195.4:878", obf_id="quic", obf=dict(warp.PRESET_BY_ID["quic"]["obf"]),
                  colo="WAW", ranges=list(GAME_PRESETS["Найденные серверы ABI (/24)"]),
                  seen_ips=["43.174.251.100", "43.174.218.66", "101.33.48.30"],
                  endpoint_list=[["162.159.195.4:878", 19, "WAW"], ["188.114.97.21:2408", 21, "WAW"],
                                 ["162.159.193.7:4500", 23, "ARN"], ["188.114.99.140:1701", 24, "WAW"],
                                 ["162.159.192.1:500", 26, "FRA"], ["188.114.96.33:7559", None, None],
                                 ["162.159.193.1:2408", None, None]])
        client = {"exe": "", "kind": "awg", "version": (3, 1, 0), "cps": True, "tool": ""}
        eng = Engine(self._emit, settings=st, client=client)
        eng.save = lambda: None
        demo_seed(eng)
        return eng

    def _demo_start(self):
        e = self.engine
        e.running = True
        e.route = dict(e.route, live=46)
        for t, lvl, msg in (
                ("23:41:02", "info", f"ABI Route {VERSION} запущен."),
                ("23:41:02", "info", "Клиент туннеля: AmneziaWG 3.1.0 — маскировка I1 (QUIC, SIP, DNS) доступна."),
                ("23:41:15", "ok", "Ответили 361 из 420. Выбран 162.159.195.4:878: до узла 19 мс, узел Варшава."),
                ("23:41:40", "ok", "Через WARP (узел Варшава) быстрее на 9 мс (медиана по 5 серверам)."),
                ("23:42:03", "ok", "Туннель включён: 14 диапазонов игры идут через WARP 162.159.195.4:878."),
                ("23:42:06", "ok", "Проверено: сервер игры отвечает через туннель за 46 мс.")):
            self._log(msg, lvl, t)
        self._on("state", {"state": "on"})
        self._on("stats", {"stats": {"handshake": time.time() - 14, "rx": 18_400_000, "tx": 3_100_000}})
        self._on("compare", {"results": e.results})
        self._on("route", {"route": e.route})
        self._on("game", {"running": True})
        self._on("diag", {"items": [
            {"status": "ok", "title": "Права администратора", "detail": ""},
            {"status": "ok", "title": "AmneziaWG 3.1.0", "detail": "Маскировка QUIC, SIP и DNS доступна."},
            {"status": "ok", "title": "Профиль WARP", "detail": "Адрес 172.16.0.2, создан 09.11.2026 23:27"},
            {"status": "ok", "title": "Рукопожатие с WARP",
             "detail": "162.159.195.4:878, маскировка «QUIC», 41 мс"},
            {"status": "ok", "title": "Данные через WARP", "detail": "Узел Варшава отвечает за 19 мс"},
            {"status": "ok", "title": "Серверы игры через WARP", "detail": "Отвечают 4 из 4, лучший 46 мс"},
            {"status": "ok", "title": "Системный туннель работает",
             "detail": "Рукопожатие 14 с назад, сервер игры отвечает за 46 мс"}]})

    def _emit(self, kind, **data):
        self.q.put((kind, data))

    def _pump(self):
        try:
            for _ in range(200):
                kind, data = self.q.get_nowait()
                self._on(kind, data)
        except queue.Empty:
            pass
        self.root.after(50, self._pump)

    def _on(self, kind, d):
        if kind == "log":
            self._log(d["text"], d["level"], d["t"])
        elif kind == "state":
            self.state = d["state"]
            self._show_state()
        elif kind == "busy":
            self.busy = d["name"]
            self.busy_lbl.configure(text=f"{self.busy}…" if self.busy else "")
            self.progress.set(bool(self.busy))
        elif kind == "progress":
            if self.busy:
                self.progress.set(True, d["done"], d["total"])
                label = d.get("label")
                if label and d["total"]:
                    self.busy_lbl.configure(text=f"{self.busy}: {label.lower()} {d['done']} из {d['total']}")
        elif kind == "refresh":
            self.refresh()
        elif kind == "route":
            self.map.show(route=d["route"])
            self._show_verdict()
        elif kind == "compare":
            self._fill_ping(d["results"])
        elif kind == "diag":
            self._fill_diag(d["items"])
        elif kind == "stats":
            self._show_stats(d["stats"])
        elif kind == "ranges":
            self._merge_ranges(d["ranges"])
        elif kind == "game":
            self.game_on = d["running"]
            self._show_side_status()

    # ---------------------------------------------------------------- каркас
    def _build(self):
        root = self.root
        side = tk.Frame(root, bg=T.INK, width=px(220))
        side.pack(side="left", fill="y")
        side.pack_propagate(False)
        tk.Frame(root, bg=T.LINE, width=1).pack(side="left", fill="y")
        content = tk.Frame(root, bg=T.INK)
        content.pack(side="left", fill="both", expand=True)

        brand = tk.Frame(side, bg=T.INK)
        brand.pack(fill="x", padx=px(20), pady=(px(24), px(28)))
        mark = tk.Canvas(brand, width=px(30), height=px(30), bg=T.INK, highlightthickness=0)
        mark.pack(side="left")
        s = px(30)
        mark.create_line(px(4), s * .7, s / 2, s * .3, s - px(4), s * .7, fill=T.SIGNAL, width=px(2.5))
        mark.create_oval(px(1), s * .7 - px(3), px(7), s * .7 + px(3), fill=T.TEXT, outline="")
        mark.create_polygon(s / 2, s * .3 - px(5), s / 2 + px(5), s * .3, s / 2, s * .3 + px(5), s / 2 - px(5),
                            s * .3, fill=T.SIGNAL, outline="")
        mark.create_rectangle(s - px(7), s * .7 - px(3), s - px(1), s * .7 + px(3), fill=T.TEXT, outline="")
        names = tk.Frame(brand, bg=T.INK)
        names.pack(side="left", padx=(px(10), 0))
        tk.Label(names, text="ABI Route", bg=T.INK, fg=T.TEXT, font=T.F["brand"], anchor="w").pack(fill="x")
        tk.Label(names, text="WARP для Arena Breakout", bg=T.INK, fg=T.FAINT, font=T.F["small"],
                 anchor="w").pack(fill="x")

        self.nav = {}
        for key, name in NAV:
            item = NavItem(side, name, lambda k=key: self.show(k))
            item.pack(fill="x")
            self.nav[key] = item

        foot = tk.Frame(side, bg=T.INK)
        foot.pack(side="bottom", fill="x", padx=px(20), pady=px(20))
        row = tk.Frame(foot, bg=T.INK)
        row.pack(fill="x")
        self.side_dot = tk.Canvas(row, width=px(10), height=px(10), bg=T.INK, highlightthickness=0)
        self.side_dot.pack(side="left")
        self.side_state = tk.Label(row, text="", bg=T.INK, fg=T.TEXT, font=T.F["body_b"], anchor="w")
        self.side_state.pack(side="left", padx=(px(8), 0))
        self.side_game = tk.Label(foot, text="", bg=T.INK, fg=T.MUTED, font=T.F["small"], anchor="w")
        self.side_game.pack(fill="x", pady=(px(4), 0))
        self.side_client = tk.Label(foot, text="", bg=T.INK, fg=T.FAINT, font=T.F["small"], anchor="w",
                                    justify="left")
        self.side_client.pack(fill="x", pady=(px(10), 0))

        head = tk.Frame(content, bg=T.INK)
        head.pack(fill="x", padx=px(32), pady=(px(22), px(12)))
        self.page_title = tk.Label(head, text="", bg=T.INK, fg=T.TEXT, font=T.F["title"], anchor="w")
        self.page_title.pack(side="left")
        self.busy_lbl = tk.Label(head, text="", bg=T.INK, fg=T.MUTED, font=T.F["small"])
        self.busy_lbl.pack(side="right", pady=(px(6), 0))
        self.progress = Progress(content)
        self.progress.pack(fill="x", padx=px(32))
        holder = tk.Frame(content, bg=T.INK)
        holder.pack(fill="both", expand=True, padx=px(32), pady=(px(16), px(24)))
        holder.grid_rowconfigure(0, weight=1)
        holder.grid_columnconfigure(0, weight=1)
        self.pages = {}
        for key, builder in (("route", self._page_route), ("ping", self._page_ping), ("warp", self._page_warp),
                             ("servers", self._page_servers), ("log", self._page_log)):
            f = tk.Frame(holder, bg=T.INK)
            f.grid(row=0, column=0, sticky="nsew")
            builder(f)
            self.pages[key] = f
        self.show("route")
        self._show_state()

    def show(self, key):
        self.page = key
        self.pages[key].tkraise()
        for k, item in self.nav.items():
            item.set_active(k == key)
        self.page_title.configure(text=dict(NAV)[key])

    def _section(self, parent, title, sub=None, wrap=620):
        f = tk.Frame(parent, bg=parent["bg"])
        tk.Label(f, text=title, bg=parent["bg"], fg=T.TEXT, font=T.F["section"], anchor="w").pack(fill="x")
        if sub:
            tk.Label(f, text=sub, bg=parent["bg"], fg=T.MUTED, font=T.F["small"], anchor="w", justify="left",
                     wraplength=px(wrap)).pack(fill="x", pady=(px(3), 0))
        return f

    def _log_widget(self, parent, height):
        t = T.text_widget(parent, height)
        t.configure(bg=T.BOARD, fg=T.TEXT, highlightthickness=0, padx=px(14), pady=px(10), spacing1=px(2),
                    spacing3=px(2), font=T.F["small"])
        for lvl, col in LEVEL_COLOR.items():
            t.tag_configure(lvl, foreground=col if lvl != "info" else T.MUTED)
        t.tag_configure("time", foreground=T.FAINT)
        t.configure(state="disabled")
        return t

    # ---------------------------------------------------------------- страница «Маршрут»
    def _page_route(self, page):
        self.map = RouteMap(page)
        self.map.pack(fill="x")

        status = tk.Frame(page, bg=T.INK)
        status.pack(fill="x", pady=(px(20), 0))
        self.start_btn = Button(status, "Запустить", self.engine_toggle, kind="primary", big=True,
                                min_width=170)
        self.start_btn.pack(side="right", anchor="n", padx=(px(24), 0))
        txt = tk.Frame(status, bg=T.INK)
        txt.pack(side="left", fill="x", expand=True)
        self.hero_title = tk.Label(txt, text="", bg=T.INK, fg=T.TEXT, font=T.F["hero"], anchor="w")
        self.hero_title.pack(fill="x")
        self.hero_sub = tk.Label(txt, text="", bg=T.INK, fg=T.MUTED, font=T.F["body"], anchor="w",
                                 justify="left", wraplength=px(560))
        self.hero_sub.pack(fill="x", pady=(px(4), 0))
        self.hero_verdict = tk.Label(txt, text="", bg=T.INK, fg=T.GOOD, font=T.F["body_b"], anchor="w",
                                     justify="left", wraplength=px(560))
        self.hero_verdict.pack(fill="x", pady=(px(8), 0))
        status.bind("<Configure>", lambda e: [w.configure(wraplength=max(px(300), e.width - self.start_btn.w
                                                                         - px(40)))
                                              for w in (self.hero_sub, self.hero_verdict)])

        tk.Frame(page, bg=T.LINE, height=1).pack(fill="x", pady=(px(18), 0))
        facts = tk.Frame(page, bg=T.INK)
        facts.pack(fill="x", pady=(px(12), 0))
        self.facts = {}
        for i, (key, label) in enumerate((("ep", "Сервер WARP"), ("obf", "Маскировка"), ("traffic", "Трафик туннеля"),
                                          ("hs", "Рукопожатие"))):
            facts.grid_columnconfigure(i, weight=1, uniform="f")
            cell = tk.Frame(facts, bg=T.INK)
            cell.grid(row=0, column=i, sticky="w")
            tk.Label(cell, text=label, bg=T.INK, fg=T.FAINT, font=T.F["small"], anchor="w").pack(fill="x")
            v = tk.Label(cell, text="—", bg=T.INK, fg=T.TEXT, font=T.F["body_b"], anchor="w")
            v.pack(fill="x", pady=(px(2), 0))
            self.facts[key] = v
        tk.Frame(page, bg=T.LINE, height=1).pack(fill="x", pady=(px(12), 0))

        self.setup_box = tk.Frame(page, bg=T.INK)
        self.events_box = tk.Frame(page, bg=T.INK)
        self.events_box.pack(fill="both", expand=True, pady=(px(16), 0))
        tk.Label(self.events_box, text="Последние события", bg=T.INK, fg=T.FAINT, font=T.F["small"],
                 anchor="w").pack(fill="x", pady=(0, px(6)))
        self.mini_log = self._log_widget(self.events_box, 5)
        self.mini_log.pack(fill="both", expand=True)

    def _build_setup(self):
        """Первый запуск: три шага по порядку, пока чего-то не хватает."""
        for w in self.setup_box.winfo_children():
            w.destroy()
        e = self.engine
        steps = [
            (bool(e.client), "Установите AmneziaWG",
             "Клиент туннеля с маскировкой. Нужна версия 2.0 или новее.", [("Открыть страницу загрузки",
                                                                            lambda: webbrowser.open(AWG_URL))]),
            (bool(e.profile), "Создайте профиль WARP",
             "Бесплатный ключ Cloudflare. Если регистрация заблокирована, импортируйте готовый конфиг.",
             [("Создать профиль", e.generate), ("Импорт конфига…", self.import_dialog)]),
            (bool(e.st.get("endpoint_list")), "Найдите сервер WARP",
             "Программа проверит около 400 серверов и выберет самый быстрый из рабочих.",
             [("Найти сервер", e.scan)]),
        ]
        if all(s[0] for s in steps):
            self.setup_box.pack_forget()
            return
        self.setup_box.pack(fill="x", pady=(px(16), 0), before=self.events_box)
        tk.Label(self.setup_box, text="Начало работы", bg=T.INK, fg=T.TEXT, font=T.F["section"],
                 anchor="w").pack(fill="x", pady=(0, px(8)))
        first_open = next(i for i, s in enumerate(steps) if not s[0])
        for i, (done, title, hint, actions) in enumerate(steps):
            row = tk.Frame(self.setup_box, bg=T.INK)
            row.pack(fill="x", pady=(0, px(8)))
            n = tk.Canvas(row, width=px(26), height=px(26), bg=T.INK, highlightthickness=0)
            n.pack(side="left", anchor="n")
            if done:
                n.create_line(px(6), px(13), px(11), px(18), px(20), px(8), fill=T.GOOD, width=px(2.5))
            else:
                n.create_rectangle(1, 1, px(25), px(25), outline=T.TEXT if i == first_open else T.FAINT)
                n.create_text(px(13), px(13), text=str(i + 1), font=T.F["num"],
                              fill=T.TEXT if i == first_open else T.FAINT)
            txt = tk.Frame(row, bg=T.INK)
            txt.pack(side="left", fill="x", expand=True, padx=(px(12), 0))
            tk.Label(txt, text=title, bg=T.INK, fg=T.FAINT if done else T.TEXT, font=T.F["body_b"],
                     anchor="w").pack(fill="x")
            tk.Label(txt, text=hint, bg=T.INK, fg=T.FAINT if done else T.MUTED, font=T.F["small"], anchor="w",
                     justify="left").pack(fill="x")
            if not done and i == first_open:
                for j, (label, cmd) in enumerate(reversed(actions)):
                    Button(row, label, cmd, kind="secondary" if j else "secondary").pack(
                        side="right", padx=(px(8), 0))

    # ---------------------------------------------------------------- страница «Пинг»
    def _page_ping(self, page):
        intro = ("Замер не трогает туннель: путь через WARP проверяется отдельным соединением прямо из "
                 "программы. Через WARP меряется ICMP — на TCP за сервер игры отвечает сам Cloudflare, такой "
                 "пинг был бы ненастоящим.")
        tk.Label(page, text=intro, bg=T.INK, fg=T.MUTED, font=T.F["body"], anchor="w", justify="left",
                 wraplength=px(760)).pack(fill="x")
        bar = tk.Frame(page, bg=T.INK)
        bar.pack(fill="x", pady=(px(14), px(12)))
        Button(bar, "Сравнить", lambda: self.engine.compare(), kind="primary").pack(side="left")
        Button(bar, "Автоподбор", lambda: self.engine.autotune()).pack(side="left", padx=(px(10), 0))
        self.ping_when = tk.Label(bar, text="", bg=T.INK, fg=T.FAINT, font=T.F["small"])
        self.ping_when.pack(side="right")
        board = tk.Frame(page, bg=T.BOARD)
        board.pack(fill="both", expand=True)
        cols = [
            {"key": "ip", "title": "Сервер", "w": 1.25, "draw": self._cell_server},
            {"key": "direct", "title": "Напрямую", "w": 1.55, "draw": lambda *a: self._cell_ms(*a, kind="direct")},
            {"key": "warp", "title": "Через WARP", "w": 1.55, "draw": lambda *a: self._cell_ms(*a, kind="warp")},
            {"key": "diff", "title": "Разница", "w": .75, "align": "e", "draw": self._cell_diff},
            {"key": "stab", "title": "Стабильность", "w": 1.25, "draw": self._cell_stab},
        ]
        self.ping_table = Table(board, cols, row_h=50, empty="Пока нет замеров. Нажмите «Сравнить» — это займёт "
                                                            "несколько секунд и не выключит туннель.")
        self.ping_table.pack(fill="both", expand=True, padx=px(4), pady=(px(6), px(4)))
        self.ping_verdict = tk.Label(page, text="", bg=T.INK, fg=T.MUTED, font=T.F["body_b"], anchor="w",
                                     justify="left", wraplength=px(760))
        self.ping_verdict.pack(fill="x", pady=(px(12), 0))
        page.bind("<Configure>", lambda e: self.ping_verdict.configure(wraplength=e.width - px(10)))

    def _cell_server(self, c, x0, y0, x1, y1, row):
        ym = (y0 + y1) / 2
        c.create_text(x0, ym - px(8), text=row["ip"], anchor="w", fill=T.TEXT, font=T.F["body"])
        how = (row["d"] or {}).get("how") or (row["w"] or {}).get("how") or ""
        c.create_text(x0, ym + px(10), text=how, anchor="w", fill=T.FAINT, font=T.F["small"])

    def _cell_ms(self, c, x0, y0, x1, y1, row, kind):
        v = row["d"] if kind == "direct" else row["w"]
        ym = (y0 + y1) / 2
        col = T.TEXT if kind == "direct" else T.SIGNAL
        bar_col = T.DIRECT if kind == "direct" else T.SIGNAL
        bx1 = x1 - px(18)
        if v:
            c.create_text(x0, ym - px(7), text=f"{v['ms']} мс", anchor="w", fill=col, font=T.F["num"])
            c.create_rectangle(x0, ym + px(9), bx1, ym + px(11), fill=T.LINE, outline="")
            frac = min(1.0, v["ms"] / row["scale"]) if row["scale"] else 0
            c.create_rectangle(x0, ym + px(9), x0 + max(px(2), (bx1 - x0) * frac), ym + px(11), fill=bar_col,
                               outline="")
        else:
            if kind == "warp" and row["tested"]:
                d_icmp = row["d"] and row["d"]["how"] == "ICMP"
                text, fg = ("нет ответа", T.BAD) if d_icmp else ("ICMP закрыт", T.FAINT)
            else:
                text, fg = ("нет ответа", T.FAINT) if kind == "direct" and row["tested_any"] else ("—", T.FAINT)
            c.create_text(x0, ym, text=text, anchor="w", fill=fg, font=T.F["body"])

    def _cell_diff(self, c, x0, y0, x1, y1, row):
        d, w = row["d"], row["w"]
        ym = (y0 + y1) / 2
        if d and w:
            dv = w["ms"] - d["ms"]
            col = T.GOOD if dv < -2 else T.CAUTION if dv > 2 else T.MUTED
            c.create_text(x1, ym, text=f"{signed(dv)} мс" if abs(dv) > 2 else "≈ 0", anchor="e", fill=col,
                          font=T.F["num"])
        else:
            c.create_text(x1, ym, text="—", anchor="e", fill=T.FAINT, font=T.F["body"])

    def _cell_stab(self, c, x0, y0, x1, y1, row):
        src = row["w"] or row["d"]
        ym = (y0 + y1) / 2
        x = x0 + px(20)
        if not src:
            c.create_text(x, ym, text="—", anchor="w", fill=T.FAINT, font=T.F["body"])
            return
        c.create_text(x, ym - px(8), text=f"разброс {src['jitter']} мс", anchor="w", fill=T.MUTED,
                      font=T.F["small"])
        c.create_text(x, ym + px(9), text=f"потери {src['loss']}%", anchor="w",
                      fill=T.BAD if src["loss"] >= 20 else T.FAINT, font=T.F["small"])

    def _fill_ping(self, results):
        vals = [v["ms"] for rr in results.values() for v in (rr.get("direct"), rr.get("warp")) if v]
        scale = max(vals) * 1.08 if vals else 0
        rows = [{"_id": ip, "ip": ip, "d": rr.get("direct"), "w": rr.get("warp"), "tested": rr.get("warp_tested"),
                 "tested_any": True, "scale": scale} for ip, rr in results.items()]
        self.ping_table.set_rows(rows)
        text, col = verdict(results)
        self.ping_verdict.configure(text=text, fg=col)
        if results:
            self.ping_when.configure(text=f"Замер в {time.strftime('%H:%M')}" if not self.demo else "Замер в 23:41")
        self._show_verdict()

    def _show_verdict(self):
        r = self.engine.route or {}
        live = r.get("live") if self.state == "on" else None
        w = live if live is not None else r.get("warp")
        d = r.get("direct")
        if r.get("handshake") is False:
            text, col = "WARP не принимает соединение — нажмите «Автоподбор» на вкладке «Пинг».", T.BAD
        elif w is not None and d is not None:
            dv = w - d
            how = "сейчас через туннель" if live is not None else "через WARP"
            if dv < -2:
                text, col = f"{how.capitalize()} пинг {w} мс — на {-dv} мс быстрее, чем напрямую.", T.GOOD
            elif dv > 2:
                text, col = f"{how.capitalize()} пинг {w} мс — на {dv} мс медленнее, чем напрямую.", T.CAUTION
            else:
                text, col = f"{how.capitalize()} пинг {w} мс — как напрямую.", T.GOOD
        elif self.engine.profile and not self.engine.results:
            text, col = "Откройте «Пинг» и нажмите «Сравнить», чтобы увидеть, помогает ли WARP.", T.MUTED
        else:
            text, col = "", T.MUTED
        self.hero_verdict.configure(text=text, fg=col)

    # ---------------------------------------------------------------- страница «WARP»
    def _page_warp(self, page):
        sp = ScrollPage(page, T.INK)
        sp.pack(fill="both", expand=True)
        body = sp.body
        body.grid_columnconfigure(0, weight=5, uniform="c")
        body.grid_columnconfigure(1, weight=6, uniform="c")
        left = tk.Frame(body, bg=T.INK)
        left.grid(row=0, column=0, sticky="nsew", padx=(0, px(18)))
        right = tk.Frame(body, bg=T.INK)
        right.grid(row=0, column=1, sticky="nsew", padx=(px(18), 0))

        self._section(left, "Профиль").pack(fill="x")
        self.profile_lbl = tk.Label(left, text="", bg=T.INK, fg=T.MUTED, font=T.F["body"], anchor="w",
                                    justify="left", wraplength=px(380))
        self.profile_lbl.pack(fill="x", pady=(px(6), px(10)))
        row = tk.Frame(left, bg=T.INK)
        row.pack(fill="x")
        self.gen_btn = Button(row, "Создать профиль", self.on_generate)
        self.gen_btn.pack(side="left")
        Button(row, "Импорт конфига…", self.import_dialog).pack(side="left", padx=(px(10), 0))

        self._section(left, "Маскировка", "Чем начинается соединение с WARP. Провайдеры блокируют WARP по "
                                         "виду первых пакетов — маскировка делает их похожими на обычный "
                                         "трафик.", wrap=380).pack(fill="x", pady=(px(26), px(8)))
        self.obf_list = RadioList(left, self.engine.set_preset, wrap=330)
        self.obf_list.pack(fill="x")
        self.obf_note = tk.Label(left, text="", bg=T.INK, fg=T.CAUTION, font=T.F["small"], anchor="w",
                                 justify="left", wraplength=px(380))
        self.obf_note.pack(fill="x", pady=(px(6), 0))

        self._section(right, "Сервер WARP", "Адрес, к которому подключается туннель. «До узла» — настоящий "
                                           "пинг до Cloudflare через WARP, а не время рукопожатия.",
                      wrap=440).pack(fill="x")
        row = tk.Frame(right, bg=T.INK)
        row.pack(fill="x", pady=(px(12), px(10)))
        Button(row, "Найти сервер", lambda: self.engine.scan(), kind="primary").pack(side="left")
        Button(row, "Автоподбор", lambda: self.engine.autotune()).pack(side="left", padx=(px(10), 0))
        board = tk.Frame(right, bg=T.BOARD, height=px(330))
        board.pack(fill="x")
        board.pack_propagate(False)
        cols = [{"key": "ep", "title": "Сервер", "w": 1.7},
                {"key": "ms", "title": "До узла", "w": .8, "align": "e", "draw": self._cell_ep_ms},
                {"key": "colo", "title": "Узел", "w": 1.1, "draw": self._cell_ep_colo},
                {"key": "cur", "title": "", "w": .8, "align": "e", "draw": self._cell_ep_cur}]
        self.ep_table = Table(board, cols, row_h=34, on_open=lambda r: self.engine.pick_endpoint(r["ep"]),
                              empty="Список пуст. Нажмите «Найти сервер».")
        self.ep_table.pack(fill="both", expand=True, padx=px(4), pady=px(4))
        tk.Label(right, text="Двойной щелчок или Enter — выбрать сервер. Остальные — запас для автосмены.",
                 bg=T.INK, fg=T.FAINT, font=T.F["small"], anchor="w").pack(fill="x", pady=(px(6), 0))

        self._section(right, "Дополнительно").pack(fill="x", pady=(px(24), px(8)))
        self.fo_var = tk.BooleanVar(value=self.engine.st.get("failover", True))
        Check(right, "Автосмена сервера и маскировки, если трафик перестал идти", self.fo_var,
              lambda: self.engine.update(failover=bool(self.fo_var.get()))).pack(anchor="w")
        mrow = tk.Frame(right, bg=T.INK)
        mrow.pack(fill="x", pady=(px(12), 0))
        tk.Label(mrow, text="MTU", bg=T.INK, fg=T.TEXT, font=T.F["body"]).pack(side="left")
        self.mtu_var = tk.StringVar(value=str(self.engine.st.get("mtu", 1280)))
        mtu = T.entry_widget(mrow, self.mtu_var, width=6)
        mtu.pack(side="left", padx=(px(10), px(10)), ipady=px(3))
        mtu.bind("<FocusOut>", lambda e: self._save_mtu())
        mtu.bind("<Return>", lambda e: self._save_mtu())
        tk.Label(mrow, text="1280 подходит почти всем. Уменьшите до 1200, если игра подвисает.", bg=T.INK,
                 fg=T.FAINT, font=T.F["small"]).pack(side="left")

    def _cell_ep_ms(self, c, x0, y0, x1, y1, row):
        ym = (y0 + y1) / 2
        if row["ms"] is not None:
            c.create_text(x1, ym, text=f"{row['ms']} мс", anchor="e", fill=T.TEXT, font=T.F["num"])
        else:
            c.create_text(x1, ym, text="в запасе", anchor="e", fill=T.FAINT, font=T.F["small"])

    def _cell_ep_colo(self, c, x0, y0, x1, y1, row):
        c.create_text(x0 + px(22), (y0 + y1) / 2, text=row["colo"] or "", anchor="w", fill=T.MUTED,
                      font=T.F["body"])

    def _cell_ep_cur(self, c, x0, y0, x1, y1, row):
        if row["cur"]:
            ym, k = (y0 + y1) / 2, px(4)
            tw = T.F["small"].measure("выбран")
            c.create_text(x1, ym, text="выбран", anchor="e", fill=T.SIGNAL, font=T.F["small"])
            x = x1 - tw - px(10)
            c.create_polygon(x, ym - k, x + k, ym, x, ym + k, x - k, ym, fill=T.SIGNAL, outline="")

    def _save_mtu(self):
        try:
            v = max(1200, min(1420, int(self.mtu_var.get())))
        except ValueError:
            v = self.engine.st.get("mtu", 1280)
        self.mtu_var.set(str(v))
        if v != self.engine.st.get("mtu"):
            self.engine.update(mtu=v)
            self.engine.log(f"MTU {v}.")
            self.engine._restart_if_running()

    def on_generate(self):
        if self.engine.profile and not messagebox.askyesno(
                APP_NAME, "Профиль уже есть. Создать новый?\nЭто помогает, если старый перестал работать."):
            return
        self.engine.generate()

    def import_dialog(self):
        d = tk.Toplevel(self.root, bg=T.INK)
        d.title("Импорт конфига WARP")
        d.transient(self.root)
        d.geometry(f"{px(640)}x{px(470)}")
        d.minsize(px(520), px(380))
        d.update_idletasks()
        T.dark_frame(d)
        box = tk.Frame(d, bg=T.INK)
        box.pack(fill="both", expand=True, padx=px(24), pady=px(20))
        tk.Label(box, text="Импорт конфига WARP", bg=T.INK, fg=T.TEXT, font=T.F["section"], anchor="w").pack(
            fill="x")
        tk.Label(box, text="Вставьте конфиг AmneziaWG или WireGuard либо строку vpn://… — например, из "
                           "генератора WARP. Ключи сохранятся только на этом компьютере.",
                 bg=T.INK, fg=T.MUTED, font=T.F["small"], anchor="w", justify="left", wraplength=px(580)).pack(
            fill="x", pady=(px(4), px(12)))
        btns = tk.Frame(box, bg=T.INK)
        btns.pack(side="bottom", fill="x", pady=(px(14), 0))
        txt = T.text_widget(box, 12, mono=True)
        txt.pack(fill="both", expand=True)
        txt.focus_set()
        try:
            clip = self.root.clipboard_get()
            if "[Interface]" in clip or clip.strip().startswith("vpn://"):
                txt.insert("1.0", clip)
        except tk.TclError:
            pass

        def open_file():
            path = filedialog.askopenfilename(parent=d, title="Конфиг WARP",
                                              filetypes=[("Конфиг", "*.conf *.txt"), ("Все файлы", "*.*")])
            if path:
                try:
                    with open(path, "r", encoding="utf-8-sig", errors="ignore") as f:
                        txt.delete("1.0", "end")
                        txt.insert("1.0", f.read())
                except OSError as e:
                    messagebox.showerror(APP_NAME, str(e), parent=d)

        def do_import():
            if self.engine.import_conf(txt.get("1.0", "end")):
                d.destroy()
            else:
                messagebox.showerror(APP_NAME, "Не получилось прочитать конфиг — подробности в журнале.", parent=d)

        Button(btns, "Открыть файл…", open_file, kind="ghost").pack(side="left")
        Button(btns, "Импортировать", do_import, kind="primary").pack(side="right")
        Button(btns, "Отмена", d.destroy).pack(side="right", padx=(0, px(10)))
        d.bind("<Escape>", lambda e: d.destroy())
        d.grab_set()

    # ---------------------------------------------------------------- страница «Серверы игры»
    def _page_servers(self, page):
        sp = ScrollPage(page, T.INK)
        sp.pack(fill="both", expand=True)
        body = sp.body
        self._section(body, "Что идёт через WARP", "Только эти IP-диапазоны. Браузер, Discord, загрузки и всё "
                                                  "остальное идут напрямую.").pack(fill="x")
        pr = tk.Frame(body, bg=T.INK)
        pr.pack(fill="x", pady=(px(14), px(10)))
        tk.Label(pr, text="Готовый список", bg=T.INK, fg=T.MUTED, font=T.F["body"]).pack(side="left")
        self.preset_var = tk.StringVar(value=list(GAME_PRESETS)[0])
        ttk.Combobox(pr, textvariable=self.preset_var, values=list(GAME_PRESETS), width=30, state="readonly",
                     style="Dark.TCombobox", font=T.F["body"]).pack(side="left", padx=px(10), ipady=px(3))
        Button(pr, "Добавить", self.do_preset).pack(side="left")
        Button(pr, "Очистить", self.do_clear_ranges, kind="ghost").pack(side="right")
        self.ranges_txt = T.text_widget(body, 9, mono=True)
        self.ranges_txt.pack(fill="x")
        self.ranges_txt.insert("1.0", "\n".join(self.engine.st["ranges"]))
        row = tk.Frame(body, bg=T.INK)
        row.pack(fill="x", pady=(px(12), 0))
        self.auto_var = tk.BooleanVar(value=self.engine.st["auto_learn"])
        Check(row, "Находить серверы игры автоматически", self.auto_var, self.collect).pack(side="left")
        tk.Label(row, text="Охват", bg=T.INK, fg=T.MUTED, font=T.F["body"]).pack(side="left", padx=(px(28), px(8)))
        self.prefix_var = tk.StringVar(value=f"/{self.engine.st['prefix']}")
        cb = ttk.Combobox(row, textvariable=self.prefix_var, values=["/24", "/20", "/16"], width=5,
                          state="readonly", style="Dark.TCombobox", font=T.F["body"])
        cb.pack(side="left", ipady=px(2))
        cb.bind("<<ComboboxSelected>>", lambda e: self.engine.update(prefix=int(self.prefix_var.get()[1:])))
        Button(row, "Сохранить маршруты", self.do_apply_routes, kind="primary").pack(side="right")
        tk.Label(body, text="Матч не стартует, хотя лобби открывается? Поставьте охват /20 или /16: игровые "
                            "UDP-серверы Windows не показывает, широкий охват их захватит.",
                 bg=T.INK, fg=T.FAINT, font=T.F["small"], anchor="w", justify="left", wraplength=px(760)).pack(
            fill="x", pady=(px(8), 0))

        cols = tk.Frame(body, bg=T.INK)
        cols.pack(fill="x", pady=(px(28), 0))
        cols.grid_columnconfigure(0, weight=1, uniform="b")
        cols.grid_columnconfigure(1, weight=1, uniform="b")
        a = tk.Frame(cols, bg=T.INK)
        a.grid(row=0, column=0, sticky="nsew", padx=(0, px(16)))
        self._section(a, "Процессы игры", "Через запятую. По их подключениям находятся серверы игры.",
                      wrap=340).pack(fill="x", pady=(0, px(8)))
        self.proc_var = tk.StringVar(value=", ".join(self.engine.st["game_processes"]))
        ent = T.entry_widget(a, self.proc_var)
        ent.pack(fill="x", ipady=px(5))
        ent.bind("<FocusOut>", lambda e: self.collect())
        b = tk.Frame(cols, bg=T.INK)
        b.grid(row=0, column=1, sticky="nsew", padx=(px(16), 0))
        self._section(b, "Не пускать через WARP", "Серверы обновлений и CDN — автопоиск их пропустит.",
                      wrap=340).pack(fill="x", pady=(0, px(8)))
        self.ignore_txt = T.text_widget(b, 3, mono=True)
        self.ignore_txt.pack(fill="x")
        self.ignore_txt.insert("1.0", "\n".join(self.engine.st.get("ignore_ranges", [])))
        self.ignore_txt.bind("<FocusOut>", lambda e: self.collect())

    def _read_nets(self, widget):
        import ipaddress
        good = []
        for line in widget.get("1.0", "end").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                ipaddress.ip_network(line, strict=False)
                good.append(line)
            except ValueError:
                self.engine.log(f"Пропущена строка — это не IP-диапазон: {line}", "warn")
        return good

    def collect(self):
        return self.engine.update(
            game_processes=[p.strip() for p in self.proc_var.get().split(",") if p.strip()],
            ranges=self._read_nets(self.ranges_txt), ignore_ranges=self._read_nets(self.ignore_txt),
            auto_learn=bool(self.auto_var.get()))

    def do_preset(self):
        from .common import normalize_ranges
        name = self.preset_var.get()
        merged = normalize_ranges(self._read_nets(self.ranges_txt) + GAME_PRESETS.get(name, []))
        self.ranges_txt.delete("1.0", "end")
        self.ranges_txt.insert("1.0", "\n".join(merged))
        self.collect()
        self.engine.log(f"Добавлен список «{name}»: теперь {len(merged)} диапазон(ов).")
        self.refresh()

    def do_clear_ranges(self):
        self.ranges_txt.delete("1.0", "end")
        self.collect()
        self.engine.log("Список диапазонов очищен.")

    def do_apply_routes(self):
        if self.collect():
            self.engine.log("Маршруты сохранены — перезапускаю туннель…" if self.engine.running else
                            "Маршруты сохранены.", "ok")
        else:
            self.engine.log("Маршруты сохранены.", "ok")

    def _merge_ranges(self, ranges):
        cur = [x.strip() for x in self.ranges_txt.get("1.0", "end").splitlines() if x.strip()]
        new = [r for r in ranges if r not in cur]
        if new:
            self.ranges_txt.insert("end", ("\n" if cur else "") + "\n".join(new))

    # ---------------------------------------------------------------- страница «Журнал»
    def _page_log(self, page):
        top = tk.Frame(page, bg=T.INK)
        top.pack(fill="x")
        head = tk.Frame(top, bg=T.INK)
        head.pack(fill="x")
        self._section(head, "Диагностика", "Проверка пути по шагам: где именно обрывается связь с WARP.").pack(
            side="left", fill="x")
        Button(head, "Проверить всё", lambda: self.engine.diagnose(), kind="primary").pack(side="right")
        self.diag_box = tk.Frame(top, bg=T.INK)
        self.diag_box.pack(fill="x", pady=(px(12), 0))
        tk.Label(self.diag_box, text="Нажмите «Проверить всё» — займёт пару секунд и не тронет туннель.",
                 bg=T.INK, fg=T.FAINT, font=T.F["small"], anchor="w").pack(fill="x")
        bottom = tk.Frame(page, bg=T.INK)
        bottom.pack(fill="both", expand=True, pady=(px(22), 0))
        head = tk.Frame(bottom, bg=T.INK)
        head.pack(fill="x", pady=(0, px(8)))
        tk.Label(head, text="Журнал", bg=T.INK, fg=T.TEXT, font=T.F["section"], anchor="w").pack(side="left")
        Button(head, "Копировать", self.copy_log, kind="ghost").pack(side="right")
        Button(head, "Папка настроек", self.open_data_dir, kind="ghost").pack(side="right", padx=(0, px(6)))
        self.log_txt = self._log_widget(bottom, 10)
        self.log_txt.pack(fill="both", expand=True)

    def _fill_diag(self, items):
        for w in self.diag_box.winfo_children():
            w.destroy()
        for it in items:
            row = tk.Frame(self.diag_box, bg=T.INK)
            row.pack(fill="x", pady=(0, px(6)))
            StatusGlyph(row, it["status"]).pack(side="left", anchor="n", pady=(px(1), 0))
            txt = tk.Frame(row, bg=T.INK)
            txt.pack(side="left", fill="x", expand=True, padx=(px(10), 0))
            tk.Label(txt, text=it["title"], bg=T.INK, fg=T.TEXT, font=T.F["body_b"], anchor="w").pack(fill="x")
            if it.get("detail"):
                tk.Label(txt, text=it["detail"], bg=T.INK, fg=T.MUTED, font=T.F["small"], anchor="w",
                         justify="left", wraplength=px(700)).pack(fill="x")

    def copy_log(self):
        self.root.clipboard_clear()
        self.root.clipboard_append(self.log_txt.get("1.0", "end").strip())
        self.engine.log("Журнал скопирован в буфер обмена.")

    def open_data_dir(self):
        from .settings import DATA_DIR
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.name == "nt":
            os.startfile(DATA_DIR)  # noqa: S606
        else:
            subprocess.Popen(["xdg-open", DATA_DIR])

    def _log(self, text, level, t):
        for w, limit in ((self.log_txt, 2000), (self.mini_log, 60)):
            w.configure(state="normal")
            w.insert("end", t + "  ", "time")
            w.insert("end", text + "\n", level)
            lines = int(w.index("end-1c").split(".")[0])
            if lines > limit:
                w.delete("1.0", f"{lines - limit}.0")
            w.see("end")
            w.configure(state="disabled")

    # ---------------------------------------------------------------- состояние
    def engine_toggle(self):
        if self.state == "starting":
            return
        self.collect()
        self.engine.toggle()

    def _show_state(self):
        title, sub, btn, kind = STATES.get(self.state, STATES["off"])
        self.hero_title.configure(text=title, fg={"on": T.SIGNAL, "wait": T.CAUTION}.get(self.state, T.TEXT))
        self.hero_sub.configure(text=sub)
        self.start_btn.set(text=btn, kind=kind, enabled=self.state != "starting")
        self.map.show(state=self.state)
        self._show_side_status()
        self._show_verdict()

    def _show_side_status(self):
        col = {"on": T.SIGNAL, "wait": T.CAUTION, "starting": T.CAUTION}.get(self.state, T.FAINT)
        self.side_dot.delete("all")
        s = px(10)
        self.side_dot.create_polygon(s / 2, 0, s, s / 2, s / 2, s, 0, s / 2, fill=col, outline="")
        self.side_state.configure(text={"on": "Туннель работает", "wait": "Ждём игру", "starting": "Запуск…"}.get(
            self.state, "Туннель выключен"))
        self.side_game.configure(text="Игра запущена" if self.game_on else "Игра не запущена")

    def _show_stats(self, s):
        self.facts["traffic"].configure(text=f"↓ {fmt_bytes(s['rx'])}   ↑ {fmt_bytes(s['tx'])}")
        if s.get("handshake"):
            age = int(time.time() - s["handshake"])
            self.facts["hs"].configure(text=f"{age} с назад", fg=T.TEXT if age < 180 else T.CAUTION)
        else:
            self.facts["hs"].configure(text="ждём…", fg=T.CAUTION)

    def refresh(self):
        e = self.engine
        p = e.profile
        if p:
            how = ("импортирован из конфига" if p.get("source") == "import" else f"создан {p.get('created', '')}")
            self.profile_lbl.configure(text=f"Профиль {how}.\nАдрес внутри WARP: {p['v4']}.", fg=T.TEXT)
            self.gen_btn.set(text="Создать новый")
        else:
            self.profile_lbl.configure(text="Профиля пока нет. Программа зарегистрирует бесплатное устройство "
                                            "Cloudflare WARP. Если регистрация не проходит, импортируйте "
                                            "готовый конфиг.", fg=T.MUTED)
            self.gen_btn.set(text="Создать профиль")
        cps = e.cps_ok
        opts = []
        if e.st.get("obf_id") == "custom":
            opts.append({"id": "custom", "title": "Из импортированного конфига", "enabled": True,
                         "hint": "Параметры Jc и I1–I5 взяты из конфига как есть."})
        for pr in warp.OBF_PRESETS:
            need = warp.needs_cps(pr["obf"])
            opts.append({"id": pr["id"], "title": pr["name"], "enabled": cps or not need,
                         "hint": pr["hint"] + ("" if cps or not need else " Нужен AmneziaWG 2.0 или новее.")})
        self.obf_list.set_options(opts, e.st.get("obf_id"))
        c = e.client
        if c and c["kind"] == "awg" and not cps:
            self.obf_note.configure(text=f"У вас AmneziaWG {tunnel.version_str(c['version'])}. Обновите до 2.0+, "
                                         "чтобы открыть маскировку QUIC, SIP и DNS.")
        elif c and c["kind"] == "wg":
            self.obf_note.configure(text="WireGuard не умеет маскировку — установите AmneziaWG.")
        else:
            self.obf_note.configure(text="")
        cur = e.st["endpoint"]
        lst = e.st.get("endpoint_list") or []
        if cur not in [x[0] for x in lst]:
            lst = [[cur, None, e.st.get("colo")]] + lst
        self.ep_table.set_rows([{"_id": ep, "ep": ep, "ms": ms, "colo": colo_name(colo), "cur": ep == cur}
                                for ep, ms, colo in lst])
        self.facts["ep"].configure(text=cur)
        self.facts["obf"].configure(text=e.preset_name())
        self.map.show(has_profile=bool(p), colo=colo_name(e.st.get("colo")) or None)
        if c:
            name = "AmneziaWG" if c["kind"] == "awg" else "WireGuard"
            self.side_client.configure(text=f"{name} {tunnel.version_str(c['version'])}\nABI Route {VERSION}")
        else:
            self.side_client.configure(text=f"AmneziaWG не найден\nABI Route {VERSION}")
        self._build_setup()
        if e.results and not self.ping_table.rows:
            self._fill_ping(e.results)

    # ---------------------------------------------------------------- выход и скриншоты
    def on_close(self):
        if self.engine.running:
            ans = messagebox.askyesnocancel(
                APP_NAME, "Туннель работает как служба Windows.\n\n"
                          "Да — свернуть окно (автопоиск и автосмена продолжат работать)\n"
                          "Нет — выключить туннель и выйти\nОтмена — вернуться")
            if ans is None:
                return
            if ans:
                self.root.iconify()
                return
            self.engine.shutdown(stop_tunnel=not self.demo)
        else:
            self.engine.shutdown(stop_tunnel=False)
        self.root.destroy()

    def screenshots(self, folder):
        """Снимки всех страниц (для CI и README). Требует Pillow."""
        os.makedirs(folder, exist_ok=True)
        keys = [k for k, _ in NAV]

        def shoot(i):
            if i >= len(keys):
                self.root.destroy()
                return
            self.show(keys[i])
            self.root.update()
            self.root.after(700, lambda: (grab(self.root, os.path.join(folder, f"{i + 1}-{keys[i]}.png")),
                                          shoot(i + 1)))
        self.root.after(1200, lambda: shoot(0))


def grab(root, path):
    root.update()
    x, y, w, h = root.winfo_rootx(), root.winfo_rooty(), root.winfo_width(), root.winfo_height()
    from PIL import ImageGrab
    if os.name == "nt":
        img = ImageGrab.grab(bbox=(x, y, x + w, y + h), all_screens=True)
    else:
        img = ImageGrab.grab(bbox=(x, y, x + w, y + h), xdisplay=os.environ.get("DISPLAY"))
    img.save(path)


def main(argv=()):
    argv = list(argv)
    demo = "--demo" in argv or "--screenshot" in argv
    app = App(demo=demo)
    if "--screenshot" in argv:
        i = argv.index("--screenshot")
        app.screenshots(argv[i + 1] if i + 1 < len(argv) else "screenshots")
    app.root.mainloop()
    return 0
