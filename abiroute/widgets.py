# -*- coding: utf-8 -*-
"""Виджеты ABI Route, нарисованные на Canvas: кнопки, переключатели, таблица, карта маршрута."""
import math
import random
import tkinter as tk
from tkinter import ttk

from . import theme as T
from .theme import px

# ----------------------------------------------------------------- кнопка


class Button(tk.Canvas):
    """Плоская кнопка. primary — янтарная со срезанными углами: главное действие экрана."""

    KINDS = {  # фон, фон при наведении, текст, рамка, срез угла
        "primary": (T.SIGNAL, T.SIGNAL_HI, T.SIGNAL_INK, None, 9),
        "secondary": (T.RAISE, T.LINE, T.TEXT, T.LINE, 0),
        "ghost": (None, T.RAISE, T.MUTED, None, 0),
    }

    def __init__(self, parent, text, command=None, kind="secondary", big=False, min_width=0):
        super().__init__(parent, bg=parent["bg"], highlightthickness=0, bd=0, takefocus=1, cursor="hand2")
        self.text, self.command, self.kind, self.big, self.min_width = text, command, kind, big, min_width
        self.hover = self.down = self.focus = False
        self.enabled = True
        for seq, fn in (("<Enter>", self._enter), ("<Leave>", self._leave), ("<ButtonPress-1>", self._press),
                        ("<ButtonRelease-1>", self._release), ("<KeyPress-Return>", self.invoke),
                        ("<KeyPress-space>", self.invoke), ("<FocusIn>", self._focus_in),
                        ("<FocusOut>", self._focus_out)):
            self.bind(seq, fn)
        self._layout()

    def _font(self):
        return T.F["button_lg" if self.big else "button"]

    def _layout(self):
        f = self._font()
        padx, pady = px(24 if self.big else 14), px(12 if self.big else 7)
        self.w = max(f.measure(self.text) + 2 * padx, px(self.min_width))
        self.h = f.metrics("linespace") + 2 * pady
        self.configure(width=self.w, height=self.h)
        self._draw()

    def _draw(self):
        self.delete("all")
        bg, bg_hover, fg, outline, cut = self.KINDS[self.kind]
        w, h, c = self.w, self.h, px(cut)
        fill = bg_hover if (self.hover and self.enabled) else bg
        if not self.enabled:
            fill, fg, outline = (T.BOARD if bg else None), T.FAINT, (T.LINE if bg else None)
        elif self.down and fill:
            fill = T.mix(fill, "#000000", 0.15)
        pts = [c, 0, w - 1, 0, w - 1, h - 1 - c, w - 1 - c, h - 1, 0, h - 1, 0, c]
        if fill or outline:
            self.create_polygon(pts, fill=fill or "", outline=outline or fill)
        if self.focus and self.enabled:
            ring = T.SIGNAL_INK if self.kind == "primary" else T.MUTED
            self.create_rectangle(px(3), px(3), w - px(4), h - px(4), outline=ring, dash=(1, 2))
        self.create_text(w // 2, h // 2, text=self.text, fill=fg, font=self._font())

    def _enter(self, _e):
        self.hover = True
        self._draw()

    def _leave(self, _e):
        self.hover = self.down = False
        self._draw()

    def _press(self, _e):
        if self.enabled:
            self.down = True
            self._draw()

    def _release(self, _e):
        fire = self.down and self.hover
        self.down = False
        self._draw()
        if fire:
            self.invoke()

    def _focus_in(self, _e):
        self.focus = True
        self._draw()

    def _focus_out(self, _e):
        self.focus = False
        self._draw()

    def invoke(self, _e=None):
        if self.enabled and self.command:
            self.command()
        return "break"

    def set(self, text=None, kind=None, enabled=None):
        if text is not None:
            self.text = text
        if kind is not None:
            self.kind = kind
        if enabled is not None:
            self.enabled = enabled
            self.configure(cursor="hand2" if enabled else "arrow")
        self._layout()

# ----------------------------------------------------------------- флажок и список вариантов


class Check(tk.Frame):
    def __init__(self, parent, text, variable, command=None):
        bg = parent["bg"]
        super().__init__(parent, bg=bg)
        self.var, self.command = variable, command
        s = px(16)
        self.box = tk.Canvas(self, width=s, height=s, bg=bg, highlightthickness=0, takefocus=1, cursor="hand2")
        self.box.pack(side="left")
        self.lbl = tk.Label(self, text=text, bg=bg, fg=T.TEXT, font=T.F["body"], cursor="hand2")
        self.lbl.pack(side="left", padx=(px(8), 0))
        for w in (self.box, self.lbl):
            w.bind("<Button-1>", self.toggle)
        self.box.bind("<KeyPress-space>", self.toggle)
        self.box.bind("<FocusIn>", lambda e: self.lbl.configure(fg=T.SIGNAL_HI))
        self.box.bind("<FocusOut>", lambda e: self.lbl.configure(fg=T.TEXT))
        variable.trace_add("write", lambda *a: self._draw())
        self._draw()

    def _draw(self):
        c, s = self.box, px(16)
        c.delete("all")
        on = bool(self.var.get())
        c.create_rectangle(0, 0, s - 1, s - 1, outline=T.TEXT if on else T.FAINT, fill=T.TEXT if on else "")
        if on:
            c.create_line(px(3.5), px(8), px(6.5), px(11), px(12.5), px(4.5), fill=T.INK, width=max(2, px(2)))

    def toggle(self, _e=None):
        self.var.set(not self.var.get())
        if self.command:
            self.command()
        return "break"


class RadioList(tk.Frame):
    """Варианты с пояснениями. Недоступный вариант виден, но не выбирается — с причиной."""

    def __init__(self, parent, on_select, wrap=360):
        super().__init__(parent, bg=parent["bg"])
        self.on_select, self.wrap = on_select, wrap
        self.value, self.rows = None, {}

    def set_options(self, options, value):
        for w in self.winfo_children():
            w.destroy()
        self.rows, self.value = {}, value
        for opt in options:
            row = tk.Frame(self, bg=self["bg"], cursor="hand2" if opt["enabled"] else "arrow")
            row.pack(fill="x", pady=(0, px(2)))
            mark = tk.Canvas(row, width=px(14), height=px(14), bg=self["bg"], highlightthickness=0)
            mark.pack(side="left", anchor="n", padx=(px(10), px(10)), pady=(px(10), 0))
            text = tk.Frame(row, bg=self["bg"])
            text.pack(side="left", fill="x", expand=True, pady=px(7))
            title = tk.Label(text, text=opt["title"], bg=self["bg"], anchor="w", font=T.F["body_b"])
            title.pack(fill="x")
            hint = tk.Label(text, text=opt["hint"], bg=self["bg"], anchor="w", justify="left",
                            font=T.F["small"], wraplength=px(self.wrap))
            hint.pack(fill="x")
            self.rows[opt["id"]] = (row, mark, title, hint, opt)
            if opt["enabled"]:
                for w in (row, mark, text, title, hint):
                    w.bind("<Button-1>", lambda e, i=opt["id"]: self._pick(i))
                    w.bind("<Enter>", lambda e, i=opt["id"]: self._paint(i, True))
                    w.bind("<Leave>", lambda e, i=opt["id"]: self._paint(i, False))
            self._paint(opt["id"], False)

    def _pick(self, oid):
        self.value = oid
        for i in self.rows:
            self._paint(i, False)
        self.on_select(oid)

    def _paint(self, oid, hover):
        row, mark, title, hint, opt = self.rows[oid]
        sel = oid == self.value
        bg = T.RAISE if sel else (T.mix(self["bg"], T.RAISE, 0.5) if hover else self["bg"])
        for w in (row, mark, title, hint, title.master):
            w.configure(bg=bg)
        title.configure(fg=T.TEXT if opt["enabled"] else T.FAINT)
        hint.configure(fg=T.MUTED if opt["enabled"] else T.FAINT)
        mark.delete("all")
        s = px(14)
        pts = [s / 2, 1, s - 1, s / 2, s / 2, s - 1, 1, s / 2]
        if sel:
            mark.create_polygon(pts, fill=T.TEXT, outline=T.TEXT)
        else:
            mark.create_polygon(pts, fill="", outline=T.FAINT if opt["enabled"] else T.LINE)

    def set_value(self, value):
        self.value = value
        for i in self.rows:
            self._paint(i, False)

# ----------------------------------------------------------------- таблица


class Table(tk.Canvas):
    """Таблица на Canvas: свои отрисовщики ячеек, наведение, выбор, прокрутка колесом.

    columns: [{"key", "title", "w": доля ширины, "align": "w"|"e"|"center", "draw": fn(c, x0, y0, x1, y1, row)}]
    """

    def __init__(self, parent, columns, row_h=34, empty="", on_open=None, on_select=None):
        super().__init__(parent, bg=parent["bg"], highlightthickness=0, bd=0, takefocus=1)
        self.columns, self.row_h, self.empty = columns, px(row_h), empty
        self.on_open, self.on_select = on_open, on_select
        self.rows, self.hover, self.sel, self.offset = [], None, None, 0
        self.head_h = px(28)
        self.bind("<Configure>", lambda e: self.redraw())
        self.bind("<Motion>", self._motion)
        self.bind("<Leave>", lambda e: self._set_hover(None))
        self.bind("<Button-1>", self._click)
        self.bind("<Double-1>", self._double)
        self.bind("<MouseWheel>", lambda e: self._scroll(-1 if e.delta > 0 else 1))
        self.bind("<Button-4>", lambda e: self._scroll(-1))
        self.bind("<Button-5>", lambda e: self._scroll(1))
        self.bind("<Up>", lambda e: self._move(-1))
        self.bind("<Down>", lambda e: self._move(1))
        self.bind("<Return>", lambda e: self._open())

    def set_rows(self, rows, keep_sel=True):
        key = self.rows[self.sel].get("_id") if (keep_sel and self.sel is not None and self.sel < len(self.rows)) \
            else None
        self.rows = rows
        self.sel = next((i for i, r in enumerate(rows) if key is not None and r.get("_id") == key), None)
        self.offset = min(self.offset, self._max_offset())
        self.redraw()

    def selected(self):
        return self.rows[self.sel] if self.sel is not None and self.sel < len(self.rows) else None

    def _max_offset(self):
        return max(0, len(self.rows) * self.row_h - (self.winfo_height() - self.head_h))

    def _xs(self, w):
        total = sum(c["w"] for c in self.columns)
        xs, x = [], px(12)
        avail = w - px(24)
        for c in self.columns:
            x1 = x + avail * c["w"] / total
            xs.append((x, x1))
            x = x1
        return xs

    def redraw(self):
        self.delete("all")
        w, h = self.winfo_width(), self.winfo_height()
        if w < 10:
            return
        xs = self._xs(w)
        for (x0, x1), c in zip(xs, self.columns):
            anchor = {"w": "w", "e": "e", "center": "center"}[c.get("align", "w")]
            x = x0 if anchor == "w" else x1 if anchor == "e" else (x0 + x1) / 2
            self.create_text(x, self.head_h / 2, text=c["title"], anchor=anchor, fill=T.FAINT, font=T.F["small"])
        self.create_line(0, self.head_h - 1, w, self.head_h - 1, fill=T.LINE)
        if not self.rows:
            if self.empty:
                self.create_text(w / 2, self.head_h + (h - self.head_h) / 2, text=self.empty, fill=T.MUTED,
                                 font=T.F["body"], width=w - px(80), justify="center")
            return
        for i, row in enumerate(self.rows):
            y0 = self.head_h + i * self.row_h - self.offset
            y1 = y0 + self.row_h
            if y1 < self.head_h or y0 > h:
                continue
            if i == self.sel or i == self.hover:
                self.create_rectangle(0, y0, w, y1 - 1, fill=T.RAISE if i == self.sel else T.mix(T.BOARD, T.RAISE, .5),
                                      outline="")
            for (x0, x1), c in zip(xs, self.columns):
                if c.get("draw"):
                    c["draw"](self, x0, y0, x1, y1, row)
                else:
                    anchor = c.get("align", "w")
                    x = x0 if anchor == "w" else x1 if anchor == "e" else (x0 + x1) / 2
                    self.create_text(x, (y0 + y1) / 2, text=str(row.get(c["key"], "")), anchor=anchor,
                                     fill=row.get("_fg", T.TEXT), font=T.F["body"])
            self.create_line(px(12), y1 - 1, w - px(12), y1 - 1, fill=T.mix(T.BOARD, T.LINE, .6))
        # заголовок поверх прокрученных строк
        self.create_rectangle(0, 0, w, self.head_h - 1, fill=self["bg"], outline="")
        for (x0, x1), c in zip(xs, self.columns):
            anchor = c.get("align", "w")
            x = x0 if anchor == "w" else x1 if anchor == "e" else (x0 + x1) / 2
            self.create_text(x, self.head_h / 2, text=c["title"], anchor=anchor, fill=T.FAINT, font=T.F["small"])
        self.create_line(0, self.head_h - 1, w, self.head_h - 1, fill=T.LINE)

    def _row_at(self, y):
        if y < self.head_h:
            return None
        i = int((y - self.head_h + self.offset) // self.row_h)
        return i if 0 <= i < len(self.rows) else None

    def _set_hover(self, i):
        if i != self.hover:
            self.hover = i
            self.redraw()

    def _motion(self, e):
        self._set_hover(self._row_at(e.y))

    def _click(self, e):
        self.focus_set()
        i = self._row_at(e.y)
        if i is not None:
            self.sel = i
            self.redraw()
            if self.on_select:
                self.on_select(self.rows[i])

    def _double(self, e):
        if self._row_at(e.y) is not None:
            self._open()

    def _open(self):
        if self.on_open and self.selected():
            self.on_open(self.selected())

    def _move(self, d):
        if not self.rows:
            return
        self.sel = 0 if self.sel is None else max(0, min(len(self.rows) - 1, self.sel + d))
        y0 = self.sel * self.row_h
        vis = self.winfo_height() - self.head_h
        if y0 < self.offset:
            self.offset = y0
        elif y0 + self.row_h > self.offset + vis:
            self.offset = y0 + self.row_h - vis
        self.redraw()

    def _scroll(self, d):
        self.offset = max(0, min(self._max_offset(), self.offset + d * self.row_h))
        self.redraw()
        return "break"

# ----------------------------------------------------------------- карта маршрута


def _bezier(p0, p1, p2, n=48):
    return [((1 - t) ** 2 * p0[0] + 2 * (1 - t) * t * p1[0] + t * t * p2[0],
             (1 - t) ** 2 * p0[1] + 2 * (1 - t) * t * p1[1] + t * t * p2[1])
            for t in (i / n for i in range(n + 1))]


def _flat(pts):
    return [v for p in pts for v in p]


def _along(pts, frac):
    """Точка на ломаной на доле frac её длины."""
    seg = [math.dist(a, b) for a, b in zip(pts, pts[1:])]
    target, acc = sum(seg) * frac, 0.0
    for (a, b), s in zip(zip(pts, pts[1:]), seg):
        if acc + s >= target and s > 0:
            t = (target - acc) / s
            return a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t
        acc += s
    return pts[-1]


_CASES = {1: [(3, 2)], 2: [(2, 1)], 3: [(3, 1)], 4: [(0, 1)], 5: [(3, 0), (2, 1)], 6: [(0, 2)], 7: [(3, 0)],
          8: [(3, 0)], 9: [(0, 2)], 10: [(0, 1), (3, 2)], 11: [(0, 1)], 12: [(3, 1)], 13: [(2, 1)], 14: [(3, 2)]}


def contour_segments(w, h, seed=1729, nx=70, ny=24):
    """Горизонтали «рельефа» для фона карты: марширующие квадраты по сумме гауссовых холмов."""
    rnd = random.Random(seed)
    hills = [(rnd.uniform(-.1, 1.1) * w, rnd.uniform(-.2, 1.2) * h, rnd.uniform(.10, .26) * w,
              rnd.uniform(-.9, 1.3)) for _ in range(8)]
    dx, dy = w / nx, h / ny
    field = [[sum(a * math.exp(-((i * dx - cx) ** 2 + (j * dy - cy) ** 2) / (2 * s * s)) for cx, cy, s, a in hills)
              for i in range(nx + 1)] for j in range(ny + 1)]
    segs = []
    for lvl in [-0.75 + k * 0.16 for k in range(14)]:
        for j in range(ny):
            for i in range(nx):
                v = (field[j][i], field[j][i + 1], field[j + 1][i + 1], field[j + 1][i])
                idx = (v[0] > lvl) * 8 + (v[1] > lvl) * 4 + (v[2] > lvl) * 2 + (v[3] > lvl)
                if idx in (0, 15):
                    continue
                x, y = i * dx, j * dy

                def edge(e):
                    a, b = ((0, 1), (1, 2), (3, 2), (0, 3))[e]
                    t = (lvl - v[a]) / ((v[b] - v[a]) or 1e-9)
                    corners = ((x, y), (x + dx, y), (x + dx, y + dy), (x, y + dy))
                    (ax, ay), (bx, by) = corners[a], corners[b]
                    return ax + (bx - ax) * t, ay + (by - ay) * t
                for e1, e2 in _CASES[idx]:
                    segs.append(edge(e1) + edge(e2))
    return segs


class RouteMap(tk.Canvas):
    """Главный экран: маршрут «Этот ПК → узел WARP → сервер игры» на тактической карте.

    Через WARP — янтарная линия (сплошная, когда туннель работает, по ней бегут пакеты),
    напрямую — стальная дуга снизу. На участках — измеренные задержки.
    """

    def __init__(self, parent, height=232):
        super().__init__(parent, bg=T.BOARD, highlightthickness=0, bd=0, height=px(height))
        self.route, self.state, self.has_profile, self.colo = {}, "off", False, ""
        self._contour_cache = (None, [])
        self._dots, self._path, self._phase, self._anim, self._pending = [], [], 0.0, None, None
        self.bind("<Configure>", lambda e: self._schedule())

    def show(self, route=None, state=None, has_profile=None, colo=None):
        if route is not None:
            self.route = route
        if state is not None:
            self.state = state
        if has_profile is not None:
            self.has_profile = has_profile
        if colo is not None:
            self.colo = colo
        self._schedule()

    def _schedule(self):
        if self._pending:
            self.after_cancel(self._pending)
        self._pending = self.after(30, self._draw)

    def _pill(self, x, y, text, color, bg=T.BOARD):
        f = T.F["num"]
        tw, th = f.measure(text), f.metrics("linespace")
        self.create_rectangle(x - tw / 2 - px(7), y - th / 2 - px(2), x + tw / 2 + px(7), y + th / 2 + px(2),
                              fill=bg, outline=T.mix(bg, color, .45))
        self.create_text(x, y, text=text, fill=color, font=f)

    def _dotted(self, pts, color, gap=9, size=2):
        step, s = px(gap), px(size)
        seg = [math.dist(a, b) for a, b in zip(pts, pts[1:])]
        total = sum(seg)
        d = step / 2
        while d < total:
            x, y = _along(pts, d / total)
            self.create_rectangle(x - s, y - s, x + s, y + s, fill=color, outline="")
            d += step

    def _draw(self):
        self._pending = None
        self.delete("all")
        self._dots = []
        w, h = self.winfo_width(), self.winfo_height()
        if w < 50:
            return
        if self._contour_cache[0] != (w, h):
            self._contour_cache = ((w, h), contour_segments(w, h))
        for s in self._contour_cache[1]:
            self.create_line(*s, fill=T.CONTOUR)
        r = self.route or {}
        on = self.state == "on"
        live = r.get("live") if on else None
        total = live if live is not None else r.get("warp")
        leg1 = r.get("leg1")
        leg2 = max(1, total - leg1) if (total is not None and leg1 is not None) else None
        blocked = r.get("handshake") is False or (r.get("handshake") and leg1 is None)

        P, W, S = (w * .12, h * .44), (w * .50, h * .30), (w * .88, h * .44)
        leg_a = _bezier(P, ((P[0] + W[0]) / 2, h * .22), W)
        leg_b = _bezier(W, ((W[0] + S[0]) / 2, h * .22), S)
        direct = _bezier(P, (w * .5, h * .86), S)
        self._path = leg_a + leg_b[1:]

        # прямой путь
        if on:
            self._dotted(direct, T.mix(T.BOARD, T.DIRECT, .55), gap=10, size=1)
        else:
            self.create_line(*_flat(direct), fill=T.DIRECT, width=px(2), capstyle="round")
        # путь через WARP
        if not self.has_profile:
            self._dotted(self._path, T.LINE, gap=10, size=1.5)
        elif blocked:
            self._dotted(leg_a, T.BAD, gap=8, size=1.5)
            self._dotted(leg_b, T.SIGNAL_DIM, gap=10, size=1.5)
            mx, my = _along(leg_a, .5)
            k = px(6)
            self.create_line(mx - k, my - k, mx + k, my + k, fill=T.BAD, width=px(2))
            self.create_line(mx - k, my + k, mx + k, my - k, fill=T.BAD, width=px(2))
        elif on:
            self.create_line(*_flat(self._path), fill=T.SIGNAL, width=px(3), capstyle="round", joinstyle="round")
        else:
            self._dotted(self._path, T.SIGNAL_DIM if self.state == "off" else T.SIGNAL, gap=9, size=1.5)

        # подписи участков
        warp_col = T.SIGNAL if on else (T.mix(T.SIGNAL, T.MUTED, .35) if self.has_profile else T.FAINT)
        if self.has_profile and not blocked:
            x, y = _along(leg_a, .5)
            self._pill(x, y - px(18), f"{leg1} мс" if leg1 is not None else "—", warp_col)
            x, y = _along(leg_b, .5)
            self._pill(x, y - px(18), f"{leg2} мс" if leg2 is not None else "—", warp_col)
        elif blocked:
            x, y = _along(leg_a, .5)
            self.create_text(x, y - px(22), text="WARP не отвечает", fill=T.BAD, font=T.F["small"])
        x, y = _along(direct, .5)
        dcol = T.DIRECT if not on else T.FAINT
        dtext = f"напрямую {r['direct']} мс" if r.get("direct") is not None else "напрямую —"
        f = T.F["num"]
        self.create_rectangle(x - f.measure(dtext) / 2 - px(8), y - px(12), x + f.measure(dtext) / 2 + px(8),
                              y + px(12), fill=T.BOARD, outline="")
        self.create_text(x, y, text=dtext, fill=dcol, font=f)

        # узлы
        self._node_pc(P)
        self._node_warp(W, on, blocked)
        self._node_server(S)
        self._label(P, "Этот ПК", "")
        sub = self.colo or ("узел WARP" if self.has_profile else "нет профиля")
        self._label(W, "WARP", sub, above=True)
        self._label(S, "Сервер игры", r.get("server") or "пока не найден")
        if total is not None and self.has_profile and not blocked:
            self.create_text(S[0], S[1] - px(52), text=f"{total} мс", fill=warp_col, font=T.F["num_lg"])
            self.create_text(S[0], S[1] - px(32), text="сейчас через туннель" if live is not None else "через WARP",
                             fill=T.FAINT, font=T.F["small"])

        # легенда
        lx, ly = px(18), h - px(18)
        self.create_line(lx, ly, lx + px(22), ly, fill=T.SIGNAL, width=px(3))
        self.create_text(lx + px(30), ly, text="через WARP", anchor="w", fill=T.MUTED, font=T.F["small"])
        lx2 = lx + px(30) + T.F["small"].measure("через WARP") + px(20)
        self.create_line(lx2, ly, lx2 + px(22), ly, fill=T.DIRECT, width=px(2))
        self.create_text(lx2 + px(30), ly, text="напрямую", anchor="w", fill=T.MUTED, font=T.F["small"])

        if on and self.has_profile and not blocked and not T.REDUCED_MOTION:
            s = px(2.5)
            self._dots = [self.create_rectangle(0, 0, s, s, fill=T.SIGNAL_HI, outline="") for _ in range(4)]
            self._tick()
        elif self._anim:
            self.after_cancel(self._anim)
            self._anim = None

    def _label(self, p, title, sub, above=False):
        x, y = p
        ty = y - px(38) if above else y + px(26)
        self.create_text(x, ty, text=title, fill=T.TEXT, font=T.F["map_title"])
        if sub:
            self.create_text(x, ty + px(18), text=sub, fill=T.MUTED, font=T.F["small"])

    def _node_pc(self, p):
        x, y = p
        r = px(9)
        self.create_oval(x - r, y - r, x + r, y + r, outline=T.TEXT, width=px(2), fill=T.BOARD)
        self.create_oval(x - px(3), y - px(3), x + px(3), y + px(3), fill=T.TEXT, outline="")

    def _node_warp(self, p, on, blocked):
        x, y = p
        r = px(11)
        col = T.BAD if blocked else (T.SIGNAL if on else (T.TEXT if self.has_profile else T.FAINT))
        self.create_polygon(x, y - r, x + r, y, x, y + r, x - r, y, fill=T.BOARD, outline=col, width=px(2))
        if on and not blocked:
            k = px(4)
            self.create_polygon(x, y - k, x + k, y, x, y + k, x - k, y, fill=T.SIGNAL, outline="")

    def _node_server(self, p):
        x, y = p
        r, t = px(8), px(5)
        self.create_rectangle(x - r, y - r, x + r, y + r, outline=T.TEXT, width=px(2), fill=T.BOARD)
        for sx, sy in ((-1, -1), (1, -1), (1, 1), (-1, 1)):  # уголки прицела
            cx, cy = x + sx * (r + px(5)), y + sy * (r + px(5))
            self.create_line(cx, cy, cx - sx * t, cy, fill=T.MUTED)
            self.create_line(cx, cy, cx, cy - sy * t, fill=T.MUTED)

    def _tick(self):
        if not self._dots or not self._path:
            self._anim = None
            return
        self._phase = (self._phase + 0.0045) % 1.0
        s = px(2.5)
        for k, item in enumerate(self._dots):
            x, y = _along(self._path, (self._phase + k / len(self._dots)) % 1.0)
            self.coords(item, x - s, y - s, x + s, y + s)
        self._anim = self.after(33, self._tick)

# ----------------------------------------------------------------- прочее


class Progress(tk.Canvas):
    """Тонкая линия хода операции: с долей — заполняется, без неё — бегущий отрезок."""

    def __init__(self, parent):
        super().__init__(parent, bg=parent["bg"], height=px(2), highlightthickness=0, bd=0)
        self.done = self.total = 0
        self.active, self._anim, self._x = False, None, 0.0

    def set(self, active, done=0, total=0):
        self.active, self.done, self.total = active, done, total
        self._draw()
        if active and not total and not self._anim and not T.REDUCED_MOTION:
            self._spin()

    def _draw(self):
        self.delete("all")
        w = self.winfo_width()
        if not self.active:
            return
        if self.total:
            self.create_rectangle(0, 0, w * min(1, self.done / self.total), px(2), fill=T.SIGNAL, outline="")
        else:
            x = self._x * (w + w * .25) - w * .25
            self.create_rectangle(max(0, x), 0, min(w, x + w * .25), px(2), fill=T.SIGNAL, outline="")

    def _spin(self):
        if not self.active or self.total:
            self._anim = None
            return
        self._x = (self._x + 0.012) % 1.0
        self._draw()
        self._anim = self.after(16, self._spin)


class StatusGlyph(tk.Canvas):
    """Значок шага диагностики: ✓, !, ✕ или пустой круг — нарисован, а не взят из шрифта."""

    COLORS = {"ok": T.GOOD, "warn": T.CAUTION, "bad": T.BAD, "idle": T.FAINT}

    def __init__(self, parent, status):
        s = px(18)
        super().__init__(parent, width=s, height=s, bg=parent["bg"], highlightthickness=0)
        c, k = self.COLORS.get(status, T.FAINT), max(2, px(2))
        if status == "ok":
            self.create_line(px(3), px(9), px(7), px(13), px(15), px(4), fill=c, width=k)
        elif status == "bad":
            self.create_line(px(4), px(4), px(14), px(14), fill=c, width=k)
            self.create_line(px(4), px(14), px(14), px(4), fill=c, width=k)
        elif status == "warn":
            self.create_line(px(9), px(2), px(9), px(11), fill=c, width=k)
            self.create_rectangle(px(8), px(14), px(10), px(16), fill=c, outline="")
        else:
            self.create_oval(px(3), px(3), px(15), px(15), outline=c, width=1)


def style_scrollbar(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure("Slim.Vertical.TScrollbar", troughcolor=T.INK, background=T.LINE, bordercolor=T.INK,
                lightcolor=T.LINE, darkcolor=T.LINE, arrowcolor=T.MUTED, gripcount=0, arrowsize=px(10))
    s.map("Slim.Vertical.TScrollbar", background=[("active", T.FAINT)])
    s.configure("Dark.TCombobox", fieldbackground=T.RAISE, background=T.RAISE, foreground=T.TEXT,
                arrowcolor=T.TEXT, bordercolor=T.LINE, lightcolor=T.RAISE, darkcolor=T.RAISE,
                selectbackground=T.RAISE, selectforeground=T.TEXT)
    s.map("Dark.TCombobox", fieldbackground=[("readonly", T.RAISE)], foreground=[("readonly", T.TEXT)],
          selectbackground=[("readonly", T.RAISE)], selectforeground=[("readonly", T.TEXT)])
    root.option_add("*TCombobox*Listbox.background", T.RAISE)
    root.option_add("*TCombobox*Listbox.foreground", T.TEXT)
    root.option_add("*TCombobox*Listbox.selectBackground", T.LINE)
    root.option_add("*TCombobox*Listbox.selectForeground", T.TEXT)


class ScrollPage(tk.Frame):
    """Страница с вертикальной прокруткой, полоса появляется только когда нужна."""

    def __init__(self, parent, bg):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, bd=0)
        self.body = tk.Frame(self.canvas, bg=bg)
        self.win = self.canvas.create_window(0, 0, anchor="nw", window=self.body)
        self.sb = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview,
                                style="Slim.Vertical.TScrollbar")
        self.canvas.configure(yscrollcommand=self.sb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body.bind("<Configure>", lambda e: self._update())
        self.canvas.bind("<Configure>", self._on_canvas)
        self.bind("<Enter>", lambda e: self.bind_all("<MouseWheel>", self._wheel))
        self.bind("<Leave>", lambda e: self.unbind_all("<MouseWheel>"))

    def _on_canvas(self, e):
        self.canvas.itemconfigure(self.win, width=e.width)
        self._update()

    def _update(self):
        self.canvas.configure(scrollregion=(0, 0, self.body.winfo_reqwidth(), self.body.winfo_reqheight()))
        need = self.body.winfo_reqheight() > self.canvas.winfo_height() + 2
        if need and not self.sb.winfo_ismapped():
            self.sb.pack(side="right", fill="y")
        elif not need and self.sb.winfo_ismapped():
            self.sb.pack_forget()
            self.canvas.yview_moveto(0)

    def _wheel(self, e):
        if isinstance(e.widget, (Table, tk.Text)) or not self.sb.winfo_ismapped():
            return
        self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
