# -*- coding: utf-8 -*-
"""Логика ABI Route без интерфейса: профиль WARP, замеры, автоподбор, туннель, фоновый контроль.

Интерфейс получает события через emit(kind, **data); все долгие операции идут в фоне.
"""
import ipaddress
import os
import random
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import net, tunnel, warp, wg
from .common import in_nets, normalize_ranges, split_endpoint
from .settings import CONF_PATH, load_settings, save_settings

COLO_CITY = {
    "AMS": "Амстердам", "ARN": "Стокгольм", "ATH": "Афины", "BCN": "Барселона", "BEG": "Белград",
    "BER": "Берлин", "BRU": "Брюссель", "BUD": "Будапешт", "CDG": "Париж", "CPH": "Копенгаген",
    "DME": "Москва", "DUB": "Дублин", "DUS": "Дюссельдорф", "EVN": "Ереван", "FCO": "Рим",
    "FRA": "Франкфурт", "GVA": "Женева", "GYD": "Баку", "HAM": "Гамбург", "HEL": "Хельсинки",
    "IST": "Стамбул", "KBP": "Киев", "KIV": "Кишинёв", "KJA": "Красноярск", "KZN": "Казань",
    "LED": "Петербург", "LHR": "Лондон", "LIS": "Лиссабон", "MAD": "Мадрид", "MAN": "Манчестер",
    "MRS": "Марсель", "MSQ": "Минск", "MUC": "Мюнхен", "MXP": "Милан", "OSL": "Осло", "OTP": "Бухарест",
    "OVB": "Новосибирск", "PRG": "Прага", "RIX": "Рига", "SOF": "София", "SVX": "Екатеринбург",
    "TBS": "Тбилиси", "TLL": "Таллин", "VIE": "Вена", "VNO": "Вильнюс", "WAW": "Варшава",
    "ZRH": "Цюрих", "ALA": "Алматы", "NQZ": "Астана", "TAS": "Ташкент", "HKG": "Гонконг",
    "SIN": "Сингапур", "NRT": "Токио", "ICN": "Сеул", "DXB": "Дубай", "ORD": "Чикаго",
    "IAD": "Вашингтон", "EWR": "Нью-Йорк", "LAX": "Лос-Анджелес", "SJC": "Сан-Хосе", "DFW": "Даллас",
}


def colo_name(code):
    return COLO_CITY.get(code or "", code or "")


class Engine:
    def __init__(self, emit, settings=None, client="auto"):
        self.emit = emit
        self.st = settings if settings is not None else load_settings()
        self.lock = threading.RLock()
        self.client = tunnel.find_client() if client == "auto" else client
        self.running = self.armed = self.pending = False
        self.busy = None
        self.cancel = threading.Event()
        self.last_restart = self.last_failover = self.started_at = 0.0
        self.fails = 0
        self.results = {ip: dict(v) for ip, v in (self.st.get("compare") or {}).items()}
        self.route = {}
        self.stats = None
        self.verify = [tuple(t) for t in self.st.get("verify_targets", [])]

    # ---------------------------------------------------------------- инфраструктура
    def log(self, text, level="info"):
        self.emit("log", text=text, level=level, t=time.strftime("%H:%M:%S"))

    def save(self):
        with self.lock:
            save_settings(self.st)

    def task(self, name, fn):
        """Запускает долгую операцию в фоне; одновременно — только одна."""
        with self.lock:
            if self.busy:
                self.log(f"Подождите: ещё идёт «{self.busy}».", "warn")
                return False
            self.busy = name
        self.cancel.clear()
        self.emit("busy", name=name)

        def run():
            try:
                fn()
            except Exception as e:  # noqa: BLE001 — показать пользователю, а не уронить поток
                self.log(f"Ошибка: {e}", "bad")
            finally:
                with self.lock:
                    self.busy = None
                self.emit("busy", name=None)
                self.emit("progress", done=0, total=0, label="")
        threading.Thread(target=run, daemon=True).start()
        return True

    def progress(self, done, total, label=""):
        self.emit("progress", done=done, total=total, label=label)

    @property
    def profile(self):
        return self.st.get("warp")

    @property
    def obf(self):
        """Маскировка, которую реально применит установленный клиент. Пробы шлют ровно её,
        иначе проба пройдёт там, где настоящий туннель заблокируют."""
        o = dict(self.st.get("obf") or {})
        c = self.client
        if c and c.get("kind") == "wg":
            return dict(warp.PRESET_BY_ID["none"]["obf"])
        if c and not c.get("cps"):
            o = {k: v for k, v in o.items() if not k.startswith("I")}
        return o

    @property
    def cps_ok(self):
        return bool(self.client and self.client.get("cps"))

    @property
    def plain_wg(self):
        return bool(self.client and self.client.get("kind") == "wg")

    def _effective_preset(self):
        """Текущая маскировка с id, который соответствует её действительным параметрам."""
        obf = self.obf
        if obf == dict(self.st.get("obf") or {}):
            return {"id": self.st.get("obf_id"), "obf": obf}
        match = next((p for p in warp.OBF_PRESETS if p["obf"] == obf), None)
        return {"id": match["id"] if match else "custom", "obf": obf}

    def preset_name(self):
        if self.plain_wg:
            return "нет (WireGuard)"
        p = warp.PRESET_BY_ID.get(self._effective_preset()["id"])
        return p["name"] if p else "своя (из конфига)"

    def set_state(self, state):
        self.emit("state", state=state)

    # ---------------------------------------------------------------- запуск
    def startup(self):
        from . import VERSION
        self.log(f"ABI Route {VERSION} запущен.")
        if os.name == "nt" and not tunnel.is_admin():
            self.log("Нет прав администратора — туннель не запустится. Запустите программу от имени "
                     "администратора.", "bad")
        c = self.client
        if not c:
            self.log("Не найден AmneziaWG. Установите его: github.com/amnezia-vpn/amneziawg-windows-client"
                     "/releases (WireGuard тоже подойдёт, но без маскировки).", "bad")
        else:
            if c["kind"] == "awg":
                note = ("маскировка I1 (QUIC, SIP, DNS) доступна" if c["cps"] else
                        "обновите до 2.0 или новее, чтобы открыть маскировку QUIC, SIP и DNS")
                self.log(f"Клиент туннеля: AmneziaWG {tunnel.version_str(c['version'])} — {note}.")
            else:
                self.log("Клиент туннеля: WireGuard — без маскировки. Для России лучше AmneziaWG.", "warn")
            if c["kind"] == "awg" and not self.cps_ok and warp.needs_cps(self.st.get("obf")):
                self.log("Выбранная маскировка требует AmneziaWG 2.0+. Пока туннель пойдёт без I1.", "warn")
            if tunnel.tunnel_running(c["kind"]):
                self.running = True
                self.started_at = time.time()
                self.set_state("on")
                self.log("Туннель уже работает в фоне.")
        if net.psutil is None:
            self.log("Не установлен psutil — автопоиск серверов игры недоступен.", "warn")
        threading.Thread(target=self._watch, daemon=True).start()

    # ---------------------------------------------------------------- профиль WARP
    def generate(self):
        def job():
            self.log("Регистрирую профиль Cloudflare WARP…")
            try:
                prof = warp.register()
            except warp.WarpError as e:
                self.log(str(e), "bad")
                return
            with self.lock:
                self.st["warp"] = prof
            self.save()
            self.emit("refresh")
            self.log(f"Профиль готов, адрес в WARP {prof['v4']}. Дальше — «Найти сервер».", "ok")
            self._restart_if_running()
        self.task("Регистрация WARP", job)

    def import_conf(self, text):
        try:
            prof, extra = warp.parse_conf(text)
        except ValueError as e:
            self.log(f"Импорт не удался: {e}", "bad")
            return False
        with self.lock:
            self.st["warp"] = prof
            if extra["endpoint"]:
                self.st["endpoint"] = extra["endpoint"]
            if extra["obf"]:
                self.st["obf"], self.st["obf_id"] = extra["obf"], "custom"
            if extra["mtu"]:
                self.st["mtu"] = max(1200, min(1420, extra["mtu"]))
        self.save()
        self.emit("refresh")
        parts = [f"адрес в WARP {prof['v4']}"]
        if extra["endpoint"]:
            parts.append(f"сервер {extra['endpoint']}")
        if extra["obf"]:
            parts.append("маскировка из конфига")
        self.log("Конфиг импортирован: " + ", ".join(parts) + ".", "ok")
        if extra["obf"] and warp.needs_cps(extra["obf"]) and not self.cps_ok:
            self.log("В конфиге есть I1–I5, а установленный AmneziaWG их не понимает — обновите его до 2.0+.",
                     "warn")
        self._restart_if_running()
        return True

    # ---------------------------------------------------------------- серверы WARP
    def _probe(self, ep, obf, targets=(), count=3, tries=2):
        r = None
        for _ in range(tries):
            r = wg.probe(self.profile, ep, obf, targets, count)
            if r["handshake"] is not None:
                break
        return r

    def scan(self):
        if not self.profile:
            self.log("Сначала создайте или импортируйте профиль WARP.", "warn")
            return
        self.task("Поиск сервера WARP", lambda: self._scan(self.obf))

    def _scan(self, obf, cands=None, quiet=False, commit=True):
        """Рукопожатие со ~400 серверами, затем реальный пинг до узла у лучших. -> [(ep, мс, colo)].

        commit=False — только узнать результат, не меняя выбранный сервер.
        """
        cands = cands or (warp.candidate_endpoints() + [self.st["endpoint"]]
                          + [e[0] for e in self.st.get("endpoint_list", [])])
        cands = list(dict.fromkeys(cands))
        if not quiet:
            self.log(f"Проверяю {len(cands)} серверов WARP рукопожатием (маскировка «{self.preset_name()}»)…")
        # сотни рукопожатий подряд: больше 8 мусорных пакетов на каждое — уже флуд, а провайдер
        # решает по первым пакетам соединения
        scan_obf = dict(obf or {}, Jc=min(int((obf or {}).get("Jc", 0) or 0), 8))
        ok = wg.scan(self.profile, cands, scan_obf, workers=64, timeout=1.2, stop=self.cancel,
                     progress=lambda d, t: self.progress(d, t, "Рукопожатия"))
        if not ok:
            if not quiet:
                self.log("Ни один сервер WARP не ответил на рукопожатие: провайдер блокирует WARP с этой "
                         "маскировкой. Нажмите «Автоподбор» — он переберёт варианты.", "bad")
            return []
        top = warp.spread([ep for ep, _ in ok], 8)
        targets = [ip for ip, _ in self.verify][:2]
        refined = []
        for i, ep in enumerate(top, 1):
            self.progress(i, len(top), "Пинг до узла")
            r = self._probe(ep, obf, targets, count=3, tries=1)
            game = [v["ms"] for v in r["targets"].values() if v]
            refined.append((ep, r["data"], r["colo"], min(game) if game else None))
        refined.sort(key=lambda x: (x[1] is None, x[3] if x[3] is not None else 9999, x[1] or 9999))
        rest = [(ep, None, None) for ep, _ in ok if ep not in top]
        lst = [(ep, ms, colo) for ep, ms, colo, _ in refined] + rest
        if refined and refined[0][1] is not None and commit:
            best = refined[0]
            with self.lock:
                self.st["endpoint_list"] = [list(x) for x in lst[:15]]
                self.st["endpoint"], self.st["colo"] = best[0], best[2]
            self.save()
            self.emit("refresh")
            if not quiet:
                where = f", узел {colo_name(best[2])}" if best[2] else ""
                self.log(f"Ответили {len(ok)} из {len(cands)}. Выбран {best[0]}: до узла {best[1]} мс{where}. "
                         f"Ещё {min(len(lst), 15) - 1} в запасе для автосмены.", "ok")
            self._restart_if_running()
        elif not quiet:
            self.log("Рукопожатие проходит, но данные через WARP не идут ни на одном сервере — провайдер "
                     "режет трафик после рукопожатия. Нажмите «Автоподбор».", "bad")
        return lst

    def pick_endpoint(self, ep):
        with self.lock:
            self.st["endpoint"] = ep
            for e in self.st.get("endpoint_list", []):
                if e[0] == ep:
                    self.st["colo"] = e[2]
        self.save()
        self.emit("refresh")
        self.log(f"Выбран сервер WARP {ep}.")
        self._restart_if_running()

    def set_preset(self, preset_id):
        p = warp.PRESET_BY_ID.get(preset_id)
        if not p:
            return
        with self.lock:
            self.st["obf_id"], self.st["obf"] = preset_id, dict(p["obf"])
        self.save()
        self.emit("refresh")
        note = " AmneziaWG этой версии не понимает I1 — нужен 2.0 или новее." if (
            warp.needs_cps(p["obf"]) and not self.cps_ok) else ""
        self.log(f"Маскировка: {p['name']}.{note}", "warn" if note else "info")
        self._restart_if_running()

    # ---------------------------------------------------------------- замеры
    def targets(self, n=8):
        """Адреса серверов игры для замеров: увиденные у игры, а если их нет — первые адреса диапазонов."""
        with self.lock:
            ports = self.st.get("tcp_ports", {})
            ign = self.st.get("ignore_ranges", [])
            ranges = list(self.st["ranges"])
            seen = [ip for ip in self.st.get("seen_ips", []) if not in_nets(ip, ign)]
        seen.sort(key=lambda ip: (not in_nets(ip, ranges), not ports.get(ip)))
        if seen:
            return seen[:n]
        ips = []
        for r in ranges[:n]:
            try:
                host = str(next(iter(ipaddress.ip_network(r, strict=False).hosts())))
            except (ValueError, StopIteration):
                continue
            if not in_nets(host, ign):
                ips.append(host)
        return ips

    def _direct_source(self):
        """Пока туннель работает, «напрямую» меряем с адреса физического адаптера."""
        return net.local_ip_for(split_endpoint(self.st["endpoint"])[0]) if self.running else None

    def compare(self):
        def job():
            ips = self.targets()
            if not ips:
                self.log("Пока нет серверов игры. Запустите игру или добавьте готовый список на вкладке "
                         "«Серверы игры».", "warn")
                return
            self.log(f"Сравниваю пинг до {len(ips)} серверов игры: напрямую и через WARP…")
            src = self._direct_source()
            ports = dict(self.st.get("tcp_ports", {}))
            self.progress(1, 3, "Замер")
            with ThreadPoolExecutor(max_workers=10) as ex:
                direct_f = [ex.submit(net.direct_ping, ip, ports.get(ip), 5, src) for ip in ips]
                warp_f = ex.submit(self._measure_warp, ips) if self.profile else None
                direct = {ip: f.result() for ip, f in zip(ips, direct_f)}
                wres = warp_f.result() if warp_f else None
            self.progress(3, 3, "Замер")
            for ip in ips:
                self.results[ip] = {"direct": direct[ip],
                                    "warp": (wres["targets"].get(ip) if wres and wres["data"] is not None
                                             else None),
                                    "warp_tested": wres is not None}
            self._remember_verify(ips, direct)
            self._store_results()
            self._update_route(wres, direct)
            self.emit("compare", results=dict(self.results))
            self._explain(wres, direct)
        self.task("Сравнение пинга", job)

    def _measure_warp(self, ips):
        """Пинг через WARP своим клиентом; если текущий сервер молчит — пробует запасные."""
        eps = [self.st["endpoint"]] + [e[0] for e in self.st.get("endpoint_list", []) if e[0] != self.st["endpoint"]]
        r = None
        for ep in eps[:3]:
            r = self._probe(ep, self.obf, ips, count=5)
            if r["handshake"] is not None:
                if ep != self.st["endpoint"]:
                    self.log(f"Текущий сервер WARP не ответил, замер шёл через запасной {ep}.", "warn")
                break
        return r

    def _remember_verify(self, ips, direct):
        good = [(ip, 0) for ip in ips if direct.get(ip) and direct[ip]["how"] == "ICMP"
                and in_nets(ip, self.st["ranges"])][:4]
        if good:
            self.verify = good
            with self.lock:
                self.st["verify_targets"] = [list(t) for t in good]
            self.save()

    def _store_results(self):
        keep = list(self.results.items())[-12:]
        self.results = dict(keep)
        with self.lock:
            self.st["compare"] = {ip: {k: v for k, v in rr.items()} for ip, rr in keep}
        self.save()

    def _update_route(self, wres, direct):
        """Данные для схемы маршрута: этот ПК → узел WARP → сервер игры."""
        main = next((ip for ip in direct if direct[ip] and wres and wres["targets"].get(ip)), None) \
            or next((ip for ip in direct if direct[ip]), None)
        route = dict(self.route)
        route["server"] = main
        route["direct"] = direct.get(main)["ms"] if main and direct.get(main) else None
        if wres:
            route["leg1"] = wres["data"]
            route["colo"] = wres["colo"] or self.st.get("colo")
            w = wres["targets"].get(main) if main else None
            route["warp"] = w["ms"] if w and wres["data"] is not None else None
            route["handshake"] = wres["handshake"] is not None
            if wres["colo"]:
                with self.lock:
                    self.st["colo"] = wres["colo"]
        self.route = route
        self.emit("route", route=dict(route))

    def _explain(self, wres, direct):
        d_ok = [ip for ip, v in direct.items() if v]
        if wres is None:
            self.log("Пинг через WARP не мерился: нет профиля WARP.", "warn")
            return
        if wres["handshake"] is None:
            self.log("Через WARP — нет ответа: сервер WARP не принимает рукопожатие. Скорее всего, провайдер "
                     "блокирует WARP с текущей маскировкой. Нажмите «Автоподбор».", "bad")
            return
        if wres["data"] is None:
            self.log("Рукопожатие с WARP проходит, но данные обратно не возвращаются — провайдер режет "
                     "трафик после рукопожатия. «Автоподбор» попробует другую маскировку.", "bad")
            return
        pairs = [(v["ms"], self.results[ip]["warp"]["ms"]) for ip, v in direct.items()
                 if v and self.results[ip].get("warp")]
        where = f" (узел {colo_name(wres['colo'])})" if wres.get("colo") else ""
        if not pairs:
            if d_ok:
                self.log("WARP работает, но серверы игры не отвечают через него на ICMP — сравнить нельзя. "
                         "Это не значит, что игра не пойдёт.", "warn")
            return
        diff = round(statistics.median([w - d for d, w in pairs]))
        if diff < -2:
            self.log(f"Через WARP{where} быстрее на {-diff} мс (медиана по {len(pairs)} серверам).", "ok")
        elif diff > 2:
            self.log(f"Через WARP{where} медленнее на {diff} мс. Если игра работает и напрямую — туннель можно "
                     "не включать; или попробуйте «Найти сервер».", "warn")
        else:
            self.log(f"Через WARP{where} пинг тот же, что напрямую (разница {diff:+d} мс).", "ok")

    # ---------------------------------------------------------------- туннель
    def toggle(self):
        if self.running or self.armed:
            self.task("Остановка", self._stop)
            return
        c = self.client
        if not c:
            self.log("Не найден AmneziaWG или WireGuard — установите AmneziaWG и перезапустите программу.",
                     "bad")
            return
        if not self.profile:
            self.log("Сначала создайте или импортируйте профиль WARP (вкладка «WARP»).", "warn")
            return
        if not self.st["ranges"]:
            if not self.st["auto_learn"]:
                self.log("Добавьте серверы игры на вкладке «Серверы игры» или включите автопоиск.", "warn")
                return
            self.armed = True
            self.set_state("wait")
            self.log("Запустите Arena Breakout Infinite — туннель включится, как только появятся её серверы.")
            return
        self.task("Запуск туннеля", self._apply)

    def _restart_if_running(self):
        if self.running:
            self.pending = True
            self.last_restart = 0

    def _conf(self):
        with self.lock:
            return warp.build_conf(self.profile, self.st["endpoint"], self.st["ranges"], self.obf,
                                   self.client["kind"], self.cps_ok, self.st.get("mtu", 1280))

    def _apply(self):
        conf = self._conf()
        n = len(normalize_ranges(self.st["ranges"]))
        self.last_restart = time.time()
        self.set_state("starting")
        ok, err = tunnel.tunnel_up(self.client["exe"], self.client["kind"], conf, CONF_PATH)
        if not ok:
            self.running = False
            self.set_state("off")
            self.log(f"Туннель не запустился: {err}", "bad")
            return False
        self.running, self.armed = True, False
        self.started_at = time.time()
        self.fails = 0
        self.set_state("on")
        self.log(f"Туннель включён: {n} диапазон(ов) игры идут через WARP {self.st['endpoint']}, "
                 "остальной трафик — напрямую.", "ok")
        threading.Thread(target=self._confirm, daemon=True).start()
        return True

    def _confirm(self):
        """Через пару секунд после запуска убеждаемся, что через системный туннель есть ответ."""
        time.sleep(3)
        live = self._live_ping()
        if live is None:
            self.log("Системный туннель пока не пропускает трафик — проверю ещё раз через 20 секунд. "
                     "Если не заработает, включится автосмена.", "warn")
        elif live.get("ms") is not None:
            self.log(f"Проверено: сервер игры отвечает через туннель за {live['ms']} мс.", "ok")

    def _live_ping(self):
        """Пинг через работающий системный туннель. -> {"ms"} | {"alive": True} | None."""
        tgt = [ip for ip, _ in self.verify if in_nets(ip, self.st["ranges"])] or \
            [ip for ip in self.targets(3) if in_nets(ip, self.st["ranges"])]
        if not tgt:
            return {"alive": True, "ms": None}
        for ip in tgt[:2]:
            r = net.icmp_ping(ip, 3, timeout_ms=1200, interval=0.1)
            if r:
                self.route = dict(self.route, live=r["ms"], server=self.route.get("server") or ip)
                self.emit("route", route=dict(self.route))
                return {"ms": r["ms"]}
        # ICMP молчит: проверяем, что туннель вообще пропускает данные (TCP отвечает узел Cloudflare)
        port = self.st.get("tcp_ports", {}).get(tgt[0]) or 443
        return {"alive": True, "ms": None} if net.tcp_ping(tgt[0], port, 1, timeout=1.5) else None

    def _stop(self):
        self.armed = False
        tunnel.tunnel_down(self.client["exe"] if self.client else None)
        self.running = False
        self.route = {k: v for k, v in self.route.items() if k != "live"}
        self.set_state("off")
        self.emit("route", route=dict(self.route))
        self.log("Туннель остановлен.")

    # ---------------------------------------------------------------- автоподбор
    def _variants(self):
        """(сервер, маскировка) для перебора: текущее, затем другие серверы и маскировки,
        которые установленный клиент умеет применять."""
        eps = warp.spread([self.st["endpoint"]] + [e[0] for e in self.st.get("endpoint_list", [])], 3)
        if self.plain_wg:
            return eps, [warp.PRESET_BY_ID["none"]]
        cur = self._effective_preset()
        return eps, [cur] + [p for p in warp.presets_for(self.cps_ok) if p["obf"] != cur["obf"]]

    def autotune(self):
        if not self.profile:
            self.log("Для автоподбора нужен профиль WARP.", "warn")
            return
        self.task("Автоподбор", self._autotune)

    def _autotune(self):
        self.log("Автоподбор: ищу сервер и маскировку, с которыми данные идут через WARP. Туннель не "
                 "выключаю — проверка идёт отдельным соединением.")
        ips = self.targets(6)
        with ThreadPoolExecutor(max_workers=6) as ex:
            src = self._direct_source()
            direct = dict(zip(ips, ex.map(lambda ip: net.icmp_ping(ip, 2, source=src), ips)))
        tgt = [ip for ip, v in direct.items() if v][:3]
        if tgt:
            self.log("Проверяю по серверам игры: " + ", ".join(tgt))
        else:
            self.log("Серверы игры не отвечают на ICMP напрямую — главным признаком будет ответ узла "
                     "Cloudflare (1.1.1.1).")
        eps, presets = self._variants()
        found, stage = self._find_working(eps, presets, tgt or ips[:3], "Автоподбор", need_game=bool(tgt))
        if found:
            self._adopt(*found)
            return
        if stage == "nohs":
            self.log("Ни один вариант не прошёл рукопожатие — провайдер блокирует WARP полностью. Что "
                     "попробовать: раздать интернет с телефона и повторить; если там работает — дело в "
                     "провайдере.", "bad")
        else:
            self.log("Рукопожатие проходит, но данные режутся на всех вариантах. Попробуйте другую сеть "
                     "(например, мобильный интернет) или новый профиль WARP.", "bad")
        if not self.cps_ok and self.client and self.client["kind"] == "awg":
            self.log("Обновите AmneziaWG до 2.0+ — откроются ещё три вида маскировки (QUIC, SIP, DNS).", "warn")

    def _find_working(self, eps, presets, tgt, label, budget=None, need_game=True):
        """Перебор своим клиентом. -> ((ep, preset, мс|None, проба), стадия 'nohs' | 'nodata').

        need_game — успех только если через WARP ответил сервер игры (иначе хватит ответа 1.1.1.1).
        """
        stage = "nohs"
        total = len(eps) * len(presets)
        n = 0
        t_end = time.time() + budget if budget else None
        for p in presets:
            hs_any = False
            for ep in eps:
                if self.cancel.is_set() or (t_end and time.time() > t_end):
                    return None, stage
                n += 1
                self.progress(n, total, label)
                r = self._probe(ep, p["obf"], tgt, count=2)
                name = warp.PRESET_BY_ID.get(p.get("id"), {}).get("name", "своя")
                if r["handshake"] is None:
                    self.log(f"{label}: {name}, {ep} — нет рукопожатия")
                    continue
                hs_any = True
                stage = "nodata"
                if r["data"] is None:
                    self.log(f"{label}: {name}, {ep} — рукопожатие есть, данные не идут")
                    continue
                game = [v["ms"] for v in r["targets"].values() if v]
                if need_game and tgt and not game:
                    self.log(f"{label}: {name}, {ep} — WARP работает, но серверы игры через него молчат")
                    continue
                return (ep, p, min(game) if game else None, r), stage
            if not hs_any and not (t_end and time.time() > t_end):
                # с этой маскировкой не ответил ни один известный сервер — ищем другие
                lst = self._scan(p["obf"], cands=warp.candidate_endpoints()[:120], quiet=True, commit=False)
                for ep, ms, colo in lst[:2]:
                    if ms is not None:
                        r = self._probe(ep, p["obf"], tgt, count=2)
                        game = [v["ms"] for v in r["targets"].values() if v]
                        if r["data"] is not None and (game or not (need_game and tgt)):
                            return (ep, p, min(game) if game else None, r), "nodata"
        return None, stage

    def _adopt(self, ep, preset, ms, r):
        with self.lock:
            self.st["endpoint"] = ep
            self.st["obf"] = dict(preset["obf"])
            self.st["obf_id"] = preset.get("id") or "custom"
            if r.get("colo"):
                self.st["colo"] = r["colo"]
        self.save()
        self.route = dict(self.route, leg1=r["data"], colo=r.get("colo"), handshake=True)
        self.emit("route", route=dict(self.route))
        self.emit("refresh")
        name = warp.PRESET_BY_ID.get(preset.get("id"), {}).get("name", "своя")
        reply = (f"сервер игры отвечает через WARP за {ms} мс" if ms is not None else
                 f"узел Cloudflare отвечает за {r['data']} мс")
        self.log(f"Работает: WARP {ep}, маскировка «{name}», {reply}. Настройки сохранены.", "ok")
        if self.running:
            self._apply()

    # ---------------------------------------------------------------- диагностика
    def diagnose(self):
        self.task("Диагностика", self._diagnose)

    def _diagnose(self):
        items = []

        def add(key, status, title, detail=""):
            items.append({"key": key, "status": status, "title": title, "detail": detail})
            self.emit("diag", items=list(items))

        if os.name == "nt":
            add("admin", "ok" if tunnel.is_admin() else "bad", "Права администратора",
                "" if tunnel.is_admin() else "Без них туннель не запустится.")
        c = self.client
        if not c:
            add("client", "bad", "Клиент туннеля не найден", "Установите AmneziaWG для Windows.")
        elif c["kind"] == "wg":
            add("client", "warn", "WireGuard", "Без маскировки — в России часто блокируется.")
        else:
            v = tunnel.version_str(c["version"])
            add("client", "ok" if c["cps"] else "warn", f"AmneziaWG {v}",
                "Маскировка QUIC, SIP и DNS доступна." if c["cps"] else
                "Обновите до 2.0+, чтобы открыть маскировку QUIC, SIP и DNS.")
        if not self.profile:
            add("profile", "bad", "Профиль WARP не создан", "Вкладка «WARP» → «Создать профиль».")
            return
        add("profile", "ok", "Профиль WARP",
            f"Адрес {self.profile['v4']}, " + ("импортирован" if self.profile.get("source") == "import"
                                               else f"создан {self.profile.get('created', '')}"))
        ips = self.targets(4)
        r = self._probe(self.st["endpoint"], self.obf, ips, count=3, tries=3)
        hs = r["handshake"]
        add("hs", "ok" if hs is not None else "bad", "Рукопожатие с WARP",
            f"{self.st['endpoint']}, маскировка «{self.preset_name()}», {round(hs)} мс" if hs is not None else
            f"{self.st['endpoint']} не ответил на 3 попытки. Провайдер блокирует WARP — нужен «Автоподбор».")
        if hs is None:
            return
        add("data", "ok" if r["data"] is not None else "bad", "Данные через WARP",
            f"Узел {colo_name(r['colo']) or 'Cloudflare'} отвечает за {r['data']} мс" if r["data"] is not None
            else "Рукопожатие есть, а ответов нет — трафик режется после рукопожатия.")
        if r["data"] is None:
            return
        if ips:
            got = {ip: v for ip, v in r["targets"].items() if v}
            add("game", "ok" if got else "warn", "Серверы игры через WARP",
                f"Отвечают {len(got)} из {len(ips)}, лучший {min(v['ms'] for v in got.values())} мс" if got
                else "Не отвечают на ICMP через WARP. Игре это не мешает, но пинг не сравнить.")
        else:
            add("game", "warn", "Серверы игры", "Пока неизвестны — запустите игру или добавьте готовый список.")
        if self.running:
            live = self._live_ping()
            st = tunnel.tunnel_stats(c, self.profile.get("peer_public_key"))
            detail = []
            if st and st["handshake"]:
                detail.append(f"рукопожатие {int(time.time() - st['handshake'])} с назад")
            if live and live.get("ms") is not None:
                detail.append(f"сервер игры отвечает за {live['ms']} мс")
            text = ", ".join(detail)
            add("tunnel", "ok" if live else "bad", "Системный туннель работает" if live else
                "Системный туннель не пропускает трафик", text[:1].upper() + text[1:] if text else
                ("" if live else "Свой клиент проходит, а служба — нет: проверьте AmneziaWG."))
        else:
            add("tunnel", "idle", "Системный туннель выключен", "Нажмите «Запустить» на главной.")

    # ---------------------------------------------------------------- фон
    def _watch(self):
        tick = 0
        while True:
            time.sleep(4)
            tick += 1
            try:
                self._watch_tick(tick)
            except Exception as e:  # noqa: BLE001
                self.log(f"Фоновая ошибка: {e}", "warn")

    def _watch_tick(self, tick):
        with self.lock:
            auto = self.st.get("auto_learn")
            names = list(self.st["game_processes"])
            prefix = int(self.st.get("prefix", 24))
            ep_ip = split_endpoint(self.st["endpoint"])[0]
        if auto:
            eps = net.game_remote_endpoints(names)
            eps.pop(ep_ip, None)
            if eps:
                self.learn(eps, prefix)
        if tick % 3 == 0:
            self.emit("game", running=net.game_running(names))
        if self.pending and not self.busy and time.time() - self.last_restart > 15:
            self.pending = False
            if self.client and self.profile and self.st["ranges"]:
                self._exclusive("Перезапуск туннеля", self._apply)
        if self.running and not self.busy and tick % 5 == 0:
            self._health()

    def _exclusive(self, name, fn):
        with self.lock:
            if self.busy:
                return
            self.busy = name
        self.emit("busy", name=name)
        try:
            fn()
        finally:
            with self.lock:
                self.busy = None
            self.emit("busy", name=None)
            self.emit("progress", done=0, total=0, label="")

    def _health(self):
        st = tunnel.tunnel_stats(self.client, (self.profile or {}).get("peer_public_key"))
        if st:
            self.stats = st
            self.emit("stats", stats=st)
        live = self._live_ping()
        broken = live is None
        if st and not st["handshake"] and time.time() - self.started_at > 45:
            broken = True
        if broken:
            self.fails += 1
            if self.fails == 1:
                self.log("Туннель не отвечает — проверю ещё раз через 20 секунд.", "warn")
        else:
            self.fails = 0
        if (self.fails >= 2 and self.st.get("failover") and time.time() - self.last_failover > 60
                and self.profile):
            self.fails = 0
            self._exclusive("Автосмена", self._failover)

    def _failover(self):
        self.last_failover = time.time()
        self.log(f"Через WARP {self.st['endpoint']} трафик перестал идти — ищу рабочий вариант…", "warn")
        tgt = [ip for ip, _ in self.verify][:2]
        eps, presets = self._variants()
        found, _ = self._find_working(eps, presets[:3], tgt, "Автосмена", budget=60, need_game=bool(tgt))
        if found:
            self._adopt(*found)
            if not self.running:
                self._apply()
            return
        self.log("Рабочая замена не найдена — переподключаю текущий сервер. Позже нажмите «Автоподбор».",
                 "warn")
        self._apply()

    def learn(self, eps, prefix):
        with self.lock:
            changed = False
            ports = self.st.setdefault("tcp_ports", {})
            for ip, port in eps.items():
                if port and ports.get(ip) != port:
                    ports.pop(ip, None)
                    ports[ip] = port
                    changed = True
            while len(ports) > 100:
                ports.pop(next(iter(ports)))
            ign = self.st.get("ignore_ranges", [])
            ips = {ip for ip in eps if not in_nets(ip, ign)}
            cur = []
            for r in self.st["ranges"]:
                try:
                    cur.append(ipaddress.ip_network(r, strict=False))
                except ValueError:
                    continue
            new = []
            for ip in sorted(ips):
                a = ipaddress.ip_address(ip)
                if any(a in n for n in cur + new):
                    continue
                new.append(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))
            seen = [ip for ip in ips if ip not in self.st["seen_ips"]]
            if seen:
                self.st["seen_ips"] = (seen + self.st["seen_ips"])[:50]
                changed = True
            if new:
                self.st["ranges"] = self.st["ranges"] + [str(n) for n in new]
                changed = True
        if changed:
            self.save()
        if not new:
            return
        self.emit("ranges", ranges=list(self.st["ranges"]))
        self.log(f"Найдены новые серверы игры: {', '.join(str(n) for n in new)}", "ok")
        if self.running or self.armed:
            self.pending = True
            if self.armed:
                self.last_restart = 0

    # ---------------------------------------------------------------- настройки из интерфейса
    def update(self, **kw):
        with self.lock:
            changed_routes = any(k in kw and kw[k] != self.st.get(k) for k in ("ranges",))
            self.st.update(kw)
        self.save()
        if changed_routes:
            self._restart_if_running()
        return changed_routes

    def shutdown(self, stop_tunnel):
        self.cancel.set()
        if stop_tunnel and self.client:
            tunnel.tunnel_down(self.client["exe"])
            self.running = False


def demo_seed(engine, rnd=None):
    """Образец данных для предпросмотра интерфейса (режим --demo, скриншоты в CI)."""
    rnd = rnd or random.Random(7)
    ips = ["43.174.251.100", "43.174.218.66", "101.33.48.30", "101.32.171.191", "129.226.1.157"]
    base = [50, 52, 211, 210, 223]
    for ip, b in zip(ips, base):
        d = {"ms": b, "min": b - 2, "jitter": rnd.randint(1, 4), "loss": 0, "how": "ICMP"}
        w = {"ms": b - rnd.randint(4, 18) if b > 100 else b + rnd.randint(1, 6), "min": b - 20,
             "jitter": rnd.randint(1, 3), "loss": 0, "how": "ICMP"}
        engine.results[ip] = {"direct": d, "warp": w, "warp_tested": True}
    engine.route = {"server": ips[0], "direct": 50, "leg1": 19, "warp": 47, "colo": "WAW", "handshake": True}
