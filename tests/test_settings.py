# -*- coding: utf-8 -*-
"""Настройки: сохранение/загрузка, устойчивость к битому файлу, санитизация."""
import abiroute.settings as s


def _patch_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(s, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(s, "SETTINGS_PATH", str(tmp_path / "settings.json"))


def test_roundtrip(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    st = s.load_settings()
    st["ranges"] = ["10.0.0.0/24"]
    st["endpoint"] = "1.2.3.4:2408"
    st["seen_ips"] = ["8.8.8.8"]
    s.save_settings(st)
    st2 = s.load_settings()
    assert st2["ranges"] == ["10.0.0.0/24"]
    assert st2["endpoint"] == "1.2.3.4:2408"
    assert st2["seen_ips"] == ["8.8.8.8"]
    assert st2["auto_learn"] is True  # значение по умолчанию на месте


def test_missing_file_gives_defaults(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    st = s.load_settings()
    assert st["endpoint"] == s.DEFAULTS["endpoint"]
    assert st["prefix"] == 24


def test_corrupt_file_gives_defaults(tmp_path, monkeypatch):
    _patch_paths(tmp_path, monkeypatch)
    (tmp_path / "settings.json").write_text("{это не json", encoding="utf-8")
    st = s.load_settings()
    assert st["endpoint"] == s.DEFAULTS["endpoint"]


def test_sanitize_drops_garbage():
    st = s.sanitize_settings({
        "ranges": ["bogus", "10.0.0.0/24", "::/0"],
        "ignore_ranges": [None, "x/99"],
        "endpoint": "no-port-here",
        "game_processes": ["", "  ", "Game.exe"],
        "prefix": 99,
        "mtu": 99999,
        "awg": {"Jc": "x", "Jmin": -5},
        "verify_targets": [["1.2.3.4", 7777], ["bad", 1], ["5.6.7.8", "oops"]],
    })
    assert st["ranges"] == ["10.0.0.0/24"]
    assert st["ignore_ranges"] == []
    assert st["endpoint"] == s.DEFAULTS["endpoint"]
    assert st["game_processes"] == ["Game.exe"]
    assert st["prefix"] == 24
    assert st["mtu"] == 1500  # 99999 зажат в верхнюю границу
    assert st["awg"]["Jc"] == 4 and st["awg"]["Jmin"] == 0
    assert st["verify_targets"] == [["1.2.3.4", 7777]]


def test_sanitize_keeps_good_values():
    st = s.sanitize_settings({
        "endpoint": "188.114.97.1:500", "ranges": ["43.153.0.0/16"],
        "prefix": 20, "mtu": 1360, "awg": {"Jc": 120, "Jmin": 23, "Jmax": 911},
    })
    assert st["endpoint"] == "188.114.97.1:500"
    assert st["prefix"] == 20 and st["mtu"] == 1360
    assert st["awg"]["Jc"] == 120
