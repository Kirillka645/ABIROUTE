# -*- coding: utf-8 -*-
"""Импортируемость всех модулей пакета (ядро обязано грузиться без GUI и без admin-прав)."""
import importlib

import pytest


@pytest.mark.parametrize("mod", ["util", "settings", "warp", "netping", "tunnel", "learn",
                                 "__main__", "gui"])
def test_import_module(mod):
    m = importlib.import_module(f"abiroute.{mod}")
    assert m is not None


def test_gui_importable_without_display():
    """gui.py должен импортироваться даже без tkinter (класс App не создаётся)."""
    import abiroute.gui as g
    assert hasattr(g, "App")
