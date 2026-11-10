# -*- coding: utf-8 -*-
"""Вспомогательные функции."""
import pytest

from abiroute import __version__, APP_NAME
from abiroute.util import fmt_bytes, split_endpoint


def test_version_present():
    assert __version__ and APP_NAME == "ABI Route"


def test_fmt_bytes():
    assert fmt_bytes(512) == "512 Б"
    assert fmt_bytes(2048) == "2.0 КБ"
    assert fmt_bytes(5 * 1024 * 1024) == "5.0 МБ"
    assert fmt_bytes(1.5 * 1024 ** 3) == "1.50 ГБ"


def test_split_endpoint():
    assert split_endpoint("162.159.192.1:2408") == ("162.159.192.1", 2408)
    assert split_endpoint("host:80") == ("host", 80)
    with pytest.raises(ValueError):
        split_endpoint("no-port")
    with pytest.raises(ValueError):
        split_endpoint(":80")
