"""
Tests fuer Jinja-Autoescape.

Auflage 231 + 253.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from flask import render_template_string

from tests.unit._helpers import build_dashboard_app


@pytest.fixture()
def app(tmp_path: Path):
    return build_dashboard_app(tmp_path)


def test_jinja_escapes_script_tag(app):
    # Auflage 253: render_template_string
    with app.app_context():
        out = render_template_string(
            "{{ x }}", x="<script>alert(1)</script>",
        )
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_jinja_escapes_quotes(app):
    with app.app_context():
        out = render_template_string(
            "{{ x }}", x='"\'>evil',
        )
    assert "<" not in out or "&lt;" in out


def test_jinja_escapes_amp(app):
    with app.app_context():
        out = render_template_string(
            "{{ x }}", x="a&b",
        )
    assert "&amp;" in out
