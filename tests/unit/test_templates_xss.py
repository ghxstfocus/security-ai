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
    # test_request_context, weil _inject_csrf
    # session liest (base.html data-csrf-token).
    with app.test_request_context():
        out = render_template_string(
            "{{ x }}", x="<script>alert(1)</script>",
        )
    assert "<script>" not in out
    assert "&lt;script&gt;" in out


def test_jinja_escapes_quotes(app):
    # test_request_context, weil _inject_csrf
    # session liest (base.html data-csrf-token).
    with app.test_request_context():
        out = render_template_string(
            "{{ x }}", x='"\'>evil',
        )
    assert "<" not in out or "&lt;" in out


def test_jinja_escapes_amp(app):
    # test_request_context, weil _inject_csrf
    # session liest (base.html data-csrf-token).
    with app.test_request_context():
        out = render_template_string(
            "{{ x }}", x="a&b",
        )
    assert "&amp;" in out


# ---------------------------------------------------------------------- #
# login.html — XSS-Tests (Auflage 273)
# ---------------------------------------------------------------------- #

def test_login_template_escapes_next(app):
    # next beginnt mit "/", _safe_next laesst durch,
    # Jinja escaped im Template.
    c = app.test_client()
    r = c.get(
        "/login?next=/foo<script>alert(1)</script>",
    )
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b"&lt;script&gt;" in r.data


def test_login_template_reduces_next_on_no_slash(app):
    # next beginnt nicht mit "/", _safe_next reduziert
    # auf "/". Kein script-Tag im Body.
    c = app.test_client()
    r = c.get(
        "/login?next=<script>alert(1)</script>",
    )
    assert r.status_code == 200
    assert b"<script>" not in r.data
    assert b'name="next"' in r.data
    assert b'value="/"' in r.data
