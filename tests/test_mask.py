from __future__ import annotations

import pytest
from hypothesis import given
from hypothesis import strategies as st

from kdiag.mask import MASK_ERROR, mask_text

CANARIES = [
    "password=hunter2-canary",
    "DB_PASSWORD: supersecret-canary",
    "Authorization: Bearer abcdef1234567890canary",
    "postgres://admin:canarypw@db.internal:5432/app",
    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJjYW5hcnkifQ.c2lnbmF0dXJl",
    "ghp_" + "a" * 36,
    "AKIAABCDEFGHIJKLMNOP",
    "-----BEGIN RSA PRIVATE KEY-----\nMIIEcanarykeymaterial\n-----END RSA PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----\nunterminated-canary-material",
    "x" * 20 + "QWxhZGRpbjpvcGVuIHNlc2FtZQQWxhZGRpbjpvcGVuIHNlc2FtZQ==",
]


@pytest.mark.parametrize("canary", CANARIES)
def test_canaries_are_removed(canary: str) -> None:
    out = mask_text(f"before {canary} after") or ""
    assert "canary" not in out.lower()
    assert "hunter2" not in out and "AKIAABCDEFGHIJKLMNOP" not in out
    assert "MIIE" not in out and "QWxhZGRpbjpv" not in out


def test_none_and_plain_text_pass_through() -> None:
    assert mask_text(None) is None
    msg = 'Failed to pull image "registry.example.com/shop/web:2.4.1": not found'
    assert mask_text(msg) == msg


def test_image_digest_is_kept_readable() -> None:
    d = "sha256:" + "a" * 64
    assert d in (mask_text(f"image app@{d}") or "")


def test_masking_is_length_bounded() -> None:
    assert len(mask_text("a b " * 5000) or "") <= 2000


@given(st.from_regex(r"zq[0-9]{10,20}", fullmatch=True), st.text(max_size=50))
def test_property_assigned_secret_never_survives(secret: str, noise: str) -> None:
    out = mask_text(f"{noise} api_key={secret} {noise}") or ""
    assert secret not in out


def test_fail_closed_on_internal_error(monkeypatch: pytest.MonkeyPatch) -> None:
    import kdiag.mask as m

    class Boom:
        def sub(self, *a: object, **k: object) -> str:
            raise RuntimeError("x")

    monkeypatch.setattr(m, "_PATTERNS", ((Boom(), ""),))
    assert m.mask_text("password=abc") == MASK_ERROR
