"""The Link Intelligence demo merchant: fixture-allowlist gating happens
BEFORE any payment challenge, and known queries are paywalled with 402."""

import os
import sys
from pathlib import Path

os.environ.setdefault("MERCHANT_ADDRESS", "0x" + "1" * 40)
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from demo.merchant import INTEL_DB, app  # noqa: E402


def test_unknown_broken_url_is_rejected_before_any_payment():
    r = TestClient(app).get("/intel", params={"broken_url": "https://evil.example/x"})
    assert r.status_code == 400  # not 402: no payment challenge was ever issued
    assert "allowlist" in r.json()["error"]


def test_missing_broken_url_is_rejected_before_any_payment():
    r = TestClient(app).get("/intel")
    assert r.status_code == 400


def test_known_broken_url_is_paywalled():
    (known,) = INTEL_DB  # single fixture entry
    r = TestClient(app).get("/intel", params={"broken_url": known})
    assert r.status_code == 402  # x402 challenge: payment required to read the record
