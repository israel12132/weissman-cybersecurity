"""
tests/unit/test_delta_scan.py
================================
Unit tests for delta-scan state management in src/delta_scan.py.

Database calls are mocked so tests run without a real database.

Run with: pytest tests/unit/test_delta_scan.py -v
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from src.delta_scan import (
    _ports_key,
    _headers_hash,
    has_changed,
    get_snapshot,
    get_known_assets,
    save_snapshot,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

class TestPortsKey:
    def test_sorted_ports(self):
        assert _ports_key([443, 80, 8080]) == _ports_key([80, 443, 8080])

    def test_same_ports_same_key(self):
        assert _ports_key([80, 443]) == _ports_key([80, 443])

    def test_different_ports_different_key(self):
        assert _ports_key([80]) != _ports_key([443])

    def test_empty_list(self):
        assert _ports_key([]) == "[]"


class TestHeadersHash:
    def test_empty_returns_empty_string(self):
        assert _headers_hash({}) == ""
        assert _headers_hash(None) == ""

    def test_same_headers_same_hash(self):
        h = {"Server": "nginx", "X-Frame": "DENY"}
        assert _headers_hash(h) == _headers_hash(h)

    def test_different_headers_different_hash(self):
        h1 = {"Server": "nginx"}
        h2 = {"Server": "apache"}
        assert _headers_hash(h1) != _headers_hash(h2)

    def test_order_independent(self):
        h1 = {"A": "1", "B": "2"}
        h2 = {"B": "2", "A": "1"}
        assert _headers_hash(h1) == _headers_hash(h2)

    def test_returns_sha256_hex(self):
        h = {"X-Test": "value"}
        result = _headers_hash(h)
        assert len(result) == 64
        assert all(c in "0123456789abcdef" for c in result)


# ---------------------------------------------------------------------------
# get_snapshot
# ---------------------------------------------------------------------------

class TestGetSnapshot:
    def _make_db_row(
        self,
        ports_json="[80, 443]",
        headers_hash="abc123",
        cve_ids_json='["CVE-2024-1"]',
        assets_json='["subdomain:api.x.com"]',
    ):
        row = MagicMock()
        row.ports_json = ports_json
        row.headers_hash = headers_hash
        row.cve_ids_json = cve_ids_json
        row.assets_json = assets_json
        return row

    @patch("src.delta_scan.get_session_factory")
    def test_returns_snapshot_dict(self, mock_factory):
        row = self._make_db_row()
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.first.return_value = row
        mock_factory.return_value = MagicMock(return_value=db)

        snap = get_snapshot("target1")
        assert snap is not None
        assert snap["ports_json"] == "[80, 443]"
        assert snap["headers_hash"] == "abc123"

    @patch("src.delta_scan.get_session_factory")
    def test_returns_none_when_not_found(self, mock_factory):
        db = MagicMock()
        db.query.return_value.filter.return_value.order_by.return_value.first.return_value = None
        mock_factory.return_value = MagicMock(return_value=db)

        snap = get_snapshot("nonexistent")
        assert snap is None

    @patch("src.delta_scan.get_session_factory")
    def test_returns_none_on_exception(self, mock_factory):
        mock_factory.side_effect = Exception("DB error")
        snap = get_snapshot("target1")
        assert snap is None


# ---------------------------------------------------------------------------
# get_known_assets
# ---------------------------------------------------------------------------

class TestGetKnownAssets:
    @patch("src.delta_scan.get_snapshot")
    def test_returns_assets_from_snapshot(self, mock_snap):
        mock_snap.return_value = {
            "assets_json": '["subdomain:api.x.com", "s3_bucket:s3://bucket"]'
        }
        assets = get_known_assets("target1")
        assert "subdomain:api.x.com" in assets
        assert "s3_bucket:s3://bucket" in assets

    @patch("src.delta_scan.get_snapshot")
    def test_returns_empty_when_no_snapshot(self, mock_snap):
        mock_snap.return_value = None
        assert get_known_assets("target1") == []

    @patch("src.delta_scan.get_snapshot")
    def test_returns_empty_on_corrupt_json(self, mock_snap):
        mock_snap.return_value = {"assets_json": "NOT_JSON"}
        assert get_known_assets("target1") == []


# ---------------------------------------------------------------------------
# has_changed
# ---------------------------------------------------------------------------

class TestHasChanged:
    @patch("src.delta_scan.get_snapshot", return_value=None)
    def test_no_snapshot_means_changed(self, _):
        assert has_changed("new_target") is True

    @patch("src.delta_scan.get_snapshot")
    def test_same_ports_no_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[80, 443]",
            "headers_hash": "",
            "cve_ids_json": "[]",
            "assets_json": "[]",
        }
        assert has_changed("t1", ports=[80, 443]) is False

    @patch("src.delta_scan.get_snapshot")
    def test_different_ports_is_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[80]",
            "headers_hash": "",
            "cve_ids_json": "[]",
            "assets_json": "[]",
        }
        assert has_changed("t1", ports=[80, 443]) is True

    @patch("src.delta_scan.get_snapshot")
    def test_same_headers_no_change(self, mock_snap):
        headers = {"Server": "nginx"}
        from src.delta_scan import _headers_hash
        mock_snap.return_value = {
            "ports_json": "[]",
            "headers_hash": _headers_hash(headers),
            "cve_ids_json": "[]",
            "assets_json": "[]",
        }
        assert has_changed("t1", headers=headers) is False

    @patch("src.delta_scan.get_snapshot")
    def test_different_headers_is_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[]",
            "headers_hash": "oldhash",
            "cve_ids_json": "[]",
            "assets_json": "[]",
        }
        assert has_changed("t1", headers={"Server": "apache"}) is True

    @patch("src.delta_scan.get_snapshot")
    def test_same_cve_ids_no_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[]",
            "headers_hash": "",
            "cve_ids_json": '["CVE-2024-1", "CVE-2024-2"]',
            "assets_json": "[]",
        }
        assert has_changed("t1", cve_ids=["CVE-2024-2", "CVE-2024-1"]) is False

    @patch("src.delta_scan.get_snapshot")
    def test_new_cve_id_is_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[]",
            "headers_hash": "",
            "cve_ids_json": '["CVE-2024-1"]',
            "assets_json": "[]",
        }
        assert has_changed("t1", cve_ids=["CVE-2024-1", "CVE-2024-99"]) is True

    @patch("src.delta_scan.get_snapshot")
    def test_new_asset_is_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[]",
            "headers_hash": "",
            "cve_ids_json": "[]",
            "assets_json": '["subdomain:old.x.com"]',
        }
        assert has_changed("t1", assets=["subdomain:old.x.com", "subdomain:new.x.com"]) is True

    @patch("src.delta_scan.get_snapshot")
    def test_no_params_means_no_change(self, mock_snap):
        mock_snap.return_value = {
            "ports_json": "[80]",
            "headers_hash": "hash",
            "cve_ids_json": '["CVE-1"]',
            "assets_json": '["subdomain:x.com"]',
        }
        # Calling has_changed without any comparison params → no change
        assert has_changed("t1") is False


# ---------------------------------------------------------------------------
# save_snapshot
# ---------------------------------------------------------------------------

class TestSaveSnapshot:
    def _setup_db_mock(self, mock_factory, existing_row=None):
        db = MagicMock()
        db.query.return_value.filter.return_value.first.return_value = existing_row
        session_factory = MagicMock(return_value=db)
        mock_factory.return_value = session_factory
        return db

    @patch("src.delta_scan.get_session_factory")
    def test_creates_new_row_when_none_exists(self, mock_factory):
        db = self._setup_db_mock(mock_factory, existing_row=None)
        save_snapshot("target1", ports=[80, 443])
        db.add.assert_called_once()
        db.commit.assert_called_once()

    @patch("src.delta_scan.get_session_factory")
    def test_updates_existing_row(self, mock_factory):
        existing = MagicMock()
        existing.ports_json = "[80]"
        existing.headers_hash = ""
        existing.cve_ids_json = "[]"
        existing.assets_json = "[]"
        db = self._setup_db_mock(mock_factory, existing_row=existing)

        save_snapshot("target1", ports=[80, 443])

        # Should update the existing row, not add a new one
        db.add.assert_not_called()
        db.commit.assert_called_once()
        assert existing.ports_json is not None

    @patch("src.delta_scan.get_session_factory")
    def test_handles_exception_gracefully(self, mock_factory):
        mock_factory.side_effect = Exception("DB error")
        # Should not raise
        save_snapshot("target1", ports=[80])

    @patch("src.delta_scan.get_session_factory")
    def test_saves_assets_json(self, mock_factory):
        existing = MagicMock()
        existing.ports_json = "[]"
        existing.headers_hash = ""
        existing.cve_ids_json = "[]"
        existing.assets_json = "[]"
        db = self._setup_db_mock(mock_factory, existing_row=existing)

        assets = ["subdomain:api.x.com", "s3_bucket:s3://bucket"]
        save_snapshot("target1", assets=assets)

        saved = json.loads(existing.assets_json)
        assert set(saved) == set(assets)
