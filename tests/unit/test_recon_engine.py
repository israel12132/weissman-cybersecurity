"""
tests/unit/test_recon_engine.py
================================
Unit tests for the attack-surface recon engine (src/recon_engine.py).

All external HTTP calls and subprocess invocations are mocked so tests run
without network access.

Run with: pytest tests/unit/test_recon_engine.py -v
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from src.recon_engine import (
    DiscoveredAsset,
    _normalize_asset_id,
    _ct_url,
    group_assets_by_confidence_and_risk,
    enumerate_subdomains_ct,
    enumerate_subdomains_dns,
    enumerate_subdomains_whois,
    scan_cloud_buckets,
    scan_gcp_buckets,
    check_exposed_api_endpoints,
    run_full_recon,
    normalized_asset_ids,
    get_new_assets_for_discovery_alert,
)


# ---------------------------------------------------------------------------
# DiscoveredAsset helpers
# ---------------------------------------------------------------------------

class TestNormalizeAssetId:
    def test_basic_subdomain(self):
        a = DiscoveredAsset("subdomain", "api.example.com", "ct", "high", "medium")
        assert _normalize_asset_id(a) == "subdomain:api.example.com"

    def test_case_normalised(self):
        a = DiscoveredAsset("subdomain", "API.Example.COM", "ct", "high", "medium")
        assert _normalize_asset_id(a) == "subdomain:api.example.com"

    def test_s3_bucket(self):
        a = DiscoveredAsset("s3_bucket", "s3://my-bucket", "bucket_scan", "high", "high")
        assert _normalize_asset_id(a) == "s3_bucket:s3://my-bucket"


class TestGroupAssetsByConfidenceAndRisk:
    def _make_assets(self):
        return [
            DiscoveredAsset("subdomain", "a.example.com", "ct", "high", "high"),
            DiscoveredAsset("subdomain", "b.example.com", "ct", "medium", "medium"),
            DiscoveredAsset("subdomain", "c.example.com", "dns_brute", "low", "low"),
            DiscoveredAsset("s3_bucket", "s3://bucket", "bucket_scan", "high", "high"),
        ]

    def test_high_confidence_group(self):
        grouped = group_assets_by_confidence_and_risk(self._make_assets())
        assert len(grouped["high_confidence"]) == 2

    def test_medium_confidence_group(self):
        grouped = group_assets_by_confidence_and_risk(self._make_assets())
        assert len(grouped["medium_confidence"]) == 1

    def test_all_key_present(self):
        grouped = group_assets_by_confidence_and_risk(self._make_assets())
        assert "all" in grouped
        assert len(grouped["all"]) == 4

    def test_by_source_key(self):
        grouped = group_assets_by_confidence_and_risk(self._make_assets())
        assert "ct" in grouped["by_source"]
        assert "dns_brute" in grouped["by_source"]

    def test_empty_input(self):
        grouped = group_assets_by_confidence_and_risk([])
        assert grouped["high_confidence"] == []
        assert grouped["all"] == []


# ---------------------------------------------------------------------------
# CT subdomain enumeration
# ---------------------------------------------------------------------------

class TestEnumerateSubdomainsCT:
    @patch("src.recon_engine.safe_get")
    def test_returns_assets_from_ct_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = json.dumps([
            {"name_value": "api.example.com"},
            {"name_value": "www.example.com\nmail.example.com"},
        ])
        mock_resp.json.return_value = json.loads(mock_resp.text)
        mock_get.return_value = mock_resp

        assets = enumerate_subdomains_ct("example.com")
        values = [a.value for a in assets]
        assert "api.example.com" in values
        assert "www.example.com" in values

    @patch("src.recon_engine.safe_get")
    def test_empty_on_non_200(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.text = ""
        mock_get.return_value = mock_resp
        assert enumerate_subdomains_ct("example.com") == []

    @patch("src.recon_engine.safe_get")
    def test_empty_on_network_error(self, mock_get):
        mock_get.side_effect = ConnectionError("down")
        assert enumerate_subdomains_ct("example.com") == []

    def test_rejects_empty_domain(self):
        assert enumerate_subdomains_ct("") == []

    def test_rejects_invalid_domain(self):
        assert enumerate_subdomains_ct("bad..domain") == []

    @patch("src.recon_engine.safe_get")
    def test_deduplicates_subdomains(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        data = [{"name_value": "api.example.com"}, {"name_value": "api.example.com"}]
        mock_resp.text = json.dumps(data)
        mock_resp.json.return_value = data
        mock_get.return_value = mock_resp

        assets = enumerate_subdomains_ct("example.com")
        values = [a.value for a in assets]
        assert values.count("api.example.com") == 1

    @patch("src.recon_engine.safe_get")
    def test_strips_wildcard_prefix(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        data = [{"name_value": "*.example.com"}]
        mock_resp.text = json.dumps(data)
        mock_resp.json.return_value = data
        mock_get.return_value = mock_resp

        assets = enumerate_subdomains_ct("example.com")
        for a in assets:
            assert "*" not in a.value

    @patch("src.recon_engine.safe_get")
    def test_all_assets_have_correct_source(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        data = [{"name_value": "sub.example.com"}]
        mock_resp.text = json.dumps(data)
        mock_resp.json.return_value = data
        mock_get.return_value = mock_resp

        assets = enumerate_subdomains_ct("example.com")
        assert all(a.source == "ct" for a in assets)


# ---------------------------------------------------------------------------
# DNS brute enumeration
# ---------------------------------------------------------------------------

class TestEnumerateSubdomainsDns:
    def test_empty_domain_returns_empty(self):
        assert enumerate_subdomains_dns("") == []

    @patch("src.recon_engine._run_rust_dns_enum", return_value=["api.example.com", "www.example.com"])
    def test_uses_rust_results_when_available(self, mock_rust):
        assets = enumerate_subdomains_dns("example.com")
        values = [a.value for a in assets]
        assert "api.example.com" in values
        assert "www.example.com" in values

    @patch("src.recon_engine._run_rust_dns_enum", return_value=[])
    @patch("socket.gethostbyname")
    def test_python_fallback_concurrent(self, mock_resolve, mock_rust):
        def _resolve(host):
            if host.startswith("api."):
                return "1.2.3.4"
            raise OSError("NXDOMAIN")

        mock_resolve.side_effect = _resolve
        wordlist = ["api", "unknown"]
        assets = enumerate_subdomains_dns("example.com", wordlist=wordlist)
        values = [a.value for a in assets]
        assert "api.example.com" in values
        assert "unknown.example.com" not in values

    @patch("src.recon_engine._run_rust_dns_enum", return_value=[])
    @patch("socket.gethostbyname", side_effect=OSError("NXDOMAIN"))
    def test_python_fallback_all_fail(self, mock_resolve, mock_rust):
        assets = enumerate_subdomains_dns("example.com", wordlist=["dev", "test"])
        assert assets == []

    @patch("src.recon_engine._run_rust_dns_enum", return_value=["a.x.com", "a.x.com"])
    def test_deduplicates(self, mock_rust):
        assets = enumerate_subdomains_dns("x.com")
        values = [a.value for a in assets]
        assert values.count("a.x.com") == 1

    @patch("src.recon_engine._run_rust_dns_enum", return_value=["api.example.com"])
    def test_source_is_dns_brute(self, _):
        assets = enumerate_subdomains_dns("example.com")
        assert all(a.source == "dns_brute" for a in assets)


# ---------------------------------------------------------------------------
# WHOIS enumeration
# ---------------------------------------------------------------------------

class TestEnumerateSubdomainsWhois:
    @patch("src.recon_engine.safe_get")
    def test_parses_comma_separated_lines(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "api.example.com,1.2.3.4\nwww.example.com,5.6.7.8\n"
        mock_get.return_value = mock_resp

        assets = enumerate_subdomains_whois("example.com")
        values = [a.value for a in assets]
        assert "api.example.com" in values
        assert "www.example.com" in values

    @patch("src.recon_engine.safe_get")
    def test_empty_on_non_200(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = ""
        mock_get.return_value = mock_resp
        assert enumerate_subdomains_whois("example.com") == []

    @patch("src.recon_engine.safe_get")
    def test_empty_on_exception(self, mock_get):
        mock_get.side_effect = Exception("error")
        assert enumerate_subdomains_whois("example.com") == []

    def test_empty_domain_returns_empty(self):
        assert enumerate_subdomains_whois("") == []

    def test_rejects_invalid_domain(self):
        assert enumerate_subdomains_whois("bad..domain") == []

    @patch("src.recon_engine.safe_get")
    def test_all_assets_have_medium_confidence(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = "sub.example.com,1.1.1.1\n"
        mock_get.return_value = mock_resp

        assets = enumerate_subdomains_whois("example.com")
        assert all(a.confidence == "medium" for a in assets)


# ---------------------------------------------------------------------------
# Cloud bucket scanning
# ---------------------------------------------------------------------------

class TestScanCloudBuckets:
    @patch("src.recon_engine._s3_bucket_exists")
    @patch("src.recon_engine._azure_blob_exists")
    def test_discovers_listable_s3_bucket(self, mock_azure, mock_s3):
        mock_s3.return_value = (True, True)   # exists, listable
        mock_azure.return_value = (False, False)

        assets = scan_cloud_buckets(["mybucket"], "example.com")
        s3_assets = [a for a in assets if a.asset_type == "s3_bucket"]
        assert len(s3_assets) > 0
        assert s3_assets[0].risk_impact == "high"

    @patch("src.recon_engine._s3_bucket_exists")
    @patch("src.recon_engine._azure_blob_exists")
    def test_non_listable_is_medium_risk(self, mock_azure, mock_s3):
        mock_s3.return_value = (True, False)  # exists, not listable
        mock_azure.return_value = (False, False)

        assets = scan_cloud_buckets(["mybucket"], "example.com")
        s3_assets = [a for a in assets if a.asset_type == "s3_bucket"]
        assert s3_assets[0].risk_impact == "medium"

    @patch("src.recon_engine._s3_bucket_exists", return_value=(False, False))
    @patch("src.recon_engine._azure_blob_exists", return_value=(False, False))
    def test_no_buckets_returns_empty(self, mock_azure, mock_s3):
        assets = scan_cloud_buckets(["test"], "example.com")
        assert assets == []


class TestScanGcpBuckets:
    @patch("src.recon_engine._gcp_bucket_exists")
    def test_discovers_gcp_bucket(self, mock_gcp):
        mock_gcp.return_value = (True, True)

        assets = scan_gcp_buckets(["my-project"], "example.com")
        gcp_assets = [a for a in assets if a.asset_type == "gcp_bucket"]
        assert len(gcp_assets) > 0
        assert all(a.value.startswith("gs://") for a in gcp_assets)


# ---------------------------------------------------------------------------
# Exposed API endpoint detection
# ---------------------------------------------------------------------------

class TestCheckExposedApiEndpoints:
    @patch("src.recon_engine.safe_get")
    def test_discovers_env_file(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b"SECRET=hidden"
        mock_get.return_value = mock_resp

        assets = check_exposed_api_endpoints(["https://example.com"])
        values = [a.value for a in assets]
        assert any("/.env" in v for v in values)

    @patch("src.recon_engine.safe_get")
    def test_skips_404_endpoints(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.content = b""
        mock_get.return_value = mock_resp

        assets = check_exposed_api_endpoints(["https://example.com"])
        assert assets == []

    @patch("src.recon_engine.safe_get")
    def test_skips_empty_response(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.content = b""
        mock_get.return_value = mock_resp

        assets = check_exposed_api_endpoints(["https://example.com"])
        assert assets == []

    def test_empty_urls_returns_empty(self):
        assert check_exposed_api_endpoints([]) == []

    def test_invalid_urls_skipped(self):
        assets = check_exposed_api_endpoints(["not-a-url", "ftp://invalid"])
        assert assets == []


# ---------------------------------------------------------------------------
# run_full_recon (integration of all sources)
# ---------------------------------------------------------------------------

class TestRunFullRecon:
    @patch("src.recon_engine.enumerate_subdomains_ct")
    @patch("src.recon_engine.enumerate_subdomains_whois")
    @patch("src.recon_engine.enumerate_subdomains_dns")
    @patch("src.recon_engine.scan_cloud_buckets")
    @patch("src.recon_engine.scan_gcp_buckets")
    def test_deduplicates_across_sources(
        self, mock_gcp, mock_buckets, mock_dns, mock_whois, mock_ct
    ):
        asset = DiscoveredAsset("subdomain", "api.example.com", "ct", "high", "medium")
        mock_ct.return_value = [asset]
        mock_whois.return_value = [asset]  # same asset from different source
        mock_dns.return_value = []
        mock_buckets.return_value = []
        mock_gcp.return_value = []

        result = run_full_recon("example.com", "c1", "Example Corp")
        values = [a.value for a in result]
        assert values.count("api.example.com") == 1

    @patch("src.recon_engine.enumerate_subdomains_ct", return_value=[])
    @patch("src.recon_engine.enumerate_subdomains_whois", return_value=[])
    @patch("src.recon_engine.enumerate_subdomains_dns", return_value=[])
    @patch("src.recon_engine.scan_cloud_buckets", return_value=[])
    @patch("src.recon_engine.scan_gcp_buckets", return_value=[])
    def test_returns_empty_when_nothing_found(self, *_):
        result = run_full_recon("nothing.com", "c2", "NoOp Corp")
        assert result == []

    @patch("src.recon_engine.enumerate_subdomains_ct")
    @patch("src.recon_engine.enumerate_subdomains_whois", return_value=[])
    @patch("src.recon_engine.enumerate_subdomains_dns", return_value=[])
    @patch("src.recon_engine.scan_cloud_buckets", return_value=[])
    @patch("src.recon_engine.scan_gcp_buckets", return_value=[])
    def test_flags_respected(self, mock_gcp, mock_buckets, mock_dns, mock_whois, mock_ct):
        run_full_recon(
            "example.com", "c3", "Corp",
            use_ct=True, use_dns_brute=False, use_whois=False,
            use_buckets=False, use_gcp=False,
        )
        mock_ct.assert_called_once()
        mock_dns.assert_not_called()
        mock_whois.assert_not_called()
        mock_buckets.assert_not_called()
        mock_gcp.assert_not_called()


# ---------------------------------------------------------------------------
# normalized_asset_ids
# ---------------------------------------------------------------------------

class TestNormalizedAssetIds:
    def test_returns_unique_ids(self):
        assets = [
            DiscoveredAsset("subdomain", "a.example.com", "ct", "high", "medium"),
            DiscoveredAsset("subdomain", "b.example.com", "dns_brute", "high", "medium"),
            DiscoveredAsset("subdomain", "a.example.com", "whois", "medium", "medium"),  # dup
        ]
        ids = normalized_asset_ids(assets)
        assert len(ids) == 2
        assert "subdomain:a.example.com" in ids

    def test_empty_list(self):
        assert normalized_asset_ids([]) == []


# ---------------------------------------------------------------------------
# get_new_assets_for_discovery_alert
# ---------------------------------------------------------------------------

class TestGetNewAssetsForDiscoveryAlert:
    @patch("src.delta_scan.get_known_assets")
    def test_returns_only_new_assets(self, mock_known):
        mock_known.return_value = ["subdomain:known.example.com"]
        discovered = [
            DiscoveredAsset("subdomain", "known.example.com", "ct", "high", "medium"),
            DiscoveredAsset("subdomain", "new.example.com", "ct", "high", "medium"),
        ]
        new = get_new_assets_for_discovery_alert("c1", discovered)
        assert len(new) == 1
        assert new[0].value == "new.example.com"

    @patch("src.delta_scan.get_known_assets")
    def test_returns_all_when_nothing_known(self, mock_known):
        mock_known.return_value = []
        discovered = [
            DiscoveredAsset("subdomain", "x.example.com", "ct", "high", "medium"),
            DiscoveredAsset("subdomain", "y.example.com", "ct", "high", "medium"),
        ]
        new = get_new_assets_for_discovery_alert("c1", discovered)
        assert len(new) == 2

    @patch("src.delta_scan.get_known_assets")
    def test_returns_empty_when_all_known(self, mock_known):
        mock_known.return_value = ["subdomain:x.example.com"]
        discovered = [DiscoveredAsset("subdomain", "x.example.com", "ct", "high", "medium")]
        new = get_new_assets_for_discovery_alert("c1", discovered)
        assert new == []
