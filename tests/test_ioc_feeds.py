from src.antivir.ioc_feeds import (
    lookup_domain,
    lookup_hash,
    merge_feed_payloads,
    normalize_domain,
    update_threat_feeds,
)


def test_merge_feed_payloads_accepts_recent_hashes_and_high_confidence_domains():
    malwarebazaar = {
        "data": [
            {"sha256_hash": "a" * 64, "signature": "ExampleStealer", "first_seen": "2026-11-04"},
            {"sha256_hash": "not-a-hash", "signature": "Noise"},
        ]
    }
    threatfox = {
        "data": [
            {"ioc": "b" * 64, "ioc_type": "sha256_hash", "confidence_level": 95,
             "malware_printable": "Vidar"},
            {"ioc": "c" * 64, "ioc_type": "sha256_hash", "confidence_level": 30,
             "malware_printable": "LowConfidence"},
            {"ioc": "https://bad.example/path", "ioc_type": "url", "confidence_level": 90,
             "malware_printable": "Stealer"},
        ]
    }

    result = merge_feed_payloads(malwarebazaar, threatfox)

    assert result["hashes"]["a" * 64]["family"] == "ExampleStealer"
    assert result["hashes"]["b" * 64]["family"] == "Vidar"
    assert "c" * 64 not in result["hashes"]
    assert result["domains"]["bad.example"]["family"] == "Stealer"


def test_domain_normalization_handles_urls_and_rejects_invalid_values():
    assert normalize_domain("https://Pool.Example:443/path") == "pool.example"
    assert normalize_domain("not a domain") == ""
    assert normalize_domain("") == ""


def test_local_ioc_lookup_matches_exact_sha256_and_domain(tmp_path):
    from pathlib import Path
    import json

    store = tmp_path / "threat_iocs.json"
    store.write_text(json.dumps({
        "hashes": {"d" * 64: {"family": "TestStealer"}},
        "domains": {"bad.example": {"family": "TestStealer"}},
    }), encoding="utf-8")

    assert lookup_hash("d" * 64, store)["family"] == "TestStealer"
    assert lookup_domain("https://bad.example/login", store)["family"] == "TestStealer"
    assert lookup_hash("not-a-hash", store) is None


def test_feed_update_uses_key_for_requests_but_never_persists_it(monkeypatch, tmp_path):
    import json
    from src.antivir import ioc_feeds

    calls = []
    def fake_post(url, body, auth_key, content_type):
        calls.append((url, auth_key, content_type))
        if "mb-api" in url:
            return {"query_status": "ok", "data": [
                {"sha256_hash": "e" * 64, "signature": "TestStealer"}
            ]}
        return {"query_status": "ok", "data": [
            {"ioc": "bad.example", "ioc_type": "domain", "confidence_level": 90,
             "malware_printable": "TestStealer"}
        ]}

    monkeypatch.setattr(ioc_feeds, "_post_json", fake_post)
    store = tmp_path / "threat_iocs.json"
    result = update_threat_feeds("fake-test-auth-key-123456", store)

    saved = store.read_text(encoding="utf-8")
    assert result["hashes"] == 1
    assert result["domains"] == 1
    assert len(calls) == 2
    assert all(call[1] == "fake-test-auth-key-123456" for call in calls)
    assert "fake-test-auth-key-123456" not in saved


def test_merge_prunes_iocs_older_than_six_months():
    from src.antivir.ioc_feeds import merge_feed_payloads

    old = {
        "hashes": {"f" * 64: {"family": "OldStealer", "first_seen": "2025-01-01T00:00:00Z"}},
        "domains": {"old.example": {"family": "OldStealer", "first_seen": "2025-01-01T00:00:00Z"}},
    }
    result = merge_feed_payloads({}, {}, existing=old)

    assert "f" * 64 not in result["hashes"]
    assert "old.example" not in result["domains"]
