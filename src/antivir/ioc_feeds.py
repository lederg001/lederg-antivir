from __future__ import annotations

import json
import os
import re
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
MAX_RESPONSE_BYTES = 8_000_000
_CACHE_LOCK = threading.Lock()
_CACHE_PATH: str | None = None
_CACHE_MTIME_NS = -1
_CACHE_DATA: dict = {"hashes": {}, "domains": {}}


def default_store_path() -> Path:
    base = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "LEDERG ANTIVIR"
    return base / "threat_iocs.json"


def _valid_hash(value: str) -> bool:
    return bool(SHA256_RE.fullmatch((value or "").casefold()))


def normalize_domain(value: str) -> str:
    raw = (value or "").strip().casefold()
    if not raw:
        return ""
    if "://" in raw:
        raw = urllib.parse.urlsplit(raw).hostname or ""
    else:
        raw = raw.split("/", 1)[0].split(":", 1)[0]
    raw = raw.strip(".")
    if len(raw) > 253 or "." not in raw or any(not part or len(part) > 63 for part in raw.split(".")):
        return ""
    if any(not re.fullmatch(r"[a-z0-9-]+", part) for part in raw.split(".")):
        return ""
    return raw


def merge_feed_payloads(
    malwarebazaar: dict,
    threatfox: dict,
    *,
    existing: dict | None = None,
) -> dict:
    """Normalize confirmed/recent feed records into bounded hash and domain IOC maps."""
    result = {
        "updated_utc": datetime.now(timezone.utc).isoformat(),
        "hashes": dict((existing or {}).get("hashes", {})),
        "domains": dict((existing or {}).get("domains", {})),
    }
    for item in malwarebazaar.get("data", []) if isinstance(malwarebazaar, dict) else []:
        digest = str(item.get("sha256_hash") or "").casefold()
        if not _valid_hash(digest):
            continue
        result["hashes"][digest] = {
            "family": str(item.get("signature") or "Unknown"),
            "source": "MalwareBazaar",
            "first_seen": str(item.get("first_seen") or ""),
            "confidence": 100,
        }

    for item in threatfox.get("data", []) if isinstance(threatfox, dict) else []:
        try:
            confidence = int(item.get("confidence_level") or 0)
        except (TypeError, ValueError):
            confidence = 0
        if confidence < 80:
            continue
        ioc_type = str(item.get("ioc_type") or "").casefold()
        value = str(item.get("ioc") or "").strip()
        family = str(item.get("malware_printable") or item.get("malware") or "Unknown")
        record = {
            "family": family,
            "source": "ThreatFox",
            "first_seen": str(item.get("first_seen") or ""),
            "confidence": confidence,
        }
        if ioc_type in {"sha256_hash", "sha256"} and _valid_hash(value):
            result["hashes"][value.casefold()] = record
        elif ioc_type in {"domain", "url"}:
            domain = normalize_domain(value)
            if domain:
                result["domains"][domain] = record

    # Bound disk usage; the feeds are refreshed regularly and newest entries win.
    result["hashes"] = dict(list(result["hashes"].items())[-50000:])
    result["domains"] = dict(list(result["domains"].items())[-20000:])
    return result


def load_ioc_store(path: Path | None = None) -> dict:
    global _CACHE_PATH, _CACHE_MTIME_NS, _CACHE_DATA
    target = Path(path or default_store_path())
    try:
        mtime = target.stat().st_mtime_ns
    except OSError:
        return {"hashes": {}, "domains": {}}
    key = str(target.resolve()).casefold()
    with _CACHE_LOCK:
        if key == _CACHE_PATH and mtime == _CACHE_MTIME_NS:
            return _CACHE_DATA
        try:
            data = json.loads(target.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("Invalid IOC store")
            data.setdefault("hashes", {})
            data.setdefault("domains", {})
        except (OSError, ValueError, TypeError):
            data = {"hashes": {}, "domains": {}}
        _CACHE_PATH = key
        _CACHE_MTIME_NS = mtime
        _CACHE_DATA = data
        return data


def lookup_hash(digest: str, path: Path | None = None) -> dict | None:
    if not _valid_hash(digest):
        return None
    return load_ioc_store(path).get("hashes", {}).get(digest.casefold())


def lookup_domain(domain: str, path: Path | None = None) -> dict | None:
    normalized = normalize_domain(domain)
    if not normalized:
        return None
    return load_ioc_store(path).get("domains", {}).get(normalized)


def _post_json(url: str, body: bytes, auth_key: str, content_type: str) -> dict:
    request = urllib.request.Request(
        url,
        data=body,
        headers={"Auth-Key": auth_key, "Content-Type": content_type, "User-Agent": "LEDERG-ANTIVIR/0.6"},
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("Threat-intel response exceeds the configured size limit")
    payload = json.loads(raw.decode("utf-8"))
    if not isinstance(payload, dict):
        raise ValueError("Threat-intel API returned an unexpected response")
    return payload


def update_threat_feeds(auth_key: str, store_path: Path | None = None) -> dict:
    """Fetch recent hash/domain IOCs. The Auth-Key is used in-memory and never persisted."""
    key = (auth_key or "").strip()
    if len(key) < 12 or len(key) > 512:
        raise ValueError("Проверь Auth-Key abuse.ch")
    malwarebazaar = _post_json(
        "https://mb-api.abuse.ch/api/v1/",
        urllib.parse.urlencode({"query": "recent_detections", "hours": "48"}).encode("ascii"),
        key,
        "application/x-www-form-urlencoded",
    )
    if malwarebazaar.get("query_status") not in {"ok", "no_results"}:
        raise ValueError(f"MalwareBazaar: {malwarebazaar.get('query_status', 'unknown error')}")
    threatfox = _post_json(
        "https://threatfox-api.abuse.ch/api/v1/",
        json.dumps({"query": "get_iocs", "days": 3}).encode("utf-8"),
        key,
        "application/json",
    )
    if threatfox.get("query_status") not in {"ok", "no_result"}:
        raise ValueError(f"ThreatFox: {threatfox.get('query_status', 'unknown error')}")

    target = Path(store_path or default_store_path())
    existing = load_ioc_store(target)
    merged = merge_feed_payloads(malwarebazaar, threatfox, existing=existing)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".tmp")
    temporary.write_text(json.dumps(merged, ensure_ascii=False, indent=2), encoding="utf-8")
    temporary.replace(target)
    with _CACHE_LOCK:
        global _CACHE_PATH, _CACHE_MTIME_NS, _CACHE_DATA
        _CACHE_PATH = None
        _CACHE_MTIME_NS = -1
        _CACHE_DATA = {"hashes": {}, "domains": {}}
    return {
        "hashes": len(merged["hashes"]),
        "domains": len(merged["domains"]),
        "new_hashes": max(0, len(merged["hashes"]) - len(existing.get("hashes", {}))),
        "new_domains": max(0, len(merged["domains"]) - len(existing.get("domains", {}))),
    }
