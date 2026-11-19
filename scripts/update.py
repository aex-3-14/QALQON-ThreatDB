#!/usr/bin/env python3
"""Metadata-only APK SHA-256 collection; gzip full snapshot + incremental deltas.

Never downloads malware samples. Only two MalwareBazaar JSON query types are allowed.
"""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import requests

API_URL = "https://mb-api.abuse.ch/api/v1/"
ROOT = Path(__file__).resolve().parents[1] / "database"
SNAPSHOT = ROOT / "apk_hashes.txt.gz"
LEGACY_PLAINTEXT = ROOT / "apk_hashes.txt"
META = ROOT / "metadata.json"
UPDATES = ROOT / "updates"
MAX_BYTES = 100_000_000  # 100 MB uncompressed (decimal); only .gz is published.
MAX_GZIP_BYTES = 90_000_000  # Leave safety room under GitHub's 100 MiB per-file limit.
LOOKBACK_HOURS = 168
FILE_TYPE_LIMIT = 1000
SHA256 = re.compile(r"^[0-9a-f]{64}$")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def gzip_bytes(data: bytes) -> bytes:
    buffer = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buffer, mtime=0, compresslevel=9) as stream:
        stream.write(data)
    return buffer.getvalue()


def fetch(query: dict) -> list[dict]:
    """Allowlisted, read-only metadata requests; no get_file/download endpoint."""
    if query not in (
        {"query": "get_file_type", "file_type": "apk", "limit": FILE_TYPE_LIMIT},
        {"query": "recent_detections", "hours": LOOKBACK_HOURS},
    ):
        raise ValueError("Unsupported query: only APK JSON metadata is allowed")
    key = os.environ.get("MALWAREBAZAAR_API_KEY")
    if not key:
        raise RuntimeError("MALWAREBAZAAR_API_KEY GitHub Actions secret is missing")
    response = requests.post(API_URL, headers={"Auth-Key": key}, data=query, timeout=60)
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError("Unexpected MalwareBazaar JSON response")
    status = payload.get("query_status")
    if status in ("no_results", "file_type_not_found"):
        return []
    if status != "ok" or not isinstance(payload.get("data"), list):
        raise RuntimeError(f"MalwareBazaar metadata request failed: {status}")
    return payload["data"]


def apk_hashes(items: list[dict]) -> set[str]:
    found = set()
    for entry in items:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("file_type") or "").casefold() != "apk":
            continue
        digest = str(entry.get("sha256_hash") or "").strip().lower()
        if SHA256.fullmatch(digest):
            found.add(digest)
    return found


def load_existing() -> list[str]:
    """Preserve snapshot line order to evict oldest entries as the cap is reached.

    For the one-time migration, the legacy plaintext file is a fallback only.
    """
    if SNAPSHOT.exists():
        with gzip.open(SNAPSHOT, "rt", encoding="ascii") as f:
            source = list(f)
    elif LEGACY_PLAINTEXT.exists():
        source = LEGACY_PLAINTEXT.read_text(encoding="ascii").splitlines()
    else:
        return []
    ordered = []
    seen = set()
    for line in source:
        item = line.strip().lower()
        if not SHA256.fullmatch(item):
            raise ValueError("Existing hash database contains an invalid SHA-256")
        if item not in seen:
            seen.add(item)
            ordered.append(item)
    return ordered


def render_hashes(ordered: list[str]) -> bytes:
    return ("\n".join(ordered) + "\n").encode("ascii") if ordered else b""


def load_previous_metadata(existing_bytes: bytes) -> tuple[int, list[dict]]:
    if not META.exists():
        return 0, []
    old = json.loads(META.read_text(encoding="utf-8"))
    expected = (old.get("full") or {}).get("plaintext_sha256") if old.get("schema_version") == 2 else old.get("sha256_of_plaintext")
    if expected is not None and sha256(existing_bytes) != expected:
        raise ValueError("Existing database does not match its metadata; refusing update")
    if old.get("schema_version") == 2:
        version = old.get("version")
        deltas = old.get("deltas")
        if not isinstance(version, int) or version < 0 or not isinstance(deltas, list):
            raise ValueError("Invalid v2 metadata")
        return version, deltas
    if old.get("schema_version") == 1:
        return 0, []
    raise ValueError("Unsupported metadata schema")


def build_update(previous: list[str], type_items: list[dict], detection_items: list[dict],
                 version: int, history: list[dict], now: str) -> tuple[bytes, bytes | None, dict]:
    known = set(previous)
    fetched = apk_hashes(type_items) | apk_hashes(detection_items)
    added = sorted(fetched - known)
    capacity = MAX_BYTES // 65  # Each 64-hex SHA-256 + newline occupies 65 bytes.
    if capacity < 1:
        raise ValueError("MAX_BYTES must fit at least one hash")
    merged = previous + added
    if len(merged) > capacity:
        to_remove = merged[:len(merged) - capacity]
        merged = merged[-capacity:]
    else:
        to_remove = []
    surviving = set(merged)
    actual_added = [x for x in added if x in surviving]
    old_remaining = set(previous) & surviving
    actual_removed = [x for x in previous if x not in old_remaining]

    plain = render_hashes(merged)
    if len(plain) > MAX_BYTES:
        raise AssertionError("Plaintext database exceeded configured limit")
    compressed = gzip_bytes(plain)
    if len(compressed) > MAX_GZIP_BYTES:
        raise ValueError("Compressed snapshot exceeds GitHub-safe limit; reduce database size")

    prior = render_hashes(previous)
    delta_bytes = None
    history = list(history)
    if plain != prior:
        # Order is significant: delete old entries, then append new hashes in the same order.
        changes = "".join("-" + x + "\n" for x in actual_removed)
        changes += "".join("+" + x + "\n" for x in actual_added)
        delta_plain = changes.encode("ascii")
        delta_bytes = gzip_bytes(delta_plain)
        next_version = version + 1
        history.append({
            "from_version": version,
            "to_version": next_version,
            "path": f"updates/{next_version:08d}.delta.gz",
            "gzip_bytes": len(delta_bytes),
            "gzip_sha256": sha256(delta_bytes),
            "plaintext_sha256_before": sha256(prior),
            "plaintext_sha256_after": sha256(plain),
            "added": len(actual_added),
            "removed": len(actual_removed),
        })
        version = next_version

    # An API limit or unlabeled samples may make this incomplete even with daily overlap.
    capped = len(type_items) >= FILE_TYPE_LIMIT
    metadata = {
        "schema_version": 2,
        "source": "MalwareBazaar Community API metadata only",
        "type": "apk_sha256",
        "updated_at": now,
        "version": version,
        "total_hashes": len(merged),
        "new_hashes_added": len(actual_added),
        "hashes_removed_due_to_cap": len(actual_removed),
        "max_plaintext_bytes": MAX_BYTES,
        "full": {
            "path": SNAPSHOT.name,
            "gzip_bytes": len(compressed),
            "gzip_sha256": sha256(compressed),
            "plaintext_bytes": len(plain),
            "plaintext_sha256": sha256(plain),
        },
        "deltas": history,
        "collection": {
            "lookback_hours": LOOKBACK_HOURS,
            "filetype_limit": FILE_TYPE_LIMIT,
            "filetype_records_returned": len(type_items),
            "recent_detections_records_returned": len(detection_items),
            "unique_apk_hashes_returned": len(fetched),
            "filetype_response_hit_cap": capped,
            "queries": ["get_file_type(apk, limit=1000)", "recent_detections(hours=168)"],
        },
        "coverage_note": "NOT guaranteed complete for 7 days: get_file_type is limited to 1000, recent_detections is labeled-only, and there is no date-paginated APK metadata feed here.",
        "client_protocol": "Download metadata first; if up-to-date stop, else apply all versioned .delta.gz steps or download full .gz once. Validate SHA-256 and store transactionally.",
    }
    return compressed, delta_bytes, metadata


def publish(snapshot_gz: bytes, delta_gz: bytes | None, metadata: dict) -> None:
    ROOT.mkdir(parents=True, exist_ok=True)
    UPDATES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".tmp_", dir=ROOT) as tmpname:
        temp = Path(tmpname)
        candidate_snapshot = temp / SNAPSHOT.name
        candidate_snapshot.write_bytes(snapshot_gz)
        candidate_metadata = temp / META.name
        candidate_metadata.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        # Put the immutable delta in place first, then snapshot, then manifest last.
        if delta_gz is not None:
            delta_target = ROOT / metadata["deltas"][-1]["path"]
            if delta_target.exists():
                raise FileExistsError(f"Refusing to overwrite versioned delta {delta_target}")
            new_delta = temp / delta_target.name
            new_delta.write_bytes(delta_gz)
            os.replace(new_delta, delta_target)
        os.replace(candidate_snapshot, SNAPSHOT)
        os.replace(candidate_metadata, META)


def fetch_or_load_cached_metadata() -> tuple[list[dict], list[dict]]:
    """Fetch MalwareBazaar metadata once per workflow, even across push retries.

    QALQON_API_CACHE points to a job-local file outside the Git checkout. Failed
    API calls never populate the cache, and no cache is required for local use.
    """
    cache_name = os.environ.get("QALQON_API_CACHE")
    cache = Path(cache_name) if cache_name else None
    if cache and cache.is_file():
        cached = json.loads(cache.read_text(encoding="utf-8"))
        if not isinstance(cached, dict):
            raise ValueError("Invalid cached MalwareBazaar metadata")
        type_items = cached.get("type_items")
        detection_items = cached.get("detection_items")
        if not isinstance(type_items, list) or not isinstance(detection_items, list):
            raise ValueError("Invalid cached MalwareBazaar result lists")
        print("Reusing previously fetched MalwareBazaar metadata for push retry")
        return type_items, detection_items

    type_items = fetch({"query": "get_file_type", "file_type": "apk", "limit": FILE_TYPE_LIMIT})
    detection_items = fetch({"query": "recent_detections", "hours": LOOKBACK_HOURS})
    if cache:
        cache.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=cache.parent,
                                         prefix=".qalqon_api_", delete=False) as f:
            temp_path = Path(f.name)
            try:
                json.dump({"type_items": type_items, "detection_items": detection_items}, f)
            except BaseException:
                temp_path.unlink(missing_ok=True)
                raise
        os.replace(temp_path, cache)
    return type_items, detection_items


def main() -> None:
    previous = load_existing()
    version, history = load_previous_metadata(render_hashes(previous))
    type_items, detection_items = fetch_or_load_cached_metadata()
    result = build_update(previous, type_items, detection_items, version, history,
                          datetime.now(timezone.utc).isoformat())
    publish(*result)
    meta = result[2]
    print(f"Database v{meta['version']}: {meta['total_hashes']} APK hashes; added {meta['new_hashes_added']}; removed {meta['hashes_removed_due_to_cap']}")
    print(f"Full gzip: {meta['full']['gzip_bytes']} bytes. Incremental delta: {len(result[1]) if result[1] else 0} bytes.")
    if meta["collection"]["filetype_response_hit_cap"]:
        print("WARNING: get_file_type returned its 1000-result cap; weekly coverage is not complete.")


if __name__ == "__main__":
    main()
