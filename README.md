# QALQON ThreatDB — hash-only, incremental APK protection

**Only SHA-256 hashes of malware-classified APK files. No APK samples, no certificate database, no executable malware is downloaded or stored.**

## What the updater does

- **Once a week, every Sunday at 03:17 UTC / 08:17 Uzbekistan time** (or via manual GitHub Actions **Run workflow**), requests only JSON metadata from the MalwareBazaar Community API.
- Uses exactly **two MalwareBazaar API calls per scheduled run**: `get_file_type(apk,limit=1000)` and `recent_detections(hours=168)`. Both request only JSON metadata. That is normally **2 API calls per week** (additional manual runs are extra). `recent_detections` covers the prior 168 hours; the file-type query is capped at 1,000 recent samples.
- Preserves unique previously seen APK SHA-256 hashes. Maximum database is **100,000,000 bytes uncompressed** (up to 1,538,461 hashes). If full, oldest-recorded hashes are evicted to make room for newer ones.
- Publishes **`database/apk_hashes.txt.gz`** as the gzip-compressed full snapshot for **first-time installs**; no plaintext snapshot is published, and users receive only compressed downloads.
- Publishes **`database/updates/00000001.delta.gz`**, `00000002.delta.gz`, etc. only when the hash set changes; these files contain only added/removed hashes.
- Publishes a lightweight `database/metadata.json` manifest with file sizes, SHA-256 integrity checksums, the version, and all deltas. The updater removes signer files and the uncompressed `apk_hashes.txt` from the GitHub repository on the first successful run, avoiding GitHub's 100 MiB per-file hard limit.

### Coverage limitation — important

**No method based on these two API queries guarantees all malicious APKs from the last seven days.** The filetype endpoint returns at most 1,000 recent records and does not expose date pagination. `recent_detections(hours=168)` includes only samples with malware-family labels. Weekly polling with a 168-hour window **cannot guarantee complete seven-day coverage**. GitHub Actions scheduled runs may be delayed or skipped, which can introduce gaps; an overlapping window does not fully solve endpoint result caps. A hash not appearing in this database is **unknown**, not safe.

MalwareBazaar API documentation: <https://bazaar.abuse.ch/api/>

GitHub file-size policy: <https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github>

## Deploy on GitHub

1. Upload the **contents** of this ZIP into your existing GitHub repository, preserving folder paths.
2. Keep your Actions repository secret `MALWAREBAZAAR_API_KEY` configured.
3. Go to **Actions → QALQON APK Hash ThreatDB → Run workflow**. The first successful workflow cleans up the old signer files and uncompressed plaintext file automatically, even if uploading the ZIP didn't delete them.
4. Check `database/metadata.json`, `database/apk_hashes.txt.gz`, and, after new hashes are found, `database/updates/*.delta.gz`.

### Git push conflicts and safe retries

The workflow fetches the **latest** `main` branch immediately before generating a database update. If someone pushes another commit during the run and Git rejects the push, it **fetches the latest branch and regenerates** the snapshot and delta from the newer database state (up to three attempts). It never force-pushes and never rebases a stale delta on top of a different database version. The two API responses are cached only inside the temporary GitHub runner for these retries, so retries do not add extra MalwareBazaar API calls. GitHub's existing workflow `concurrency` setting is retained.

Tracked Python `__pycache__` files are removed from Git automatically on the next successful workflow run; `.gitignore` prevents them from coming back. If branch protection rules prevent the Actions bot from pushing, an authorized repository administrator must adjust permissions or use an approved pull-request workflow; push retries cannot bypass branch protection.

If you run this locally: `python -m pip install requests; python -m unittest discover -s tests -v; MALWAREBAZAAR_API_KEY=... python scripts/update.py`.

## Android QALQON client protocol (not implemented in this repository)

Base URL (replace `USERNAME`):

`https://raw.githubusercontent.com/USERNAME/QALQON-ThreatDB/main/database/`

1. **Every 24 hours in the Android app** (use `WorkManager` with network constraints), fetch **`metadata.json` first**, usually a few KB. Use HTTP caching (`ETag` / `If-None-Match`) when available, and compare the manifest `version` with the locally stored database version. If identical or HTTP `304 Not Modified`, skip database downloads. Save the version only after a successful database update. **This daily check must be implemented in QALQON itself; the GitHub workflow cannot schedule Android devices.**
2. **First install, or an unknown local version:** download `full.path` (`apk_hashes.txt.gz`) once; check `full.gzip_bytes` and SHA-256 (`full.gzip_sha256`), decompress with a bound of `full.plaintext_bytes`, and check `full.plaintext_sha256`. Parse each line as a 64-character hex hash. Store data and version **in one transaction** (e.g., in SQLite). Files are in insertion order, oldest to newest.
3. **Every later update:** if local version equals manifest `version`, nothing to download. Otherwise find a consecutive chain in `deltas` from the local version to manifest version. Fetch only those `.delta.gz` files, not the full database. Verify every delta SHA-256 and gzip length, and enforce reasonable decompression limits. In each delta, `-HASH` removes an entry and `+HASH` appends a new entry. Apply a delta **transactionally**; verify `plaintext_sha256_before` and `plaintext_sha256_after` by hashing the newline-separated table contents **in insertion order**. Commit the version only after verification succeeds.
4. When a client has never had the database or can't find/verify the delta chain, fetch the full compressed snapshot once. Preserve the previous working local database if an update fails. A failed verification is an error, **not a clean scan verdict**.
5. Use SQL `SELECT 1 FROM hashes WHERE hash=? LIMIT 1` for lookups, and a stable insertion-order column for the checksum. Cache APK file hashes for unchanged packages. Consider unmetered-only full downloads and mobile-data deltas.

**Important:** This ZIP modifies your GitHub updater, **not the Android app**. Data savings require implementing the delta protocol in QALQON. If the app simply downloads `apk_hashes.txt.gz` every time, it will still download the full database every time.

### Threat intelligence integrity

SHA-256 values protect against *accidental corruption*, **not** a compromised GitHub repository or malicious manifest replacement. For a production security app, digitally sign `metadata.json` using an offline private release key, pin the corresponding public key in the Android app, and verify the signature before trusting new hashes. Keep the API key **only** in GitHub Actions, never in the Android app. Do not use ZIP/APK downloads or the `get_file` API endpoint.

### Repository history

Even if users download only deltas, GitHub stores versions of the full compressed snapshot in Git history. At high volumes, move occasional full snapshots to a release or object storage to avoid repository growth. The file-size cap is an uncompressed database limit, **not a guarantee of stable repository storage size**.
