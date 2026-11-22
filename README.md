# QALQON ThreatDB — APK hashes and the latest delta

**Only SHA-256 hashes of malware-classified APK files. No APK samples, no certificate database, no executable malware is downloaded or stored.**

## What the updater does

- **Once a week, every Sunday at 03:17 UTC / 08:17 Uzbekistan time** (or via manual GitHub Actions **Run workflow**), requests only JSON metadata from the MalwareBazaar Community API.
- Uses exactly **two MalwareBazaar API calls per scheduled run**: `get_file_type(apk,limit=1000)` and `recent_detections(hours=168)`. Both request only JSON metadata. That is normally **2 API calls per week** (additional manual runs are extra). `recent_detections` covers the prior 168 hours; the file-type query is capped at 1,000 recent samples.
- Preserves unique previously seen APK SHA-256 hashes. Maximum database is **100,000,000 bytes uncompressed** (up to 1,538,461 hashes). If full, oldest-recorded hashes are evicted to make room for newer ones.
- Publishes **`database/apk_hashes.txt.gz`** as the gzip-compressed full snapshot for first installs and clients that need to catch up.
- Keeps only the latest `database/updates/NNNNNNNN.delta.gz`, containing additions and removals from the immediately preceding version. An update that changes the database publishes the new delta and removes earlier numbered deltas from the live branch. A run with no hash changes keeps the current version and its delta, when verified.
- Publishes `database/metadata.json` with the version, full snapshot checksums and at most one entry in `deltas`. The numbered delta URL is specific to a database version and compatible with the existing QALQON Android updater.

### Coverage limitation — important

**No method based on these two API queries guarantees all malicious APKs from the last seven days.** The filetype endpoint returns at most 1,000 recent records and does not expose date pagination. `recent_detections(hours=168)` includes only samples with malware-family labels. Weekly polling with a 168-hour window **cannot guarantee complete seven-day coverage**. GitHub Actions scheduled runs may be delayed or skipped, which can introduce gaps; an overlapping window does not fully solve endpoint result caps. A hash not appearing in this database is **unknown**, not safe.

MalwareBazaar API documentation: <https://bazaar.abuse.ch/api/>

GitHub file-size policy: <https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github>

## Deploy on GitHub

1. Overlay the contents of this ZIP onto the existing ThreatDB checkout, preserving folder paths. Keep the live `database/metadata.json` and `database/apk_hashes.txt.gz` in place. The ZIP contains source files and omits generated database files.
2. Commit and push the source changes to `main`. Keep your Actions repository secret `MALWAREBAZAAR_API_KEY` configured.
3. Go to **Actions → QALQON APK Hash ThreatDB → Run workflow**. The first successful run prunes the older numbered deltas even if the hash list is unchanged. It also removes any deprecated signer and plaintext files.
4. Check that `database/metadata.json` lists at most one delta and the live `database/updates/` directory contains at most one numbered delta. The full `database/apk_hashes.txt.gz` is still available.

### Git push conflicts and safe retries

The workflow fetches the **latest** `main` branch immediately before generating a database update. If someone pushes another commit during the run and Git rejects the push, it **fetches the latest branch and regenerates** the snapshot and delta from the newer database state (up to three attempts). It never force-pushes and never rebases a stale delta on top of a different database version. The two API responses are cached only inside the temporary GitHub runner for these retries, so retries do not add extra MalwareBazaar API calls. GitHub's existing workflow `concurrency` setting is retained.

Tracked Python `__pycache__` files are removed from Git automatically on the next successful workflow run; `.gitignore` prevents them from coming back. If branch protection rules prevent the Actions bot from pushing, an authorized repository administrator must adjust permissions or use an approved pull-request workflow; push retries cannot bypass branch protection.

If you run this locally: `python -m pip install requests; MALWAREBAZAAR_API_KEY=... python scripts/update.py`.

## Android QALQON integration

QALQON v0.8.0 targeted-fixes already implements this protocol in `app/src/main/java/uz/qalqon/app/updates/ThreatUpdater.kt`. Its `BASE` already points at:

`https://raw.githubusercontent.com/pi314159userinf-dev/QALQON-ThreatDB/main/database/`

If your APK was built from that source and you still use that repository, deploy the updater and use the manual database check in QALQON's Updates screen. If the repository name or owner changes, update `BASE` in your Android source and rebuild.

- Every 24 hours in the Android app, WorkManager can check `metadata.json` while automatic updates are enabled and network and battery constraints are met. An HTTP 304 or an unchanged database checksum skips the payload download.
- An app one version behind can apply the latest delta if its local snapshot matches the required starting checksum. First installs, clients more than one version behind, and clients that cannot verify the delta download `apk_hashes.txt.gz`.
- QALQON verifies the compressed payload and the resulting hash list before installing the downloaded snapshot. If the update fails verification, it keeps the previous database. The downloaded database lives separately from the built-in `assets/apk_hashes.txt`, which remains available for offline scanning.

### Threat intelligence integrity

SHA-256 values protect against *accidental corruption*, **not** a compromised GitHub repository or malicious manifest replacement. For a production security app, digitally sign `metadata.json` using an offline private release key, pin the corresponding public key in the Android app, and verify the signature before trusting new hashes. Keep the API key **only** in GitHub Actions, never in the Android app. Do not use ZIP/APK downloads or the `get_file` API endpoint.

### Repository history

Older deltas and snapshots remain in Git history after they disappear from the live branch. At high volumes, move occasional full snapshots to a release or object storage to avoid repository growth. The file-size cap is an uncompressed database limit, **not a guarantee of stable repository storage size**.
