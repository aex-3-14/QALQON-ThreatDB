# QALQON APK hash database

- `metadata.json`: latest version, full-file checksums and incremental update history
- `apk_hashes.txt.gz`: gzip full APK SHA-256 list (64 lowercase hex characters per line, ordered oldest-to-newest)
- `updates/NNNNNNNN.delta.gz`: gzip UTF-8 additions (`+<64hex>`) and removals (`-<64hex>`), newline-separated

Only metadata and hashes; no APK samples. `android_signer_*` files and the plaintext `apk_hashes.txt` are deliberately removed by the GitHub Actions workflow on its next successful run.
