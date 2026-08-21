# Phase 3: Cryptography Scanner

## Objectives
- Create `scanner/` package
- Implement cryptography inspector
- Generate CBOM JSON

## Status
- [x] Package structure created — inspector/qtrust_inspector/ + inspector/pyproject.toml, installed as `cryptography-inspector` (editable, via root pyproject.toml)
- [x] Scanner implemented — cli.py, scanner.py (TLS/SSH/network scans), file_scanner.py (PEM files, ~/.ssh), models.py
- [x] CBOM generation working — ScanResult.to_cbom() produces qtrust.cbom.v1 JSON

## Verification
- `crypto-inspector host example.com` — TLS scan OK, CBOM JSON saved
- `crypto-inspector directory <dir>` — SSH key discovery OK
- Unit tests: `pytest inspector/tests/test_scanner.py` — 5 passed, 1 skipped (nmap binary not installed)

## Fixes applied
- Tab-character syntax errors in cli.py (`p\t_in` → `p in`, `r\t_in` → `r in`)
- Mismatched quote in cli.py (`"__main__'` → `"__main__"`)
- models.py rewritten: AssetFinding (key_type, key_size, issuer, subject, serial_number, not_before/after, expired, cipher, metadata) + location property; ScanResult with scan_timestamp, started_at/completed_at, finding_count/by_algorithm/by_type, to_cbom()
- scanner.py: nmap PortScanner wrapped in try/except (degrades when nmap binary absent), scan_directory fixed
- Root __init__.py removed (invalid imports), backend main.py import fixed to qtrust_inspector.scanner

## Note
- The `crypto-inspector verify`/`register` CLI commands delegate to the SDK (Phase 2)