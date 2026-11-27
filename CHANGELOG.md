# Changelog

All notable changes to this project will be documented in this file.

## [1.2.0] - 2026-11-27
### Added
- DET-PHI-01: PHI bulk download from an unfamiliar network. Rule query, Sentinel rule export, response playbook (Logic App template and Graph permission script), synthetic test harness, and lab validation results from 20 to 24 November 2026.
- DA-03: hourly health rule for OfficeActivity records that arrive more than a day late.
- Sample watchlist `PHI-Sensitive-Sites-sample.csv`.
- `docs/DET-PHI-01/`: write-up (PDF) and redacted evidence screenshots.
- `tools/validate.js`: offline KQL syntax and schema check.

## [1.1.0] - 2026-11-15
### Added
- INV-03: hunting query for every sign-in (interactive and non-interactive) since each leaver's own leave date, across the full retention window. Suggested by UriShay (CyberSnap) on Microsoft Tech Community.
### Changed
- README: DET-LEAVER-01 mapped to Valid Accounts T1078 / T1078.004 (previously T1098); clarified that validation was done in a lab environment.

 ## [1.0.0] - 2026-11-11
### Added
- Initial release of leaver account detections (v1 and v2).
- Leaver account re-enablement detection (DET-LEAVER-02).
- Investigation queries for account change and sign-in history.
- Detection Assurance health checks (A01, A03, DA-02).
- Brute force detection rule (MITRE T1110.001).
