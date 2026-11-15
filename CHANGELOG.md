# Changelog

All notable changes to this project will be documented in this file.

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
