# DET-PHI-01 evidence

`DET-PHI-01-brief.pdf` is the full write-up. The screenshots below back the live results in it. Browser bars, tabs, tenant names and the subscription ID are removed or blacked out; nothing else is edited. Times are West Africa Time (UTC+1).

| File | Shows |
|---|---|
| `01-incident-181-two-alerts-closed.png` | 23 Nov: a second alert joined the open incident (2 alerts) |
| `02-runs-history-no-run-after-2206.png` | 23 Nov: no playbook run for that second alert |
| `03-vpn-americas-ip.png` | 24 Nov morning: VPN exit shown by the client (IPv4) |
| `04-download-complete.png` | 24 Nov morning: 60-file download finished |
| `05-officeactivity-arrived.png` | Download records: 60 files, IPv6 address, arrival time |
| `06-incident-203-created.png` | Incident 203 created 07:06:52, High |
| `07-runs-history-auto-run.png` | Playbook started automatically 07:07:08 |
| `08-run-diagram-all-green.png` | Every playbook step succeeded |
| `09-revoke-request-and-response.png` | Graph revokeSignInSessions request and `"value": true` |
| `10-revoke-status-200.png` | Status 200, client tracking ID ending _203 |
| `11-case-187-overview.png` | The incident in the Defender portal (case 187 = incident 203) |
| `12-case-187-comment.png` | Playbook comment with the full account name |
| `13-opera-session-killed.png` | Test account's browser asked to sign in again |
| `14-entra-audit-revoke-actor.png` | Entra ID audit log: revocation initiated by the playbook |
| `15-entra-audit-modified-properties.png` | StsRefreshTokensValidFrom old and new values |
| `16-scope-site-url.png` | Morning run matched the folder-name regex, not the watchlist |
| `17-health-check-zero-late.png` | DA-03 query: zero late records |
| `18-watchlist-item-added.png` | 24 Nov evening: test OneDrive added to the watchlist |
| `19-folder-renamed-q4-admin.png` | Folder renamed so the regex cannot match |
| `20-q4-admin-records-arrived.png` | Evening download records: 60 files from `Documents/Q4_admin` |
| `21-runs-history-auto-run-2302.png` | Playbook started automatically 23:02:36 |
| `22-run-2302-diagram.png` | Evening run: revoke and success comment green, failure comment skipped |
| `23-run-2302-tracking-203.png` | Status 200, client tracking ID ending _203 (same incident, so AUTO-004) |
| `24-opera-session-killed-2309.png` | First reload at 23:09: password prompt |
| `25-incident-203-two-alerts.png` | Incident 203 now has 2 alerts |
| `26-alert-custom-details.png` | StartTime, EndTime and Sites on the evening alert |
| `27-entra-audit-2302-actor.png` | Entra ID audit log at 23:02:37, initiated by the playbook |
| `28-entra-audit-2302-modified.png` | StsRefreshTokensValidFrom moved to 2026-11-24T22:02:36Z |
