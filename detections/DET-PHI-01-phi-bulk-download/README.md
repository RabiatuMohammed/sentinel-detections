# DET-PHI-01: PHI bulk download from an unfamiliar network

Rabiatu Mohammed · Secure Scale Systems Ltd · validated 20 to 24 November 2026

This rule alerts when one user downloads 50 or more distinct files from PHI locations in SharePoint or OneDrive, from an IP address that does not appear in that user's sign-in history. On a High incident a Logic App playbook revokes the user's sign-in sessions and comments on the incident. It runs as a scheduled Sentinel rule, hourly, over a 14-day query period.

| ATT&CK technique | ID | What the rule sees |
|---|---|---|
| Data from Cloud Storage | T1530 | Bulk `FileDownloaded` and `FileSyncDownloadedFull` events in OfficeActivity |
| Data from Information Repositories: SharePoint | T1213.002 | Downloads concentrated in PHI sites and libraries |
| Valid Accounts: Cloud Accounts | T1078.004 | Activity from an IP or country absent from the account's sign-in history |

| Framework | Reference |
|---|---|
| NIST CSF 2.0 | DE.CM-03, DE.AE-02, DE.AE-03 |
| HIPAA Security Rule | 45 CFR 164.312(b), 164.308(a)(1)(ii)(D) |

## How this was built

I wrote the first version and set the requirements: catch a stolen session pulling patient records in bulk, High when the account has no sign-in history or the download comes from a new country.

Claude (Anthropic) rewrote the query, drafted the playbook template and the test harness, and helped draft this README and the write-up in `docs/DET-PHI-01/`. I deployed every piece myself in my own Microsoft 365 and Sentinel tenant and ran the live tests.

Testing caught three things the drafts had wrong. The live workspace rejected `SiteUrl`, a column that does not exist, even though the offline parser had accepted it; the real column is `Site_Url`. The first playbook run returned a 400 because Logic Apps reads `@@` as an escaped `@`. One audit record arrived 674 minutes after the event, which is why the rule now reads records by arrival time.

Before publishing I checked the write-up against Microsoft's documentation and my screenshots and removed two statements that went past the evidence.

## Files

| Path | Contents |
|---|---|
| `detection.kql` | The rule query |
| `rule.json` | Analytics rule exported from Sentinel (ARM template, one parameter: `workspace`) |
| `v1-original.kql` | The first version of the query, with two lines patched so it runs. Kept only for the before/after test |
| `tests/fixtures.kql` | Synthetic data that replaces the real tables with `let` statements |
| `tests/build.sh` | Builds `test-rewritten.kql`, `test-original.kql` and `debug-pipeline.kql` from the fixtures |
| `playbook/PB-PHI-Exfil-Contain.json` | Logic App playbook (ARM template, cleaned from the portal export) |
| `playbook/grant-graph-permission.ps1` | Grants the playbook identity `User.RevokeSessions.All` on Microsoft Graph |
| `../../tools/validate.js` | Offline syntax and schema check with Microsoft's Kusto.Language parser |
| `../../assurance/DA-03-officeactivity-late-arrival.kql` | Companion health rule: alerts when OfficeActivity records arrive more than 1 day late |
| `../../assurance/DA-03-officeactivity-late-arrival.rule.json` | The health rule exported from Sentinel (ARM template, one parameter: `workspace`) |
| `../../watchlists/PHI-Sensitive-Sites-sample.csv` | Sample watchlist (contoso URLs) |
| `../../docs/DET-PHI-01/` | Write-up (PDF) and the redacted screenshots behind every live result below |

## Prerequisites

I check telemetry before anything else, because an empty table returns no rows and no error, so a rule can look healthy while it is blind. In my lab tenant, non-interactive sign-ins outnumbered interactive ones by roughly 30 to 1, which is why the baseline reads both tables; a device refreshing its token never shows up in the interactive one.

- Microsoft 365 connector, with SharePoint and OneDrive audit logs flowing to `OfficeActivity`
- Microsoft Entra ID connector, with `SigninLogs` and `AADNonInteractiveUserSignInLogs` enabled
- Owner or User Access Administrator on the playbook resource group (the playbook template creates a role assignment)
- An admin who can consent to `AppRoleAssignment.ReadWrite.All` in Microsoft Graph (for the Graph permission script)

```kql
union OfficeActivity, SigninLogs, AADNonInteractiveUserSignInLogs
| where TimeGenerated > ago(7d)
| summarize Records = count() by Type
```

## Setup order

### 1. Check telemetry

Run the query above over a few days. If `OfficeActivity` is empty, stop and fix the connector first; nothing below fires without it.

### 2. Watchlist

Create a watchlist with alias `PHI-Sensitive-Sites` (start from `watchlists/PHI-Sensitive-Sites-sample.csv`): CSV header `SiteUrl,DataOwner,Notes`, SearchKey `SiteUrl`, one row per SharePoint or OneDrive site that holds PHI. The data or records owner maintains it. The rule scopes on the watchlist first and falls back to the regex, so a site with a neutral name like Oncology still gets covered.

If the watchlist is missing or empty, the rule still runs and scopes on `SensitivePathRegex` alone. I saw this in the lab before the watchlist existed.

### 3. Analytics rule

Deploy `rule.json` to the Sentinel workspace's resource group, passing the workspace name as `workspace`. The deployment command used for client tenants is [MISSING: not yet run from this repo].

Settings carried in the export:

| Setting | Value |
|---|---|
| Frequency / lookback | 1 hour / 14 days |
| Alert threshold | Results greater than 0 |
| Event grouping | One alert per result row (one row per user) |
| Severity | Medium by default, overridden by the `Severity` column |
| Entities | Account: `UserId` (FullName), IP: `IPAddress` (Address) |
| Custom details | UnfamiliarFiles, Countries, Sites, SampleFiles, BaselineIPCount, StartTime, EndTime |
| Incidents | Created; grouped by Account over 24 hours; closed incidents not reopened |
| Incident correlation | Enabled (adds `#INC_CORR#` to the description) |

In a client tenant, I would run the rule with incident creation turned off for 14 days and review every alert in `SecurityAlert` before turning incidents on.

### 4. Playbook

Deploy `playbook/PB-PHI-Exfil-Contain.json` to the resource group that will hold the playbook. It creates the Sentinel API connection (managed identity), the Logic App with a system-assigned identity, and a Microsoft Sentinel Responder role assignment for that identity on the resource group. The deployment outputs `PlaybookPrincipalId`.

The template is the portal export of the playbook I ran live, with the subscription ID and region removed and the connection and role assignment added. Until it has been deployed from this repo to a test resource group and run once, I treat it as untested.

### 5. Graph permission

```powershell
./playbook/grant-graph-permission.ps1 -PlaybookPrincipalId <PlaybookPrincipalId>
```

The script grants only `User.RevokeSessions.All` (application) and prints the identity's Graph assignments afterwards.

### 6. Sentinel permission to run playbooks

Azure Security Insights needs Microsoft Sentinel Automation Contributor on the playbook's resource group.

In the lab, the Defender portal's Playbook permissions grant failed with: `Failed to grant permissions: Error: Service principal not found for application ID: 58131f34-bef7-4935-999e-0c16b96a1de9`. In Azure IAM, Azure Security Insights already held the role on the resource group, and adding it again returned that the assignment already existed. The playbook was selectable in the automation rule and ran without a permissions error. Check the IAM role assignment and a real run, not the portal's permissions view, and do not create anything for the unknown application ID.

### 7. Health rule (DA-03)

Deploy `assurance/DA-03-officeactivity-late-arrival.rule.json` the same way as `rule.json`, or create the rule by hand from `assurance/DA-03-officeactivity-late-arrival.kql`: run every 1 hour, look back 14 days, alert when results are greater than 0, severity Low, incidents enabled. The 14-day lookback matters: a scheduled rule cannot see records older than its lookback, so a short lookback would never see a record that is a day late.

### 8. Automation rules

The Defender portal does not export automation rules, so these are built by hand. Create both as **Standard rules**, where the action **Run Logic App playbook** is available. In the lab, the new Enhanced rule form offered **Run generated playbook** as its action; I did not check whether it can run a Logic App.

| Field | AUTO-003 | AUTO-004 |
|---|---|---|
| Trigger | When incident is created | When incident is updated |
| Conditions | Analytic rule name contains `PHI bulk download from unfamiliar network` | Alerts: Added, AND analytic rule name contains `PHI bulk download from unfamiliar network` |
| Action | Run playbook `PB-PHI-Exfil-Contain` | Run playbook `PB-PHI-Exfil-Contain` |
| Order | After any triage rules that assign or tag incidents | After AUTO-003 |
| Expiration | Indefinite | Indefinite |

AUTO-004 covers a second alert for the same account inside the 24-hour incident grouping window; it ran on incident 203 on 24 Nov. The escalation case, a Medium incident that a later High alert raises to High, is not tested, and it depends on the incident's severity being updated before the playbook reads it. Revoking sessions twice is harmless. The edit view does not allow the trigger to change, so AUTO-004 has to be built new rather than duplicated from AUTO-003.

The lab copies of both rules also have `Account name equals testleaver`. That condition limits the playbook to my test account, so it cannot revoke the lab admin's own sessions during testing. Remove it from both for production.

## Playbook behaviour

| Incident severity | Action |
|---|---|
| High | For each account entity: revoke sign-in sessions through Microsoft Graph, then comment on the incident. If the revoke fails or times out, a separate comment says containment FAILED, gives the Graph status code and asks for a manual revoke |
| Medium | Comment on the incident asking an analyst to confirm with the user. No automatic action |

Revoking sessions is the containment step because a password reset on its own leaves some sessions alive: in Microsoft's token revocation table, some tokens and cookies issued before a reset keep working. `revokeSignInSessions` invalidates all of the user's refresh tokens and session cookies, which is what cuts an AiTM attacker off. Containment stops at revocation on purpose: locking a clinician out mid-shift is a patient-safety event, so disabling the account stays with a human.

What the playbook does when the revoke call itself fails is expected behaviour, not tested behaviour: the failure comment posts, the run is listed as Succeeded because the failure was handled, and the Revoke step shows as failed inside the run.

## Tuning

All tunables are `let` statements at the top of `detection.kql`. In a client tenant I would raise `FileThreshold` first, because clinical audit and research teams legitimately export large case sets and that is where the false positives will come from.

| Parameter | Default | What I would change |
|---|---|---|
| `DetectionWindow` | 1h | Keep equal to the rule frequency so each record is evaluated once |
| `MaxArrivalDelay` | 1d | Raise only if DA-03 shows records arriving later than a day |
| `BaselinePeriod` | 14d | Must not exceed the rule query period |
| `BaselineGap` | 1d | Keep at or above `MaxArrivalDelay` so an attacker's recent sign-ins never count as familiar |
| `FileThreshold` | 50 | Raise for departments that export large case sets |
| `ExcludedAccounts` | `[]` | Add backup, migration and eDiscovery accounts, each approved by name |
| `SensitivePathRegex` | word-boundary PHI pattern | Add the tenant's own library naming conventions |

## Testing

```bash
cd tests && ./build.sh
```

Paste `test-rewritten.kql` into the Logs blade of any Sentinel or Log Analytics workspace; the output must match the table below. The fixtures replace `OfficeActivity`, both sign-in tables and the watchlist with synthetic data, so no real data is read. `test-original.kql` patches only the two broken lines of the first version so its detection logic can be compared.

Two traps cost me time. Log Analytics did not resolve `let` names starting with an underscore (`Unknown function: '_dl'`), so the fixtures use none. And a blank line ends a block in the Logs editor, so a pasted harness can run only its first half; `build.sh` strips blank lines from the built files. When a run returns the wrong rows, `debug-pipeline.kql` counts the rows left after each filter so I can see where a row dropped out.

| User | Scenario | Rewritten rule | First version |
|---|---|---|---|
| Alice | 60 PHI files from an attacker IP in another country; attacker sign-in inside the window | High | Missed: attacker IP absorbed into the baseline |
| Carol | 70 PHI files, no sign-in history | High | Missed: dropped by the inner join |
| Grace | 55 PHI files from an attacker IP; UserId casing differs from UPN | High | Missed: case-sensitive join |
| Hank | 60 files from a site named "Patients-Records" | High | Missed: has_any("patient") does not match "Patients" |
| Ivy | 60 PHI files from a new IP in her usual country | Medium | Alert |
| Frank | Sync client re-downloads 5 files 60 times from a new IP | No alert | Alert (false positive) |
| Bob | 80 PHI files from his known IP | No alert | No alert |
| Dave | 30 PHI files from an unfamiliar IP | No alert | No alert |
| Erin | 60 non-PHI files from an unfamiliar IP | No alert | No alert |

Severity for Alice, Grace and Hank depends on the workspace geolocation database placing the attacker IP in a different country from the baseline. If it cannot resolve either address, those rows report Medium.

## Validation results (lab, November 2026)

The live runs used a test account downloading 60 synthetic files through a VPN. Every row below matches a screenshot in `docs/DET-PHI-01/evidence/`.

| Test | Result |
|---|---|
| Synthetic harness | Rewritten rule: 4 of 4 attacker scenarios, 0 false positives. v1: did not run as written (`SiteUrl` does not exist in OfficeActivity; `!in` cannot take a per-row list). With those two lines patched: 0 of 4, 1 false positive |
| Regression after the arrival-time change | Same results as before the change |
| Late-arriving data | One `FileDownloaded` record arrived 674 minutes after the event; two others arrived in 8 and 6 minutes |
| Zip downloads | A 60-file OneDrive web download (one zip in the browser) logged 60 `FileDownloaded` events, one per file |
| Live detection | 60 test files downloaded by a test account through a VPN raised a High alert on the next hourly run |
| Playbook, first run | Failed: `400 BadRequest`. The URI contained a literal `{item()?['UPNSuffix']}` (Logic Apps reads `@@` as an escaped @), and Graph required a `Content-Type` header |
| Playbook, after fix | Revoke returned `200`, `"value": true`. The Entra ID audit log for the test account recorded the change initiated by PB-PHI-Exfil-Contain |
| Incident comment | The first successful run wrote a literal `{item()?['UPNSuffix']}` in the comment while every step showed Succeeded. Fixed the same way; confirmed by reading `SecurityIncident.Comments` |
| Session kill | Reloading the test account's browser session redirected to the Microsoft sign-in page and asked for the password |
| Repeat alert inside the grouping window (before AUTO-004) | A second alert for the same account (23 Nov 22:06) joined the open incident. The playbook did not run; run history shows no run after 13:37 that day |
| Clean automatic run (24 Nov) | 60 files downloaded at 06:11:54 WAT. Records arrived at 06:21:22, incident created at 07:06:52 (High, one alert), playbook started at 07:07:08 with no manual step. Revoke returned `200`; the Entra ID audit log recorded the change at 07:07:09, initiated by PB-PHI-Exfil-Contain. The incident comment carried the full UPN. A reload at about 09:13 showed "Please sign in". Download to containment: 55 minutes |
| Scope match in the clean run | Matched on the regex fallback (`Documents/medical_records` in the test account's own OneDrive). The watchlist path was tested separately that evening (below) |
| Logged IP vs VPN client | The VPN client showed an IPv4 address; SharePoint logged an IPv6 address for the same downloads |
| Watchlist path and repeat alert (24 Nov, evening) | Test account's OneDrive added to the watchlist and the folder renamed to `Q4_admin`, so the regex could not match. 60 files downloaded at 22:35:59 WAT, records arrived 22:41:12, alert at 23:02:03 joined the open incident 203 (AlertCount 2). AUTO-004 started the playbook at 23:02:36 (client tracking ID ending `_203`). Revoke returned `200`; the success comment posted and the failure comment was skipped. Entra ID audit log at 23:02:37, initiated by PB-PHI-Exfil-Contain. Download to containment: about 27 minutes |
| Custom details | The 23:02 alert carried `StartTime` 2026-11-24T21:35:59Z and `EndTime` 21:36:03Z, Sites listing only the watchlisted OneDrive, BaselineIPCount 8 |
| Session kill timing | First reload after the 23:02 revoke, at 23:09, went to the password prompt. The session ended within 6.5 minutes of the revoke; the exact delay was not measured |

## Known limitations

### By design

- **Accounts with no successful sign-in in 14 days are rated High** (guests, service accounts, users back from leave). The left outer join keeps them on purpose: an account with no history is the highest-risk case. Approved bulk-download service accounts go in `ExcludedAccounts`.
- **Only files from unfamiliar IPs count toward the threshold.** 190 files at home plus 10 from an attacker IP does not cross the line on the attacker's 10 alone. An attacker who takes fewer than 50 files in one hourly window stays under it.
- **An IP a user first used within the last day counts as unfamiliar.** Users on mobile networks that rotate IPs will produce Medium alerts. Medium only adds a comment; it never revokes. If the volume is a problem in a client tenant, treat a download IP in the same /24 (IPv4) or /64 (IPv6) as a known IP as familiar.
- **An attacker who signs in more than `BaselineGap` before downloading is already in the baseline** (for example with a token stolen days earlier). The baseline ends a day back so that a sign-in during the attack is never learned as familiar; the cost is this blind spot. Only the new-country check is left to raise severity. Token theft from days earlier is the job of identity risk detections such as Entra ID Protection.
- **An analyst who raises severity by hand does not trigger the playbook.** The analyst can run it from the incident.

### Mitigated

- **Records that arrive more than `MaxArrivalDelay` after the event are not evaluated.** DA-03 runs hourly and raises a Low incident for any such record, so a late record shows up as an assurance incident rather than vanishing silently. A manual run of the query on 24 Nov returned zero late records.
- **The Defender portal lists each alert at the start of the 14-day lookback, not at the download time.** Read the real times from the `StartTime` and `EndTime` custom details.

### Open

- **Masked sign-in IPs never match.** For a federated account, the sign-in logs showed the IP masked as `132.148.54.XXX`, so that account's downloads always count as unfamiliar. Planned fix: store the unmasked prefix in the baseline, match downloads on it, and add a harness user for the case.
- **IPv4 and IPv6 are compared as plain addresses.** In the lab, the VPN client showed an IPv4 address while SharePoint logged the downloads over IPv6. A dual-stack user who signs in over one and downloads over the other looks unfamiliar to the rule. How often this raises a false alert was not measured.
- **The escalation case is not tested:** a Medium incident raised to High by a later alert.
- **The revoke-failed comment has not been tested with a real failure.**
- **Containment timing was not measured exactly.** On 24 Nov the session was already dead at the first check, 6.5 minutes after the revoke.
- **The Sentinel connector actions in the playbook (Entities - Get Accounts, Add comment to incident) were shown as Preview in the designer.** I tested them as they behaved in November 2026 and would rerun the live test if Microsoft changes them.
