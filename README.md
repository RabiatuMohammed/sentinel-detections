# Sentinel detections

KQL detections and data-source health checks I designed, deployed and tested in a live Microsoft 365 and Microsoft Sentinel environment (Secure Scale Systems, internal projects, October to November 2026).

Two questions drive this repo: does a detection catch what it should without burying the analyst in noise, and is the data it depends on actually arriving?

## What's here

| File | What it does |
|---|---|
| `detections/01-brute-force-detection.md` | Detects multiple failed sign-ins (MITRE T1110.001) |
| `detections/DET-LEAVER-01-leaver-signin-v2.kql` | One alert per person who has left but whose account still signs in after their leave date |
| `detections/DET-LEAVER-01-leaver-signin-v1.kql` | The first version, kept to show what changed |
| `detections/DET-LEAVER-02-leaver-account-reenabled.kql` | Alerts when a leaver's account is switched back on, and shows who did it |
| `detections/DET-PHI-01-phi-bulk-download/` | Alerts when one user downloads 50+ patient-data files from an IP they have never signed in from, and revokes their sessions on High. Includes the rule export, the response playbook and a synthetic test harness |
| `investigation/INV-01-account-change-history.kql` | Every change made to one account, and who or what made it |
| `investigation/INV-02-account-signin-history.kql` | Every sign-in attempt for one account, with result code, IP, browser and OS |
| `investigation/INV-03-leaver-signins-since-leave-date.kql` | Hunting: every sign-in (interactive and non-interactive) by each leaver since their own leave date, with days to first return |
| `assurance/A01-data-source-health-overview.kql` | Every table: last data, 30-day volume, active days, Healthy / Delayed / Silent |
| `assurance/A03-expected-tables-missing.kql` | The tables my rules depend on, flagging any with no data in 30 days |
| `assurance/DA-02-critical-log-source-silent.kql` | Hourly rule that raises an incident when a normally active source goes quiet |
| `assurance/DA-03-officeactivity-late-arrival.kql` | Hourly rule that raises an incident when OfficeActivity records arrive more than a day late (DET-PHI-01 ignores them) |
| `watchlists/Leavers-sample.csv` | Sample leavers list (fake accounts) |
| `watchlists/PHI-Sensitive-Sites-sample.csv` | Sample list of SharePoint and OneDrive sites that hold patient data (contoso URLs) |
| `docs/DET-PHI-01/` | DET-PHI-01 write-up (PDF) and the redacted screenshots from the live tests |
| `tools/validate.js` | Offline syntax and schema check for the KQL, using Microsoft's Kusto.Language parser |


## MITRE ATT&CK Mapping

| ID | Detection Rule | Tactic | Technique | Sub-technique | Data Source | Status |
|:---|:---|:---|:---|:---|:---|:---|
| **DET-01** | [Potential Brute Force Attack](detections/01-brute-force-detection.md) | Credential Access (TA0006) | Brute Force (T1110) | Password Guessing (T1110.001) | SigninLogs | Validated |
| **DET-02** | [Leaver Account Sign-In](detections/DET-LEAVER-01-leaver-signin-v2.kql) | Initial Access (TA0001), Persistence (TA0003) | Valid Accounts (T1078) | Cloud Accounts (T1078.004) | SigninLogs, Watchlist | Validated |
| **DET-03** | [Leaver Account Re-enabled](detections/DET-LEAVER-02-leaver-account-reenabled.kql) | Persistence (TA0003) | Account Manipulation (T1098) | - | AuditLogs, Watchlist | Validated |
| **DET-04** | [PHI Bulk Download from Unfamiliar Network](detections/DET-PHI-01-phi-bulk-download/) | Collection (TA0009), Initial Access (TA0001) | Data from Cloud Storage (T1530), Data from Information Repositories (T1213), Valid Accounts (T1078) | SharePoint (T1213.002), Cloud Accounts (T1078.004) | OfficeActivity, SigninLogs, AADNonInteractiveUserSignInLogs, Watchlist | Validated |
| **INV-03** | [Leaver Sign-ins Since Leave Date](investigation/INV-03-leaver-signins-since-leave-date.kql) | Initial Access (TA0001), Persistence (TA0003) | Valid Accounts (T1078) | Cloud Accounts (T1078.004) | SigninLogs, AADNonInteractiveUserSignInLogs, Watchlist | Validated |
| **ASSUR-01** | [Data Source Health Overview](assurance/A01-data-source-health-overview.kql) | Defense Evasion (TA0005) | Indicator Removal (T1070) | - | Usage | Validated |
| **ASSUR-02** | [Critical Log Source Silent](assurance/DA-02-critical-log-source-silent.kql) | Defense Evasion (TA0005) | Indicator Removal (T1070) | Disable or Modify Cloud Logs (T1562.008) | Multiple tables | Validated |
| **ASSUR-03** | [OfficeActivity Late Arrival](assurance/DA-03-officeactivity-late-arrival.kql) | - | - | - | OfficeActivity | Validated |

### Legend
- **DET** = Detection Rule
- **ASSUR** = Detection Assurance (Health Check)
- **INV** = Investigation Query
- Validated = Tested in a live Microsoft 365 and Microsoft Sentinel lab environment

## Leaver account detection

**The problem.** When someone leaves and their account isn't disabled, their sign-ins look completely normal: same IP range, same apps. Location-based rules won't catch it. The only signal is that the person is no longer meant to be there, and that information lives with HR, not in the logs.

**Approach.**
1. Threat modelling for a hospital on Microsoft 365 (STRIDE, scored with DREAD).
2. Pseudo-logic: *when* an account signs in successfully, *and* it is on HR's leavers list, *and* the sign-in is after the leave date, *then* raise one High alert per leaver, *except* IT closing the account or a rehire.
3. Feasibility: sign-ins are in `SigninLogs`; the leavers list is loaded as a Sentinel watchlist.
4. Tested by putting my own account on the list with a past leave date.

**Tuning.**

| Version | Result | Change |
|---|---|---|
| v1 | 103 rows for one test leaver | Matched sign-ins against the list only |
| v2 | 1 row: 103 sign-ins, first and last seen, 4 apps, 2 IPs | Added the leave-date check and grouped per person |

**A bug worth recording.** v2 first failed with "Failed to resolve scalar expression named 'LeaveDate'". Inspecting the raw watchlist showed the CSV had been saved with a space after each comma, so the column was really `" LeaveDate"`. The final query reads the `Watchlist` table directly and tolerates both forms with `coalesce()` and `trim()`.

## Catching the re-enable, not just the sign-in

DET-LEAVER-01 fires when a leaver signs in, which is after the harm. So I tested a worse version of the problem on 1 November 2026, using a test account:

| Time (UTC) | What happened | Log |
|---|---|---|
| 13:11 | Account disabled, her leave date | AuditLogs: Disable account |
| 13:15 | She tries to sign in and is refused | SigninLogs: 50057, account disabled |
| 13:29 | Account re-enabled | AuditLogs: Enable account |
| 13:31 | She signs in again | SigninLogs: 0, success |

The re-enable is the moment that matters. Disabling her was the right ending, so undoing it needs a reason. **DET-LEAVER-02** fires on the "Enable account" event for anyone on the leavers list, two minutes before the sign-in, and shows who re-enabled the account. Against the test it returned one row, at 13:29:17.

Two things I learned on the way:
- The sign-in screen told the user her account was **locked**, but the log said **disabled** (50057). Locked would have been 50053. Go by the code.
- Most of the 22 audit events for the account were Microsoft's own services tidying up after each change. Only two rows were a person making a decision. INV-01 shows the app name for the rest, so they're easy to set aside.

## Hunting from the leave date

The scheduled rules look back 7 days, so a leaver who got back in three weeks ago never appears. After I published the leaver write-up, UriShay (CyberSnap) suggested a hunting query anchored on each person's leave date instead. **INV-03** does this:

- Looks back across the full 90-day window, then keeps only sign-ins after each person's own leave date.
- Includes `AADNonInteractiveUserSignInLogs`. A device that is still signed in refreshes tokens with no password prompt, and those sign-ins never appear in `SigninLogs`.
- Adds `SignInSources` (which tables the access came from) and `DaysToFirstReturn` (where to start the investigation timeline).

In testing, the test leaver showed 38 sign-ins from both tables, back the same day they left. `FirstSeenAfterLeave` is the earliest sign-in still in retention, so if it sits at the retention edge, the true first return may be earlier.

## PHI bulk download (DET-PHI-01)

**The problem.** An attacker with a stolen session token can sign in past MFA and pull patient records in bulk before anyone notices. Healthcare ransomware groups steal data before encrypting it, so the download is the last point to stop the breach.

**What it does.** Counts distinct files a user downloads from patient-data locations in SharePoint and OneDrive (a watchlist of sites, with a regex on folder names as a fallback), keeps only downloads from IPs that user has never signed in from in the previous 14 days, and alerts at 50 files. High when the account has no sign-in history or the download comes from a new country; Medium otherwise. On High, a Logic App playbook revokes the user's sign-in sessions and comments on the incident.

**Tested.** A synthetic harness of nine users runs the rule unchanged in any workspace. Live tests in the lab on 20 to 24 November 2026 used a test account downloading 60 synthetic files through a VPN:

| Run | Result |
|---|---|
| 24 Nov, morning | Download to containment in 55 minutes, no manual step. Entra ID audit log shows the revocation by the playbook |
| 24 Nov, evening | Watchlist-only match; the alert joined an open incident and a second automation rule ran the playbook. Download to containment in about 27 minutes; the session was dead at the first check, 6.5 minutes after the revoke |

Things the live tests changed: an audit record arrived 674 minutes late, so the rule now reads records by arrival time and DA-03 watches for anything later than a day; the VPN client showed an IPv4 address while SharePoint logged IPv6; and the first playbook run failed with a 400 because Logic Apps reads `@@` as an escaped `@`.

Full write-up, setup order, limitations and evidence: [`detections/DET-PHI-01-phi-bulk-download/`](detections/DET-PHI-01-phi-bulk-download/) and [`docs/DET-PHI-01/`](docs/DET-PHI-01/).

## Data source health (Detection Assurance)

A detection can be enabled and look healthy while its data source has stopped sending. Nothing errors.

- **A01** reads the `Usage` table, which is cheap and covers every table that sends data.
- **A03** covers the gap A01 can't see: a source that never connected has no Usage rows at all.
- In my environment, A03 showed **3 of 6** sources my rules depended on had sent nothing for 30 days (OfficeActivity, DeviceProcessEvents, DeviceLogonEvents), so **4 of 10** rules could not fire.
- **DA-02** now checks every hour, with a separate allowed-silence window per table. AuditLogs being quiet for two days is normal in a small tenant; SigninLogs being quiet for two days is not.
- **DA-03** checks every hour for OfficeActivity records that arrive more than a day after the event, which DET-PHI-01 would never evaluate.

## Using these

- Create a watchlist with alias `Leavers`, SearchKey `UserPrincipalName`, from your HR leavers data.
- For DET-PHI-01, create a watchlist with alias `PHI-Sensitive-Sites`, SearchKey `SiteUrl`, and follow the setup order in its README.
- Adjust the `Thresholds` table in DA-02 to how often each of your tables normally receives data.
- Run any query in Logs over a few days before turning it into a rule.

No tenant IDs, real user data or secrets are included.

Where an AI assistant drafted code or documentation, that detection's README says which parts and how I tested them.
