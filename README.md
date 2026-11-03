# Sentinel detections

KQL detections and data-source health checks I built and tested in a live Microsoft 365 and Microsoft Sentinel environment (Secure Scale Systems, internal projects, October 2026).

Two questions drive this repo: does a detection catch what it should without burying the analyst in noise, and is the data it depends on actually arriving?

## What's here

| File | What it does |
|---|---|
| `detections/DET-LEAVER-01-leaver-signin-v2.kql` | One alert per person who has left but whose account still signs in after their leave date |
| `detections/DET-LEAVER-01-leaver-signin-v1.kql` | The first version, kept to show what changed |
| `detections/DET-LEAVER-02-leaver-account-reenabled.kql` | Alerts when a leaver's account is switched back on, and shows who did it |
| `investigation/INV-01-account-change-history.kql` | Every change made to one account, and who or what made it |
| `investigation/INV-02-account-signin-history.kql` | Every sign-in attempt for one account, with result code, IP, browser and OS |
| `assurance/A01-data-source-health-overview.kql` | Every table: last data, 30-day volume, active days, Healthy / Delayed / Silent |
| `assurance/A03-expected-tables-missing.kql` | The tables my rules depend on, flagging any with no data in 30 days |
| `assurance/DA-02-critical-log-source-silent.kql` | Hourly rule that raises an incident when a normally active source goes quiet |
| `watchlists/Leavers-sample.csv` | Sample leavers list (fake accounts) |

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

## Data source health (Detection Assurance)

A detection can be enabled and look healthy while its data source has stopped sending. Nothing errors.

- **A01** reads the `Usage` table, which is cheap and covers every table that sends data.
- **A03** covers the gap A01 can't see: a source that never connected has no Usage rows at all.
- In my environment, A03 showed **3 of 6** sources my rules depended on had sent nothing for 30 days (OfficeActivity, DeviceProcessEvents, DeviceLogonEvents), so **4 of 10** rules could not fire.
- **DA-02** now checks every hour, with a separate allowed-silence window per table. AuditLogs being quiet for two days is normal in a small tenant; SigninLogs being quiet for two days is not.

## Using these

- Create a watchlist with alias `Leavers`, SearchKey `UserPrincipalName`, from your HR leavers data.
- Adjust the `Thresholds` table in DA-02 to how often each of your tables normally receives data.
- Run any query in Logs over a few days before turning it into a rule.

No tenant IDs, real user data or secrets are included.
