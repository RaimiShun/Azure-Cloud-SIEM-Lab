# [INC-2026-0812] Living-off-the-Land Execution & Command-Line Auditing

## Incident Overview
Incident ID: INC-2026-0812

Severity: Medium (Threat Hunting / Detection Engineering)

Analyst: Raimi Bin Yusdi (L1 SOC Analyst)

Status: Remediated / Hardened

Timestamp: 2026-08-12 13:45:00 MYT

----

## Threat Analysis & Auditing Setup
Target Domain / Host: LAB.local / DC01.LAB.local

### GPO Audit Policy Enforced:
Advanced Audit Policy ➔ Detailed Tracking ➔ Audit Process Creation (Success and Failure)

<img width="1915" height="2084" alt="Screenshot 2026-08-12 124746" src="https://github.com/user-attachments/assets/d4c5ed91-6921-4170-99ca-091ed17c32d3" />


### Command-Line Logging Enforced: 
Administrative Templates ➔ System ➔ Audit Process Creation ➔ Include command line in process creation events

<img width="1915" height="2086" alt="Screenshot 2026-08-12 125004" src="https://github.com/user-attachments/assets/e31afb9a-b991-4f33-9de4-8752414c3c81" />


### Local Event Verification:
Event ID 4688 verified locally on DC01.LAB.local confirming parameter capture.

#### Tested Binaries / IoC:
Living-off-the-Land binary (`certutil.exe`) executing outbound payload retrieval switches (`-urlcache -f`).

<img width="1917" height="2088" alt="Screenshot 2026-08-12 133938" src="https://github.com/user-attachments/assets/9b21a63b-e128-418e-8318-aba645fa39ac" />

----

## SIEM Log Correlation (Azure Log Analytics)
* Multi-channel KQL analysis across Security logs ingested into SOC-Practice-Workspace confirmed process creation telemetry and command-line arguments.
* LotL Execution Stream: Querying Event ID 4688 matched the exact execution timestamp and command parameters for certutil.exe.

<img width="1917" height="2086" alt="Screenshot 2026-08-12 134534" src="https://github.com/user-attachments/assets/28b3f4da-14dc-41ba-97c4-204af14c496f" />

### KQL Query Executed:
```kusto
Event
| where EventLog in ("Security")
| where EventID == 4688
| where EventData has "certutil"
| project TimeGenerated, Computer, EventData
```
### Extracted Artifact Data:
* **Process Name:** C:\Windows\System32\certutil.exe
* **Parent Process:** C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
* **Captured Command Line:** `"C:\Windows\system32\certutil.exe" -urlcache -f [https://raw.githubusercontent.com/RaimiShun/Active-Directory-Home-Lab/main/README.md](https://raw.githubusercontent.com/RaimiShun/Active-Directory-Home-Lab/main/README.md) C:\Windows\Temp\payload_test.txt`
* **Verdict:** True Positive — Successful detection of Living-off-the-Land (LotL) payload download syntax via SIEM event correlation.

----

## Recommended Containment & Remediation Actions
* **Detection Rule Baseline:** Deploy custom Sentinel / KQL alert rules targeting native Windows binaries (`certutil.exe`, `bitsadmin.exe`, `wmic.exe`) when invoked with URL parameters.
* **Host Hardening:** Enforce AppLocker or Windows Defender Application Control (WDAC) policies to restrict administrative CLI tool execution for non-privileged accounts.
* **Network Boundary Rules:** Monitor and block outbound HTTP/HTTPS connections originated directly by administrative binaries at the Secure Web Gateway (SWG).
* **Continuous Telemetry Audit:** Maintain domain-wide Group Policy enforcement for Event ID 4688 command-line logging across all Domain Controllers and endpoints.
