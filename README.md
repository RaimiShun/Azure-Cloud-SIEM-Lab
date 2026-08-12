# Enterprise Hybrid Cloud SIEM & Threat Ingestion Pipeline

## Executive Overview
Designed, deployed, and configured a hybrid security monitoring architecture linking an on-premises Active Directory Domain Controller to Azure Cloud. Established automated log streaming via Data Collection Rules (DCR) and implemented advanced KQL data partitioning to triage identity-based threat events (brute force, account lockouts, and successful authentications).

---

## Technical Architecture & Components
* **On-Premises Endpoint:** Windows Server 2022 Active Directory (`DC01.LAB.local`) hosted on VirtualBox.
* **Hybrid Cloud Connector:** Azure Arc Agent (`azcmagent`).
* **Log Collector & Pipeline:** Azure Monitor Agent (AMA) via custom Data Collection Rule (`dcr-windows-security-logs`).
* **SIEM Storage & Analytics Engine:** Azure Log Analytics Workspace (`law-soc-practice`).

---

## Technical Verification & Evidence

### 1. Hybrid Endpoint Onboarding
Successfully registered the local Active Directory Domain Controller into Azure Arc, establishing persistent health heartbeats and extension deployment capabilities.

<img width="1918" height="2085" alt="Screenshot 2026-08-11 114955" src="https://github.com/user-attachments/assets/80a9a6a2-6886-4469-aea8-370903b66d5d" />


### 2. Telemetry Pipeline & Data Collection Rules (DCR)
Configured granular security event filtering at the agent level to capture Audit Success and Audit Failure security events directly into the cloud workspace.

<img width="1916" height="2083" alt="Screenshot 2026-08-11 120157" src="https://github.com/user-attachments/assets/18690936-c12a-4727-80b0-c2371922479f" />


### 3. Log Ingestion & KQL Partitioning Triage
Executed advanced KQL partitioning queries to isolate and correlate high-value Event IDs without drowning out low-volume critical alerts.

<img width="1919" height="2082" alt="Screenshot 2026-08-11 123837" src="https://github.com/user-attachments/assets/33f46ff2-f32b-4e1c-874e-3059726c4547" />


```kusto
Event
| where EventLog == "Security"
| where EventID in (4624, 4625, 4740)
| partition by EventID
(
    top 6 by TimeGenerated desc
)
| project TimeGenerated, Computer, EventID, RenderedDescription, UserName
| order by TimeGenerated desc
```
#### Incident Triage Capabilities 
- **EventID 4625**: Detected failed authentication attempts indicative of brute-force or credential-stuffing activity.
- **EventID 4740**: Identified domain account lockout triggers caused by threshold violations.
- **EventID 4624**: Verified legitimate logon completion for account remediation and tracking.

----

## Advanced Threat Investigations
* **[INC-2026-0811: Phishing Triage & Endpoint Persistence Incident](docs/Phishing_Threat_Triage.md)**
  * Detailed investigation report covering email header breakdown, Base64 decoding via CyberChef, VirusTotal threat intelligence verification, and multi-channel KQL correlation for Windows Event IDs 4625, 4740, and 7045.

* **[INC-2026-0812: Living-off-the-Land Execution & Command-Line Auditing](docs/Living-off-the-Land%20Execution%20%26%20Command-Line%20Auditing.md)**
    * Hands-on threat hunting report covering domain-wide GPO process creation auditing, local Event ID 4688 verification, and KQL query analysis in Azure Log Analytics to detect certutil.exe payload downloads.

