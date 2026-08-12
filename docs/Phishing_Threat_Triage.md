# [INC-2026-0811] Phishing Triage & Endpoint Persistence Incident

## 1. Incident Overview
* **Incident ID:** INC-2026-0811
* **Severity:** Medium (Escalated to L2 / Incident Response)
* **Analyst:** Raimi Bin Yusdi (L1 SOC Analyst)
* **Status:** In Progress / Containment Initiated
* **Timestamp:** 2026-08-11 14:15:00 MYT

## 2. Threat Analysis & Header Breakdown
* **Email Subject:** URGENT: Action Required - Password Expiration Notice
* **Sender Domain:** `mail.secure-login-update.xyz` (External / Unregistered)
* **Sender IP:** `185.220.101.5`
* **Spoofed Header:** `support@provido-global.com.secure-login-update.xyz`
* **Authentication Status:** SPF: FAIL | DKIM: FAIL | DMARC: FAIL
* **Extracted IoC Payload:** `Security Update Module` (`Security Update Assistant`)

## 3. SIEM Log Correlation (Azure Log Analytics)
* Multi-channel KQL analysis across `Security` and `System` logs confirmed suspicious post-phishing activity matching the email delivery window.
* **Failed Authentication Stream:** Verified consecutive Event ID 4625 entries (Failed Logon) leading to an Event ID 4740 (Account Lockout) on `DC01.LAB.local`.
* **Persistence Mechanism Detected:** Identified subsequent Event ID 7045 entries (`Security Update Assistant` / `Security Update Module`) executing on the host.

<img width="3839" height="2085" alt="Screenshot 2026-08-11 150540" src="https://github.com/user-attachments/assets/62cfb219-e6be-4f33-b30a-b2ec682a6e16" />

* **Verdict:** True Positive — Credential Harvesting leading to Account Lockout and Host Persistence.

## 4. Recommended Containment & Remediation Actions
1. **Perimeter Block:** Add IP `185.220.101.5` and domain `secure-login-update.xyz` to firewall and email gateway blocklists.
2. **Identity Remediation:** Force immediate password reset and revoke active session tokens for affected domain accounts.
3. **Host Remediation:** Remove unauthorized services (`Security Update Module` / `Security Update Assistant`) on `DC01.LAB.local` and perform host-level AV scan.
4. **Purge Email:** Execute tenant-wide purge of malicious message across all user mailboxes.


## 5. Case Study: Real-World Obfuscated Phishing Analysis

### Background & Discovery
Analyzed a live inbound phishing attack targeting personal email infrastructure ("Warning! Your Cloud Storage Is Full"). The email successfully bypassed preliminary gateway filters due to partial authentication alignment.

### Email Header & Authentication Breakdown
* **From Header:** `alert-6220@zcctk.ynt`
* **Sending Domain / IP:** `sb021.iptv-bitcoin-france.biz.ua` (`147.135.203.120`)
* **SPF Check:** `PASS` (Sender IP explicitly authorized by sending domain)
* **DKIM Check:** `PASS` (Valid signature for `CVZ6.sb021.iptv-bitcoin-france.biz.ua`)
* **DMARC Check:** `FAIL` (Header From domain alignment mismatch)

<img width="1915" height="2086" alt="Screenshot 2026-08-11 152115" src="https://github.com/user-attachments/assets/c7ce03ee-e32e-49a3-ae23-5c7e5e159cba" />

### Obfuscation Decoding via CyberChef
1. **Raw Payload Extraction:** Inspected raw MIME email source to extract an embedded Base64 HTML block.
2. **CyberChef Recipe (`From Base64`):** Decoded the payload revealing underlying HTML structure.
3. **Extracted IoC Link:** Identified a obfuscated landing page URI hosted on GCP storage:
   `https://storage.googleapis.com/midfielders/midfielders.html#...`

<img width="1918" height="2085" alt="Screenshot 2026-08-11 152613" src="https://github.com/user-attachments/assets/ea899ebb-968e-440e-ac61-9374264fca07" />

### VirusTotal Reputation & Verdict
* **Threat Score:** Flagged as **Malicious / Malware** by multiple vendor engines (BitDefender, SafeToOpen, G-Data).
* **Key Takeaway:** Demonstrates how threat actors leverage trusted cloud infrastructure (GCP bucket storage) combined with Base64 encoding to bypass traditional secure email gateways (SEGs).

* <img width="1916" height="2084" alt="Screenshot 2026-08-11 152626" src="https://github.com/user-attachments/assets/a3c3934f-1440-4f04-87fc-692c674dbd4a" />

## Case Study Response & Remediation Actions
### 1. **DMARC Policy Audit & Gateway Policy Recommendations:** 
Queried the sending infrastructure's DMARC DNS record (`nslookup -type=TXT _dmarc.sb021.iptv-bitcoin-france.biz.ua`) to evaluate perimeter alignment enforceability.
<img width="1732" height="917" alt="Screenshot 2026-08-12 100708" src="https://github.com/user-attachments/assets/e20bb7f0-5d3e-48f5-a529-59b9917c5b03" />

* **Finding:** The sending infrastructure lacks a published DMARC record, permitting spoofed header messages to pass initial SPF checks.
* **Enterprise Recommendation:** Enforce strict inbound Secure Email Gateway (SEG) rules to quarantine or reject (p=reject) external messages that lack valid domain alignment.

-----

### 2. **Infrastructure Abuse Submission & Email Perimeter Containment:** 
Initiated targeted abuse reporting to trigger malicious domain takedowns and configured mail filtering controls to block repeated attempts.
* **Takedown Request:** Submitted the extracted malicious GCP payload URL (`https://storage.googleapis.com/midfielders/midfielders.html#`)
<img width="1916" height="2080" alt="Screenshot 2026-08-12 100138" src="https://github.com/user-attachments/assets/dad5e71e-b4ef-4173-838a-f20aed26d5a2" />

* **Perimeter Filter Rule:** Created a targeted inbox filter to immediately drop and purge subsequent inbound traffic originating from sb021.iptv-bitcoin-france.biz.ua
<img width="1918" height="2086" alt="Screenshot 2026-08-12 101842" src="https://github.com/user-attachments/assets/d332c19b-6322-4661-a363-b1ca313e380c" />

-----

### 3. **Host Level Perimeter Blocking (IoC Isolation):** 
Executed perimeter containment on the local endpoint to block outbound communication channels to the identified attacker infrastructure.
* **Firewall Enforcement:** Created an explicit outbound block rule (Block - Phishing IoC) within Windows Defender Firewall targeting IP address 147.135.203.120, preventing host-level callbacks or payload retrievals.
<img width="1916" height="346" alt="Screenshot 2026-08-12 102328" src="https://github.com/user-attachments/assets/7ecab517-60bf-44e1-9e51-c0cda99f11b5" />
