# Ghrab VOC — Full Vulnerability Operations Report
_Generated 7/22/2026, 8:59:15 AM_

---

# Ghrab VOC — Command Center Report
_Generated 7/22/2026, 8:59:15 AM_

## Key Metrics

| Metric | Value |
|---|---|
| Total findings | 32 |
| Immediate (GRS ≥ 80) | 4 |
| Act (GRS 60–79) | 8 |
| Average GRS | 54.7 |
| KEV-listed | 7 |
| DORA CIF scope | 15 |
| Crown jewels | 11 |
| Attack paths discovered | 22 |

## Executive Synthesis

Velon Health Systems’ vulnerability posture is **CRITICAL**, with immediate risk of large-scale breach due to systemic failures in segmentation, credential hygiene, and internet-facing RCE exposures. The **single most urgent finding** is **CVE-2018-7600 (Drupalgeddon2 RCE) on PORTAL01 (DMZ)**, enabling full system compromise of the patient portal and lateral movement into the App Tier via the excessive DMZ-to-AppTier firewall rule (RULE-VL-003). The **AppSec Team** is the most exposed, owning three of the top five critical findings (Drupal, WebLogic, Spring4Shell) and failing to enforce secure SDLC or service account isolation. The **dominant systemic pattern** is **network trust collapse**: flat segmentation (e.g., Corporate LAN → Clinical/Biomed VLAN), excessive firewall rules, and VPN split-tunneling into management zones, directly violating HIPAA 164.312(e) and enabling credential reuse (e.g., shared local admin) to pivot across trust boundaries.

## Top Urgent Findings

- **GRS 100 (IMMEDIATE)** — Patient Portal Webshell Upload Following RCE — PORTAL01 · QID 12061 · Owner: AppSec Team
- **GRS 100 (IMMEDIATE)** — Drupal Core Remote Code Execution (Drupalgeddon2) — PORTAL01 · QID 12055 · Owner: AppSec Team
- **GRS 100 (IMMEDIATE)** — Fortinet FortiOS Authentication Bypass on Administrative Interface — CLINIC-VPN-GW01 · QID 46840 · Owner: Network Team
- **GRS 85 (IMMEDIATE)** — Oracle WebLogic Server Remote Code Execution — EHR-APP01 · QID 20144 · Owner: AppSec Team
- **GRS 78.8 (ACT)** — Spring Framework Remote Code Execution (Spring4Shell) — TELEHEALTH-APP01 · QID 150455 · Owner: AppSec Team

## Top Attack Paths

- **DISC-01** (score 108) — PORTAL01 → DB-EHR01
- **DISC-02** (score 108) — CLINIC-VPN-GW01 → DB-EHR01
- **DISC-03** (score 98) — PORTAL01 → EHR-APP01
- **DISC-04** (score 98) — CLINIC-VPN-GW01 → EHR-APP01
- **DISC-05** (score 96.25) — PORTAL01 → DB-CLAIMS01

---

# Ghrab VOC — Attack Path Discovery Report
_Generated 7/22/2026, 8:59:15 AM_

## Discovered Paths (22)

### DISC-01 — PORTAL01 → DB-EHR01 (score 108)
Confidence: — · Novelty: — · Blast radius: 3 · Hops: 4

Kill chain: Internet → PORTAL01 → TELEHEALTH-APP01 → DB-CLAIMS01 → DB-EHR01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **TELEHEALTH-APP01** via segmentation (QID 200901) — exploited via Hardcoded Database Credentials in Telehealth Application Configuration File
  3. **DB-CLAIMS01** via credential (QID 150467) — exploited via Excessive Database Link Privileges Between Telehealth and Claims Databases (Excessive Access)
  4. **DB-EHR01** via lateral — exploited via EHR Application Service Account Has db_owner Rights on EHR Database (Excessive Privilege)

### DISC-02 — CLINIC-VPN-GW01 → DB-EHR01 (score 108)
Confidence: — · Novelty: — · Blast radius: 3 · Hops: 4

Kill chain: Internet → CLINIC-VPN-GW01 → TELEHEALTH-APP01 → DB-CLAIMS01 → DB-EHR01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **TELEHEALTH-APP01** via segmentation (QID 200901) — exploited via Hardcoded Database Credentials in Telehealth Application Configuration File
  3. **DB-CLAIMS01** via credential (QID 150467) — exploited via Excessive Database Link Privileges Between Telehealth and Claims Databases (Excessive Access)
  4. **DB-EHR01** via lateral — exploited via EHR Application Service Account Has db_owner Rights on EHR Database (Excessive Privilege)

### DISC-03 — PORTAL01 → EHR-APP01 (score 98)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → PORTAL01 → EHR-APP01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **EHR-APP01** via segmentation (QID 200901) — exploited via Oracle WebLogic Server Remote Code Execution

### DISC-04 — CLINIC-VPN-GW01 → EHR-APP01 (score 98)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → CLINIC-VPN-GW01 → EHR-APP01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **EHR-APP01** via segmentation (QID 200901) — exploited via Oracle WebLogic Server Remote Code Execution

### DISC-05 — PORTAL01 → DB-CLAIMS01 (score 96.25)
Confidence: — · Novelty: — · Blast radius: 2 · Hops: 3

Kill chain: Internet → PORTAL01 → TELEHEALTH-APP01 → DB-CLAIMS01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **TELEHEALTH-APP01** via segmentation (QID 200901) — exploited via Hardcoded Database Credentials in Telehealth Application Configuration File
  3. **DB-CLAIMS01** via credential (QID 150467) — exploited via Excessive Database Link Privileges Between Telehealth and Claims Databases (Excessive Access)

### DISC-06 — CLINIC-VPN-GW01 → DB-CLAIMS01 (score 96.25)
Confidence: — · Novelty: — · Blast radius: 2 · Hops: 3

Kill chain: Internet → CLINIC-VPN-GW01 → TELEHEALTH-APP01 → DB-CLAIMS01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **TELEHEALTH-APP01** via segmentation (QID 200901) — exploited via Hardcoded Database Credentials in Telehealth Application Configuration File
  3. **DB-CLAIMS01** via credential (QID 150467) — exploited via Excessive Database Link Privileges Between Telehealth and Claims Databases (Excessive Access)

### DISC-07 — PORTAL01 → BACKUP-MGR01 (score 95.75)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → PORTAL01 → BACKUP-MGR01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **BACKUP-MGR01** via segmentation (QID 200955) — exploited via Backup Management Console Uses Default Credentials

### DISC-08 — CLINIC-VPN-GW01 → BACKUP-MGR01 (score 95.75)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → CLINIC-VPN-GW01 → BACKUP-MGR01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **BACKUP-MGR01** via segmentation (QID 200955) — exploited via Backup Management Console Uses Default Credentials

### DISC-09 — PORTAL01 → DC01 (score 95)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → PORTAL01 → JUMP01 → DC01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **DC01** via domain (QID 91145) — exploited via Active Directory sAMAccountName Spoofing Privilege Escalation (noPac)

### DISC-10 — PORTAL01 → INFUSION-GW01 (score 95)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → PORTAL01 → JUMP01 → INFUSION-GW01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **INFUSION-GW01** via domain (QID 91145) — exploited via Infusion Pump Gateway - VxWorks IPnet TCP/IP Stack Buffer Overflow

### DISC-11 — PORTAL01 → PHARMACY-DISPENSE01 (score 95)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → PORTAL01 → JUMP01 → PHARMACY-DISPENSE01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **PHARMACY-DISPENSE01** via domain (QID 91145) — exploited via Automated Dispensing Cabinet Shares Administrative Credential With General IT Administration (Excessive Access)

### DISC-12 — CLINIC-VPN-GW01 → INFUSION-GW01 (score 95)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → CLINIC-VPN-GW01 → JUMP01 → INFUSION-GW01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **INFUSION-GW01** via domain (QID 91145) — exploited via Infusion Pump Gateway - VxWorks IPnet TCP/IP Stack Buffer Overflow

### DISC-13 — CLINIC-VPN-GW01 → PHARMACY-DISPENSE01 (score 95)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → CLINIC-VPN-GW01 → JUMP01 → PHARMACY-DISPENSE01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **PHARMACY-DISPENSE01** via domain (QID 91145) — exploited via Automated Dispensing Cabinet Shares Administrative Credential With General IT Administration (Excessive Access)

### DISC-14 — PORTAL01 → TELEHEALTH-APP01 (score 91.25)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → PORTAL01 → TELEHEALTH-APP01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **TELEHEALTH-APP01** via segmentation (QID 200901) — exploited via Hardcoded Database Credentials in Telehealth Application Configuration File

### DISC-15 — PORTAL01 → HYPERVISOR01 (score 91.25)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → PORTAL01 → HYPERVISOR01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **HYPERVISOR01** via segmentation (QID 200955) — exploited via VMware vCenter Server Arbitrary File Upload Remote Code Execution

### DISC-16 — CLINIC-VPN-GW01 → TELEHEALTH-APP01 (score 91.25)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → CLINIC-VPN-GW01 → TELEHEALTH-APP01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **TELEHEALTH-APP01** via segmentation (QID 200901) — exploited via Hardcoded Database Credentials in Telehealth Application Configuration File

### DISC-17 — CLINIC-VPN-GW01 → HYPERVISOR01 (score 91.25)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → CLINIC-VPN-GW01 → HYPERVISOR01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **HYPERVISOR01** via segmentation (QID 200955) — exploited via VMware vCenter Server Arbitrary File Upload Remote Code Execution

### DISC-18 — PORTAL01 → PACS-MODALITY01 (score 90.5)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → PORTAL01 → JUMP01 → PACS-MODALITY01
  1. **PORTAL01** via entry (QID 12055) — exploited via Patient Portal Webshell Upload Following RCE
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **PACS-MODALITY01** via domain (QID 91145)

### DISC-19 — CLINIC-VPN-GW01 → PACS-MODALITY01 (score 90.5)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 3

Kill chain: Internet → CLINIC-VPN-GW01 → JUMP01 → PACS-MODALITY01
  1. **CLINIC-VPN-GW01** via entry (QID 46840) — exploited via VPN Split-Tunnel ACL Grants Clinic Remote Users Access to Management VLAN (Excessive Access)
  2. **JUMP01** via segmentation (QID 200955) — exploited via Cached Domain Admin Credentials Present on Jump Host (Credential Hygiene Violation)
  3. **PACS-MODALITY01** via domain (QID 91145)

### DISC-20 — velon-claims-db → velon-claims-db (score 86.08)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 1

Kill chain: Internet → velon-claims-db
  1. **velon-claims-db** via entry (QID 300228) — exploited via Azure SQL Database 'velon-claims-db' Publicly Accessible With Weak Administrator Password

### DISC-21 — velon-imaging-archive → velon-claims-db (score 86.08)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → velon-imaging-archive → velon-claims-db
  1. **velon-imaging-archive** via entry (QID 300201) — exploited via Azure Blob Storage Container Publicly Readable - Contains SAS Token Backup File
  2. **velon-claims-db** via lateral — exploited via Azure SQL Database 'velon-claims-db' Publicly Accessible With Weak Administrator Password

### DISC-22 — GUEST-AP-SW01 → DC01 (score 85.72)
Confidence: — · Novelty: — · Blast radius: 1 · Hops: 2

Kill chain: Internet → GUEST-AP-SW01 → DC01
  1. **GUEST-AP-SW01** via entry (QID 110001) — exploited via Guest/Patient Wireless VLAN Not Isolated From Corporate LAN (Misconfigured Trunk)
  2. **DC01** via segmentation (QID 110001) — exploited via Active Directory sAMAccountName Spoofing Privilege Escalation (noPac)

## Analyst-Detected Paths (6)

_Reasoned from the asset/ownership/reachability grounding alone by the Analyst Detection Agent — no candidate list, no answer key. Every hop verified against a real finding._

### PORTAL01 → DB-EHR01 — grounded (confidence high)
  1. PORTAL01 → EHR-APP01 (QID 12055) via RULE-VL-003
  2. EHR-APP01 → DB-EHR01 (QID 20144) via RULE-VL-004
  3. DB-EHR01 → DB-EHR01 (QID 200933) via N/A
**Impact:** Full EHR database compromise, PHI breach

### CLINIC-VPN-GW01 → HYPERVISOR01 — grounded (confidence high)
  1. CLINIC-VPN-GW01 → JUMP01 (QID 46840) via RULE-VL-007
  2. JUMP01 → HYPERVISOR01 (QID 91145) via CRED-VL-01
  3. JUMP01 → HYPERVISOR01 (QID 46912) via RULE-VL-010
**Impact:** Full virtualization layer takeover, VM escape

### GUEST-AP-SW01 → DC01 — grounded (confidence high)
  1. GUEST-AP-SW01 → WKS-CLIN01 (QID 110001) via RULE-VL-008
  2. WKS-CLIN01 → DC01 (QID 48113) via RULE-VL-005
  3. DC01 → DC01 (QID 91278) via N/A
**Impact:** Domain admin takeover, AD forest compromise

### velon-claims-db → DB-CLAIMS01 — grounded (confidence high)
  1. velon-claims-db → velon-claims-db (QID 300228) via RULE-VL-014
  2. velon-claims-db → DB-CLAIMS01 (QID 201055) via N/A
**Impact:** Claims database exfiltration, PHI breach

### velon-imaging-archive → velon.onmicrosoft.com — grounded (confidence high)
  1. velon-imaging-archive → velon-imaging-archive (QID 300201) via RULE-VL-013
  2. velon-imaging-archive → velon-app-sp (QID 300214) via N/A
  3. velon-app-sp → velon.onmicrosoft.com (QID 300251) via N/A
**Impact:** Full Azure tenant takeover, cloud crown jewels

### WKS-CLIN01 → INFUSION-GW01 — grounded (confidence medium)
  1. WKS-CLIN01 → DC01 (QID 91260) via RULE-VL-005
  2. DC01 → PHARMACY-DISPENSE01 (QID 201011) via CRED-VL-01
  3. PHARMACY-DISPENSE01 → INFUSION-GW01 (QID 200999) via RULE-VL-005
**Impact:** Infusion pump gateway takeover, patient safety risk

## Documented Paths (held-out verification ground truth)

_Never ingested or shown to the engine/agents — used only to grade rediscovery._

- **PATH-A** — GUEST-AP-SW01 → FILESRV01 (GUEST-AP-SW01 → PRINT01 → FILESRV01 → FILESRV01)
- **PATH-B** — PORTAL01 → DB-EHR01 (PORTAL01 → PORTAL01 → LB01 → EHR-APP01 → DB-EHR01)
- **PATH-C** — velon-imaging-archive → velon-claims-db (velon-imaging-archive → velon-app-sp → velon-claims-db)
- **PATH-D** — CLINIC-VPN-GW01 → BACKUP-MGR01 (CLINIC-VPN-GW01 → CLINIC-VPN-GW01 policy → JUMP01 → HYPERVISOR01 → BACKUP-MGR01)
- **PATH-E** — DC01 → PHARMACY-DISPENSE01 (DC01 → DC01 → Clinical/Biomed VLAN Firewall Policy → INFUSION-GW01 → PHARMACY-DISPENSE01)
- **PATH-F** — TELEHEALTH-APP01 → DB-CLAIMS01 (TELEHEALTH-APP01 → TELEHEALTH-APP01 → TELEHEALTH-APP01 → DB-CLAIMS01)

---

# Ghrab VOC — Correlation & Toxic Combinations Report
_Generated 7/22/2026, 8:59:15 AM_


---

# Ghrab VOC — Teams & Ownership Report
_Generated 7/22/2026, 8:59:15 AM_

| Team | Findings | Avg GRS | Peak GRS | Immediate | KEV | DORA CIF |
|---|---|---|---|---|---|---|
| AppSec Team | 7 | 72.4 | 100 | 3 | 4 | 4 |
| Network Team | 7 | 56.5 | 100 | 1 | 1 | 2 |
| Cloud Team | 5 | 55 | 78.5 | 0 | 1 | 2 |
| DBA Team | 4 | 58.5 | 78.5 | 0 | 0 | 4 |
| IT Infrastructure Team | 11 | 36.7 | 72.7 | 0 | 2 | 5 |
| Clinical Engineering & Compliance | 2 | 61.3 | 64.5 | 0 | 0 | 2 |
| Compliance-GRC | 3 | 58.4 | 61.2 | 0 | 0 | 2 |

---

# Ghrab VOC — Compliance Posture Report
_Generated 7/22/2026, 8:59:15 AM_

## Auditor Briefing

Velon Health Systems exhibits systemic gaps in network segmentation, access control, and vulnerability management that expose critical clinical and business systems to high-impact cyber threats. Internet-facing systems (patient portal, VPN, telehealth) contain unpatched remote code execution vulnerabilities, while excessive network reachability and shared credentials enable lateral movement into HIPAA/FDA-scoped clinical zones. Cloud and on-premises identity controls are misconfigured, granting excessive privileges to service accounts and administrators. These deficiencies violate core HIPAA Security Rule requirements and FDA postmarket cybersecurity guidance, placing patient safety and regulatory compliance at significant risk.

## Frameworks in Scope

`HIPAA Security Rule`, `FDA Premarket Cybersecurity Guidance`, `FDA Postmarket Cybersecurity Guidance`, `CIS Controls`, `CIS Azure Benchmark`, `EU DORA`

## DORA CIF Overlay

Under EU DORA, the 15 findings flagged as 'DORA CIF' (Critical or Important Function) must be remediated within the prescribed SLA—typically 30 days for critical, 60 for important—regardless of internal risk acceptance. Failure to meet these deadlines may result in supervisory intervention and potential penalties.

## Key Gaps

- **[HIPAA Security Rule 164.308(a)(1) - Security Management Process]** Lack of effective vulnerability management and risk analysis controls leading to remote code execution vulnerabilities in internet-facing and critical application systems (Drupal, WebLogic, Spring, Active Directory). (QIDs: 12061, 12055, 20144, 150455, 91278, 201099, 200999)
- **[HIPAA Security Rule 164.312(e) - Transmission Security]** Excessive network reachability and misconfigured segmentation allowing unauthorized access from low-trust zones (DMZ, Guest WiFi, Clinic VPN) into high-trust and critical zones (App Tier, Management, Clinical/Biomed). (QIDs: 46840, 200999, 200901, 200955, 110001)
- **[HIPAA Security Rule 164.312(a)(1) - Access Control]** Excessive privileges and weak authentication controls across databases, applications, and cloud services, including shared credentials, hardcoded secrets, and over-permissive service accounts. (QIDs: 300228, 201011, 200933, 201055, 150467, 150401, 110102)
- **[FDA Postmarket Cybersecurity Guidance / HIPAA 164.312(a)]** Critical biomedical devices (infusion pump gateway, automated dispensing cabinet) exposed to network-based attacks due to unpatched firmware and shared administrative credentials with general IT systems. (QIDs: 400012, 201011)
- **[CIS Azure Benchmark / HIPAA 164.308(a)(4)]** Excessive IAM privileges in Azure AD, including subscription 'Owner' role assignments and publicly accessible storage containers containing sensitive backup files. (QIDs: 300214, 300251, 300201)
- **[CIS Control 5 - Account Management]** Poor credential hygiene, including local administrator password reuse, cached domain admin credentials on jump hosts, and applications running with excessive SYSTEM privileges. (QIDs: 201033, 91022, 91145)

---

## Findings Summary

32 total findings. Export the Findings page separately for the full CSV table.
