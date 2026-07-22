# Ghrab VOC — Full Vulnerability Operations Report
_Generated 7/22/2026, 11:55:24 AM_

---

# Ghrab VOC — Command Center Report
_Generated 7/22/2026, 11:55:24 AM_

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

Velon Health Systems’ vulnerability posture is **CRITICAL**, with immediate risk to HIPAA/FDA-scoped clinical systems due to unpatched RCE chains and flat network trust. The **single most urgent finding** is the **Patient Portal Webshell Upload (QID 12061)** on PORTAL01 (DMZ), chaining CVE-2018-7600 (Drupalgeddon2) with excessive DMZ-to-AppTier firewall rules (RULE-VL-003), enabling pivot to EHR-APP01 (Crown Jewel) and onward to DB-EHR01 via RULE-VL-004—validated by prior agents as a toxic combination. The **most exposed team** is **AppSec**, owning both the portal and EHR application tiers, where unpatched WebLogic (CVE-2020-14882) and Spring4Shell (CVE-2022-22965) vulnerabilities compound the risk. Systemically, **excessive network reachability rules** (e.g., RULE-VL-003, RULE-VL-005, RULE-VL-007) and **shared credentials** (e.g., ‘svc_clinical’, local admin reuse) create lateral pathways that bypass intended segmentation, violating HIPAA 164.312(e) and FDA premarket guidance. Immediate containment requires patching PORTAL01, scoping RULE-VL-003 to tcp/7002, and isolating the clinical VLAN from corporate AD (RULE-VL-005).

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
_Generated 7/22/2026, 11:55:24 AM_

## Attack-Surface Synthesis

Velon Health Systems exhibits a high-risk attack surface characterized by pervasive credential reuse, flat trust models, and misconfigured segmentation. Internet-facing entry points (PORTAL01, CLINIC-VPN-GW01) provide initial access, while shared local administrator passwords, service accounts, and Azure AD misconfigurations enable lateral movement across trust boundaries. Clinical devices (HIPAA/FDA-scoped) are particularly vulnerable due to direct AD integration and weak isolation from corporate networks. Cloud assets introduce additional risk via excessive IAM privileges and public exposure, creating parallel attack paths that bypass on-premises controls. Immediate remediation should prioritize credential hygiene, network tiering, and cloud IAM least-privilege principles to disrupt these toxic combinations.

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

## Toxic Combinations

### Shared Local Administrator Password Across Clinical Workstations and File Server
The same local administrator password (QID 91022) is reused on FILESRV01 (Corporate LAN) and clinical workstations (e.g., WKS-CLIN01). An attacker compromising PORTAL01 (DISC-01) or CLINIC-VPN-GW01 (DISC-02) can pivot to FILESRV01 via SMB (QID 150401) and extract the shared credential, then laterally move to clinical workstations in the Corporate LAN. From there, the flat trust (QID 200999) allows Kerberos/LDAP/SMB access to the Clinical/Biomed Critical Zone (VLAN 40), enabling attacks on INFUSION-GW01 or PHARMACY-DISPENSE01.
**Why it matters:** This bypasses network segmentation by leveraging credential reuse and flat trust, directly linking internet-facing entry points to HIPAA/FDA-scoped clinical devices without requiring additional exploits.
QIDs: 91022, 150401, 200999, 12055, 46840, 400012, 201011

### Clinical Integration Service Account ('svc_clinical') as a Cross-Zone Pivot
The 'svc_clinical' account (QID 91260) has a weak, non-rotated password and is valid on DC01 (Corporate LAN) and likely on clinical devices (e.g., INFUSION-GW01, PHARMACY-DISPENSE01) due to shared AD integration. An attacker compromising DC01 via JUMP01 (DISC-09) or GUEST-AP-SW01 (DISC-22) can extract this credential and use it to authenticate directly to clinical devices in VLAN 40, bypassing the intended network isolation (QID 201099).
**Why it matters:** This credential acts as a 'skeleton key' across trust boundaries, enabling direct access to FDA-regulated devices from corporate or guest networks without exploiting additional vulnerabilities.
QIDs: 91260, 91145, 91278, 201099, 110001, 400012, 201011

### Azure AD Global Administrator Privilege Escalation to Cloud-Hosted EHR Data
The Azure AD tenant (velon.onmicrosoft.com) has excessive Global Administrator role assignments (QID 300251). An attacker compromising the Azure AD App Registration (QID 300214) via PORTAL01 (DISC-01) or CLINIC-VPN-GW01 (DISC-02) can escalate privileges to Global Administrator. This grants full control over velon-claims-db (QID 300228) and velon-imaging-archive (QID 300201), enabling exfiltration or manipulation of PHI without touching on-premises systems.
**Why it matters:** This cloud-based pivot circumvents on-premises segmentation entirely, providing a direct path to sensitive data with minimal detection risk due to the lack of on-premises telemetry.
QIDs: 300251, 300214, 300228, 300201, 12055, 46840

### Hardcoded Database Credentials in Telehealth App Linking Cloud and On-Premises
TELEHEALTH-APP01 contains hardcoded database credentials (QID 150467) for DB-CLAIMS01. These credentials are likely reused for the cloud-hosted velon-claims-db (QID 300228) due to shared application logic. An attacker compromising TELEHEALTH-APP01 (DISC-05/DISC-06) can extract these credentials and use them to access velon-claims-db directly from the internet, bypassing the need for on-premises lateral movement.
**Why it matters:** This creates a 'bridge' between on-premises and cloud environments, allowing attackers to leap from a DMZ application to a publicly exposed cloud database with a single credential reuse.
QIDs: 150467, 201055, 300228, 12055, 46840

## Analyst-Detected Paths (6)

_Reasoned from the asset/ownership/reachability grounding alone by the Analyst Detection Agent — no candidate list, no answer key. Every hop verified against a real finding._

### PORTAL01 → DB-EHR01 — grounded (confidence high)
  1. PORTAL01 → EHR-APP01 (QID 12055) via RULE-VL-003
  2. EHR-APP01 → DB-EHR01 (QID 20144) via RULE-VL-004
  3. DB-EHR01 → DB-EHR01 (QID 200933) via None
**Impact:** Full EHR database compromise, PHI breach

### CLINIC-VPN-GW01 → HYPERVISOR01 — grounded (confidence high)
  1. CLINIC-VPN-GW01 → JUMP01 (QID 46840) via RULE-VL-007
  2. JUMP01 → HYPERVISOR01 (QID 91145) via CRED-VL-01
  3. HYPERVISOR01 → HYPERVISOR01 (QID 46912) via None
**Impact:** Full virtualization layer takeover

### GUEST-AP-SW01 → INFUSION-GW01 — grounded (confidence medium)
  1. GUEST-AP-SW01 → WKS-CLIN01 (QID 110001) via RULE-VL-008
  2. WKS-CLIN01 → DC01 (QID 48113) via RULE-VL-005
  3. DC01 → INFUSION-GW01 (QID 200999) via RULE-VL-005
**Impact:** Infusion pump gateway takeover, patient harm

### velon-claims-db → DB-CLAIMS01 — grounded (confidence high)
  1. velon-claims-db → TELEHEALTH-APP01 (QID 300228) via None
  2. TELEHEALTH-APP01 → DB-CLAIMS01 (QID 150467) via RULE-VL-004
**Impact:** Claims database exfiltration, fraud

### velon-imaging-archive → velon-claims-db — grounded (confidence high)
  1. velon-imaging-archive → velon-app-sp (QID 300201) via None
  2. velon-app-sp → velon-claims-db (QID 300214) via None
**Impact:** Full Azure subscription takeover

### PORTAL01 → DC01 — grounded (confidence high)
  1. PORTAL01 → PRINT01 (QID 12055) via RULE-VL-003
  2. PRINT01 → DC01 (QID 46587) via CRED-VL-01
  3. DC01 → DC01 (QID 91278) via None
**Impact:** Full Active Directory domain compromise

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
_Generated 7/22/2026, 11:55:24 AM_


---

# Ghrab VOC — Teams & Ownership Report
_Generated 7/22/2026, 11:55:24 AM_

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
_Generated 7/22/2026, 11:55:24 AM_

## Auditor Briefing

Velon Health Systems exhibits systemic gaps in HIPAA and FDA compliance, with 12 critical vulnerabilities enabling remote code execution across patient portals, EHR systems, and clinical devices. Network segmentation failures and excessive privileges create attack paths from untrusted zones (guest WiFi, DMZ) into HIPAA/FDA-scoped environments. DORA's 24-hour reporting requirement applies to 15 findings tied to critical functions, including telehealth and infusion pump gateways. Immediate remediation of RCE vectors and network trust violations is required to mitigate patient safety risks and regulatory exposure.

## Frameworks in Scope

`HIPAA Security Rule`, `FDA Premarket Cybersecurity Guidance`, `FDA Postmarket Cybersecurity Guidance`, `CIS Controls`, `CIS Azure Benchmark`, `EU DORA`

## DORA CIF Overlay

DORA CIF-scoped findings (15/32) are subject to the EU's 24-hour incident reporting SLA for critical or important functions. Non-capped SLAs (e.g., PrintNightmare, SMBGhost) may still trigger DORA obligations if exploited, but are not pre-classified as CIF-related.

## Key Gaps

- **[HIPAA Security Rule 164.308(a)(1) - Security Management Process]** Failure to implement risk analysis, risk management, and access controls for critical systems (EHR, telehealth, patient portal, AD, clinical/biomed VLAN). Multiple RCE vectors exist due to unpatched software and flat network trust. (QIDs: 12061, 12055, 20144, 150455, 91278, 201099, 200999)
- **[HIPAA Security Rule 164.312(e) - Transmission Security]** Lack of network segmentation and encryption controls. Excessive firewall rules, VPN split-tunneling into management VLAN, and misconfigured guest WiFi trunk allow lateral movement into critical zones. (QIDs: 46840, 200999, 200901, 200955, 110001)
- **[HIPAA Security Rule 164.312(a)(1) - Access Control]** Excessive privileges across clinical, database, and application layers. Shared credentials, hardcoded secrets, and overly permissive NTFS/SMB shares violate least privilege and separation of duties. (QIDs: 201011, 200933, 201055, 150467, 150401, 110102)
- **[FDA Postmarket Cybersecurity Guidance]** Unpatched VxWorks buffer overflow in infusion pump gateway and shared administrative credentials in dispensing cabinets create unacceptable risk to patient safety and device integrity. (QIDs: 400012, 201011)
- **[CIS Azure Benchmark]** Excessive IAM privileges in Azure AD (Global Admin, Owner roles) and publicly accessible storage with sensitive data (SAS tokens) violate cloud security best practices. (QIDs: 300214, 300201, 300251)

---

## Findings Summary

32 total findings. Export the Findings page separately for the full CSV table.
