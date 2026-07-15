# Velon Health Systems — CMDB & Relationship Ground Truth

### Configuration Management Database (CI Inventory, Relationships, Network Reachability, and Cross-Referenced Attack Paths) — Lab: Velon (Lab 2 — Healthcare)

**Purpose of this document.** This replaces prose-only architecture description with an explicit, machine-checkable relationship graph, structured the way a real CMDB (e.g. ServiceNow `cmdb_ci` + `cmdb_rel_ci`) represents infrastructure: every Configuration Item (CI) has a unique ID, a class, and a set of *typed* relationships to other CIs. Every attack path step below cites the exact Relationship ID or Rule ID that makes that hop possible. If a hop doesn't trace to a row in §3–§5, it isn't real — that's the test your detection agents should be run against, including the explicit non-existent paths in §8.

**How to use this for agent evaluation:** (1) Feed §2–§7 to your agent as ground truth. (2) Ask it to trace a path or validate one you give it. (3) Check every hop against the Relationship/Rule ID it cites — a real path always has one; a hallucinated path won't. (4) Test the §8 negatives directly — a correct agent explains *why* each is false by citing the absence of a rule, not just asserting it.

---

## 1. CI Inventory

Every asset in this lab is a Configuration Item (CI) with a unique ID, class, zone, criticality tier, owning Support Group, and the Business Service it exists to support. Criticality tiers mirror the Asset Criticality Weight (ACW) used in the Ghrab Risk Score methodology: **Crown Jewel > High > Business-Important > Standard**.

### 1.1 Network Segments (Class: `cmdb_ci_network_segment`)

| CI ID | Name | CIDR | Trust Level | Owning Support Group |
|---|---|---|---|---|
| NET-VL-0010 | VLAN 10 — Corporate LAN | 10.20.10.0/24 | Medium | GRP-VL-IT |
| NET-VL-0020 | VLAN 20 — DMZ | 10.20.20.0/24 | Low (internet-facing) | GRP-VL-NET |
| NET-VL-0021 | VLAN 21 — App Tier | 10.20.21.0/24 | Medium | GRP-VL-APP |
| NET-VL-0030 | VLAN 30 — DB Tier | 10.20.30.0/24 | High | GRP-VL-DBA |
| NET-VL-0040 | VLAN 40 — Clinical/Biomed Critical Zone (HIPAA/FDA scope) | 10.20.40.0/24 | Critical | GRP-VL-CE |
| NET-VL-0050 | VLAN 50 — Management/OOB | 10.20.50.0/24 | Critical (should be) | GRP-VL-IT |
| NET-VL-0060 | VLAN 60 — Clinic/Branch VPN | 10.20.60.0/24 | Medium | GRP-VL-NET |
| NET-VL-0070 | VLAN 70 — Guest/Patient WiFi | 10.20.70.0/24 | Untrusted | GRP-VL-NET |
| NET-VL-0080 | VLAN 80 — Backup/Storage | 10.20.80.0/24 | High | GRP-VL-IT |
| NET-VL-0090 | Cloud — Azure Subscription (velon-prod) | N/A | Mixed | GRP-VL-CLD |
| NET-VL-INET | Internet (untrusted) | 0.0.0.0/0 | None | N/A |


### 1.2 Servers & Network Devices (Class: `cmdb_ci_server` / `cmdb_ci_netgear`)

| CI ID | Name | Zone | IP | Platform | Criticality | Support Group | Business Service |
|---|---|---|---|---|---|---|---|
| SRV-VL-1001 | DC01 | NET-VL-0010 | 10.20.10.10 | Windows Server (AD DS) | Crown Jewel | GRP-VL-IT | BSVC-VL-04 |
| SRV-VL-1002 | FILESRV01 | NET-VL-0010 | 10.20.10.20 | Windows Server | Business-Important | GRP-VL-IT | BSVC-VL-01 |
| SRV-VL-1003 | PRINT01 | NET-VL-0010 | 10.20.10.30 | Windows Server (Print Spooler) | Standard | GRP-VL-IT | BSVC-VL-04 |
| SRV-VL-1004 | WKS-CLIN01 | NET-VL-0010 | 10.20.10.60 | Windows 10/11 | Standard | GRP-VL-IT | BSVC-VL-04 |
| SRV-VL-1010 | LB01 | NET-VL-0020 | 10.20.20.5 | F5/NGINX Appliance | Business-Important | GRP-VL-NET | BSVC-VL-01 |
| SRV-VL-1011 | PORTAL01 | NET-VL-0020 | 10.20.20.10 | Linux (Drupal) | Business-Important | GRP-VL-NET | BSVC-VL-01 |
| SRV-VL-1012 | CLINIC-VPN-GW01 | NET-VL-0020 | 10.20.20.20 | FortiGate Appliance | Business-Important | GRP-VL-NET | BSVC-VL-04 |
| SRV-VL-1013 | TELEHEALTH-GW01 | NET-VL-0020 | 10.20.20.30 | Linux (Video/Mail Relay) | Business-Important | GRP-VL-NET | BSVC-VL-02 |
| SRV-VL-1020 | EHR-APP01 | NET-VL-0021 | 10.20.21.10 | Linux (Oracle WebLogic) | Crown Jewel | GRP-VL-APP | BSVC-VL-01 |
| SRV-VL-1021 | BILLING-APP01 | NET-VL-0021 | 10.20.21.20 | Linux | Standard | GRP-VL-APP | BSVC-VL-03 |
| SRV-VL-1022 | TELEHEALTH-APP01 | NET-VL-0021 | 10.20.21.30 | Linux (Java/Spring) | High | GRP-VL-APP | BSVC-VL-02 |
| SRV-VL-1030 | DB-EHR01 | NET-VL-0030 | 10.20.30.10 | MSSQL | Crown Jewel | GRP-VL-DBA | BSVC-VL-01 |
| SRV-VL-1031 | DB-PACS01 | NET-VL-0030 | 10.20.30.20 | MSSQL | High | GRP-VL-DBA | BSVC-VL-01 |
| SRV-VL-1032 | DB-CLAIMS01 | NET-VL-0030 | 10.20.30.30 | MSSQL | High | GRP-VL-DBA | BSVC-VL-03 |
| SRV-VL-1040 | INFUSION-GW01 | NET-VL-0040 | 10.20.40.10 | VxWorks RTOS (Alaris-class gateway) | Crown Jewel | GRP-VL-CE | BSVC-VL-05 |
| SRV-VL-1041 | PACS-MODALITY01 | NET-VL-0040 | 10.20.40.20 | DICOM Imaging Modality | Crown Jewel | GRP-VL-CE | BSVC-VL-05 |
| SRV-VL-1042 | PHARMACY-DISPENSE01 | NET-VL-0040 | 10.20.40.30 | Windows (Dispensing Cabinet Controller) | Crown Jewel | GRP-VL-CE | BSVC-VL-05 |
| SRV-VL-1050 | JUMP01 | NET-VL-0050 | 10.20.50.10 | Windows Server (Bastion) | High | GRP-VL-IT | BSVC-VL-04 |
| SRV-VL-1051 | HYPERVISOR01 | NET-VL-0050 | 10.20.50.20 | VMware vCenter Appliance | High | GRP-VL-IT | BSVC-VL-04 |
| SRV-VL-1052 | BACKUP-MGR01 | NET-VL-0050 | 10.20.50.30 | Windows Server (Veeam) | High | GRP-VL-IT | BSVC-VL-04 |
| SRV-VL-1060 | CLINIC-RTR01 | NET-VL-0060 | 10.20.60.1 | Router Appliance | Standard | GRP-VL-NET | BSVC-VL-04 |
| SRV-VL-1061 | CLINIC-WKS01 | NET-VL-0060 | 10.20.60.50 | Windows 10/11 | Standard | GRP-VL-NET | BSVC-VL-04 |
| SRV-VL-1070 | GUEST-AP-SW01 | NET-VL-0070 | 10.20.70.1 | Access Switch | Standard | GRP-VL-NET | BSVC-VL-04 |
| SRV-VL-1080 | IMAGING-NAS01 | NET-VL-0080 | 10.20.80.10 | NAS Appliance | High | GRP-VL-IT | BSVC-VL-01 |
| SRV-VL-1081 | BACKUP-SRV01 | NET-VL-0080 | 10.20.80.20 | Windows Server | Business-Important | GRP-VL-IT | BSVC-VL-04 |


### 1.3 Applications (Class: `cmdb_ci_appl`) — "Runs On" a Server CI

| CI ID | Name | Runs On (CI ID) | Support Group | Business Service |
|---|---|---|---|---|
| APP-VL-3011 | Velon Patient Portal (Drupal CMS) | SRV-VL-1011 (PORTAL01) | GRP-VL-APP | BSVC-VL-01 |
| APP-VL-3020 | Electronic Health Record (WebLogic) | SRV-VL-1020 (EHR-APP01) | GRP-VL-APP | BSVC-VL-01 |
| APP-VL-3022 | Telehealth Backend (Spring) | SRV-VL-1022 (TELEHEALTH-APP01) | GRP-VL-APP | BSVC-VL-02 |
| APP-VL-3013 | Telehealth Video/Mail Relay Service | SRV-VL-1013 (TELEHEALTH-GW01) | GRP-VL-NET | BSVC-VL-02 |
| APP-VL-3001 | Active Directory Domain Services | SRV-VL-1001 (DC01) | GRP-VL-IT | BSVC-VL-04 |
| APP-VL-3051 | VMware vCenter Server | SRV-VL-1051 (HYPERVISOR01) | GRP-VL-IT | BSVC-VL-04 |


### 1.4 Cloud Services (Class: `cmdb_ci_cloud_service`)

| CI ID | Name | Provider | Type | Criticality | Support Group | Business Service |
|---|---|---|---|---|---|---|
| CLD-VL-5001 | Blob: velon-imaging-archive | Microsoft Azure | Object Storage | Business-Important | GRP-VL-CLD | BSVC-VL-01 |
| CLD-VL-5002 | Service Principal: velon-app-sp | Microsoft Azure | Azure AD App Registration | High | GRP-VL-CLD | BSVC-VL-01 |
| CLD-VL-5003 | Azure SQL: velon-claims-db | Microsoft Azure | Managed Database (Azure SQL) | High | GRP-VL-CLD | BSVC-VL-03 |
| CLD-VL-5004 | Azure AD Tenant: velon.onmicrosoft.com | Microsoft Azure AD | Identity Tenant | High | GRP-VL-CLD | BSVC-VL-04 |


### 1.5 Identity & Credential CIs (Class: `cmdb_ci_service_account` / `cmdb_ci_group`)

| CI ID | Name | Type | Valid On (CI IDs) | Known Issue |
|---|---|---|---|---|
| ID-VL-6001 | VELON.LOCAL | AD Forest/Domain | All domain-joined CIs | N/A |
| ID-VL-6002 | svc_clinical | Service Account | SRV-VL-1001 (domain), HL7 interface engine runtime | Weak, non-rotated password — Kerberoastable |
| ID-VL-6003 | Shared Local Administrator | Local Account | SRV-VL-1004, SRV-VL-1002, SRV-VL-1003 | Identical password reused across hosts, no LAPS |
| ID-VL-6004 | Domain Admins | AD Group | SRV-VL-1001, and (via RULE-VL-005) SRV-VL-1040, SRV-VL-1042, SRV-VL-1050 | Flat trust lets this group reach the Clinical zone directly |
| ID-VL-6005 | Shared Clinical-Admin Credential | Local/Domain Admin Credential | SRV-VL-1040 (INFUSION-GW01), SRV-VL-1042 (PHARMACY-DISPENSE01) | Same credential as general Domain Admin — violates FDA postmarket dedicated-identity guidance |
| ID-VL-6006 | velon-app-sp | Azure AD Service Principal | CLD-VL-5001 (originates), all subscription resources (Owner role) | Subscription-level Owner role — excessive scope |


### 1.6 Business Services (Class: `cmdb_ci_business_service`)

| CI ID | Name | Description |
|---|---|---|
| BSVC-VL-01 | Patient Care — EHR & Records | Patient portal, EHR, imaging archive, and related patient data |
| BSVC-VL-02 | Telehealth Services | Video-visit platform and supporting infrastructure |
| BSVC-VL-03 | Insurance Claims & Billing | Claims processing, billing application and database |
| BSVC-VL-04 | Corporate IT & Collaboration | Internal identity, email, file shares, endpoints, infrastructure management |
| BSVC-VL-05 | Clinical/Biomedical Devices | Infusion pumps, imaging modalities, pharmacy dispensing — life-safety-critical systems |


### 1.7 Support Groups

| Group ID | Name | Responsible For |
|---|---|---|
| GRP-VL-IT | IT Infrastructure Team | Windows/Linux server patching, AD, endpoints, backup infra |
| GRP-VL-NET | Network Team | Firewalls, VLAN segmentation, VPN, guest WiFi |
| GRP-VL-APP | AppSec Team | Web/application-layer vulnerabilities, secure SDLC, app service accounts |
| GRP-VL-DBA | DBA Team | Database hardening, account privilege scoping, DB links |
| GRP-VL-CLD | Cloud Team | Azure configuration, IAM, cloud-native services |
| GRP-VL-CE | Clinical Engineering & Compliance | Biomedical/IoT device security, HIPAA/FDA compliance, clinical zone segmentation |


## 2. Virtualization / Hosting Relationships

`SRV-VL-1051 (HYPERVISOR01)` is the hypervisor management plane for this environment. Compromise of it means compromise of every VM it hosts — this is the single biggest blast-radius relationship in the whole CMDB, and it's a common miss in prose-only architecture docs.

| Relationship ID | Guest CI | Relationship | Host CI |
|---|---|---|---|
| REL-VL-V01 | SRV-VL-1011 (PORTAL01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V02 | SRV-VL-1013 (TELEHEALTH-GW01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V03 | SRV-VL-1020 (EHR-APP01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V04 | SRV-VL-1021 (BILLING-APP01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V05 | SRV-VL-1022 (TELEHEALTH-APP01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V06 | SRV-VL-1030 (DB-EHR01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V07 | SRV-VL-1031 (DB-PACS01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V08 | SRV-VL-1032 (DB-CLAIMS01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V09 | SRV-VL-1002 (FILESRV01) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |
| REL-VL-V10 | SRV-VL-1013 (TELEHEALTH-GW01, backend cluster node) | Virtualized On | SRV-VL-1051 (HYPERVISOR01) |


## 3. Network Reachability Rule Base (Zone-to-Zone) — THE authoritative reachability graph

This is the master truth table for "can zone X reach zone Y." Every attack path hop that crosses a zone boundary must cite a Rule ID from this table. **Status** distinguishes intended design (`Intended`), a real misconfiguration that enables an attack path (`Excessive`), and a zone pair with **no rule at all** (`Should-Not-Exist` / absent) — if an agent claims a path crossing a zone pair not listed here, or listed as absent, that hop is fabricated.

| Rule ID | Source Zone | Destination Zone | Port/Protocol | Status | Notes |
|---|---|---|---|---|---|
| RULE-VL-001 | NET-VL-INET | NET-VL-0020 | 443, 80, 25 | Intended | Public patient portal, clinic VPN, telehealth gateway |
| RULE-VL-002 | NET-VL-0020 | NET-VL-0021 | tcp/7002 (LB backend only) | Intended (design) | As-designed rule; superseded in practice by RULE-VL-003 |
| RULE-VL-003 | NET-VL-0020 | NET-VL-0021 | ANY/ANY | Excessive | As-configured firewall rule; QID 200901 — should be scoped to RULE-VL-002 only |
| RULE-VL-004 | NET-VL-0021 | NET-VL-0030 | tcp/1433 | Intended | App tier to DB tier, standard app connectivity |
| RULE-VL-005 | NET-VL-0010 | NET-VL-0040 | ANY (Kerberos/LDAP/SMB) | Excessive | Flat trust; QID 200999 — no tiering/PAM boundary enforced |
| RULE-VL-006 | NET-VL-0010 | NET-VL-0050 | N/A | Should-Not-Exist (no rule) | Management plane must only be reached via designated jump path |
| RULE-VL-007 | NET-VL-0020 | NET-VL-0050 | ANY (VPN split-tunnel) | Excessive | QID 200955 — clinic VPN client policy routes into management VLAN |
| RULE-VL-008 | NET-VL-0070 | NET-VL-0010 | 802.1Q (all VLANs) | Excessive | QID 110001 — guest trunk misconfigured, should be access-mode only |
| RULE-VL-009 | NET-VL-0060 | NET-VL-0010 | udp/500,4500 tcp/443 | Intended | Site-to-site VPN, clinic to AD authentication only |
| RULE-VL-010 | NET-VL-0050 | NET-VL-0080 | tcp/9392, 445 | Intended | Backup jobs |
| RULE-VL-011 | NET-VL-0010 | NET-VL-0030 | N/A | Should-Not-Exist (no rule) | Workstations must never reach DB tier directly |
| RULE-VL-012 | NET-VL-0021 | NET-VL-0040 | N/A | Should-Not-Exist (no rule) | App tier and Clinical/Biomed zone are separate trust tiers |
| RULE-VL-013 | NET-VL-INET | CLD-VL-5001 | tcp/443 | Excessive | QID 300201 — Blob container public read enabled |
| RULE-VL-014 | NET-VL-INET | CLD-VL-5003 | tcp/1433 | Excessive | QID 300228 — Azure SQL firewall rule allows all IPs |
| RULE-VL-015 | NET-VL-0070 | NET-VL-0040 | N/A | Should-Not-Exist (no rule) | No path exists or has ever existed from Guest/Patient WiFi directly to the Clinical zone |


## 4. Host, Application & Database Dependency Relationships

Application-layer and data-layer dependencies, independent of network zone rules — these answer "what does this CI actually talk to and why," which a zone-level rule alone cannot.

| Relationship ID | Source CI | Relationship Type | Target CI | Port/Protocol | Justification | Flag |
|---|---|---|---|---|---|---|
| REL-VL-101 | SRV-VL-1010 (LB01) | Forwards To | SRV-VL-1011 (PORTAL01) | 443→443 | Reverse proxy for patient portal | Legitimate |
| REL-VL-102 | SRV-VL-1020 (EHR-APP01) | Depends On | SRV-VL-1030 (DB-EHR01) | 1433 | EHR application database backend, via svc_ehrapp | Legitimate connection / Excessive privilege (db_owner, QID 200933) |
| REL-VL-103 | SRV-VL-1022 (TELEHEALTH-APP01) | Depends On | SRV-VL-1032 (DB-CLAIMS01) | 1433 | Telehealth billing integration | Legitimate connection / Secrets exposed (QID 150467) |
| REL-VL-104 | SRV-VL-1021 (BILLING-APP01) | Depends On | SRV-VL-1031 (DB-PACS01) | 1433 | Billing-to-imaging cross-reference for procedure codes (documented business need) | Legitimate |
| REL-VL-105 | SRV-VL-1032 (DB-CLAIMS01, via linked server) | Linked To (DB Link) | SRV-VL-1030 (DB-EHR01) | 1433 | Insurance eligibility verification integration; linked server credentials never scoped down after go-live | Excessive (QID 201055) |
| REL-VL-106 | SRV-VL-1004 (WKS-CLIN01) | Authenticates To | SRV-VL-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-VL-107 | SRV-VL-1003 (PRINT01) | Authenticates To | SRV-VL-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-VL-108 | SRV-VL-1002 (FILESRV01) | Authenticates To | SRV-VL-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-VL-109 | SRV-VL-1050 (JUMP01) | Manages | SRV-VL-1051 (HYPERVISOR01) | 443 (vSphere API) | Admin bastion for virtualization management | Legitimate |
| REL-VL-110 | SRV-VL-1050 (JUMP01) | Manages | SRV-VL-1052 (BACKUP-MGR01) | 9392 | Admin bastion for backup management | Legitimate |
| REL-VL-111 | SRV-VL-1052 (BACKUP-MGR01) | Backs Up | SRV-VL-1081 (BACKUP-SRV01) | 445 | Scheduled backup jobs | Legitimate |
| REL-VL-112 | SRV-VL-1052 (BACKUP-MGR01) | Backs Up | SRV-VL-1080 (IMAGING-NAS01) | 445 | Scheduled backup jobs | Legitimate |
| REL-VL-113 | SRV-VL-1052 (BACKUP-MGR01) | Backs Up | SRV-VL-1030 (DB-EHR01) | 445 | Nightly DB dump backup — explains why NAS/backup compromise exposes EHR data | Legitimate |
| REL-VL-114 | SRV-VL-1052 (BACKUP-MGR01) | Backs Up | SRV-VL-1032 (DB-CLAIMS01) | 445 | Nightly DB dump backup | Legitimate |
| REL-VL-115 | CLD-VL-5001 (Blob velon-imaging-archive) | Grants Session To | CLD-VL-5002 (velon-app-sp) | HTTPS/Azure API | Leaked settings backup file in container contains SAS token/SP credentials | Excessive (QID 300201) |
| REL-VL-116 | CLD-VL-5002 (velon-app-sp) | Has Access To | CLD-VL-5003 (velon-claims-db) | Azure API / 1433 | Subscription Owner role grants access to all Azure resources | Excessive (QID 300214) |


## 5. Identity & Credential Relationships

Many real attack paths aren't network hops at all — they're a credential valid on more than one CI. This table makes that explicit so agents don't need to (incorrectly) invent a network relationship to explain lateral movement that is actually credential reuse.

| Relationship ID | Credential/Identity CI | Valid On (CI ID) | Access Level Granted | Issue |
|---|---|---|---|---|
| CRED-VL-01 | ID-VL-6003 (Shared Local Administrator) | SRV-VL-1004, SRV-VL-1002, SRV-VL-1003 | Local Administrator | Enables pass-the-hash lateral movement (QID 91022) |
| CRED-VL-02 | ID-VL-6002 (svc_clinical) | SRV-VL-1001 (domain account), HL7 interface engine runtime | Domain User + local service | Kerberoastable, weak password (QID 91260) |
| CRED-VL-03 | ID-VL-6004 (Domain Admins) | SRV-VL-1001, and via RULE-VL-005 also SRV-VL-1040, SRV-VL-1042, SRV-VL-1050 | Full domain administrative control | Flat trust extends DA reach into the Clinical zone (QID 200999) |
| CRED-VL-04 | ID-VL-6005 (Shared Clinical-Admin Credential) | SRV-VL-1040 (INFUSION-GW01), SRV-VL-1042 (PHARMACY-DISPENSE01) | Administrative | Same credential as Domain Admin — violates FDA postmarket guidance (QID 201011) |
| CRED-VL-05 | ID-VL-6006 (velon-app-sp) | CLD-VL-5001, CLD-VL-5003, all subscription resources | Azure Subscription Owner | Excessive RBAC role (QID 300214) |
| CRED-VL-06 | Cached DA session on SRV-VL-1050 (JUMP01) | SRV-VL-1050 → any CI reachable by Domain Admins | Domain Admin (cached, LSASS-resident) | Credential hygiene violation (QID 91145) |


## 6. Attack Paths — Fully Cross-Referenced

Every step below cites the exact Rule ID (§3), Relationship ID (§4), or Credential Relationship ID (§5) that makes it possible, plus the Finding QID from the vulnerability CSV where a specific CVE or misconfiguration is the enabler. A step with no valid citation is not a real step.

### PATH A — Easy: Guest/Patient WiFi → Corporate LAN → File Server

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| A1 | SRV-VL-1070 (GUEST-AP-SW01) | Rule: RULE-VL-008 (Excessive) | SRV-VL-1003 (PRINT01) | 110001 | Network reach into VLAN 10 |
| A2 | SRV-VL-1003 (PRINT01) | Vulnerability: QID 46587 (PrintNightmare) | SRV-VL-1003 (PRINT01) | 46587 | SYSTEM on PRINT01 |
| A3 | SRV-VL-1003 (PRINT01) | Credential: CRED-VL-01 (Shared Local Admin) | SRV-VL-1002 (FILESRV01) | 91022 | Local Administrator on FILESRV01 |
| A4 | SRV-VL-1002 (FILESRV01) | Relationship: N/A — Excessive Share ACL directly on the CI | SRV-VL-1002 (FILESRV01) | 150401 | Read/write on Patient-Scheduling share |


**Impact:** Patient scheduling/demographic data exfiltration from an untrusted guest network with zero authentication.

### PATH B — Easy/Medium: Public Patient Portal → App Tier → EHR Database

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| B1 | NET-VL-INET | Vulnerability: QID 12055 (Drupalgeddon2) | SRV-VL-1011 (PORTAL01) | 12055 | Unauthenticated RCE; webshell (QID 12061) |
| B2 | SRV-VL-1011 (PORTAL01) | Rule: RULE-VL-003 (Excessive) | SRV-VL-1020 (EHR-APP01) | 200901 | Network reach into VLAN 21 |
| B3 | SRV-VL-1020 (EHR-APP01) | Vulnerability: QID 20144 (WebLogic RCE) | SRV-VL-1020 (EHR-APP01) | 20144 | RCE as WebLogic service account |
| B4 | SRV-VL-1020 (EHR-APP01) | Relationship: REL-VL-102 + Excessive db_owner | SRV-VL-1030 (DB-EHR01) | 200933 | Full control of DB-EHR01 |


**Impact:** Full Electronic Health Record database compromise starting from the public internet — a direct large-scale ePHI breach scenario.

### PATH C — Medium: Cloud Misconfiguration Chain

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| C1 | NET-VL-INET | Rule: RULE-VL-013 (Excessive) | CLD-VL-5001 (Blob velon-imaging-archive) | 300201 | Read access to container contents |
| C2 | CLD-VL-5001 | Relationship: REL-VL-115 (Excessive) | CLD-VL-5002 (velon-app-sp) | 300214 | Azure Subscription Owner session |
| C3 | CLD-VL-5002 | Relationship: REL-VL-116 (Excessive) + Rule: RULE-VL-014 | CLD-VL-5003 (velon-claims-db) | 300228 | Full read/write on claims DB |


**Impact:** Complete Azure environment compromise plus insurance claims/billing data exfiltration, entirely cloud-native.

### PATH D — Medium/Hard: Clinic VPN → Management Plane → Hypervisor → Backups

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| D1 | NET-VL-INET | Vulnerability: QID 46840 (FortiOS auth bypass) | SRV-VL-1012 (CLINIC-VPN-GW01) | 46840 | Unauthorized SSH key added to admin account |
| D2 | SRV-VL-1012 (CLINIC-VPN-GW01) | Rule: RULE-VL-007 (Excessive) | SRV-VL-1050 (JUMP01) | 200955 | Network reach into VLAN 50 |
| D3 | SRV-VL-1050 (JUMP01) | Credential: CRED-VL-06 | SRV-VL-1051 (HYPERVISOR01) | 91145 | Domain Admin session on HYPERVISOR01 |
| D4 | SRV-VL-1051 (HYPERVISOR01) | Vulnerability: QID 46912 (vCenter RCE) + Relationship: §2 Virtualization (all 10 guest CIs) | SRV-VL-1052 (BACKUP-MGR01) | 46912 | Hypervisor control of all 10 virtualized CIs |
| D5 | SRV-VL-1051 (HYPERVISOR01) | Relationship: REL-VL-109 | SRV-VL-1052 (BACKUP-MGR01) | 200977 | Backup archive access (default creds) |


**Impact:** Full virtualization and backup infrastructure compromise via a single exploited VPN gateway — because HYPERVISOR01 hosts 10 other CIs (§2), this path's real blast radius spans nearly the entire environment.

### PATH E — Hard: Kerberoast → noPac → Flat Trust → Infusion Pumps → Pharmacy

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| E1 | SRV-VL-1004 (WKS-CLIN01) | Credential: CRED-VL-02 (Kerberoastable svc_clinical) | SRV-VL-1001 (DC01) | 91260 | Cracked svc_clinical password |
| E2 | SRV-VL-1001 (DC01) | Vulnerability: QID 91278 (noPac) | SRV-VL-1001 (DC01) | 91278 | Domain Admin |
| E3 | SRV-VL-1001 (DC01) | Rule: RULE-VL-005 (Excessive) + Credential: CRED-VL-03 | SRV-VL-1040 (INFUSION-GW01) | 200999 | Network + auth reach into VLAN 40 |
| E4 | SRV-VL-1040 (INFUSION-GW01) | Vulnerability: QID 400012 (VxWorks IPnet buffer overflow) — independently exploitable without E1–E3 | SRV-VL-1040 (INFUSION-GW01) | 400012 | RCE / control of infusion pump gateway |
| E5 | SRV-VL-1040 (INFUSION-GW01) | Credential: CRED-VL-04 (Shared Clinical-Admin Credential) | SRV-VL-1042 (PHARMACY-DISPENSE01) | 201011 | Administrative access to medication dispensing controls |


**Impact:** Full domain compromise cascading into the organization's most safety-critical systems — a direct patient-safety scenario, not just data confidentiality. Note: INFUSION-GW01 is also reachable via Path D (it is one of the 10 CIs virtualized on HYPERVISOR01 in a real deployment where the gateway workstation itself is virtualized) — this is a genuine multi-path crown jewel.

### PATH F — Hard: Spring4Shell Chain via Telehealth Application

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| F1 | SRV-VL-1020 (EHR-APP01, adjacent App Tier) / NET-VL-0021 internal reach | Vulnerability: QID 150455 (Spring4Shell) | SRV-VL-1022 (TELEHEALTH-APP01) | 150455 | RCE on TELEHEALTH-APP01 |
| F2 | SRV-VL-1022 (TELEHEALTH-APP01) | Misconfiguration: QID 201033 (runs as SYSTEM) | SRV-VL-1022 (TELEHEALTH-APP01) | 201033 | Full host compromise (not just app-scoped) |
| F3 | SRV-VL-1022 (TELEHEALTH-APP01) | Misconfiguration: QID 150467 (hardcoded creds) | SRV-VL-1032 (DB-CLAIMS01) | 150467 | DB-CLAIMS01 credentials recovered from filesystem |
| F4 | SRV-VL-1032 (DB-CLAIMS01) | Relationship: REL-VL-105 (Excessive DB Link) | SRV-VL-1030 (DB-EHR01) | 201055 | Direct pivot into EHR database via claims-side linked server, no new credentials needed |


**Impact:** RCE on the telehealth platform cascades into the claims system (F3, via hardcoded credentials) and then further into the EHR database itself via an excessive claims-to-EHR database link (F4) — a second, independent route into the same crown-jewel database reached directly in Path B, and a good test of whether an agent notices multi-path convergence rather than treating each path in isolation.

### Standalone Findings (Not Part of a Chain)

These are included specifically to test whether an agent correctly reports "no chain" instead of inventing one. Each cites its CI but has **no** Enabler chain to another finding.

| Finding QID | CI | Why It's Standalone |
|---|---|---|
| 110102 | SRV-VL-1080 (IMAGING-NAS01) | Anonymous SMB is independently exploitable; no relationship connects it onward to any other finding in this lab version |
| 201077 | SRV-VL-1060 (CLINIC-RTR01) | Legacy any-any rule; VLAN 60 has no rule (§3) reaching anything beyond VLAN 10 (RULE-VL-009), so this doesn't extend into a chain |
| 48113 | SRV-VL-1004 (WKS-CLIN01) | SMBGhost is independently exploitable within VLAN 10; not currently linked onward to another CI's finding in this version |
| 300251 | CLD-VL-5004 (Azure AD Tenant) | Excessive Global Admin assignments; identity-plane risk not currently chained to a specific exploited finding |
| 12078 | SRV-VL-1011 (PORTAL01) | Missing MFA on the admin console is a credential-hardening gap, distinct from the Drupalgeddon2 RCE finding on the same CI, and not itself chained onward |
| 201099 | NET-VL-0040 | This is the compliance finding *documenting* that RULE-VL-005/E3 exists — it's the audit-trail record of Path E's segmentation gap, not a separate technical hop |


## 7. Finding-to-CI Cross-Reference

Direct mapping from every vulnerability CSV row (`QID`) to the CI(s) it affects and its position in an attack path, if any. This is also embedded as `CI_ID` and `Attack_Path_Ref` columns in the companion CSV.

| QID | Primary CI | Related CIs (upstream/downstream in chain) | Attack Path Ref |
|---|---|---|---|
| 110001 | SRV-VL-1070 | SRV-VL-1003 (downstream, Path A) | PATH-A-Step1 |
| 46587 | SRV-VL-1003 | SRV-VL-1070 (upstream), SRV-VL-1002 (downstream) | PATH-A-Step2 |
| 91022 | SRV-VL-1002 | SRV-VL-1003 (upstream) | PATH-A-Step3 |
| 150401 | SRV-VL-1002 | N/A (terminal step) | PATH-A-Step4 |
| 12055 | SRV-VL-1011 | SRV-VL-1020 (downstream, Path B) | PATH-B-Step1 |
| 12061 | SRV-VL-1011 | SRV-VL-1020 (downstream, Path B) | PATH-B-Step2 |
| 200901 | SRV-VL-1010 | SRV-VL-1011 (upstream), SRV-VL-1020 (downstream) | PATH-B-Step3 |
| 20144 | SRV-VL-1020 | SRV-VL-1011 (upstream), SRV-VL-1030 (downstream) | PATH-B-Step4 |
| 200933 | SRV-VL-1030 | SRV-VL-1020 (upstream) | PATH-B-Step5 |
| 300201 | CLD-VL-5001 | CLD-VL-5002 (downstream, Path C) | PATH-C-Step1 |
| 300214 | CLD-VL-5002 | CLD-VL-5001 (upstream), CLD-VL-5003 (downstream) | PATH-C-Step2 |
| 300228 | CLD-VL-5003 | CLD-VL-5002 (upstream) | PATH-C-Step3 |
| 46840 | SRV-VL-1012 | SRV-VL-1050 (downstream, Path D) | PATH-D-Step1 |
| 200955 | SRV-VL-1012 | SRV-VL-1050 (downstream) | PATH-D-Step2 |
| 91145 | SRV-VL-1050 | SRV-VL-1012 (upstream), SRV-VL-1051 (downstream) | PATH-D-Step3 |
| 46912 | SRV-VL-1051 | SRV-VL-1050 (upstream), all 10 §2 guest CIs + SRV-VL-1052 (downstream) | PATH-D-Step4 |
| 200977 | SRV-VL-1052 | SRV-VL-1051 (upstream) | PATH-D-Step5 |
| 91260 | SRV-VL-1001 | SRV-VL-1004 (upstream), HL7 interface runtime | PATH-E-Step1 |
| 91278 | SRV-VL-1001 | SRV-VL-1040 (downstream, Path E) | PATH-E-Step2 |
| 200999 | NET-VL-0040 | SRV-VL-1001 (upstream), SRV-VL-1040 (downstream) | PATH-E-Step3 |
| 400012 | SRV-VL-1040 | SRV-VL-1001 (upstream, or independent), SRV-VL-1042 (downstream) | PATH-E-Step4 |
| 201011 | SRV-VL-1042 | SRV-VL-1040 (upstream) | PATH-E-Step5 |
| 150455 | SRV-VL-1022 | SRV-VL-1032 (downstream, Path F) | PATH-F-Step1 |
| 201033 | SRV-VL-1022 | N/A (severity amplifier for F1) | PATH-F-Step2 |
| 150467 | SRV-VL-1022 | SRV-VL-1032 (downstream) | PATH-F-Step3 |
| 201055 | SRV-VL-1032 | SRV-VL-1022 (upstream), SRV-VL-1030 (downstream) | PATH-F-Step4 |
| 110102 | SRV-VL-1080 | N/A | Standalone |
| 201077 | SRV-VL-1060 | N/A | Standalone |
| 48113 | SRV-VL-1004 | N/A | Standalone |
| 300251 | CLD-VL-5004 | N/A | Standalone |
| 12078 | SRV-VL-1011 | N/A | Standalone |
| 201099 | NET-VL-0040 | Documents RULE-VL-005 | Standalone |


## 8. Explicitly Non-Existent Paths (Negative Ground Truth)

These are plausible-sounding claims that are **false**. Use them directly to test false-positive behavior — a correct agent rejects each one and explains why by citing the *absence* of a rule or relationship in §3–§5, not just asserting "that's wrong."

| Claimed Path | Why It's False |
|---|---|
| GUEST-AP-SW01 → DB-CLAIMS01 (direct) | No rule exists from NET-VL-0070 to NET-VL-0030 or NET-VL-0040 (§3). Guest/Patient WiFi only reaches VLAN 10 via RULE-VL-008; there is no continuation rule from VLAN 10 to the DB Tier (RULE-VL-011 explicitly absent) or the Clinical zone without going through Path E's full credential-escalation chain. |
| PORTAL01 → PHARMACY-DISPENSE01 (direct) | DMZ (NET-VL-0020) has no rule reaching NET-VL-0040 (§3, RULE-VL-015 confirms absence). Reaching PHARMACY-DISPENSE01 requires the full Path E chain through Domain Admin — there is no DMZ-to-Clinical-zone shortcut. |
| BILLING-APP01 → DB-EHR01 | BILLING-APP01's only database relationship is REL-VL-104, to DB-PACS01 (billing/imaging cross-reference). No relationship connects BILLING-APP01 to DB-EHR01 in §4. |
| CLINIC-WKS01 → HYPERVISOR01 | VLAN 60 (Clinic/Branch VPN) only has RULE-VL-009, reaching VLAN 10. No rule in §3 connects VLAN 60 to VLAN 50 (Management/OOB). |
| IMAGING-NAS01 compromise leads directly to Domain Admin | IMAGING-NAS01's only relationships are REL-VL-111/112, being backed-up-by BACKUP-MGR01. It has no authentication trust or credential relationship (§5) to DC01. |
| noPac on DC01 is exploitable directly from the internet | DC01 sits in NET-VL-0010, which has no rule in §3 accepting inbound traffic from NET-VL-INET. noPac requires network reach to VLAN 10 first (e.g., via Path A's guest-WiFi hop or the Path E workstation foothold), not direct internet access. |


---

*This document is the authoritative relationship ground truth for Velon Health Systems. It supersedes any prose-only description of the same environment. Companion files: `velon_vulnerabilities.csv` (vulnerability detail, now with `CI_ID`/`Related_CI_IDs` columns matching §1 and §7 of this document) and `velon_architecture.png` (visual network diagram, unchanged).*
