# Velon Health Systems — CMDB & Relationship Ground Truth

### Configuration Management Database — CI Inventory, Relationships & Network Reachability

**Purpose of this document.** A machine-checkable relationship graph, structured the way a real CMDB (e.g. ServiceNow `cmdb_ci` + `cmdb_rel_ci`) represents infrastructure: every Configuration Item (CI) has a unique ID, a class, and a set of *typed* relationships to other CIs — §2 hosting, §3 zone-to-zone reachability, §4 host/app/db dependencies, §5 identity & credential relationships. This inventory describes the environment as it is; it does **not** enumerate attack paths. Determining whether an attacker can chain these relationships into a route to a crown jewel is the detection system's job, not something this document hands over.

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
