# Ghrab Financial Group — CMDB & Relationship Ground Truth

### Configuration Management Database — CI Inventory, Relationships & Network Reachability

**Purpose of this document.** A machine-checkable relationship graph, structured the way a real CMDB (e.g. ServiceNow `cmdb_ci` + `cmdb_rel_ci`) represents infrastructure: every Configuration Item (CI) has a unique ID, a class, and a set of *typed* relationships to other CIs — §2 hosting, §3 zone-to-zone reachability, §4 host/app/db dependencies, §5 identity & credential relationships. This inventory describes the environment as it is; it does **not** enumerate attack paths. Determining whether an attacker can chain these relationships into a route to a crown jewel is the detection system's job, not something this document hands over.

---

## 1. CI Inventory

Every asset in this lab is a Configuration Item (CI) with a unique ID, class, zone, criticality tier, owning Support Group, and the Business Service it exists to support. Criticality tiers mirror the Asset Criticality Weight (ACW) used in the Ghrab Risk Score methodology: **Crown Jewel > High > Business-Important > Standard**.

### 1.1 Network Segments (Class: `cmdb_ci_network_segment`)

| CI ID | Name | CIDR | Trust Level | Owning Support Group |
|---|---|---|---|---|
| NET-GH-0010 | VLAN 10 — Corporate LAN | 10.10.10.0/24 | Medium | GRP-GH-IT |
| NET-GH-0020 | VLAN 20 — DMZ | 10.10.20.0/24 | Low (internet-facing) | GRP-GH-NET |
| NET-GH-0021 | VLAN 21 — App Tier | 10.10.21.0/24 | Medium | GRP-GH-APP |
| NET-GH-0030 | VLAN 30 — DB Tier | 10.10.30.0/24 | High | GRP-GH-DBA |
| NET-GH-0040 | VLAN 40 — Finance/Trading Critical Zone (CDE/SWIFT) | 10.10.40.0/24 | Critical | GRP-GH-GRC |
| NET-GH-0050 | VLAN 50 — Management/OOB | 10.10.50.0/24 | Critical (should be) | GRP-GH-IT |
| NET-GH-0060 | VLAN 60 — Branch/VPN | 10.10.60.0/24 | Medium | GRP-GH-NET |
| NET-GH-0070 | VLAN 70 — Guest WiFi | 10.10.70.0/24 | Untrusted | GRP-GH-NET |
| NET-GH-0080 | VLAN 80 — Backup/Storage | 10.10.80.0/24 | High | GRP-GH-IT |
| NET-GH-0090 | Cloud — AWS VPC (ghrab-cloud-vpc) | N/A | Mixed | GRP-GH-CLD |
| NET-GH-INET | Internet (untrusted) | 0.0.0.0/0 | None | N/A |

### 1.2 Servers & Network Devices (Class: `cmdb_ci_server` / `cmdb_ci_netgear`)

| CI ID | Name | Zone | IP | Platform | Criticality | Support Group | Business Service |
|---|---|---|---|---|---|---|---|
| SRV-GH-1001 | DC01 | NET-GH-0010 | 10.10.10.10 | Windows Server (AD DS) | Crown Jewel | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1002 | FILESRV01 | NET-GH-0010 | 10.10.10.20 | Windows Server | Business-Important | GRP-GH-IT | BSVC-GH-01 |
| SRV-GH-1003 | WKS-HR02 | NET-GH-0010 | 10.10.10.55 | Windows 10/11 | Standard | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1004 | WKS-FIN01 | NET-GH-0010 | 10.10.10.50 | Windows 10/11 | Standard | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1005 | PRINT01 | NET-GH-0010 | 10.10.10.30 | Network Print Appliance | Standard | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1010 | LB01 | NET-GH-0020 | 10.10.20.5 | F5/NGINX Appliance | Business-Important | GRP-GH-NET | BSVC-GH-01 |
| SRV-GH-1011 | WEB-PORTAL01 | NET-GH-0020 | 10.10.20.10 | Linux (Apache) | Business-Important | GRP-GH-NET | BSVC-GH-01 |
| SRV-GH-1012 | VPN-GW01 | NET-GH-0020 | 10.10.20.20 | FortiGate Appliance | Business-Important | GRP-GH-NET | BSVC-GH-04 |
| SRV-GH-1013 | MAIL-RELAY01 | NET-GH-0020 | 10.10.20.30 | Windows Server (Exchange) | Business-Important | GRP-GH-NET | BSVC-GH-04 |
| SRV-GH-1020 | APP-CRM01 | NET-GH-0021 | 10.10.21.10 | Linux (Apache Struts2) | Business-Important | GRP-GH-APP | BSVC-GH-01 |
| SRV-GH-1021 | APP-HR01 | NET-GH-0021 | 10.10.21.20 | Linux | Standard | GRP-GH-APP | BSVC-GH-04 |
| SRV-GH-1022 | APP-TRADE01 | NET-GH-0021 | 10.10.21.30 | Linux (Java) | High | GRP-GH-APP | BSVC-GH-02 |
| SRV-GH-1030 | DB-CRM01 | NET-GH-0030 | 10.10.30.10 | MSSQL | Business-Important | GRP-GH-DBA | BSVC-GH-01 |
| SRV-GH-1031 | DB-FIN01 | NET-GH-0030 | 10.10.30.20 | Oracle | High | GRP-GH-DBA | BSVC-GH-02 |
| SRV-GH-1032 | DB-TRADE01 | NET-GH-0030 | 10.10.30.30 | Oracle | High | GRP-GH-DBA | BSVC-GH-02 |
| SRV-GH-1040 | TRADE-CORE01 | NET-GH-0040 | 10.10.40.10 | Windows Server | Crown Jewel | GRP-GH-GRC | BSVC-GH-02 |
| SRV-GH-1041 | SETTLEMENT01 | NET-GH-0040 | 10.10.40.20 | Linux | Crown Jewel | GRP-GH-GRC | BSVC-GH-02 |
| SRV-GH-1042 | SWIFT-GATEWAY01 | NET-GH-0040 | 10.10.40.30 | Linux (SWIFT Alliance Access) | Crown Jewel | GRP-GH-GRC | BSVC-GH-03 |
| SRV-GH-1050 | JUMP01 | NET-GH-0050 | 10.10.50.10 | Windows Server (Bastion) | High | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1051 | VCENTER01 | NET-GH-0050 | 10.10.50.20 | VMware vCenter Appliance | High | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1052 | BACKUP-MGR01 | NET-GH-0050 | 10.10.50.30 | Windows Server (Veeam) | High | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1060 | BRANCH-RTR01 | NET-GH-0060 | 10.10.60.1 | Router Appliance | Standard | GRP-GH-NET | BSVC-GH-04 |
| SRV-GH-1061 | BRANCH-WKS01 | NET-GH-0060 | 10.10.60.50 | Windows 10/11 | Standard | GRP-GH-NET | BSVC-GH-04 |
| SRV-GH-1070 | GUEST-AP-SW01 | NET-GH-0070 | 10.10.70.1 | Access Switch | Standard | GRP-GH-NET | BSVC-GH-04 |
| SRV-GH-1080 | NAS01 | NET-GH-0080 | 10.10.80.10 | NAS Appliance | High | GRP-GH-IT | BSVC-GH-04 |
| SRV-GH-1081 | BACKUP-SRV01 | NET-GH-0080 | 10.10.80.20 | Windows Server | Business-Important | GRP-GH-IT | BSVC-GH-04 |

### 1.3 Applications (Class: `cmdb_ci_appl`) — "Runs On" a Server CI

| CI ID | Name | Runs On (CI ID) | Support Group | Business Service |
|---|---|---|---|---|
| APP-GH-3011 | Ghrab Public Website (WordPress CMS) | SRV-GH-1011 (WEB-PORTAL01) | GRP-GH-APP | BSVC-GH-01 |
| APP-GH-3020 | Ghrab CRM (Apache Struts2) | SRV-GH-1020 (APP-CRM01) | GRP-GH-APP | BSVC-GH-01 |
| APP-GH-3022 | Ghrab Trading Platform (Java) | SRV-GH-1022 (APP-TRADE01) | GRP-GH-APP | BSVC-GH-02 |
| APP-GH-3013 | Exchange Mail Service | SRV-GH-1013 (MAIL-RELAY01) | GRP-GH-NET | BSVC-GH-04 |
| APP-GH-3001 | Active Directory Domain Services | SRV-GH-1001 (DC01) | GRP-GH-IT | BSVC-GH-04 |
| APP-GH-3051 | VMware vCenter Server | SRV-GH-1051 (VCENTER01) | GRP-GH-IT | BSVC-GH-04 |

### 1.4 Cloud Services (Class: `cmdb_ci_cloud_service`)

| CI ID | Name | Provider | Type | Criticality | Support Group | Business Service |
|---|---|---|---|---|---|---|
| CLD-GH-5001 | S3: ghrab-public-assets | AWS | Object Storage | Business-Important | GRP-GH-CLD | BSVC-GH-05 |
| CLD-GH-5002 | IAM Role: ghrab-app-role | AWS | IAM Role | High | GRP-GH-CLD | BSVC-GH-05 |
| CLD-GH-5003 | RDS: ghrab-finance-rds | AWS | Managed Database (PostgreSQL) | High | GRP-GH-CLD | BSVC-GH-05 |
| CLD-GH-5004 | Entra ID Tenant: ghrab.onmicrosoft.com | Microsoft Entra ID | Identity Tenant | High | GRP-GH-CLD | BSVC-GH-04 |

### 1.5 Identity & Credential CIs (Class: `cmdb_ci_service_account` / `cmdb_ci_group`)

| CI ID | Name | Type | Valid On (CI IDs) | Known Issue |
|---|---|---|---|---|
| ID-GH-6001 | GHRAB.LOCAL | AD Forest/Domain | All domain-joined CIs | N/A |
| ID-GH-6002 | svc_trade | Service Account | SRV-GH-1001 (domain), SRV-GH-1022 (runs as) | Weak, non-rotated password — Kerberoastable |
| ID-GH-6003 | Shared Local Administrator | Local Account | SRV-GH-1003, SRV-GH-1004, SRV-GH-1002 | Identical password reused across hosts, no LAPS |
| ID-GH-6004 | Domain Admins | AD Group | SRV-GH-1001, and (via REL rule NET-GH-0010→NET-GH-0040) SRV-GH-1040, SRV-GH-1050 | Flat trust lets this group reach the Finance zone directly |
| ID-GH-6005 | Shared SWIFT-Admin Credential | Local/Domain Admin Credential | SRV-GH-1040 (TRADE-CORE01), SRV-GH-1042 (SWIFT-GATEWAY01) | Same credential as general Domain Admin — violates SWIFT CSP dedicated-identity requirement |
| ID-GH-6006 | ghrab-app-role | AWS IAM Role | CLD-GH-5001 (originates), all AWS resources (AdministratorAccess) | AdministratorAccess policy attached — excessive scope |

### 1.6 Business Services (Class: `cmdb_ci_business_service`)

| CI ID | Name | Description |
|---|---|---|
| BSVC-GH-01 | Retail Banking & Lending | Customer-facing banking site, CRM, and related customer data |
| BSVC-GH-02 | Securities Trading & Settlement | Core trading platform, trade database, settlement processing |
| BSVC-GH-03 | SWIFT Payment Messaging | Interbank payment messaging gateway |
| BSVC-GH-04 | Corporate IT & Collaboration | Internal identity, email, file shares, endpoints, infrastructure management |
| BSVC-GH-05 | Cloud Data & Analytics | AWS-hosted storage, identity, and managed database services |

### 1.7 Support Groups

| Group ID | Name | Responsible For |
|---|---|---|
| GRP-GH-IT | IT Infrastructure Team | Windows/Linux server patching, AD, endpoints, backup infra |
| GRP-GH-NET | Network Team | Firewalls, VLAN segmentation, VPN, routing, WiFi |
| GRP-GH-APP | AppSec Team | Web/application-layer vulnerabilities, secure SDLC, app service accounts |
| GRP-GH-DBA | DBA Team | Database hardening, account privilege scoping, DB links |
| GRP-GH-CLD | Cloud Team | AWS configuration, IAM, cloud-native services |
| GRP-GH-GRC | Compliance-GRC Team | PCI DSS/SWIFT CSP scope validation, segmentation testing |

## 2. Virtualization / Hosting Relationships

`SRV-GH-1051 (VCENTER01)` is the hypervisor management plane for this environment. Compromise of it means compromise of every VM it hosts — this is the single biggest blast-radius relationship in the whole CMDB, and it's a common miss in prose-only architecture docs.

| Relationship ID | Guest CI | Relationship | Host CI |
|---|---|---|---|
| REL-GH-V01 | SRV-GH-1011 (WEB-PORTAL01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V02 | SRV-GH-1013 (MAIL-RELAY01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V03 | SRV-GH-1020 (APP-CRM01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V04 | SRV-GH-1021 (APP-HR01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V05 | SRV-GH-1022 (APP-TRADE01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V06 | SRV-GH-1030 (DB-CRM01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V07 | SRV-GH-1031 (DB-FIN01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V08 | SRV-GH-1032 (DB-TRADE01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V09 | SRV-GH-1040 (TRADE-CORE01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V10 | SRV-GH-1041 (SETTLEMENT01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V11 | SRV-GH-1042 (SWIFT-GATEWAY01) | Virtualized On | SRV-GH-1051 (VCENTER01) |
| REL-GH-V12 | SRV-GH-1002 (FILESRV01) | Virtualized On | SRV-GH-1051 (VCENTER01) |

## 3. Network Reachability Rule Base (Zone-to-Zone) — THE authoritative reachability graph

This is the master truth table for "can zone X reach zone Y." Every attack path hop that crosses a zone boundary must cite a Rule ID from this table. **Status** distinguishes intended design (`Intended`), a real misconfiguration that enables an attack path (`Excessive`), and a zone pair with **no rule at all** (`Should-Not-Exist` / absent) — if an agent claims a path crossing a zone pair not listed here, or listed as absent, that hop is fabricated.

| Rule ID | Source Zone | Destination Zone | Port/Protocol | Status | Notes |
|---|---|---|---|---|---|
| RULE-GH-001 | NET-GH-INET | NET-GH-0020 | 443, 80, 25 | Intended | Public web, VPN, mail relay |
| RULE-GH-002 | NET-GH-0020 | NET-GH-0021 | tcp/8443 (LB backend only) | Intended (design) | As-designed rule; superseded in practice by RULE-GH-003 |
| RULE-GH-003 | NET-GH-0020 | NET-GH-0021 | ANY/ANY | Excessive | As-configured firewall rule; QID 200114 — should be scoped to RULE-GH-002 only |
| RULE-GH-004 | NET-GH-0021 | NET-GH-0030 | tcp/1433, 1521 | Intended | App tier to DB tier, standard app connectivity |
| RULE-GH-005 | NET-GH-0010 | NET-GH-0040 | ANY (Kerberos/LDAP/SMB) | Excessive | Flat trust; QID 200512 — no tiering/PAM boundary enforced |
| RULE-GH-006 | NET-GH-0010 | NET-GH-0050 | N/A | Should-Not-Exist (no rule) | Management plane must only be reached via designated jump path |
| RULE-GH-007 | NET-GH-0020 | NET-GH-0050 | ANY (VPN split-tunnel) | Excessive | QID 200401 — VPN client policy routes into management VLAN |
| RULE-GH-008 | NET-GH-0070 | NET-GH-0010 | 802.1Q (all VLANs) | Excessive | QID 105001 — guest trunk misconfigured, should be access-mode only |
| RULE-GH-009 | NET-GH-0060 | NET-GH-0010 | udp/500,4500 tcp/443 | Intended | Site-to-site VPN, branch to AD authentication only |
| RULE-GH-010 | NET-GH-0050 | NET-GH-0080 | tcp/9392, 445 | Intended | Backup jobs |
| RULE-GH-011 | NET-GH-0010 | NET-GH-0030 | N/A | Should-Not-Exist (no rule) | Workstations must never reach DB tier directly |
| RULE-GH-012 | NET-GH-0021 | NET-GH-0040 | N/A | Should-Not-Exist (no rule) | App tier and Finance/Trading zone are separate trust tiers |
| RULE-GH-013 | NET-GH-INET | CLD-GH-5001 | tcp/443 | Excessive | QID 300011 — bucket policy grants public read |
| RULE-GH-014 | NET-GH-INET | CLD-GH-5003 | tcp/5432 | Excessive | QID 300067 — RDS publicly accessible flag enabled |
| RULE-GH-015 | NET-GH-0070 | NET-GH-0040 | N/A | Should-Not-Exist (no rule) | No path exists or has ever existed from Guest WiFi directly to the Finance zone |

## 4. Host, Application & Database Dependency Relationships

Application-layer and data-layer dependencies, independent of network zone rules — these answer "what does this CI actually talk to and why," which a zone-level rule alone cannot.

| Relationship ID | Source CI | Relationship Type | Target CI | Port/Protocol | Justification | Flag |
|---|---|---|---|---|---|---|
| REL-GH-101 | SRV-GH-1010 (LB01) | Forwards To | SRV-GH-1011 (WEB-PORTAL01) | 443→443 | Reverse proxy for public website | Legitimate |
| REL-GH-102 | SRV-GH-1020 (APP-CRM01) | Depends On | SRV-GH-1030 (DB-CRM01) | 1433 | CRM app database backend, via svc_crmapp | Legitimate connection / Excessive privilege (db_owner, QID 200338) |
| REL-GH-103 | SRV-GH-1022 (APP-TRADE01) | Depends On | SRV-GH-1032 (DB-TRADE01) | 1521 | Trading platform database backend | Legitimate connection / Secrets exposed (QID 150233) |
| REL-GH-104 | SRV-GH-1021 (APP-HR01) | Depends On | SRV-GH-1031 (DB-FIN01) | 1521 | Payroll integration read access (documented business need) | Legitimate |
| REL-GH-105 | SRV-GH-1032 (DB-TRADE01) | Linked To (DB Link) | SRV-GH-1041 (SETTLEMENT01) | 1521 | One-time historical migration link, never removed | Excessive (QID 200622) |
| REL-GH-106 | SRV-GH-1003 (WKS-HR02) | Authenticates To | SRV-GH-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-GH-107 | SRV-GH-1004 (WKS-FIN01) | Authenticates To | SRV-GH-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-GH-108 | SRV-GH-1002 (FILESRV01) | Authenticates To | SRV-GH-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-GH-109 | SRV-GH-1050 (JUMP01) | Manages | SRV-GH-1051 (VCENTER01) | 443 (vSphere API) | Admin bastion for virtualization management | Legitimate |
| REL-GH-110 | SRV-GH-1050 (JUMP01) | Manages | SRV-GH-1052 (BACKUP-MGR01) | 9392 | Admin bastion for backup management | Legitimate |
| REL-GH-111 | SRV-GH-1052 (BACKUP-MGR01) | Backs Up | SRV-GH-1081 (BACKUP-SRV01) | 445 | Scheduled backup jobs | Legitimate |
| REL-GH-112 | SRV-GH-1052 (BACKUP-MGR01) | Backs Up | SRV-GH-1080 (NAS01) | 445 | Scheduled backup jobs | Legitimate |
| REL-GH-113 | SRV-GH-1052 (BACKUP-MGR01) | Backs Up | SRV-GH-1031 (DB-FIN01) | 445 | Nightly DB dump backup — explains why NAS/backup compromise exposes finance data | Legitimate |
| REL-GH-114 | SRV-GH-1052 (BACKUP-MGR01) | Backs Up | SRV-GH-1032 (DB-TRADE01) | 445 | Nightly DB dump backup | Legitimate |
| REL-GH-115 | CLD-GH-5001 (S3 ghrab-public-assets) | Grants Session To | CLD-GH-5002 (ghrab-app-role) | HTTPS/AWS API | Leaked backup file in bucket contains role credentials | Excessive (QID 300011) |
| REL-GH-116 | CLD-GH-5002 (ghrab-app-role) | Has Access To | CLD-GH-5003 (ghrab-finance-rds) | AWS API / 5432 | AdministratorAccess policy grants access to all AWS resources | Excessive (QID 300045) |

## 5. Identity & Credential Relationships

Many real attack paths aren't network hops at all — they're a credential valid on more than one CI. This table makes that explicit so agents don't need to (incorrectly) invent a network relationship to explain lateral movement that is actually credential reuse.

| Relationship ID | Credential/Identity CI | Valid On (CI ID) | Access Level Granted | Issue |
|---|---|---|---|---|
| CRED-GH-01 | ID-GH-6003 (Shared Local Administrator) | SRV-GH-1003, SRV-GH-1004, SRV-GH-1002 | Local Administrator | Enables pass-the-hash lateral movement (QID 90013) |
| CRED-GH-02 | ID-GH-6002 (svc_trade) | SRV-GH-1001 (domain account), SRV-GH-1022 (service runtime identity) | Domain User + local service | Kerberoastable, weak password (QID 90344) |
| CRED-GH-03 | ID-GH-6004 (Domain Admins) | SRV-GH-1001, and via RULE-GH-005 also SRV-GH-1040, SRV-GH-1042, SRV-GH-1050 | Full domain administrative control | Flat trust extends DA reach into the Finance zone (QID 200512) |
| CRED-GH-04 | ID-GH-6005 (Shared SWIFT-Admin Credential) | SRV-GH-1040 (TRADE-CORE01), SRV-GH-1042 (SWIFT-GATEWAY01) | Administrative | Same credential as Domain Admin — violates SWIFT CSP (QID 200533) |
| CRED-GH-05 | ID-GH-6006 (ghrab-app-role) | CLD-GH-5001, CLD-GH-5003, all AWS resources | AWS AdministratorAccess | Excessive IAM policy (QID 300045) |
| CRED-GH-06 | Cached DA session on SRV-GH-1050 (JUMP01) | SRV-GH-1050 → any CI reachable by Domain Admins | Domain Admin (cached, LSASS-resident) | Credential hygiene violation (QID 90211) |
