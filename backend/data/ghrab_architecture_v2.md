# Ghrab Financial Group — CMDB & Relationship Ground Truth

### Configuration Management Database (CI Inventory, Relationships, Network Reachability, and Cross-Referenced Attack Paths) — Lab: Ghrab (Lab 1 — Finance)

**Purpose of this document.** This replaces prose-only architecture description with an explicit, machine-checkable relationship graph, structured the way a real CMDB (e.g. ServiceNow `cmdb_ci` + `cmdb_rel_ci`) represents infrastructure: every Configuration Item (CI) has a unique ID, a class, and a set of *typed* relationships to other CIs. Every attack path step below cites the exact Relationship ID or Rule ID that makes that hop possible. If a hop doesn't trace to a row in §3–§5, it isn't real — that's the test your detection agents should be run against, including the explicit non-existent paths in §8.

**How to use this for agent evaluation:** (1) Feed §2–§7 to your agent as ground truth. (2) Ask it to trace a path or validate one you give it. (3) Check every hop against the Relationship/Rule ID it cites — a real path always has one; a hallucinated path won't. (4) Test the §8 negatives directly — a correct agent explains *why* each is false by citing the absence of a rule, not just asserting it.

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


## 6. Attack Paths — Fully Cross-Referenced

Every step below cites the exact Rule ID (§3), Relationship ID (§4), or Credential Relationship ID (§5) that makes it possible, plus the Finding QID from the vulnerability CSV where a specific CVE or misconfiguration is the enabler. A step with no valid citation is not a real step.

### PATH A — Easy: Guest WiFi → Corporate LAN → File Server

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| A1 | SRV-GH-1070 (GUEST-AP-SW01) | Rule: RULE-GH-008 (Excessive) | SRV-GH-1003 (WKS-HR02) | 105001 | Network reach into VLAN 10 |
| A2 | SRV-GH-1003 (WKS-HR02) | Vulnerability: QID 38689 (EternalBlue) | SRV-GH-1003 (WKS-HR02) | 38689 | SYSTEM on WKS-HR02 |
| A3 | SRV-GH-1003 (WKS-HR02) | Credential: CRED-GH-01 (Shared Local Admin) | SRV-GH-1002 (FILESRV01) | 90013 | Local Administrator on FILESRV01 |
| A4 | SRV-GH-1002 (FILESRV01) | Relationship: N/A — Excessive Share ACL directly on the CI | SRV-GH-1002 (FILESRV01) | 150220 | Read/write on HR-Confidential share |


**Impact:** Confidential HR data exfiltration from an untrusted guest network with zero authentication.

### PATH B — Easy/Medium: Public Web → App Tier → CRM Database

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| B1 | NET-GH-INET | Vulnerability: QID 11827 (Drupal-class SQLi in WordPress plugin) | SRV-GH-1011 (WEB-PORTAL01) | 11827 | Admin panel access; webshell (QID 11831) |
| B2 | SRV-GH-1011 (WEB-PORTAL01) | Rule: RULE-GH-003 (Excessive) | SRV-GH-1020 (APP-CRM01) | 200114 | Network reach into VLAN 21 |
| B3 | SRV-GH-1020 (APP-CRM01) | Vulnerability: QID 13398 (Struts2 RCE) | SRV-GH-1020 (APP-CRM01) | 13398 | RCE as app service account |
| B4 | SRV-GH-1020 (APP-CRM01) | Relationship: REL-GH-102 + Excessive db_owner | SRV-GH-1030 (DB-CRM01) | 200338 | Full control of DB-CRM01 |


**Impact:** Full CRM customer database compromise starting from the public internet.

### PATH C — Medium: Cloud Misconfiguration Chain

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| C1 | NET-GH-INET | Rule: RULE-GH-013 (Excessive) | CLD-GH-5001 (S3 ghrab-public-assets) | 300011 | Read access to bucket contents |
| C2 | CLD-GH-5001 | Relationship: REL-GH-115 (Excessive) | CLD-GH-5002 (ghrab-app-role) | 300045 | AWS AdministratorAccess session |
| C3 | CLD-GH-5002 | Relationship: REL-GH-116 (Excessive) + Rule: RULE-GH-014 | CLD-GH-5003 (ghrab-finance-rds) | 300067 | Full read/write on finance RDS |


**Impact:** Complete AWS environment compromise plus finance database exfiltration, entirely cloud-native.

### PATH D — Medium/Hard: VPN → Management Plane → Hypervisor → Backups

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| D1 | NET-GH-INET | Vulnerability: QID 43111 (FortiOS path traversal) | SRV-GH-1012 (VPN-GW01) | 43111 | Plaintext VPN credentials |
| D2 | SRV-GH-1012 (VPN-GW01) | Rule: RULE-GH-007 (Excessive) | SRV-GH-1050 (JUMP01) | 200401 | Network reach into VLAN 50 |
| D3 | SRV-GH-1050 (JUMP01) | Credential: CRED-GH-06 | SRV-GH-1051 (VCENTER01) | 90211 | Domain Admin session on VCENTER01 |
| D4 | SRV-GH-1051 (VCENTER01) | Vulnerability: QID 43287 (vCenter RCE) + Relationship: §2 Virtualization (all 12 guest CIs) | SRV-GH-1052 (BACKUP-MGR01) | 43287 | Hypervisor control of all 12 virtualized CIs |
| D5 | SRV-GH-1051 (VCENTER01) | Relationship: REL-GH-109 | SRV-GH-1052 (BACKUP-MGR01) | 200455 | Backup archive access (default creds) |


**Impact:** Full virtualization and backup infrastructure compromise via a single leaked VPN credential — because VCENTER01 hosts 12 other CIs (§2), this path's real blast radius spans nearly the entire environment.

### PATH E — Hard: Kerberoast → Zerologon → Flat Trust → Trading Core → SWIFT

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| E1 | SRV-GH-1004 (WKS-FIN01) | Credential: CRED-GH-02 (Kerberoastable svc_trade) | SRV-GH-1001 (DC01) | 90344 | Cracked svc_trade password |
| E2 | SRV-GH-1001 (DC01) | Vulnerability: QID 90512 (Zerologon) | SRV-GH-1001 (DC01) | 90512 | Domain Admin |
| E3 | SRV-GH-1001 (DC01) | Rule: RULE-GH-005 (Excessive) + Credential: CRED-GH-03 | SRV-GH-1040 (TRADE-CORE01) | 200512 | Network + auth reach into VLAN 40 |
| E4 | SRV-GH-1040 (TRADE-CORE01) | Vulnerability: QID 45923 (BlueKeep) — independently exploitable without E1–E3 | SRV-GH-1040 (TRADE-CORE01) | 45923 | RCE / Domain Admin session on TRADE-CORE01 |
| E5 | SRV-GH-1040 (TRADE-CORE01) | Credential: CRED-GH-04 (Shared SWIFT-Admin Credential) | SRV-GH-1042 (SWIFT-GATEWAY01) | 200533 | Administrative access to SWIFT gateway |


**Impact:** Full domain compromise cascading into the organization's most critical trading and payment infrastructure. Note: TRADE-CORE01 is also reachable via Path D (it is one of the 12 CIs virtualized on VCENTER01) — this is a genuine multi-path crown jewel, not a single linear chain.

### PATH F — Hard: Log4Shell Chain via Trading Application

| Step | Source CI | Enabler (Type: Ref ID) | Target CI | Finding QID | Access Gained |
|---|---|---|---|---|---|
| F1 | SRV-GH-1020 (APP-CRM01, adjacent App Tier) / NET-GH-0021 internal reach | Vulnerability: QID 150221 (Log4Shell) | SRV-GH-1022 (APP-TRADE01) | 150221 | RCE on APP-TRADE01 |
| F2 | SRV-GH-1022 (APP-TRADE01) | Misconfiguration: QID 200601 (runs as SYSTEM) | SRV-GH-1022 (APP-TRADE01) | 200601 | Full host compromise (not just app-scoped) |
| F3 | SRV-GH-1022 (APP-TRADE01) | Misconfiguration: QID 150233 (hardcoded creds) | SRV-GH-1032 (DB-TRADE01) | 150233 | DB-TRADE01 credentials recovered from filesystem |
| F4 | SRV-GH-1032 (DB-TRADE01) | Relationship: REL-GH-105 (Excessive DB Link) | SRV-GH-1041 (SETTLEMENT01) | 200622 | Direct pivot into settlement database, no new credentials needed |


**Impact:** RCE on the trading platform cascades directly into the settlement system via a purely database-layer trust relationship, bypassing network segmentation entirely.

### Standalone Findings (Not Part of a Chain)

These are included specifically to test whether an agent correctly reports "no chain" instead of inventing one. Each cites its CI but has **no** Enabler chain to another finding.

| Finding QID | CI | Why It's Standalone |
|---|---|---|
| 105102 | SRV-GH-1080 (NAS01) | Anonymous SMB is independently exploitable; no relationship connects it onward to any other finding in this lab version |
| 200711 | SRV-GH-1060 (BRANCH-RTR01) | Legacy any-any rule; VLAN 60 has no rule (§3) reaching anything beyond VLAN 10 (RULE-GH-009), so this doesn't extend into a chain |
| 43055 | SRV-GH-1013 (MAIL-RELAY01) | ProxyShell is independently exploitable via RULE-GH-001; not currently linked onward to another CI's finding in this version |
| 200788 | CLD-GH-5004 (Entra ID Tenant) | Excessive Global Admin assignments; identity-plane risk not currently chained to a specific exploited finding |
| 43602 | SRV-GH-1004 (WKS-FIN01) | Outlook NTLM leak is a credential-harvesting precursor but has no confirmed onward relationship distinct from Path E's own Kerberoasting route |
| 200812 | NET-GH-0040 | This is the compliance finding *documenting* that RULE-GH-005/E3 exists — it's the audit-trail record of Path E's segmentation gap, not a separate technical hop |


## 7. Finding-to-CI Cross-Reference

Direct mapping from every vulnerability CSV row (`QID`) to the CI(s) it affects and its position in an attack path, if any. This is also embedded as `CI_ID` and `Attack_Path_Ref` columns in the companion CSV.

| QID | Primary CI | Related CIs (upstream/downstream in chain) | Attack Path Ref |
|---|---|---|---|
| 105001 | SRV-GH-1070 | SRV-GH-1003 (downstream, Path A) | PATH-A-Step1 |
| 38689 | SRV-GH-1003 | SRV-GH-1070 (upstream), SRV-GH-1002 (downstream) | PATH-A-Step2 |
| 90013 | SRV-GH-1002 | SRV-GH-1003 (upstream) | PATH-A-Step3 |
| 150220 | SRV-GH-1002 | N/A (terminal step) | PATH-A-Step4 |
| 11827 | SRV-GH-1011 | SRV-GH-1020 (downstream, Path B) | PATH-B-Step1 |
| 11831 | SRV-GH-1011 | SRV-GH-1020 (downstream, Path B) | PATH-B-Step2 |
| 200114 | SRV-GH-1010 | SRV-GH-1011 (upstream), SRV-GH-1020 (downstream) | PATH-B-Step3 |
| 13398 | SRV-GH-1020 | SRV-GH-1011 (upstream), SRV-GH-1030 (downstream) | PATH-B-Step4 |
| 200338 | SRV-GH-1030 | SRV-GH-1020 (upstream) | PATH-B-Step5 |
| 300011 | CLD-GH-5001 | CLD-GH-5002 (downstream, Path C) | PATH-C-Step1 |
| 300045 | CLD-GH-5002 | CLD-GH-5001 (upstream), CLD-GH-5003 (downstream) | PATH-C-Step2 |
| 300067 | CLD-GH-5003 | CLD-GH-5002 (upstream) | PATH-C-Step3 |
| 43111 | SRV-GH-1012 | SRV-GH-1050 (downstream, Path D) | PATH-D-Step1 |
| 200401 | SRV-GH-1012 | SRV-GH-1050 (downstream) | PATH-D-Step2 |
| 90211 | SRV-GH-1050 | SRV-GH-1012 (upstream), SRV-GH-1051 (downstream) | PATH-D-Step3 |
| 43287 | SRV-GH-1051 | SRV-GH-1050 (upstream), all 12 §2 guest CIs + SRV-GH-1052 (downstream) | PATH-D-Step4 |
| 200455 | SRV-GH-1052 | SRV-GH-1051 (upstream) | PATH-D-Step5 |
| 90344 | SRV-GH-1001 | SRV-GH-1004 (upstream), SRV-GH-1022 (svc_trade runtime) | PATH-E-Step1 |
| 90512 | SRV-GH-1001 | SRV-GH-1040 (downstream, Path E) | PATH-E-Step2 |
| 200512 | NET-GH-0040 | SRV-GH-1001 (upstream), SRV-GH-1040 (downstream) | PATH-E-Step3 |
| 45923 | SRV-GH-1040 | SRV-GH-1001 (upstream, or independent), SRV-GH-1042 (downstream) | PATH-E-Step4 |
| 200533 | SRV-GH-1042 | SRV-GH-1040 (upstream) | PATH-E-Step5 |
| 150221 | SRV-GH-1022 | SRV-GH-1032 (downstream, Path F) | PATH-F-Step1 |
| 200601 | SRV-GH-1022 | N/A (severity amplifier for F1) | PATH-F-Step2 |
| 150233 | SRV-GH-1022 | SRV-GH-1032 (downstream) | PATH-F-Step3 |
| 200622 | SRV-GH-1032 | SRV-GH-1041 (downstream) | PATH-F-Step4 |
| 105102 | SRV-GH-1080 | N/A | Standalone |
| 200711 | SRV-GH-1060 | N/A | Standalone |
| 43055 | SRV-GH-1013 | N/A | Standalone |
| 200788 | CLD-GH-5004 | N/A | Standalone |
| 43602 | SRV-GH-1004 | N/A | Standalone |
| 200812 | NET-GH-0040 | Documents RULE-GH-005 | Standalone |


## 8. Explicitly Non-Existent Paths (Negative Ground Truth)

These are plausible-sounding claims that are **false**. Use them directly to test false-positive behavior — a correct agent rejects each one and explains why by citing the *absence* of a rule or relationship in §3–§5, not just asserting "that's wrong."

| Claimed Path | Why It's False |
|---|---|
| GUEST-AP-SW01 → DB-TRADE01 (direct) | No rule exists from NET-GH-0070 to NET-GH-0030 or NET-GH-0040 (§3). Guest WiFi only reaches VLAN 10 via RULE-GH-008; there is no continuation rule from VLAN 10 to the DB Tier (RULE-GH-011 explicitly absent) or the Finance zone without going through Path E's full credential-escalation chain. |
| WEB-PORTAL01 → SWIFT-GATEWAY01 (direct) | DMZ (NET-GH-0020) has no rule reaching NET-GH-0040 (§3, RULE-GH-015 confirms absence). Reaching SWIFT-GATEWAY01 requires the full Path E chain through Domain Admin — there is no DMZ-to-Finance-zone shortcut. |
| APP-HR01 → DB-TRADE01 | APP-HR01's only database relationship is REL-GH-104, to DB-FIN01 (payroll integration). No relationship connects APP-HR01 to DB-TRADE01 in §4. |
| BRANCH-WKS01 → VCENTER01 | VLAN 60 (Branch/VPN) only has RULE-GH-009, reaching VLAN 10. No rule in §3 connects VLAN 60 to VLAN 50 (Management/OOB). |
| NAS01 compromise leads directly to Domain Admin | NAS01's only relationships are REL-GH-111/112, being backed-up-by BACKUP-MGR01. It has no authentication trust or credential relationship (§5) to DC01. |
| Zerologon on DC01 is exploitable directly from the internet | DC01 sits in NET-GH-0010, which has no rule in §3 accepting inbound traffic from NET-GH-INET. Zerologon requires network reach to VLAN 10 first (e.g., via Path A's guest-WiFi hop or the Path E workstation foothold), not direct internet access. |


---

*This document is the authoritative relationship ground truth for Ghrab Financial Group. It supersedes any prose-only description of the same environment. Companion files: `ghrab_vulnerabilities.csv` (vulnerability detail, now with `CI_ID`/`Related_CI_IDs` columns matching §1 and §7 of this document) and `ghrab_architecture.png` (visual network diagram, unchanged).*
