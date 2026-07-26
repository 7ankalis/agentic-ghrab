# Elihowa Retail Group

> Sector: a mid-market e-commerce retailer
> Frameworks: PCI DSS, GDPR

### Configuration Management Database — CI Inventory, Relationships & Network Reachability

**Purpose of this document.** A machine-checkable relationship graph, structured the way a real CMDB (e.g. ServiceNow `cmdb_ci` + `cmdb_rel_ci`) represents infrastructure: every Configuration Item (CI) has a unique ID, a class, and a set of *typed* relationships to other CIs — §2 zone-to-zone reachability, §3 host/app/db dependencies, §4 identity & credential relationships. This inventory describes the environment as it is; it does **not** enumerate attack paths. Determining whether an attacker can chain these relationships into a route to a crown jewel is the detection system's job, not something this document hands over.

---

## 1. CI Inventory

Every asset in this lab is a Configuration Item (CI) with a unique ID, class, zone, criticality tier, owning Support Group, and the Business Service it exists to support. Criticality tiers: **Crown Jewel > High > Business-Important > Standard**.

### 1.1 Network Segments (Class: `cmdb_ci_network_segment`)

| CI ID | Name | CIDR | Trust Level | Owning Support Group |
|---|---|---|---|---|
| NET-EL-0010 | VLAN 10 — Corporate LAN | 10.40.10.0/24 | Medium | GRP-EL-IT |
| NET-EL-0020 | VLAN 20 — DMZ / E-Commerce | 10.40.20.0/24 | Low (internet-facing) | GRP-EL-NET |
| NET-EL-0030 | VLAN 30 — Payment Processing Zone (PCI CDE) | 10.40.30.0/24 | Critical (isolated) | GRP-EL-PAY |
| NET-EL-INET | Internet (untrusted) | 0.0.0.0/0 | None | N/A |

VLAN 30 is designated as logically isolated from the other two zones — it is scoped out of general corporate routing and out of the DMZ entirely. Whether that isolation actually holds in practice is a function of the reachability rules in §2, not an assumption to take at face value.

### 1.2 Servers & Network Devices (Class: `cmdb_ci_server`)

| CI ID | Name | Zone | IP | Platform | Criticality | Support Group | Business Service |
|---|---|---|---|---|---|---|---|
| SRV-EL-1001 | DC01 | NET-EL-0010 | 10.40.10.10 | Windows Server (AD DS) | High | GRP-EL-IT | BSVC-EL-03 |
| SRV-EL-1002 | FILESRV01 | NET-EL-0010 | 10.40.10.20 | Windows Server | Business-Important | GRP-EL-IT | BSVC-EL-03 |
| SRV-EL-1003 | WKS-ACCT01 | NET-EL-0010 | 10.40.10.40 | Windows 10/11 | Standard | GRP-EL-IT | BSVC-EL-03 |
| SRV-EL-1004 | WKS-SUPPORT01 | NET-EL-0010 | 10.40.10.45 | Windows 10/11 | Standard | GRP-EL-IT | BSVC-EL-03 |
| SRV-EL-1005 | BACKUP-MGR01 | NET-EL-0010 | 10.40.10.50 | Windows Server (Veeam) | High | GRP-EL-IT | BSVC-EL-03 |
| SRV-EL-1006 | PRINT01 | NET-EL-0010 | 10.40.10.60 | Network Print Appliance | Standard | GRP-EL-IT | BSVC-EL-03 |
| SRV-EL-1010 | LB01 | NET-EL-0020 | 10.40.20.5 | NGINX Appliance | Business-Important | GRP-EL-NET | BSVC-EL-01 |
| SRV-EL-1011 | WEB-SHOP01 | NET-EL-0020 | 10.40.20.10 | Linux (Adobe Commerce/Magento) | Business-Important | GRP-EL-NET | BSVC-EL-01 |
| SRV-EL-1012 | API-GW01 | NET-EL-0020 | 10.40.20.20 | Linux (Node.js) | Business-Important | GRP-EL-APP | BSVC-EL-01 |
| SRV-EL-1013 | VPN-GW01 | NET-EL-0020 | 10.40.20.30 | FortiGate Appliance | Business-Important | GRP-EL-NET | BSVC-EL-03 |
| SRV-EL-1030 | PAY-PROC01 | NET-EL-0030 | 10.40.30.10 | Linux (Payment Switch) | Crown Jewel | GRP-EL-PAY | BSVC-EL-02 |
| SRV-EL-1031 | DB-PAY01 | NET-EL-0030 | 10.40.30.20 | Oracle | Crown Jewel | GRP-EL-PAY | BSVC-EL-02 |
| SRV-EL-1032 | HSM-GW01 | NET-EL-0030 | 10.40.30.30 | HSM Appliance (Thales) | Crown Jewel | GRP-EL-PAY | BSVC-EL-02 |
| SRV-EL-1033 | PAY-ADMIN01 | NET-EL-0030 | 10.40.30.40 | Linux (hardened admin bastion, not domain-joined) | High | GRP-EL-PAY | BSVC-EL-02 |

Note: PAY-PROC01, DB-PAY01, HSM-GW01, and PAY-ADMIN01 are dedicated physical/appliance hardware, not domain-joined and not virtualized alongside the corporate estate — a deliberate PCI segmentation control.

### 1.3 Applications (Class: `cmdb_ci_appl`) — "Runs On" a Server CI

| CI ID | Name | Runs On (CI ID) | Support Group | Business Service |
|---|---|---|---|---|
| APP-EL-3011 | Elihowa Online Shop (Adobe Commerce/Magento) | SRV-EL-1011 (WEB-SHOP01) | GRP-EL-APP | BSVC-EL-01 |
| APP-EL-3012 | Order Processing API | SRV-EL-1012 (API-GW01) | GRP-EL-APP | BSVC-EL-01 |
| APP-EL-3001 | Active Directory Domain Services | SRV-EL-1001 (DC01) | GRP-EL-IT | BSVC-EL-03 |
| APP-EL-3030 | Payment Switch Application | SRV-EL-1030 (PAY-PROC01) | GRP-EL-PAY | BSVC-EL-02 |

### 1.4 Cloud Services (Class: `cmdb_ci_cloud_service`)

| CI ID | Name | Provider | Type | Criticality | Support Group | Business Service |
|---|---|---|---|---|---|---|
| CLD-EL-5001 | Blob Storage: elihowa-product-images | Azure | Object Storage | Business-Important | GRP-EL-CLD | BSVC-EL-01 |

### 1.5 Identity & Credential CIs (Class: `cmdb_ci_service_account` / `cmdb_ci_group`)

| CI ID | Name | Type | Valid On (CI IDs) | Known Issue |
|---|---|---|---|---|
| ID-EL-6001 | ELIHOWA.LOCAL | AD Forest/Domain | All domain-joined CIs (VLAN 10 only — VLAN 30 hosts are not domain members) | N/A |
| ID-EL-6002 | svc_backup | Service Account | SRV-EL-1005 (runs as, domain account), SRV-EL-1033 (backup agent authenticates as) | Weak, non-rotated password; same credential accepted by both the corporate backup manager and the payment-zone jump host |
| ID-EL-6003 | Shared Local Administrator | Local Account | SRV-EL-1002, SRV-EL-1003, SRV-EL-1004 | Identical password reused across hosts, no LAPS |
| ID-EL-6004 | Domain Admins | AD Group | SRV-EL-1001 only | N/A — scoped correctly, does not extend into NET-EL-0030 |

### 1.6 Business Services (Class: `cmdb_ci_business_service`)

| CI ID | Name | Description |
|---|---|---|
| BSVC-EL-01 | E-Commerce Platform | Public storefront, order API, product catalog |
| BSVC-EL-02 | Payment Processing (PCI CDE) | Card-present/card-not-present transaction switch, cardholder data store, key management |
| BSVC-EL-03 | Corporate IT & Support | Internal identity, file shares, endpoints, backup infrastructure |

### 1.7 Support Groups

| Group ID | Name | Responsible For |
|---|---|---|
| GRP-EL-IT | IT Infrastructure Team | Windows/Linux server patching, AD, endpoints, backup infra |
| GRP-EL-NET | Network Team | Firewalls, VLAN segmentation, VPN, load balancing |
| GRP-EL-APP | AppSec/Dev Team | Web/application-layer vulnerabilities, secure SDLC |
| GRP-EL-PAY | Payment Systems Team | PCI CDE hardening, payment switch, HSM, card data handling |
| GRP-EL-CLD | Cloud Team | Azure configuration, storage, IAM |

## 2. Network Reachability Rule Base (Zone-to-Zone) — THE authoritative reachability graph

This is the master truth table for "can zone X reach zone Y." Every attack path hop that crosses a zone boundary must cite a Rule ID from this table. **Status** distinguishes intended design (`Intended`), a real misconfiguration that enables an attack path (`Excessive`), and a zone pair with **no rule at all** (`Should-Not-Exist` / absent) — if an agent claims a path crossing a zone pair not listed here, or listed as absent, that hop is fabricated.

| Rule ID | Source Zone | Destination Zone | Port/Protocol | Status | Notes |
|---|---|---|---|---|---|
| RULE-EL-001 | NET-EL-INET | NET-EL-0020 | 443, 80 | Intended | Public storefront + order API |
| RULE-EL-002 | NET-EL-0020 | NET-EL-0010 | tcp/8080 (helpdesk ticket sync only) | Intended (design) | As-designed rule; superseded in practice by RULE-EL-003 |
| RULE-EL-003 | NET-EL-0020 | NET-EL-0010 | ANY/ANY | Excessive | As-configured firewall rule; QID 200114 — should be scoped to RULE-EL-002 only |
| RULE-EL-004 | NET-EL-0010 | NET-EL-0020 | tcp/443 (admin console) | Intended | IT/Network admin access to DMZ management interfaces |
| RULE-EL-005 | NET-EL-0010 | NET-EL-0030 | N/A | Should-Not-Exist (no rule) | Corporate LAN must never directly reach the PCI CDE |
| RULE-EL-006 | NET-EL-0020 | NET-EL-0030 | N/A | Should-Not-Exist (no rule) | DMZ never routes to the CDE — no rule has ever existed here |
| RULE-EL-007 | NET-EL-INET | NET-EL-0030 | N/A | Should-Not-Exist (no rule) | No direct internet path to the CDE |
| RULE-EL-008 | NET-EL-0030 | NET-EL-0010 | N/A | Should-Not-Exist (no rule) | CDE is one-way isolated; it never initiates connections outward |
| RULE-EL-009 | NET-EL-0010 | NET-EL-0030 | tcp/445 (Veeam backup agent only) | Excessive | QID 200718 — scoped to the backup agent port, but sourced from the general Corporate LAN backup manager rather than a dedicated, access-controlled backup network; the sole documented exception to CDE isolation |

## 3. Host, Application & Database Dependency Relationships

Application-layer and data-layer dependencies, independent of network zone rules.

| Relationship ID | Source CI | Relationship Type | Target CI | Port/Protocol | Justification | Flag |
|---|---|---|---|---|---|---|
| REL-EL-101 | SRV-EL-1010 (LB01) | Forwards To | SRV-EL-1011 (WEB-SHOP01) | 443→443 | Reverse proxy for storefront | Legitimate |
| REL-EL-102 | SRV-EL-1011 (WEB-SHOP01) | Depends On | SRV-EL-1012 (API-GW01) | 8443 | Storefront calls order API | Legitimate |
| REL-EL-103 | SRV-EL-1005 (BACKUP-MGR01) | Backs Up | SRV-EL-1033 (PAY-ADMIN01) | 445 | Nightly config backup of the payment-zone admin jump host, per RULE-EL-009 | Legitimate connection / segmentation exception |
| REL-EL-104 | SRV-EL-1005 (BACKUP-MGR01) | Backs Up | SRV-EL-1002 (FILESRV01) | 445 | Scheduled backup job | Legitimate |
| REL-EL-105 | SRV-EL-1033 (PAY-ADMIN01) | Manages | SRV-EL-1030 (PAY-PROC01) | 22 | Payment team jump host administers the payment switch | Legitimate |
| REL-EL-106 | SRV-EL-1033 (PAY-ADMIN01) | Manages | SRV-EL-1031 (DB-PAY01) | 1521 | Payment team jump host administers the card data store | Legitimate |
| REL-EL-107 | SRV-EL-1030 (PAY-PROC01) | Depends On | SRV-EL-1031 (DB-PAY01) | 1521 | Payment switch persists transaction/cardholder data | Legitimate |
| REL-EL-108 | SRV-EL-1030 (PAY-PROC01) | Depends On | SRV-EL-1032 (HSM-GW01) | 1500 | Key management / PIN block translation | Legitimate |
| REL-EL-109 | SRV-EL-1003 (WKS-ACCT01) | Authenticates To | SRV-EL-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-EL-110 | SRV-EL-1004 (WKS-SUPPORT01) | Authenticates To | SRV-EL-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-EL-111 | SRV-EL-1002 (FILESRV01) | Authenticates To | SRV-EL-1001 (DC01) | Kerberos/LDAP | Domain join | Legitimate |
| REL-EL-112 | CLD-EL-5001 (Blob: elihowa-product-images) | Serves | APP-EL-3011 (Elihowa Online Shop) | HTTPS | Product image CDN origin | Legitimate |

## 4. Identity & Credential Relationships

Many real attack paths aren't network hops at all — they're a credential valid on more than one CI. This table makes that explicit so agents don't need to (incorrectly) invent a network relationship to explain lateral movement that is actually credential reuse.

| Relationship ID | Credential/Identity CI | Valid On (CI ID) | Access Level Granted | Issue |
|---|---|---|---|---|
| CRED-EL-01 | ID-EL-6003 (Shared Local Administrator) | SRV-EL-1002, SRV-EL-1003, SRV-EL-1004 | Local Administrator | Enables pass-the-hash lateral movement across corporate endpoints |
| CRED-EL-02 | ID-EL-6002 (svc_backup) | SRV-EL-1005 (domain account, runs backup service), SRV-EL-1033 (backup agent auth) | Local Administrator on both hosts | Weak, reused password; the only credential that is simultaneously valid on a Corporate LAN host and a PCI CDE host |
| CRED-EL-03 | ID-EL-6004 (Domain Admins) | SRV-EL-1001 only | Full domain administrative control | Correctly scoped — does not extend into NET-EL-0030; VLAN 30 hosts are not domain members |
