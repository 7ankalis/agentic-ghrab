# Ghrab Financial Group — Vulnerable Enterprise Lab
### Architecture & Attack Path Reference for Vulnerability Management AI/Agent Testing

**Status:** Fully fictional lab environment. All hostnames, IPs, employee/team names, and the "Ghrab" entity are synthetic. CVEs referenced are real, publicly disclosed vulnerabilities used here strictly to give the lab realistic remediation content for testing a VM RAG/agent pipeline (similar in spirit to a HackTheBox Pro Lab or Tenable-style exposure-management sandbox).

**Purpose:** This document, together with `ghrab_vulnerabilities.csv` (Qualys-style export) and `ghrab_architecture.png` (network/attack-path diagram), forms a ground-truth dataset. Use it to:
- Feed your RAG pipeline a realistic "customer environment" knowledge base.
- Ask your VM operator-facing agent questions ("What's our exposure on the trading platform?", "Who owns remediation for CVE-2020-1472?", "What's the fastest path to Domain Admin?") and check answers against this ground truth to catch hallucination.
- Stand up the actual lab (via GNS3/EVE-NG/Proxmox/VMware Workstation + vulnerable VM images) if you want a live, exploitable target range in addition to the RAG dataset.

---

## 1. Company Profile (Fictional)

**Ghrab Financial Group** is a mid-sized fictional financial services firm offering retail banking, corporate lending, and securities trading/settlement. It has:
- 1 HQ site, 1 branch office, remote/VPN workforce
- A hybrid on-prem + AWS + Microsoft Entra ID (Azure AD) footprint
- A PCI DSS-scoped Cardholder Data Environment (CDE) and a SWIFT-connected payment gateway (both fictional but modeled on real compliance obligations, useful for testing compliance-aware remediation answers)
- ~9 network segments (VLANs), 3 cloud services in scope, and 6 internal teams with distinct ownership boundaries

## 2. Network Segmentation (VLANs / Zones)

| VLAN | Zone Name | CIDR | Purpose | Trust Level | Owning Team |
|---|---|---|---|---|---|
| 10 | Corporate LAN | 10.10.10.0/24 | Workstations, file server, Domain Controller | Medium | IT Infrastructure Team |
| 20 | DMZ | 10.10.20.0/24 | Public web, VPN gateway, mail relay | Low (internet-facing) | Network Team |
| 21 | App Tier | 10.10.21.0/24 | Internal application servers (CRM, HR, Trading app) | Medium | AppSec Team |
| 30 | DB Tier | 10.10.30.0/24 | Backend databases | High | DBA Team |
| 40 | Finance/Trading Critical Zone | 10.10.40.0/24 | Trading core, settlement, SWIFT gateway — **CDE/SWIFT scope** | Critical | Compliance-GRC + Network Team |
| 50 | Management / Out-of-Band | 10.10.50.0/24 | Jump hosts, vCenter, backup manager | Critical (should be) | IT Infrastructure Team |
| 60 | Branch/VPN | 10.10.60.0/24 | Branch office router + workstation | Medium | Network Team |
| 70 | Guest WiFi | 10.10.70.0/24 | Guest wireless — **should be fully isolated** | Untrusted | Network Team |
| 80 | Backup/Storage | 10.10.80.0/24 | NAS and backup servers | High | IT Infrastructure Team |
| Cloud | AWS + Entra ID | N/A | S3, IAM, RDS, Entra tenant | Mixed | Cloud Team |

> **Design intent for testing:** Several of the segmentation boundaries above are *deliberately* broken (see §4) — this is what your agents should be able to detect and recommend fixing, not something to treat as accepted architecture.

## 3. Asset Inventory

### 3.1 Corporate LAN (VLAN 10)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| DC01 | 10.10.10.10 | Active Directory Domain Controller | Zerologon (CVE-2020-1472), Kerberoastable `svc_trade` account |
| FILESRV01 | 10.10.10.20 | File server (HR/Finance shares) | Excessive share ACLs ("Everyone: Full Control") |
| WKS-HR02 | 10.10.10.55 | HR workstation | EternalBlue (CVE-2017-0144), SMBv1 enabled |
| WKS-FIN01 | 10.10.10.50 | Finance workstation | Outlook NTLM leak (CVE-2023-23397) |
| PRINT01 | 10.10.10.30 | Network printer | (Reserved for future low-severity findings) |

### 3.2 DMZ (VLAN 20)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| LB01 | 10.10.20.5 | Reverse proxy / load balancer | Overly permissive backend ACL (ANY-ANY to App Tier) |
| WEB-PORTAL01 | 10.10.20.10 | Public marketing site (WordPress) | SQLi (CVE-2023-30777) + upload RCE |
| VPN-GW01 | 10.10.20.20 | FortiGate SSL-VPN | CVE-2018-13379 credential disclosure |
| MAIL-RELAY01 | 10.10.20.30 | Exchange mail relay | ProxyShell (CVE-2021-34473) |

### 3.3 App Tier (VLAN 21)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| APP-CRM01 | 10.10.21.10 | Internal CRM (Apache Struts2) | CVE-2017-5638 RCE |
| APP-HR01 | 10.10.21.20 | HR application | (Reserved / baseline-only host for noise testing) |
| APP-TRADE01 | 10.10.21.30 | Trading platform (Java) | Log4Shell (CVE-2021-44228), runs as SYSTEM, hardcoded DB creds |

### 3.4 DB Tier (VLAN 30)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| DB-CRM01 | 10.10.30.10 | MSSQL for CRM | App service account has `db_owner` (excessive) |
| DB-FIN01 | 10.10.30.20 | Oracle finance reporting DB | (Referenced by cloud RDS mirror scenario) |
| DB-TRADE01 | 10.10.30.30 | Oracle trading DB | Excessive DB Link to SETTLEMENT01 |

### 3.5 Finance/Trading Critical Zone (VLAN 40 — CDE/SWIFT scope)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| TRADE-CORE01 | 10.10.40.10 | Core trading execution server | BlueKeep (CVE-2019-0708) |
| SETTLEMENT01 | 10.10.40.20 | Trade settlement processing | Reachable via excessive DB link |
| SWIFT-GATEWAY01 | 10.10.40.30 | SWIFT payment messaging gateway | Administered with shared Domain Admin credential (violates SWIFT CSP) |

### 3.6 Management / Out-of-Band (VLAN 50)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| JUMP01 | 10.10.50.10 | Admin bastion/jump host | Cached Domain Admin credentials |
| VCENTER01 | 10.10.50.20 | VMware vCenter | CVE-2021-21972 RCE |
| BACKUP-MGR01 | 10.10.50.30 | Veeam Backup & Replication console | Default credentials |

### 3.7 Branch/VPN (VLAN 60)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| BRANCH-RTR01 | 10.10.60.1 | Branch router | Legacy "any-any" firewall rule never removed |
| BRANCH-WKS01 | 10.10.60.50 | Branch workstation | Baseline host |

### 3.8 Guest WiFi (VLAN 70)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| GUEST-AP-SW01 | 10.10.70.1 | Guest wireless access switch | Trunk port misconfigured, allows VLAN hopping into VLAN 10 |

### 3.9 Backup/Storage (VLAN 80)
| Host | IP | Role | Notable Issue |
|---|---|---|---|
| NAS01 | 10.10.80.10 | Network storage | Anonymous SMB access enabled |
| BACKUP-SRV01 | 10.10.80.20 | Backup server | Baseline host |

### 3.10 Cloud (AWS + Microsoft Entra ID)
| Asset | Type | Notable Issue |
|---|---|---|
| `ghrab-public-assets` | S3 bucket | Public read, contains a leaked credentials backup file |
| `ghrab-app-role` | IAM role | `AdministratorAccess` attached (excessive) |
| `ghrab-finance-rds` | RDS (PostgreSQL) | Publicly accessible, weak master password |
| `ghrab.onmicrosoft.com` | Entra ID tenant | 14 accounts hold Global Administrator (excessive) |

## 4. Teams & Ownership Model

| Team | Responsible For | Example Owned Assets |
|---|---|---|
| **IT Infrastructure Team** | Windows/Linux server patching, AD, endpoints, backup infra | DC01, WKS-*, FILESRV01, JUMP01, VCENTER01, BACKUP-MGR01, NAS01 |
| **Network Team** | Firewalls, VLAN segmentation, VPN, routing, WiFi | LB01, VPN-GW01, GUEST-AP-SW01, BRANCH-RTR01, inter-VLAN ACLs |
| **AppSec Team** | Web/application-layer vulnerabilities, secure SDLC, app service accounts | WEB-PORTAL01, APP-CRM01, APP-TRADE01 |
| **DBA Team** | Database hardening, account privilege scoping, DB links | DB-CRM01, DB-FIN01, DB-TRADE01 |
| **Cloud Team** | AWS/Azure configuration, IAM, cloud-native services | S3, IAM roles, RDS, Entra ID tenant |
| **Compliance-GRC Team** | PCI DSS / SWIFT CSP scope validation, segmentation testing, policy exceptions | CDE (VLAN 40) segmentation, SWIFT-GATEWAY01 governance |

This ownership mapping is intentionally used as the `Responsible_Team` field in the CSV so you can test whether your agent correctly routes a remediation recommendation to the right operational team (a common real-world VM program failure mode — e.g., recommending a network fix to the DBA team).

## 5. Attack Paths (Easy → Hard)

Each path is a chain of CVEs/misconfigurations/excessive-privilege findings. Path step IDs match the `Attack_Path_Ref` column in the CSV, so you can validate whether your agent correctly reconstructs the chain when asked "how could an attacker reach X?"

### PATH A — Easy: Guest WiFi → Corporate LAN → File Server
1. **A1** — Misconfigured trunk port on `GUEST-AP-SW01` allows VLAN hopping from Guest WiFi (VLAN 70) into Corporate LAN (VLAN 10).
2. **A2** — `WKS-HR02` is vulnerable to EternalBlue (CVE-2017-0144); attacker gains SYSTEM.
3. **A3** — Reused local Administrator password (no LAPS) allows pass-the-hash to `FILESRV01`.
4. **A4** — Excessive share ACL ("Everyone: Full Control") on the HR share exposes confidential HR/payroll data.
   **Impact:** Confidential HR data exfiltration from an untrusted guest network with zero authentication.

### PATH B — Easy/Medium: Public Web → App Tier → CRM Database
1. **B1** — SQL injection (CVE-2023-30777) in WordPress plugin on `WEB-PORTAL01` yields admin access; webshell uploaded.
2. **B2** — Overly permissive DMZ→App-Tier firewall rule (ANY-ANY instead of scoped to LB01→8443) allows pivot to `APP-CRM01`.
3. **B3** — Apache Struts2 RCE (CVE-2017-5638) on `APP-CRM01`.
4. **B4** — Excessive `db_owner` privilege on the CRM app's DB service account allows full compromise of `DB-CRM01`.
   **Impact:** Full CRM customer database compromise starting from the public internet.

### PATH C — Medium: Cloud Misconfiguration Chain
1. **C1** — Public S3 bucket `ghrab-public-assets` leaks an AWS credentials backup file.
2. **C2** — Leaked credentials belong to `ghrab-app-role`, which has `AdministratorAccess` (excessive) attached.
3. **C3** — Full AWS account control is used to reach `ghrab-finance-rds`, a publicly accessible RDS instance with a weak master password.
   **Impact:** Complete AWS environment compromise + finance database exfiltration, entirely cloud-native, no on-prem foothold required.

### PATH D — Medium/Hard: VPN → Management Plane → Hypervisor → Backups
1. **D1** — FortiGate SSL-VPN path traversal (CVE-2018-13379) leaks valid VPN credentials.
2. **D2** — Overly broad VPN split-tunnel ACL routes remote users into the Management VLAN (50), which it should never reach.
3. **D3** — `JUMP01` bastion host has cached Domain Admin credentials from a prior troubleshooting session (violates tiered admin model).
4. **D4** — vCenter RCE (CVE-2021-21972) on `VCENTER01` grants full hypervisor/VM control.
5. **D5** — Pivot to `BACKUP-MGR01` (default credentials) exposes backup archives containing finance DB dumps.
   **Impact:** Full virtualization + backup infrastructure compromise via a single leaked VPN credential.

### PATH E — Hard: Kerberoast → Zerologon → Flat Trust → Trading Core → SWIFT
1. **E1** — Weak-password Kerberoastable service account `svc_trade` cracked offline via a TGS ticket request.
2. **E2** — Zerologon (CVE-2020-1472) against `DC01` escalates to Domain Admin (this step alone is also independently exploitable without E1).
3. **E3** — Flat trust: firewall between Corporate LAN and the Finance/Trading Critical Zone (VLAN 40) allows full AD authentication with no tiering/PAM boundary.
4. **E4** — Domain Admin creds (or the independent BlueKeep CVE-2019-0708) compromise `TRADE-CORE01`.
5. **E5** — `SWIFT-GATEWAY01` is administered with the same shared Domain Admin credential (violates SWIFT CSP dedicated-identity requirement), giving the attacker a path toward payment-messaging manipulation.
   **Impact:** Full domain compromise cascading into the organization's most critical trading and payment infrastructure — the "crown jewels" scenario.

### PATH F — Hard: Log4Shell Chain via Trading Application
1. **F1** — Log4Shell (CVE-2021-44228) on `APP-TRADE01`'s log ingestion endpoint yields RCE.
2. **F2** — The trading service runs as local SYSTEM instead of a scoped service account, so RCE = full host compromise.
3. **F3** — Hardcoded DB credentials in `application.properties` are trivially recovered from the compromised filesystem.
4. **F4** — Excessive/unused DB Link from `DB-TRADE01` to `SETTLEMENT01` allows direct pivot into the settlement database without needing separate credentials.
   **Impact:** RCE on the trading platform cascades directly into the settlement system via a purely database-layer trust relationship, bypassing network segmentation entirely.

### Additional standalone findings (breadth/noise for RAG evaluation)
Not part of a chained path — included to test whether your agent correctly treats isolated findings as isolated rather than inventing a chain that doesn't exist:
- Anonymous SMB on `NAS01` (backup exposure)
- Legacy "any-any" rule on `BRANCH-RTR01`
- ProxyShell on `MAIL-RELAY01` (independently exploitable, not currently chained into another path in this version of the lab)
- Excessive Entra ID Global Administrator assignments (14 accounts)
- Undocumented segmentation paths into the CDE (compliance gap, PCI DSS 11.3.4)

## 6. Suggested Use With Your VM Agent / RAG Pipeline

1. **Ingest** this MD file and the CSV as the knowledge base / ground truth corpus.
2. **Render** `ghrab_architecture.png` as reference context for questions involving topology.
3. **Ask evaluation questions** such as:
   - "What CVEs affect the Finance/Trading Critical Zone and who owns remediation?" (Ground truth: CVE-2019-0708 on TRADE-CORE01, IT Infrastructure Team; plus the flat-trust misconfig owned jointly by Network Team/Compliance-GRC.)
   - "Is there a path from Guest WiFi to Domain Admin?" (Ground truth: No direct single path in this version — Guest WiFi leads to Path A only, which does not by itself reach DC01; a hallucinating agent might incorrectly merge Path A and Path E.)
   - "Which team should fix the S3 bucket exposure?" (Ground truth: Cloud Team, QID 300011.)
   - "What's the CVSS of the Zerologon finding?" (Ground truth: 10.0, QID 90512.)
4. **Score hallucination** by checking whether the agent invents CVEs/hosts not present in the CSV, misattributes ownership, or fabricates attack-path connections that don't exist in §5.

## 7. Notes on Building a Live/Exploitable Version (Optional)

If you want this to also function as an actual exploitable range (not just a RAG ground-truth dataset):
- Use **EVE-NG**, **GNS3**, or **Proxmox** for the VLAN/routing fabric (virtual switches/routers per VLAN table in §2).
- Populate hosts with intentionally vulnerable, EOL software versions matching the CVEs listed (e.g., an old Struts2/Log4j2 WAR, unpatched Windows Server builds pre-dating the relevant KBs, FortiOS pre-6.0.5).
- Use **LocalStack** or a sandboxed AWS account for the S3/IAM/RDS misconfigurations, and a disposable/test Entra ID tenant for the identity findings — never replicate these misconfigurations against production cloud accounts.
- Keep the lab fully air-gapped or isolated from production networks given the intentionally weakened security controls.

---
*Generated as a synthetic dataset for defensive AI/agent testing purposes. No real organization named "Ghrab" is depicted or implied.*
