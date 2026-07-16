# Ghrab — Documented Attack Paths (VERIFICATION ORACLE ONLY)

> Not ingested by the platform. Held out as ground truth to score whether the
> AI/graph engine rediscovers these paths on its own. See tests/test_rediscovery.py.

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
