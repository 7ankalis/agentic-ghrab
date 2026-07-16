# Velon — Documented Attack Paths (VERIFICATION ORACLE ONLY)

> Not ingested by the platform. Held out as ground truth to score whether the
> AI/graph engine rediscovers these paths on its own. See tests/test_rediscovery.py.

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
