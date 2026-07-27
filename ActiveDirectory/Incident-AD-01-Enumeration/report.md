# Incident AD-01: Active Directory Enumeration via BloodHound & LDAP Recon

**Investigation ID:** AD-01
**Date:** June 2026
**Analyst:** Shakshi
**Lab Environment:** SOC.LAB (SOC Home Lab — VirtualBox)
**MITRE ATT&CK Techniques:** T1069.002 (Domain Groups), T1087.002 (Domain Account), TA0007 (Discovery)

---

## 1. Executive Summary

A simulated attacker on the Kali-Attacker host used valid low-privilege domain credentials (`jsmith`) to enumerate the SOC.LAB Active Directory domain via `bloodhound-python`. The collector queried the domain controller (DC01.SOC.LAB) over LDAP and successfully mapped the full object graph: 11 users, 52 groups, 4 OUs, 2 GPOs, 19 containers, and 3 domain-joined computers. The resulting BloodHound graph revealed a viable attack path from low-privilege AD objects to Domain Admins via chained `GenericWrite` and `AddKeyCredentialLink` relationships, exposing a privilege escalation path that would not be obvious from a standard AD permissions review.

This investigation demonstrates how a single compromised domain account — even one with no special privileges — can be used to fully map an Active Directory environment and surface escalation paths to full domain compromise, without triggering any alerts in a poorly instrumented environment.

## 2. Timeline of Events

| Time | Event |
|---|---|
| T+0:00 | Attacker authenticates as `jsmith` and launches `bloodhound-python` against DC01.SOC.LAB |
| T+0:01 | TGT obtained for `jsmith`; LDAP connection established to `dc01.soc.lab` |
| T+0:01–0:09 | Domain, computer, user, group, GPO, OU, and container enumeration completed |
| T+0:09 | Collection completed: 11 users, 52 groups, 2 GPOs, 4 OUs, 19 containers, 0 trusts, 3 computers |
| T+~5h (post-collection) | Analyst imports collection into BloodHound; Cypher query reveals escalation path from the compromised service account to Domain Admins |

## 3. Attack Methodology

**Tool:** `bloodhound-python` (BloodHound.py, compatible with BloodHound Legacy 4.2/4.3)

**Command executed:**
```bash
bloodhound-python -u jsmith -p 'Password123!' -d SOC.LAB -ns 192.168.10.10 -c All
```

This performs LDAP-based collection using the credentials of a standard domain user — no elevated privileges are required to enumerate the majority of an AD environment by default. The `-c All` flag collects every available data category: users, groups, computers, GPOs, OUs, ACLs, sessions, and trusts.

**MITRE ATT&CK mapping:**
- **T1087.002 — Account Discovery: Domain Account:** enumeration of all 11 domain user accounts via LDAP
- **T1069.002 — Permission Groups Discovery: Domain Groups:** enumeration of 52 domain groups and their memberships
- **TA0007 — Discovery (tactic):** overall reconnaissance phase preceding any credential theft or lateral movement

After collection, the attacker loaded the data into BloodHound's Cypher query interface and traced inbound object control relationships. The resulting graph (see Evidence section) shows that members of `ENTERPRISE KEY ADMINS@SOC.LAB` and `KEY ADMINS@SOC.LAB` hold `AddKeyCredentialLink` rights on `DC01.SOC.LAB`, which can be abused to perform a Shadow Credentials attack and request a TGT as the domain controller's computer account — a direct path toward `SOC.LAB` domain compromise and ultimately `DOMAIN ADMINS@SOC.LAB`.

## 4. Log Evidence

**LDAP enumeration output (`bloodhound-python` console):**
```
INFO: BloodHound.py for BloodHound LEGACY (BloodHound 4.2 and 4.3)
INFO: Found AD domain: soc.lab
INFO: Getting TGT for user
INFO: Connecting to LDAP server: dc01.soc.lab
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 3 computers
INFO: Connecting to LDAP server: dc01.soc.lab
INFO: Found 11 users
INFO: Found 52 groups
INFO: Found 2 gpos
INFO: Found 4 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: DESKTOP-VP8JNI5.SOC.LAB
INFO: Querying computer: WindowsClient11.SOC.LAB
INFO: Querying computer: DC01.SOC.LAB
INFO: Done in 00M 09S
```

This confirms the LDAP queries reached DC01 successfully and returned a complete, unfiltered view of the domain — no LDAP query throttling or anomaly detection intervened.

**Screenshot references:**
- `screenshots/bloodhound-python-output.png` — full terminal output of the collection run
- `screenshots/shortest-path-to-DA.png` — BloodHound Cypher graph showing the GenericWrite/AddKeyCredentialLink/CoerceToTGT path from low-privilege groups to DOMAIN ADMINS@SOC.LAB

## 5. Network Evidence

LDAP traffic was generated to DC01.SOC.LAB (192.168.10.10) on TCP port 389 during the collection window.

## 6. IOC Table

| Indicator | Value | Notes |
|---|---|---|
| Source host | 192.168.10.5 (Kali-Attacker) | Origin of enumeration |
| Source user | jsmith@SOC.LAB | Low-privilege domain account used for collection |
| Target | DC01.SOC.LAB (192.168.10.10) | Domain controller queried over LDAP |
| Tool signature | `bloodhound-python` / `BloodHound.py` | LDAP query pattern, high object enumeration volume in short window |
| Protocol | LDAP (TCP 389) | Used for all enumeration queries |

## 7. Root Cause

The root cause is not a misconfiguration in the traditional sense — by default, any authenticated domain user can read most AD objects via LDAP. The real exposure is the **excessive permission chain** discovered during enumeration: `ENTERPRISE KEY ADMINS` and `KEY ADMINS` groups hold `AddKeyCredentialLink` on the domain controller computer object, which is a known Shadow Credentials abuse primitive. This was not something a standard AD audit would catch without graph-based analysis.

## 8. Impact Assessment

**Severity: Medium (Reconnaissance), High (if escalation path is exploited)**

On its own, AD enumeration does not compromise anything — but it gives an attacker a complete roadmap to domain compromise without needing to guess or brute-force their way through the environment. In this case, the enumeration directly revealed a path to Domain Admins, meaning a follow-on attack (Shadow Credentials abuse via `AddKeyCredentialLink`) could fully compromise the domain.

## 9. Recommendations

1. **Enable LDAP query auditing** — Wazuh/Sysmon should be configured to detect anomalous query volume from a single account in a short time window (Event ID 4662 with object access auditing enabled).
2. **Restrict `AddKeyCredentialLink` rights** on sensitive computer objects (especially domain controllers) to only Tier-0 administrative accounts.
3. **Deploy a BloodHound canary/honeypot object** to detect when enumeration tools are run against the domain.
4. **Review `KEY ADMINS` and `ENTERPRISE KEY ADMINS` group membership** regularly — these groups are frequently overlooked in standard AD permission reviews.
5. **Rate-limit or alert on LDAP queries** that retrieve excessive object counts in a short timeframe from non-service accounts.

## 10. Lessons Learned

This investigation reinforced that Active Directory's default permission model allows nearly unrestricted reconnaissance by any authenticated user, and that the real risk often lies not in the enumeration itself but in the privilege escalation paths it reveals. Using BloodHound's graph-based analysis surfaced an `AddKeyCredentialLink` exposure that would be very difficult to spot through manual ACL review. This is also a reminder that detection must focus not just on "is someone running BloodHound" but on instrumenting the underlying LDAP query behavior, since the tool itself leaves a fairly quiet footprint if not specifically monitored for.
