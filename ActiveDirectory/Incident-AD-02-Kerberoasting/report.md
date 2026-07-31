# Incident AD-02: Kerberoasting Attack Against Service Account

**Investigation ID:** AD-02
**Date:** June 2026
**Analyst:** Shakshi
**Lab Environment:** SOC.LAB (SOC Home Lab — VirtualBox)
**MITRE ATT&CK Technique:** T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting (TA0006 Credential Access)

---

## 1. Executive Summary

Using valid low-privilege domain credentials (`jsmith`), a simulated attacker requested a Kerberos service ticket (TGS) for the `svc_backup` service account, which is configured with a Service Principal Name (SPN) and is therefore "Kerberoastable." The ticket was extracted via Impacket's `GetUserSPNs` tool, saved offline, and cracked using Hashcat in approximately the runtime of a standard rule-based attack, recovering the plaintext password `Back2024!`. This investigation confirms that any domain account with an SPN and a weak or reused password is a direct credential-theft target requiring no privilege escalation or exploitation — only a valid, low-privilege domain logon.

The attack was successfully detected via custom Wazuh and splunk correlation rule built specifically to flag Kerberos service ticket requests (Event ID 4769) using RC4-HMAC encryption (`ticketEncryptionType: 0x17`), which is the well-known signature of a Kerberoasting request, since RC4 tickets are intentionally requested by attackers over the stronger AES default in order to enable faster offline cracking.

## 2. Timeline of Events

| Time | Event |
|---|---|
| T+0:00 | Attacker authenticates as `jsmith` on Kali-Attacker |
| T+0:00 | `impacket-GetUserSPNs` queries DC01.SOC.LAB for all SPN-registered accounts |
| T+0:00 | Tool identifies `svc_backup` account (SPN: `HTTP/backupserver.soc.lab`) |
| T+0:00 | TGS-REQ issued for `svc_backup`; DC01 returns RC4-encrypted service ticket (Event ID 4769, `ticketEncryptionType: 0x17`) |
| T+0:00 | Wazuh custom rule 100010 fires, classifying the event as potential Kerberoasting activity |
| T+0:00 | Hash saved to `kerberoast.hash` in `$krb5tgs$23$...` format |
| T+~X min | `hashcat -m 13100 kerberoast.hash --show` recovers plaintext: `Back2024!` |

## 3. Attack Methodology

**Tools:** Impacket (`GetUserSPNs`), Hashcat

**Step 1 — Identify and request the SPN ticket:**
```bash
impacket-GetUserSPNs SOC.LAB/jsmit:Password123! -dc-ip 192.168.10.10 -request -outputfile kerberoast.hash
```

This authenticates as `jsmith`, queries the domain for all accounts with a registered SPN, and requests a TGS for each one found. The domain controller has no way to distinguish this from a legitimate service ticket request — any authenticated user can request a TGS for any SPN-registered account, by design of the Kerberos protocol.

**Step 2 — Crack the extracted hash offline:**
```bash
hashcat -m 13100 kerberoast.hash --show
```

Mode `13100` is Hashcat's Kerberos 5 TGS-REP etype 23 (RC4-HMAC) cracking mode. The recovered credential was:
```
svc_backup : Back2024!
```

**Why this works:** The `svc_backup` account was deliberately configured (Phase 1, Day 4B) with an SPN via `setspn`, making it eligible for Kerberoasting. Because the account's password was set to a value crackable within a standard wordlist/rule attack, the ticket's RC4-HMAC encryption was reversible in a practical timeframe.

**MITRE ATT&CK mapping:**
- **T1558.003 — Steal or Forge Kerberos Tickets: Kerberoasting**
- **TA0006 — Credential Access** (tactic)

## 4. Log Evidence

**Raw Wazuh alert (Event ID 4769) — RC4 Kerberoasting indicator:**
```json
"data": {
  "win": {
    "eventdata": {
      "targetUserName": "jsmith@SOC.LAB",
      "ipAddress": "::ffff:192.168.10.5",
      "targetDomainName": "SOC.LAB",
      "serviceName": "svc_backup",
      "ticketEncryptionType": "0x17",
      "status": "0x0"
    },
    "system": {
      "eventID": "4769",
      "channel": "Security"
    }
  }
}
```

This is the precise detection signature documented in the lab's detection plan: Event ID 4769 (Kerberos service ticket requested) combined with `ticketEncryptionType: 0x17` (RC4-HMAC), requested by a non-machine account (`jsmith`) against a service account (`svc_backup`).

**Custom Wazuh detection rule (fired):**
```xml
<!-- Escalating Kerberoasting Events -->
<rule id="100010" level="10">
    <if_sid>60100, 60101, 60103, 60106</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.ticketEncryptionType">^0x17$|^0x18$|^23$</field>
    <description>Security Alert: Potential Kerberoasting activity detected via weak encryption ticket request (RC4-HMAC).</description>
    <group>credential_access,mitre_t1558.003</group>
</rule>

<!-- Fallback Debug Rule (verifies ANY 4769 logs are being parsed) -->
<rule id="100011" level="5">
    <if_sid>60100, 60101, 60103, 60106</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <description>Security Event: Generic Kerberos Ticket Request (Event ID 4769) parsed by SIEM.</description>
    <group>windows_security</group>
</rule>
```

Rule `100011` was kept in place as a parsing-verification fallback to confirm that 4769 events were reaching Wazuh at all, separate from the RC4-specific detection logic in rule `100010`. This was a deliberate debugging decision during rule development and is worth keeping as a sanity-check rule even post-tuning.

**Screenshot references:**
- `screenshots/getuserspns-output.png` — Impacket output identifying and requesting the SPN ticket
- `screenshots/kerberoast-hash-extracted.png` — extracted `$krb5tgs$23$...` hash confirmed via `cat`
- `screenshots/hashcat-cracked.png` — Hashcat recovering the plaintext password
- `screenshots/wazuh-4769-rc4-detection.png` — raw Wazuh log confirming detection of the RC4 ticket request

## 5. Network Evidence

A Kerberos TGS-REQ/TGS-REP exchange occurred between 192.168.10.5 (Kali-Attacker) and 192.168.10.10 (DC01.SOC.LAB) on TCP/UDP port 88. *(Reference `pcaps/kerberoasting.pcap` here with a note on the AS-REQ/TGS-REQ message types visible in Wireshark, and the absence of a prior AS-REQ for a new TGT — since `jsmith` already had a valid TGT cached — which can itself be a secondary detection point.)*

## 6. IOC Table

| Indicator | Value | Notes |
|---|---|---|
| Source host | 192.168.10.5 (Kali-Attacker) | Origin of the TGS request |
| Source user | jsmith@SOC.LAB | Authenticated low-privilege account used to request the ticket |
| Target service account | svc_backup | SPN-registered, Kerberoastable account |
| Target SPN | HTTP/backupserver.soc.lab | Registered via `setspn` in Phase 1 |
| Encryption type | 0x17 (RC4-HMAC) | Kerberoasting detection signature |
| Cracked credential | svc_backup : Back2024! | Recovered via Hashcat mode 13100 |
| Detection rule | Wazuh rule ID 100010 | Fired on RC4-encrypted 4769 event |

## 7. Root Cause

Two compounding factors enabled this attack: (1) the `svc_backup` account was registered with an SPN, making it a valid Kerberoasting target by protocol design, and (2) the account's password (`Back2024!`) was within the range crackable by a standard offline attack. Kerberoasting itself cannot be fully prevented since SPN-registered accounts must support ticket issuance — the real control point is password strength and ticket encryption type enforcement.

## 8. Impact Assessment

**Severity: High**

Successful cracking of `svc_backup`'s password grants the attacker that account's full privileges. Service accounts are frequently over-privileged (backup operators, scheduled task runners, etc.), making compromise of even a single Kerberoastable account a common initial step toward lateral movement or domain-wide impact, depending on what `svc_backup` has access to in the environment.

## 9. Recommendations

1. **Enforce AES encryption for Kerberos service tickets** domain-wide via Group Policy (`msDS-SupportedEncryptionTypes`), removing RC4 as a viable downgrade option for ticket requests.
2. **Set strong, randomly generated passwords (25+ characters) for all service accounts**, or migrate to **Group Managed Service Accounts (gMSA)**, which rotate passwords automatically and are effectively immune to offline cracking.
3. **Monitor and alert on all 4769 events with RC4 encryption type**, especially against accounts with SPNs — this is exactly what rule 100010 implements, and it should be tuned for low false-positive volume in larger environments with many legacy services.
4. **Audit which accounts hold SPNs** regularly using `setspn -Q */*`, and remove SPNs from accounts that don't strictly require them.
5. **Restrict privileges of all service accounts** to the minimum necessary (least privilege), so that even if Kerberoasted, the blast radius is limited.

## 10. Lessons Learned

This was the most valuable investigation in the lab so far because it demonstrates the full attacker-to-defender loop: understanding *why* Kerberoasting works at the protocol level (any authenticated user can request a TGS for any SPN), reproducing the attack accurately, and then writing a detection rule that targets the specific technical signature (RC4 encryption type) rather than just alerting on "Kerberos ticket requested," which would be far too noisy in a real environment. Building the fallback rule (100011) was also a useful lesson in detection engineering discipline — verifying that the underlying event is even reaching the SIEM before assuming a more specific rule's silence means "no attack," rather than "broken log pipeline."

**Note:** During testing, the SPN was briefly observed registered against an incorrect domain suffix due to a `setspn` configuration error in Phase 1. This was corrected to `HTTP/backupserver.soc.lab` prior to finalizing this report; if revisiting `setspn` commands in future lab phases, always confirm the domain suffix matches the lab's actual domain (`SOC.LAB`) before registering new SPNs.
