# Incident AD-02: RDP Brute Force Attack Against Domain Controller

**Investigation ID:** AD-02 \
**Date:** July 2026 \
**Analyst:** Shakshi \
**Lab Environment:** SOC.LAB (SOC Home Lab - VirtualBox) \
**MITRE ATT&CK Techniques:** T1110.001 (Brute Force: Password Guessing), T1021.001 (Remote Services: Remote Desktop Protocol), TA0006 (Credential Access), TA0008 (Lateral Movement)

---

## 1. Executive Summary

A simulated attacker launched a dictionary-based brute force attack against the Domain Administrator account over RDP (TCP port 3389) on DC01.SOC.LAB (192.168.10.10) using Hydra with the `rockyou.txt` wordlist. The attack generated 14.3 million login attempts in rapid succession, producing a high-volume spike of Event ID 4625 (Failed Logon, Logon Type 10) on the domain controller within a 60-second window.

An RDP brute force is a threshold-based attack that generates hundreds of SIEM alerts in seconds. This investigation demonstrates the opposite detection philosophy: instead of hunting for a single anomalous event, the defender identifies an unmistakable volume spike and correlates it with a single source IP. The attack was detected via a custom Wazuh rule (ID 100031) triggering on 10+ failed Logon Type 10 events within 60 seconds, and confirmed in Splunk via a failure count aggregation query.

## 2. Timeline of Events

| Time | Event |
|---|---|
| T+0:00 | Attacker launches Hydra: `hydra -l Administrator -P rockyou.txt rdp://192.168.10.10` |
| T+0:00 | Rapid-fire RDP authentication attempts begin against DC01.SOC.LAB port 3389 |
| T+0:00–T+1:00 | 14,344,399 password attempts queued; Hydra runs 4 parallel children |
| T+0:05 | Wazuh rule 100031 fires: 10+ Event ID 4625 Logon Type 10 events within 60 seconds |
| T+0:05 | Splunk failure count aggregation shows spike from 192.168.10.5 against Administrator |
| T+1:00 | Attacker terminates Hydra after 60-second logging generation window |

## 3. Attack Methodology

**Tool:** Hydra (multi-threaded network login brute forcer)

**Attack command:**
```bash
hydra -l Administrator -P /usr/share/wordlists/rockyou.txt rdp://192.168.10.10
```

Hydra opens multiple parallel TCP connections to RDP port 3389, submitting password guesses from `rockyou.txt` sequentially. Each failed attempt generates a Windows Security Event ID 4625 on DC01 with `logonType = 10` (RemoteInteractive), the logon type specific to RDP/Terminal Services sessions.

**What makes this detectable:** Unlike low-and-slow password spraying (which spaces attempts across time and accounts to stay under lockout thresholds), a dictionary brute force against a single account generates a concentrated burst of 4625 events from one source IP in seconds. There is no evasion - the attack prioritizes speed over stealth, betting that the target account's password will be found before defenses respond.

**Why the attack targets the Administrator account:** The built-in `Administrator` account cannot be locked out by the default account lockout policy in Windows (it requires explicit policy enforcement). An attacker targeting a lockable account would trigger account lockout after 5-10 failures, stopping the attack entirely. Targeting `Administrator` removes this protection.

**MITRE ATT&CK mapping:**
- **T1110.001 - Brute Force: Password Guessing** (repeated authentication attempts)
- **T1021.001 - Remote Services: Remote Desktop Protocol** (attack vector)
- **TA0006 - Credential Access** (tactic: attempting to obtain credentials)
- **TA0008 - Lateral Movement** (tactic: RDP as a lateral movement protocol if successful)

## 4. Log Evidence

**Event ID 4625 - Failed Logon, Logon Type 10 (RDP):**

Each Hydra attempt generates a 4625 event on DC01 with these fields:
```
EventID: 4625
LogonType: 10 (RemoteInteractive)
TargetUserName: Administrator
IpAddress: 192.168.10.5
Status: 0xC000006D (wrong password)
```

`Logon Type 10` is the precise Windows identifier for Remote Desktop / Terminal Services authentication, distinguishing this from other network logon types.

**Custom Wazuh detection rule (fired):**
```xml
<!-- DETECTION: RDP Brute Force Pattern -->
<rule id="100031" level="10">
    <if_sid>60100, 60101, 60103</if_sid>
    <field name="win.system.eventID">^4625$</field>
    <field name="win.eventdata.logonType">^10$</field>
    <frequency>10</frequency>
    <timeframe>60</timeframe>
    <description>Security Alert: Active RDP Brute Force attack detected — 10+ failed Remote Desktop logon attempts within 60 seconds.</description>
    <group>brute_force,mitre_t1110.001</group>
</rule>
```

The `<frequency>10</frequency>` + `<timeframe>60</timeframe>` combination creates a sliding-window threshold: Wazuh fires the alert only after 10 matching events occur within any 60-second window, preventing single-failed-logon noise from triggering the rule while catching a genuine brute force in near-real-time.

**Splunk SPL search for RDP brute force:**
```spl
index=main sourcetype=_json "data.win.system.eventID"=4625
    "data.win.eventdata.logonType"=10
| stats count as Failure_Count
    by data.win.system.computer data.win.eventdata.targetUserName data.win.eventdata.ipAddress
| rename data.win.system.computer as Target_Host
         data.win.eventdata.targetUserName as Attacker_Account
         data.win.eventdata.ipAddress as Source_IP
| sort - Failure_Count
```

Expected result: `Administrator` from `192.168.10.5` with `Failure_Count` in the thousands, clearly distinguishable from any legitimate failed logon (which would generate 1-5 events at most).

**Screenshot references:**

### Attack
- `attack/hydra-rdp-bruteforce.png` - Hydra terminal showing rapid password attempts against rdp://192.168.10.10 from rockyou.txt (14.3M wordlist)

### Detection
- `detection/splunk-4625-rdp-failures.png` - Splunk SPL aggregation showing Failure_Count spike for Administrator from 192.168.10.5

## 5. Network Evidence

High volume TCP connection attempts to DC01.SOC.LAB (192.168.10.10) on port 3389 from 192.168.10.5 (Kali-Attacker).

## 6. IOC Table

| Indicator | Value | Notes |
|---|---|---|
| Attacker host | 192.168.10.5 (Kali-Attacker) | Source of all RDP attempts |
| Target host | 192.168.10.10 (DC01.SOC.LAB) | Domain controller - main RDP target |
| Target account | Administrator | Built-in account; not subject to default lockout policy |
| Attack protocol | RDP (TCP 3389) | Remote Desktop Protocol |
| Tool | Hydra | Multi-threaded brute force; 4 parallel children |
| Wordlist | rockyou.txt | 14,344,399 passwords |
| Detection event | Event ID 4625, Logon Type 10 | RDP-specific failure indicator |
| Detection threshold | 10 failures / 60 seconds | Wazuh rule 100031 |

## 7. Root Cause

RDP was exposed on port 3389 of the domain controller with no network-layer access restriction (firewall rule, VPN requirement, or IP allowlist). The built-in Administrator account was not renamed or disabled, making it a predictable target. No account lockout policy was enforced for the Administrator account, allowing unlimited sequential attempts. Any one of these three controls would have either blocked or significantly degraded the attack.

## 8. Impact Assessment

**Severity: Critical (if successful) / High (as detected)**

A successful RDP brute force against the domain controller's Administrator account would grant full GUI access to the DC with the highest-privilege account in the domain immediate full domain compromise with no further escalation required. The attack as executed did not succeed in recovering the password within the 60-second window, but the Failure_Count in the thousands demonstrates how quickly a weak password could be found. In a production environment, exposing RDP directly on a domain controller to any network segment is itself a critical finding independent of whether a brute force has been attempted.

## 9. Recommendations

1. **Block RDP (TCP 3389) at the network perimeter** and restrict it to a dedicated management VLAN or VPN-only access. Domain controllers should never have RDP reachable from workstation subnets.
2. **Disable or rename the built-in Administrator account** and use a named admin account with a non-guessable username, removing the attacker's certainty about the target username.
3. **Enforce account lockout on all accounts**, including privileged ones - configure a Fine-Grained Password Policy (PSO) to apply lockout to the Administrator account specifically.
4. **Enable Network Level Authentication (NLA)** for RDP, which requires valid credentials before the RDP session is even established, reducing the attack surface and making brute forcing less efficient.
5. **Deploy IP-based rate limiting or auto-blocking** (e.g., Wazuh active response with `firewall-drop`) to automatically block source IPs generating high failure volumes - this transforms Wazuh from a passive detector to an active countermeasure.
6. **Monitor and alert on any RDP logon attempt to domain controllers** from non-admin workstations - legitimate admins should never need to RDP to a DC from a standard workstation.

## 10. Lessons Learned

This investigation is intentionally contrasted with AS-REP Roasting (AD-03) to illustrate the signal-to-noise tradeoff in attack detection. AS-REP Roasting generates a single, quiet, successful event that is easy to miss without a targeted detection rule. An RDP brute force generates thousands of noisy events in seconds and is detectable but only if the SIEM is collecting Logon Type 10 failures and has a threshold alert configured. A SIEM that collects events but has no tuned rules is as blind as one with no collection at all.

The threshold-based detection (10 failures in 60 seconds) also introduces a design decision: too low a threshold creates alert fatigue from legitimate failed logins; too high a threshold and a slow, distributed brute force slips through. In a real environment, this rule would be tuned with a baseline of normal failed logon rates per host, and a separate low-frequency spray detection rule would complement it.
