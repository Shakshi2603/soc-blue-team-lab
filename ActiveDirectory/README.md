# Active Directory — Kill Chain Attack Investigations

## The Story

These five investigations document a complete attacker kill chain against the `SOC.LAB` Active Directory environment — from the first moment the attacker touches the network to full lateral movement and `SYSTEM`-level access on a domain workstation.

The sequence follows attacker logic, not lab build order:

1. **Enumerate first** — map the domain with a low-privilege account to find targets and escalation paths
2. **Get credentials** — brute-force RDP to compromise the `jsmith` account (initial access)
3. **Abuse Kerberos** — use `jsmith` to Kerberoast a service account and crack its password offline
4. **Establish persistence** — exploit a pre-authentication misconfiguration on `jsmith` for a protocol-level backdoor that survives password resets
5. **Move laterally** — dump `jsmith`'s NTLM hash with Mimikatz and pass it to gain `SYSTEM` on a domain workstation

Each investigation includes the attack reproduction, SIEM detection (Wazuh + Splunk), custom detection rules, and NIST IR-format analysis.

---

## Domain Configuration

| Setting | Value |
|---|---|
| Domain Name | SOC.LAB |
| Domain Controller | DC01.SOC.LAB (192.168.10.10) |
| OS | Windows Server 2022 |
| Workstations | WindowsClient11 (Win11, 192.168.10.21) |

## Organisational Units

| OU | Purpose |
|---|---|
| SOC-Users | Standard domain user accounts |
| SOC-Admins | Privileged administrative accounts |
| SOC-Servers | Server computer objects |
| SOC-Workstations | Workstation computer objects |

## User Accounts Created

| Username | Role | Notes |
|---|---|---|
| jsmith | Standard domain user | Initial access target; compromised via RDP brute force |
| svc_backup | Service account | SPN registered — Kerberoastable |

## SPNs Registered

| Account | SPN |
|---|---|
| svc_backup | HTTP/backupserver.soc.lab |

## Audit Policy & Logging

- GPO audit policy enabled for: Logon Events, Account Management, DS Access, Privilege Use, and Object Access
- Sysmon deployed on DC01, WindowsClient11
- Wazuh agents enrolled on all Windows machines
- Windows Security Event Log forwarded to Wazuh SIEM

---

## Kill Chain Investigations

| Step | ID | Investigation | MITRE Technique | Status |
|---|---|---|---|---|
| 1 — Reconnaissance | AD-01 | [BloodHound & LDAP Enumeration](./Incident-AD-01-Enumeration/) | T1069.002, T1087.002 | ✅ Complete |
| 2 — Initial Access | AD-02 | [RDP Brute Force Against Domain Controller](./Incident-AD-02-RDPBruteForce/) | T1110.001, T1021.001 | ✅ Complete |
| 3 — Credential Access | AD-03 | [Kerberoasting Service Account](./Incident-AD-03-Kerberoasting/) | T1558.003 | ✅ Complete |
| 4 — Persistence | AD-04 | [AS-REP Roasting — Protocol-Level Backdoor](./Incident-AD-04-ASREPRoasting/) | T1558.004 | ✅ Complete |
| 5 — Lateral Movement | AD-05 | [Pass-the-Hash via Mimikatz + smbexec](./Incident-AD-05-PassTheHash/) | T1550.002 | ✅ Complete |
