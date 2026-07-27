# Active Directory — Phase 3 Setup & Attack Investigations

## Domain Configuration

| Setting | Value |
|---|---|
| Domain Name | SOC.LAB |
| Domain Controller | DC01.SOC.LAB (192.168.10.10) |
| OS | Windows Server 2022 |
| Workstations | WS01 (Win10, .20), WS02 (Win11, .21) |

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
| jsmith | Standard domain user | Used as attacker's compromised account |
| svc_backup | Service account | SPN registered — Kerberoastable |

## SPNs Registered

| Account | SPN |
|---|---|
| svc_backup | HTTP/backupserver.soc.lab |

## Audit Policy & Logging

- GPO audit policy enabled for: Logon Events, Account Management,
  DS Access, Privilege Use, and Object Access
- Sysmon deployed on DC01, WS01, WS02
- Wazuh agents enrolled on all Windows machines
- Windows Security Event Log forwarded to Wazuh SIEM

## Investigations

| ID | Name | MITRE | Status |
|---|---|---|---|
| AD-01 | BloodHound & LDAP Enumeration | T1069.002, T1087.002 | ✅ Complete |
| AD-02 | Kerberoasting | T1558.003 | ✅ Complete |
| AD-03 | AS-REP Roasting | T1558.004 | ⏳ Upcoming |
| AD-04 | Pass-the-Hash | T1550.002 | ⏳ Upcoming |
