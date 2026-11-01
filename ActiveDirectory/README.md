# Active Directory Attack Investigations

This directory contains five controlled investigations performed in the isolated `SOC.LAB` VirtualBox environment. The sequence demonstrates how an attacker can move from domain discovery to credential access and lateral movement, and how defenders can use Windows telemetry and SIEM detections to investigate the activity.

## Lab environment

| Component | Details |
|---|---|
| Domain | `SOC.LAB` |
| Domain controller | `DC01.SOC.LAB` - Windows Server 2022 - `192.168.10.10` |
| Windows 10 workstation | `192.168.10.20` |
| Windows 11 workstation | `192.168.10.21` |
| Attacker VM | Kali Linux - `192.168.10.5` |
| Primary monitoring | Wazuh; Splunk evidence is included in selected investigations |

All names, addresses, accounts, and credentials in these reports are synthetic lab data. Secrets and reusable credential material are intentionally redacted from the public documentation.

## Investigation index

| ID | Investigation | ATT&CK mapping | Primary analyst focus |
|---|---|---|---|
| AD-01 | [Active Directory enumeration](./Incident-AD-01-Enumeration/) | T1069.002, T1087.002 | LDAP discovery, BloodHound collection, attack-path review |
| AD-02 | [RDP brute-force activity](./Incident-AD-02-RDPBruteForce/) | T1110.001, T1021.001 | Windows failed-logon telemetry and threshold-based detection |
| AD-03 | [Kerberoasting](./Incident-AD-03-Kerberoasting/) | T1558.003 | Kerberos service-ticket requests and suspicious encryption types |
| AD-04 | [AS-REP Roasting](./Incident-AD-04-ASREPRoasting/) | T1558.004 | Kerberos pre-authentication configuration and Event ID 4768 |
| AD-05 | [Pass-the-Hash](./Incident-AD-05-PassTheHash/) | T1550.002; related credential access T1003.001 | NTLM authentication and lateral-movement investigation |

## Investigation workflow

The reports document the relevant attack simulation, observed telemetry, detection logic, evidence, and defensive recommendations where available. They are practical lab exercises, not claims of production incident response experience.

## Important distinctions

- Kerberoasting and AS-REP Roasting are credential-access techniques; AS-REP Roasting is not itself a persistence technique.
- A suspicious Kerberos encryption type or event is an investigative indicator, not proof of malicious activity in isolation.
- Event IDs and detection results must be interpreted in context and correlated with host, account, source, and baseline behaviour.
