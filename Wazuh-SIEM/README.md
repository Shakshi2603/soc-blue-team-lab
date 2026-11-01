# Wazuh detection content

This folder contains the custom Wazuh local-rule configuration currently tracked in the repository.

## Files

- [`local_rules.xml`](../rules/wazuh/local_rules.xml) — custom rules for selected SSH authentication, web enumeration, file-integrity, active-response, and Kerberos events.

## Rule groups currently represented

| Rule ID | Intended detection | Telemetry / parent rule |
|---|---|---|
| 100001 | SSH authentication brute-force escalation | Parent rule 2502 |
| 100002 | Web directory-enumeration user-agent indicators | Parent rules 31122 / 31108 |
| 100003 | Modification involving `/etc/passwd` | Syscheck-related parent rules |
| 100004–100005 | Active-response execution / reversal events | Parent rules 601 / 602 |
| 100010 | Potential Kerberoasting indicator | Windows Event ID 4769 with selected encryption-type values |
| 100011 | Generic Kerberos service-ticket event parsing check | Windows Event ID 4769 |

## Validation notes

These are lab rules, not production-ready detections. Before deployment, validate parent rule IDs, field names, decoder output, and event schemas against the installed Wazuh version and actual incoming events. A single indicator (for example, an RC4-encrypted service ticket) should be treated as a triage signal and correlated with account, host, source, volume, and baseline context.

## Testing and evidence

For each rule, document:

1. Required log source and agent configuration.
2. A controlled test event or simulation.
3. The matching raw event and decoded fields.
4. The resulting Wazuh alert and rule ID.
5. Expected benign matches and known blind spots.

The tracked XML is the source of truth; this README describes its current contents and does not imply that every rule has been validated in a production environment.
