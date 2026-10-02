# GrabThePhisher — Threat Intel Investigation

**Category:** Threat Intel | **Difficulty:** Easy | **Platform:** CyberDefenders
**ATT&CK:** T1566.003 (Phishing via Service), T1056.003 (Input Capture: Web Portal), T1567 (Exfiltration Over Web Service), T1016 (System Network Configuration Discovery)

## Scenario
An attacker compromised a server and used it to host a cloned login page impersonating MetaMask/PancakeSwap, a decentralized exchange on BNB Chain, in order to harvest victims' crypto wallet seed phrases. As the analyst, the task is to recover the phishing kit, determine how it captures and exfiltrates victim data, and extract any available threat intelligence on the operator.

## Methodology
- Extracted the provided archive (`95-GrabThePhisher.zip`) and reviewed the folder structure
- Located the `metamask/` folder and identified `index.html` as the cloned phishing landing page and `metamask.php` as the backend handler
- Read through `metamask.php` to trace where submitted form data goes
- Investigated the external API calls in the code (`api.sypexgeo.net`, `api.telegram.org`) to determine their purpose
- Reviewed `log/log.txt` for evidence of harvested data
- Checked the PHP file for attacker-identifying artifacts (comments, hardcoded tokens)

## Findings

### Kit structure
The archive extracts into several directories: `src`, `log`, `metamask`, `images`, `.github`, `_next`, and `cgi-bin`, plus site logo images. The `.github` folder contains `.yml`/`.md` CI-config and code-of-conduct files,suggesting the base template was cloned or forked from a legitimate open-source project rather than built from scratch. The actual phishing logic lives in `metamask/`:
- `index.html` - cloned PancakeSwap/MetaMask landing page
- `metamask.php` - backend handler that captures and exfiltrates submitted data
- `log/log.txt` - local copy of every harvested submission

### Lure
- **Brand impersonated:** PancakeSwap / MetaMask (wallet seed-phrase prompt)
- **Attacker hosting domain:** Not recoverable from the kit archive alone — no domain or server IP is hardcoded in the reviewed files
- **Delivery mechanism:** Cloned login page hosted on a compromised server

### Credential harvesting & exfiltration
`metamask.php` captures the submitted wallet seed phrase (`$_POST['data']`) along with the victim's IP, geolocated country/city, and browser user-agent, then pushes it through **two parallel channels**:
1. **Local log file** - appended to `log/log.txt` via `file_put_contents()`
2. **Real-time alert** - sent via `sendTel()`, which calls the Telegram Bot
API's `sendMessage` endpoint (`api.telegram.org/bot<token>/sendMessage`) with the data URL-encoded into the message body

The kit also queries `api.sypexgeo.net`, a third-party IP-geolocation service, using the victim's `REMOTE_ADDR` to enrich each captured submission with country and city before sending it to the attacker.

### Threat actor intel
- **Telegram Bot Token:** `5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10`
- **Telegram Chat ID:** `5442785564`
- **Signed alias:** a comment block in `metamask.php` reads "With love and respect to all the hustlers out there... Regards, **j1j1b1s@m3r0**" - a self-attribution left by the kit's author/distributor
- No hosting domain or server IP was identified in the reviewed files

### IOC Table
| Type | Value | Notes |
|---|---|---|
| Telegram Bot Token | `5457463144:AAG8t4k7e2ew3tTi0IBShcWbSia0Irvxm10` | Used by `sendTel()` for real-time exfil |
| Telegram Chat ID | `5442785564` | Destination for harvested credentials |
| Exfil Endpoint | `api.telegram.org/bot<token>/sendMessage` | Legitimate service abused for exfiltration |
| Third-party API | `api.sypexgeo.net` | Used to geolocate victims by IP |
| Threat Actor Alias | `j1j1b1s@m3r0` | Self-attributed in PHP source comment |
| Impersonated Brand | PancakeSwap / MetaMask (pancakeswap.finance) | Legitimate brand being spoofed — **not** attacker infrastructure |

## MITRE ATT&CK Mapping
| Tactic | Technique | Evidence |
|---|---|---|
| Initial Access | T1566.003 - Phishing via Service | Cloned PancakeSwap/MetaMask login page served to lure victims into submitting wallet seed phrases |
| Credential Access | T1056.003 - Input Capture: Web Portal Capture | `metamask.php` captures the `data` field from the submitted form (`$_POST['data']`) |
| Exfiltration | T1567 - Exfiltration Over Web Service | Harvested data sent via the Telegram Bot API (`sendMessage`), abusing a legitimate web service to evade network-based detection |
| Discovery | T1016 - System Network Configuration Discovery | Kit queries `api.sypexgeo.net` with the victim's IP to resolve country/city before exfiltration |

## Verdict & Escalation Ticket
- **Severity:** High
- **Summary:** Confirmed cryptocurrency wallet phishing kit actively harvesting seed phrases and exfiltrating them in real time via a Telegram bot, with a redundant local log as backup.
- **Evidence:** Hardcoded Telegram bot token/chat ID and `sendTel()` function in `metamask.php`; harvested seed-phrase entries recovered from `log.txt`
- **Verdict:** True Positive
- **Action Taken:** Documented and extracted IOCs (bot token, chat ID, geolocation service used) for reporting
- **Recommendation:** Report the Telegram bot token/chat ID to Telegram's abuse team for takedown; since no attacker-controlled domain was recovered, monitor for reuse of this bot token or the "j1j1b1s@m3r0" alias across other phishing kit samples; issue a user awareness notice on verifying wallet-connect URLs before entering seed phrases.

## Lessons Learned
This lab required investigating from the **attacker's infrastructure side** (the kit itself) rather than the victim's inbox. The most useful takeaway was that exfiltration didn't rely on attacker-owned infrastructure at all — using
the Telegram Bot API let the attacker receive stolen data in real time while
blending into legitimate HTTPS traffic to a trusted domain (`api.telegram.org`),
which is harder to flag than a lookalike C2 domain would be.
