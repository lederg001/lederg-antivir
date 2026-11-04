# LEDERG ANTIVIR

**Windows 10/11 x64 endpoint-defense prototype** with a dark LEDERG interface, one-click checks, signed-application recognition, process-linked network telemetry and hash-verified quarantine.

> LEDERG ANTIVIR is a defensive companion to Microsoft Defender, not a certified antivirus or a replacement for endpoint protection. Heuristic detections are not proof of malware.

## What users see

- **Overview:** a large “ПРОВЕРИТЬ СИСТЕМУ” action, clear scan progress, result counts and direct actions.
- **Network & processes:** new external connections with process, PID, IP, port, risk and containment state.
- **Quarantine:** isolated objects, SHA-256 integrity verification and controlled restore.
- **Protection Center:** read-only status of Microsoft Defender, Windows Firewall, LSA protection, Credential Guard and optional Sysmon telemetry.
- **Threat database:** tracked infostealer families, MITRE ATT&CK techniques, protection guidance and community-feed references.
- **Trusted applications:** publisher + expected install path rules and a reference catalogue of common services/domains.
- The avatar/shield mark is drawn by the application; no remote avatar image or account data is required.

## One-click system check

The main check starts a Microsoft Defender Quick Scan where available and locally reviews executable/script files in common user locations: Desktop, Downloads, Temp, AppData and Startup folders.

Local heuristics calculate SHA-256 and show the exact reasons. A file is not deleted automatically because it happens to be in AppData or Temp. The default state of automatic protection is **OFF**.

## Trusted applications and false-positive control

Opera, Discord, Chrome, Edge, Firefox, Brave, Steam, Spotify, Telegram, Slack, Zoom, Signal, OneDrive and Dropbox have publisher/path rules.

An application is treated as trusted only if:
1. Windows reports a valid Authenticode signature;
2. the certificate subject matches the expected publisher token;
3. the executable is in a typical install path for that application.

A filename alone is never enough. An unsigned `Discord.exe` copied to Temp is not automatically trusted. Signatures are read using PowerShell `Get-AuthenticodeSignature` and cached briefly by file path and modification time.

The common-domain catalogue (for example `opera.com`, `discord.com`, `discord.gg`, `google.com`, `microsoft.com`, `telegram.org`, and Steam/Spotify domains) is informational. It is **not** a global domain allowlist: the current monitor sees process/IP/port connection metadata, not reliable per-process DNS hostname attribution. Shared CDN, hosting and cloud IPs can serve both benign and malicious tenants.

## Auto-protection against exact known IOCs

Auto-protection can be enabled manually from the overview and requires Windows administrator rights. For a network event, automatic containment is restricted to all of these conditions:
- exact executable name from the narrow IOC list;
- known suspicious directory marker from the narrow IOC list;
- established connection to a public IP.

For eligible network events, LEDERG attempts to add an outbound Windows Firewall rule, stop the associated process and move the executable to the SHA-256-verified quarantine. For local scans, only the exact filename + path combination is auto-quarantined.

Automatic containment is deliberately narrow. A suspicious unknown program is reported for user review; it is not automatically killed or quarantined just because it is unsigned or stored in AppData. WARP, Zapret, WinDivert and their protected process names are not blocked or reconfigured.

## Threat intelligence coverage

The reference catalogue currently tracks Windows and cross-platform families/variants including Vidar, LummaC2, Rhadamanthys, StealC, RedLine, Raccoon Stealer, MetaStealer, RisePro, Meduza, XLoader/Formbook, Agent Tesla, StrelaStealer and other names from public reporting.

It also documents relevant ATT&CK behavior: browser credential stores, session-cookie theft, LSASS access, startup persistence, PowerShell, web-protocol C2 and cloud-storage exfiltration.

**Important:** this catalogue is contextual threat intelligence, not a signature for every listed family. Names in the catalogue do not mean LEDERG can detect every sample of that malware.

### Community feeds

References are included for MalwareBazaar (malware sample hashes and metadata), ThreatFox (malware-related IOCs) and URLhaus (malware distribution URLs and host indicators).

The abuse.ch community API requires an API key. This repository version lists the feeds and documents them, but it does **not yet download, update or apply live IOCs from those services**. No claim of a live continuously updated threat database is made.

## Windows protection status

The Protection Center only reads security posture. It does not change Windows security policy: Defender antivirus and real-time protection state, firewall profile status, LSA protection / Credential Guard registry indicators and optional Sysmon event-log availability.

Microsoft Defender remains enabled and is used for on-demand scans. ASR, LSA protection, Credential Guard and Sysmon should be configured according to device compatibility and administrator policy; LEDERG does not enable these controls automatically.

## Network monitoring scope

The monitor polls established TCP connections and connected UDP sockets (roughly every 2.5 seconds) and records process, PID, executable path where available, remote IP and port. It does **not** sniff packet contents, decrypt HTTPS, inspect passwords/cookies/tokens or prove that data was exfiltrated. Short-lived connections can be missed and process paths may be unavailable if Windows denies access.

Manual process blocking creates a Windows Firewall rule for all outbound connections from that executable path — not just one remote IP/port. Review the target carefully before blocking.

## Run from source

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

## Tests and Windows x64 build

```powershell
python -m pytest -q
pyinstaller --noconfirm --clean --onefile --windowed --uac-admin --paths src --name LEDERG-ANTIVIR app.py
```

Every push to `main` runs tests and builds a Windows x64 GitHub Actions artifact.

## Selected public references

- [MITRE ATT&CK — Vidar](https://attack.mitre.org/software/S9050/)
- [MITRE ATT&CK — XLoader / Formbook](https://attack.mitre.org/software/S1207/)
- [MITRE ATT&CK — Agent Tesla](https://attack.mitre.org/software/S0331/)
- [MITRE ATT&CK — StrelaStealer](https://attack.mitre.org/software/S1183/)
- [MITRE ATT&CK — Credentials from Web Browsers](https://attack.mitre.org/techniques/T1555/003/)
- [MITRE ATT&CK — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/)
- [Microsoft — ASR rules reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft — Sysmon configuration and event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files)
- [abuse.ch / Spamhaus threat-intelligence API documentation](https://abusech-docs.spamhaus.com/api-reference)

Keep Microsoft Defender real-time protection enabled. Review detections before manually blocking applications or restoring files from quarantine.
