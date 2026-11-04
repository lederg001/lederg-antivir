# LEDERG ANTIVIR

**Windows 10/11 x64 endpoint-defense prototype** with a custom black/red window frame, system tray, one-click local checks, startup-persistence inspection, signed-application recognition and hash-verified quarantine.

[Download LEDERG ANTIVIR v0.6.0](https://github.com/lederg001/lederg-antivir/releases/tag/v0.6.0) — latest Windows x64 build.

> LEDERG ANTIVIR is an independent defensive toolset and endpoint-monitoring prototype, not a certified replacement for a full antivirus engine or Windows kernel file-system minifilter.

## User interface and lifecycle

- Custom black LEDERG title bar, animated rounded pill buttons, keyboard focus and hover feedback.
- Page views are built once and reused instead of destroying/recreating controls on every tab switch, preventing stale widget references and reducing UI churn.
- System tray menu: show window, quick scan, startup scan, toggle auto-protection and fully exit.
- Closing the window hides it in the tray; use **Полностью выйти** in the tray menu to stop monitoring and exit.
- Per-user Windows logon startup is optional. When enabled, LEDERG starts hidden in the tray after sign-in.
- Auto-protection preference is stored locally in `%LOCALAPPDATA%\\LEDERG ANTIVIR\\settings.json` and restored on the next launch.
- Enabling auto-protection also offers to register LEDERG in the current user's `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` key.
- The application no longer forces an administrator UAC prompt on every normal launch. Firewall rules still require elevated rights; without them, process stop/quarantine can be limited by Windows permissions.

## One-click local inspection

The main **ПРОВЕРИТЬ СИСТЕМУ** action independently reviews EXE/DLL/SCR/BAT/CMD/PS1/VBS/JS files in common user locations (Desktop, Downloads, Temp, AppData and Startup) and scans startup persistence entries. Selected script types are checked for correlated browser-store access, decryption, collection and outbound-transfer markers.

High-confidence script detections (score 90+) in user-writable folders may be quarantined automatically only when auto-protection is enabled. Known infostealer executable names are flagged for review; a filename alone never triggers automatic termination.

Microsoft Defender status and an optional manual full scan remain available as supplementary Windows features; they are not used as the LEDERG local scanner's detection engine.

## Startup persistence inspection

The **Автозагрузка** view reads, without modifying them:
- Current-user and machine `Run` / `RunOnce` registry keys;
- 32-bit machine `Wow6432Node` Run entries;
- Explorer policy Run keys;
- Current-user and all-users Startup folders, including shortcut target resolution where Windows exposes it.

Entries are scored using exact known IOC path/name matches, missing targets, unsigned binaries under writable user locations and suspicious script parameters such as encoded or hidden PowerShell. The exact LEDERG ANTIVIR HKCU Run entry is excluded from self-detection only when its command resolves to the currently running executable (or the expected Python launcher plus this app.py in source mode); a matching name alone is not trusted. A valid signature and expected install path can prevent false alarms for known applications.

MITRE ATT&CK documents Registry Run Keys / Startup Folder as persistence technique **T1547.001**. This scanner is a user-mode inventory and heuristic review; it does not cover every persistence mechanism such as services, drivers, WMI subscriptions, scheduled tasks, browser extensions or bootkits.

Startup inspection is read-only: unknown or suspicious entries are shown for review and are not silently deleted or disabled.

## Trusted applications and false-positive control

Opera, Discord, Chrome, Edge, Firefox, Brave, Steam, Spotify, Telegram, Slack, Zoom, Signal, OneDrive and Dropbox have publisher/path rules.

An application is treated as trusted only if Windows reports a valid Authenticode signature, the certificate subject matches the expected publisher token and the executable is in a typical installation path. A filename alone is never enough; an unsigned `Discord.exe` copied to Temp is not automatically trusted.

The common-domain catalogue is informational rather than a global allowlist. The connection monitor sees process/IP/port metadata, not reliable per-process DNS hostname attribution. Shared CDN and cloud IPs may host both benign and malicious services.

## Automatic protection and miner containment

Auto-protection defaults to **OFF**. When explicitly enabled, its preference persists and LEDERG can restore it after the next Windows sign-in when per-user autostart is active.

Known exact stealer IOC files can be stopped, blocked and SHA-256-verified into quarantine. Cryptominer detection uses a separate correlation engine:
- known miner executable names and renamed miner command-line patterns;
- Stratum protocol, algorithm/wallet/pool arguments and known public pool hints;
- sustained high per-process CPU in multiple monitor samples;
- outbound connections to common mining-pool ports.

A miner is eligible for automatic containment only at a high combined score (80/100 or more), with sustained CPU plus miner command/name evidence and a pool indicator. With auto-protection enabled, LEDERG attempts an outbound Windows Firewall rule and terminates the matching PID only after re-checking that the PID still points to the same executable. Miner binaries are not silently deleted or quarantined. A miner name alone or high CPU alone is not enough.

Firewall rule creation requires administrator rights. If the app is not elevated, the firewall step may fail; LEDERG reports the result and may still stop an eligible process if Windows permissions allow it. Normal startup is not forced to elevate. WARP, Zapret, WinDivert and protected Windows processes are not terminated or reconfigured.

## Safe incident response

LEDERG provides local containment, evidence review and process-specific outbound blocking. It does not flood attacker infrastructure, send deceptive traffic to third-party servers or tamper with systems outside the device owner's control.

## Threat-intelligence scope

The curated reference catalogue currently contains 40 family/panel entries, including Vidar, LummaC2, Rhadamanthys, StealC, RedLine, Raccoon, MetaStealer, RisePro, Meduza, SalatStealer, Amatera, Fickle, GhostSpy, XLoader/Formbook, Agent Tesla, StrelaStealer, Remus, ACR Stealer, Odyssey, ArechClient2, CallbackBeaver, Tenzor, Cuttlefish, Beavertail, DanaBot, Ailurophile, PoisonX, Katz, Sys01, Snake Keylogger, WorldWind, Atomic Stealer, Poseidon and MacSync. Sources include Microsoft, Recorded Future, Red Canary, Flare and CIS/MS-ISAC 2025–2026 reporting. The catalogue also lists common mining tools such as XMRig, CPUMiner, T-Rex, PhoenixMiner, NBMiner, lolMiner, GMiner, SRBMiner, TeamRedMiner and NanoMiner. Many mining tools are legitimate software, not malware by themselves.

The app tracks ATT&CK T1539 (Steal Web Session Cookie), T1550.004 (Web Session Cookie), T1555.003 (Credentials from Web Browsers), T1185 (Browser Session Hijacking), T1496 and T1496.001 (Resource/Compute Hijacking). Contextual family entries are not individual malware signatures. References are included for MalwareBazaar, ThreatFox and URLhaus; live IOC ingestion from these feeds is not yet implemented.

**MFA / 2FA clarification:** a stolen session cookie or access token may let an attacker reuse a session that was already authenticated, bypassing some MFA prompts. It does not reveal the one-time code or the authenticator's second-factor secret. After a suspected compromise, use a clean device to revoke active sessions/tokens, sign out all devices, change passwords and check account recovery methods.

## Network and behavior-monitoring scope

The connection metadata monitor polls established TCP connections and connected UDP sockets roughly every 3 seconds. It records process, PID, executable path where available, remote IP and port. A separate process-behavior pass runs roughly every 6 seconds; it samples CPU for processes and reads command lines only for likely candidates, reducing repeated process metadata work.

### Optional Sysmon event telemetry

When Sysmon is already installed and its Operational channel is readable, LEDERG can additionally ingest recent Event IDs 1 (process creation), 3 (network connection), 10 (process access), 11 (file creation), 13 (registry value set) and 22 (DNS query). The reader is read-only: it does not install Sysmon, alter its configuration or change Windows audit policy. It highlights suspicious access to LSASS/browser processes, autorun registry changes, suspicious command lines, and DNS/network indicators associated with mining pools. These events are review signals and do not independently trigger process termination.

Sysmon reference and setup documentation: [Microsoft Sysmon overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview).

**Traffic visibility limit:** this is not a packet sniffer or full WFP/NDIS sensor. LEDERG sees socket metadata and configured Windows event telemetry; it does not inspect encrypted HTTPS payloads, read cookies/passwords, or prove that data was exfiltrated. Full packet capture would require a separate low-level driver/sensor and can conflict with VPN, WARP, Zapret or other network filters.

Manual process blocking creates an outbound Windows Firewall rule for all outbound connections from that executable path, not just one remote IP/port.

## Developer and community

- Telegram: [@LEDERG_ru](https://t.me/LEDERG_ru)
- Discord community: [LEDERG](https://discord.gg/kDRMWqKmZp)

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
pyinstaller --noconfirm --clean --onefile --windowed --paths src --collect-all pystray --collect-all PIL --name LEDERG-ANTIVIR app.py
```

GitHub Actions runs tests and packages the Windows x64 EXE on every push to `main`.

## v0.6.0 changes

- Full interface refresh with animated rounded pill buttons and persistent page views; tab switches no longer destroy and recreate every control.
- Search field for the threat catalogue.
- Optional read-only Sysmon ingestion for process creation, network connections, process access, startup-file creation, registry autoruns and DNS queries.
- Reduced monitoring overhead: network polling is separated from process behavior sampling, and command lines are read only for candidate processes.
- Expanded the curated threat catalogue to 40 family/panel entries, including 2025–2026 reporting on Cuttlefish, Beavertail, DanaBot, Ailurophile, PoisonX, Katz, Sys01 and WorldWind.
- High-confidence (90+) suspicious scripts in user-writable folders can be quarantined when auto-protection is explicitly enabled; known stealer filenames are flagged for review.
- Safe defensive response only: no traffic flooding, false-data exfiltration, or interference with third-party infrastructure.

The catalogue is curated threat context, not a claim to include every malware variant. New private, renamed and rapidly changing samples cannot all be enumerated by name; reliable coverage comes from behavior, verified hashes and maintained feeds. Live feed ingestion is still not implemented.

## v0.5.0 changes

- Correlated cryptominer detection using process identity, pool/Stratum command-line markers, sustained CPU samples and common pool ports.
- Optional high-confidence miner containment when auto-protection is enabled: outbound Firewall rule plus PID/path-verified process termination; miner files are not silently deleted.
- Static script checks for combined browser-profile access, decryption, data collection and outbound-transfer indicators.
- Expanded 2026 infostealer/session-theft and mining-tool reference catalogue.
- Exact LEDERG ANTIVIR autostart identity is marked trusted, preventing the application from flagging its own Run entry.
- Developer contact and community links in the app sidebar.

Validation: 44 tests passed and the Windows x64 PyInstaller build completed successfully on GitHub Actions before the final VBS/JS scan-scope addition. The release workflow re-runs tests and rebuilds the final executable.

## Selected references

- [MITRE ATT&CK — Registry Run Keys / Startup Folder (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — Windows startup persistence detection strategy](https://attack.mitre.org/detectionstrategies/DET0365/)
- [MITRE ATT&CK — Steal Web Session Cookie (T1539)](https://attack.mitre.org/techniques/T1539/)
- [MITRE ATT&CK — Web Session Cookie (T1550.004)](https://attack.mitre.org/techniques/T1550/004/)
- [MITRE ATT&CK — Session Cookie Detection (DET0074)](https://attack.mitre.org/detectionstrategies/DET0074/)
- [MITRE ATT&CK — Resource Hijacking (DET0267)](https://attack.mitre.org/detectionstrategies/DET0267/)
- [MITRE ATT&CK — Compute Hijacking (DET0540)](https://attack.mitre.org/detectionstrategies/DET0540/)
- [CIS / MS-ISAC — Remus session-theft activity, 2026](https://www.cisecurity.org/insights/blog/sltt-c2-traffic-tied-to-remus-malware-distribution-operation)
- [Barracuda — Session cookies and identity theft, 2026](https://blog.barracuda.com/2026/10/14/malware-brief-infostealers-stolen-identities)
- [Microsoft — Run and RunOnce Registry Keys](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Microsoft — Configure startup applications in Windows](https://support.microsoft.com/en-us/windows/experience/startup-boot/configure-startup-applications-in-windows)
- [pystray — system tray usage](https://pystray.readthedocs.io/en/latest/usage.html)
- [Microsoft — dark window title bar guidance](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/ui/apply-windows-themes)

Keep Microsoft Defender real-time protection enabled as an additional layer. Review detections before manually blocking applications or restoring files from quarantine.
