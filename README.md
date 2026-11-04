# LEDERG ANTIVIR

**Windows 10/11 x64 endpoint-defense prototype** with a custom black/red window frame, system tray, one-click local checks, startup-persistence inspection, signed-application recognition and hash-verified quarantine.

[Download LEDERG ANTIVIR v0.4.0](https://github.com/lederg001/lederg-antivir/releases/tag/v0.4.0) — latest Windows x64 build.

> LEDERG ANTIVIR is an independent defensive toolset and endpoint-monitoring prototype, not a certified replacement for a full antivirus engine or Windows kernel file-system minifilter.

## User interface and lifecycle

- Custom black LEDERG title bar with minimize-to-tray, maximize/restore and hide controls.
- System tray menu: show window, quick scan, startup scan, toggle auto-protection and fully exit.
- Closing the window hides it in the tray; use **Полностью выйти** in the tray menu to stop monitoring and exit.
- Per-user Windows logon startup is optional. When enabled, LEDERG starts hidden in the tray after sign-in.
- Auto-protection preference is stored locally in `%LOCALAPPDATA%\\LEDERG ANTIVIR\\settings.json` and restored on the next launch.
- Enabling auto-protection also offers to register LEDERG in the current user's `HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` key.
- The application no longer forces an administrator UAC prompt on every normal launch. Firewall rules still require elevated rights; without them, process stop/quarantine can be limited by Windows permissions.

## One-click local inspection

The main **ПРОВЕРИТЬ СИСТЕМУ** action independently reviews EXE/DLL/SCR/BAT/CMD/PS1 files in common user locations (Desktop, Downloads, Temp, AppData and Startup) and scans startup persistence entries. It no longer depends on starting a Microsoft Defender scan to perform its own local analysis.

Microsoft Defender status and an optional manual full scan remain available as supplementary Windows features; they are not used as the LEDERG local scanner's detection engine.

## Startup persistence inspection

The **Автозагрузка** view reads, without modifying them:
- Current-user and machine `Run` / `RunOnce` registry keys;
- 32-bit machine `Wow6432Node` Run entries;
- Explorer policy Run keys;
- Current-user and all-users Startup folders, including shortcut target resolution where Windows exposes it.

Entries are scored using exact known IOC path/name matches, missing targets, unsigned binaries under writable user locations and suspicious script parameters such as encoded or hidden PowerShell. A valid signature and expected install path can prevent false alarms for known applications.

MITRE ATT&CK documents Registry Run Keys / Startup Folder as persistence technique **T1547.001**. This scanner is a user-mode inventory and heuristic review; it does not cover every persistence mechanism such as services, drivers, WMI subscriptions, scheduled tasks, browser extensions or bootkits.

Startup inspection is read-only: unknown or suspicious entries are shown for review and are not silently deleted or disabled.

## Trusted applications and false-positive control

Opera, Discord, Chrome, Edge, Firefox, Brave, Steam, Spotify, Telegram, Slack, Zoom, Signal, OneDrive and Dropbox have publisher/path rules.

An application is treated as trusted only if Windows reports a valid Authenticode signature, the certificate subject matches the expected publisher token and the executable is in a typical installation path. A filename alone is never enough; an unsigned `Discord.exe` copied to Temp is not automatically trusted.

The common-domain catalogue is informational rather than a global allowlist. The connection monitor sees process/IP/port metadata, not reliable per-process DNS hostname attribution. Shared CDN and cloud IPs may host both benign and malicious services.

## Automatic protection

Auto-protection defaults to **OFF**. When explicitly enabled, its preference persists and LEDERG can restore it after the next Windows sign-in when per-user autostart is active.

Automatic file quarantine is limited to exact previously tracked filename + suspicious path IOC combinations. For eligible network events, LEDERG attempts an outbound Windows Firewall rule, process termination and SHA-256-verified quarantine. Unknown unsigned programs or ordinary AppData processes are not automatically killed based on one weak signal.

Firewall rule creation requires administrator rights. Normal startup is not forced to elevate; when running without elevation, Windows may reject the firewall action, and LEDERG reports that result. WARP, Zapret, WinDivert and their protected process names are not blocked or reconfigured.

## Safe incident response

LEDERG provides local containment, evidence review and process-specific outbound blocking. It does not flood attacker infrastructure, send deceptive traffic to third-party servers or tamper with systems outside the device owner's control.

## Threat-intelligence scope

The reference catalogue tracks public reporting on Vidar, LummaC2, Rhadamanthys, StealC, RedLine, Raccoon Stealer, MetaStealer, RisePro, Meduza, XLoader/Formbook, Agent Tesla, StrelaStealer and other families. It includes MITRE ATT&CK techniques for browser credential stores, session-cookie theft, LSASS access, startup persistence, PowerShell, web-protocol C2 and cloud-storage exfiltration.

This catalogue is contextual intelligence, not a signature for each family. References are included for MalwareBazaar, ThreatFox and URLhaus; live IOC ingestion from these feeds is not yet implemented.

## Network monitoring scope

The monitor polls established TCP connections and connected UDP sockets (roughly every 2.5 seconds) and records process, PID, executable path where available, remote IP and port. It does not sniff packet contents, decrypt HTTPS, inspect passwords/cookies/tokens or prove that data was exfiltrated. Short-lived connections can be missed.

Manual process blocking creates an outbound Windows Firewall rule for all outbound connections from that executable path, not just one remote IP/port.

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

## Selected references

- [MITRE ATT&CK — Registry Run Keys / Startup Folder (T1547.001)](https://attack.mitre.org/techniques/T1547/001/)
- [MITRE ATT&CK — Windows startup persistence detection strategy](https://attack.mitre.org/detectionstrategies/DET0365/)
- [Microsoft — Run and RunOnce Registry Keys](https://learn.microsoft.com/windows/win32/setupapi/run-and-runonce-registry-keys)
- [Microsoft — Configure startup applications in Windows](https://support.microsoft.com/en-us/windows/experience/startup-boot/configure-startup-applications-in-windows)
- [pystray — system tray usage](https://pystray.readthedocs.io/en/latest/usage.html)
- [Microsoft — dark window title bar guidance](https://learn.microsoft.com/en-us/windows/apps/desktop/modernize/ui/apply-windows-themes)

Keep Microsoft Defender real-time protection enabled as an additional layer. Review detections before manually blocking applications or restoring files from quarantine.
