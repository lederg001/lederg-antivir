# LEDERG ANTIVIR

**Windows 10/11 x64 endpoint-defense prototype** focused on suspicious files, stealer-like behavior, process-linked network telemetry and hash-verified quarantine.

> This is a defensive prototype, not a replacement for Microsoft Defender or a certified antivirus. Heuristics can produce false positives and cannot prove a file is safe.

## Current capabilities

- Dark LEDERG desktop UI with network, quarantine and threat-coverage views.
- Live polling of established external TCP/UDP connections, attributed to process name, PID and executable path when Windows grants access.
- Transparent risk scoring for previously observed suspicious paths/names and executables connecting from user-writable locations.
- Optional automatic containment, disabled by default, restricted to exact prior IOCs + an established public-IP connection.
- Manual process-specific outbound block/unblock using Windows Firewall; never disables WARP, Zapret, WinDivert or Windows Firewall services.
- File/folder scans for EXE/DLL/SCR/BAT/CMD/PS1, SHA-256 and visible reasons.
- Quarantine moves files to a non-executable extension, records original path and SHA-256, verifies integrity and supports restore.
- Tracked families from public reporting: Vidar, LummaC2, Rhadamanthys, StealC, RedLine, Raccoon Stealer, MetaStealer, Acreed, Warden Stealer and Remus.

## Network monitoring scope

The monitor inspects **connection metadata**, not packet payloads. It does not decrypt HTTPS, read passwords/cookies/tokens, or capture message contents. It reports newly observed established external connections approximately every 2.5 seconds. This is not proof that data was exfiltrated; encrypted traffic can be legitimate, and malware can use trusted processes or another host process.

The executable requests Windows administrator elevation so the OS exposes broader process/network telemetry and Firewall containment can work. Auto-containment remains OFF until explicitly enabled in the UI. It only blocks the exact executable path when both its old IOC name and suspicious directory match and it has an established public-IP connection. Other findings are alerts for review.

## Run from source

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

## Tests and build

```powershell
python -m pytest -q
pyinstaller --noconfirm --clean --onefile --windowed --uac-admin --paths src --name LEDERG-ANTIVIR app.py
```

GitHub Actions tests every push to `main` and builds a Windows x64 artifact. Push a tag such as `v0.1.0` to publish `LEDERG-ANTIVIR.exe` to GitHub Releases.

## Threat intelligence references

- [MITRE ATT&CK — Vidar](https://attack.mitre.org/software/S9050/)
- [Microsoft Security Blog — 2026 stealer campaigns](https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-ai-hype-in-social-engineering/)
- [Recorded Future — 2025 Year in Review](https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf)
- [Outpost24 — Breached Password Report 2026](https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf)

Keep Microsoft Defender real-time protection enabled. Review every detection before quarantine or firewall blocking.
