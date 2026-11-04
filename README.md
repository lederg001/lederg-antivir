# LEDERG ANTIVIR

Windows x64 desktop utility for suspicious-file triage and hash-verified quarantine.

> This is an early defensive tool, not a replacement for Microsoft Defender. It uses transparent heuristics and known indicators; a low score is not proof of safety.

## Features
- Scan selected files or folders (EXE/DLL/SCR/BAT/CMD/PS1)
- SHA-256 hashes and transparent risk reasons
- User-confirmed quarantine with hash verification
- Protected system/program paths are refused
- No automatic deletion, no network, no persistence, no credential collection

## Run from source
```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```

## Build
GitHub Actions builds a Windows x64 single-file executable on tag `v*` and attaches it to a Release.

## Safety
Review scan results before quarantining. Restore only items you trust. Keep Defender enabled.
