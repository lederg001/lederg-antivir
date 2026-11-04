from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class DefenderStatus:
    antivirus_enabled: bool
    realtime_enabled: bool
    running_mode: str
    signature_updated: str = "Unknown"


def parse_defender_status(payload: str) -> DefenderStatus:
    data = json.loads(payload)
    return DefenderStatus(
        antivirus_enabled=bool(data.get("AntivirusEnabled", False)),
        realtime_enabled=bool(data.get("RealTimeProtectionEnabled", False)),
        running_mode=str(data.get("AMRunningMode", "Unknown")),
        signature_updated=str(data.get("AntivirusSignatureLastUpdated", "Unknown")),
    )


def build_scan_command(scan_type: str) -> list[str]:
    allowed = {"QuickScan", "FullScan", "CustomScan"}
    if scan_type not in allowed:
        raise ValueError(f"Unsupported Microsoft Defender scan type: {scan_type}")
    command = f"Start-MpScan -ScanType {scan_type}"
    if scan_type == "CustomScan":
        command += " -ScanPath $env:LEDERG_SCAN_PATH"
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command]


def get_defender_status() -> DefenderStatus:
    if os.name != "nt":
        raise OSError("Microsoft Defender integration is available only on Windows")
    script = (
        "Get-MpComputerStatus | Select-Object AntivirusEnabled, "
        "RealTimeProtectionEnabled, AMRunningMode, AntivirusSignatureLastUpdated | "
        "ConvertTo-Json -Compress"
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True, text=True, timeout=15, check=False,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "Defender status query failed").strip())
    try:
        return parse_defender_status(result.stdout.strip())
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("Could not parse Microsoft Defender status output") from exc


def start_defender_scan(scan_type: str, scan_path: Path | None = None) -> int:
    if os.name != "nt":
        raise OSError("Microsoft Defender scans are available only on Windows")
    if scan_type == "CustomScan":
        if scan_path is None:
            raise ValueError("A file or folder path is required for a custom scan")
        path = Path(scan_path).expanduser().resolve(strict=True)
        if not path.exists():
            raise FileNotFoundError(path)
    elif scan_path is not None:
        raise ValueError("Scan path is only valid for CustomScan")
    else:
        path = None

    environment = os.environ.copy()
    if path is not None:
        environment["LEDERG_SCAN_PATH"] = str(path)
    process = subprocess.Popen(
        build_scan_command(scan_type),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    return int(process.pid)
