from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass

from .defender import get_defender_status


@dataclass
class ProtectionCheck:
    name: str
    state: str
    detail: str
    recommendation: str = ""


def parse_firewall_profiles(payload: str) -> tuple[bool | None, int]:
    """Return (all_enabled, profile_count) for Get-NetFirewallProfile JSON."""
    data = json.loads(payload)
    if isinstance(data, dict):
        profiles = [data]
    elif isinstance(data, list):
        profiles = data
    else:
        raise ValueError("Unexpected firewall profile payload")
    if not profiles:
        return None, 0
    enabled = [bool(item.get("Enabled", False)) for item in profiles]
    return all(enabled), len(enabled)


def _registry_dword(key_path: str, value_name: str) -> int | None:
    if os.name != "nt":
        return None
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _kind = winreg.QueryValueEx(key, value_name)
            return int(value)
    except (OSError, ImportError, ValueError, TypeError):
        return None


def get_security_posture() -> list[ProtectionCheck]:
    """Read-only snapshot of Windows protections. No settings are changed."""
    if os.name != "nt":
        return [
            ProtectionCheck("Windows Security", "UNAVAILABLE", "Проверка доступна только в Windows"),
        ]

    checks: list[ProtectionCheck] = []
    try:
        defender = get_defender_status()
        active = defender.antivirus_enabled and defender.realtime_enabled
        checks.append(ProtectionCheck(
            "Microsoft Defender", "ON" if active else "ATTENTION",
            f"Антивирус: {'ON' if defender.antivirus_enabled else 'OFF'} · Защита в реальном времени: {'ON' if defender.realtime_enabled else 'OFF'}",
            "Включи защиту в приложении Безопасность Windows" if not active else "",
        ))
    except Exception as exc:
        checks.append(ProtectionCheck("Microsoft Defender", "UNKNOWN", f"Статус недоступен: {exc}"))

    lsa = _registry_dword(r"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL")
    checks.append(ProtectionCheck(
        "LSA protection", "ON" if lsa in (1, 2) else "REVIEW",
        "Защита LSA включена" if lsa in (1, 2) else "Нет подтверждения включённой защиты LSA",
        "Проверь совместимость и включение LSA protection в Windows Security / политике устройства" if lsa not in (1, 2) else "",
    ))

    credential_guard = _registry_dword(
        r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\CredentialGuard", "Enabled"
    )
    checks.append(ProtectionCheck(
        "Credential Guard", "ON" if credential_guard == 1 else "REVIEW",
        "Credential Guard включён" if credential_guard == 1 else "Не подтверждено включение Credential Guard",
        "Доступность зависит от редакции Windows, оборудования и VBS" if credential_guard != 1 else "",
    ))

    firewall_script = (
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", firewall_script],
            capture_output=True, text=True, timeout=12, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if result.returncode == 0:
            enabled, count = parse_firewall_profiles(result.stdout.strip())
            checks.append(ProtectionCheck(
                "Windows Firewall", "ON" if enabled else "ATTENTION",
                f"Активно профилей: {count}; все включены: {'да' if enabled else 'нет'}",
                "Проверь профили Windows Firewall" if not enabled else "",
            ))
        else:
            checks.append(ProtectionCheck("Windows Firewall", "UNKNOWN", "Статус профилей недоступен"))
    except Exception:
        checks.append(ProtectionCheck("Windows Firewall", "UNKNOWN", "Статус профилей недоступен"))

    try:
        result = subprocess.run(
            ["wevtutil.exe", "gl", "Microsoft-Windows-Sysmon/Operational"],
            capture_output=True, text=True, timeout=8, check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        installed = result.returncode == 0
        checks.append(ProtectionCheck(
            "Sysmon telemetry", "ON" if installed else "OPTIONAL",
            "Журнал Sysmon доступен" if installed else "Sysmon не обнаружен — это дополнительный датчик, не обязательная зависимость",
            "Для расширенного аудита установи Sysmon из официального пакета Microsoft Sysinternals" if not installed else "",
        ))
    except Exception:
        checks.append(ProtectionCheck("Sysmon telemetry", "UNKNOWN", "Не удалось проверить журнал Sysmon"))

    return checks
