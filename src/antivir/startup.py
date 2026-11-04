from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .core import is_exact_ioc_file
from .network import get_authenticode_publisher, is_trusted_application

APP_RUN_VALUE = "LEDERG ANTIVIR"
RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
STARTUP_EXTENSIONS = {".exe", ".com", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".lnk"}
WRITABLE_MARKERS = (
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\appdata\\local\\",
    "\\temp\\",
    "\\downloads\\",
    "\\public\\",
)
SUSPICIOUS_ARGUMENTS = (
    "-encodedcommand",
    "-enc ",
    "-windowstyle hidden",
    "-w hidden",
    "frombase64string",
    "downloadstring(",
    "invoke-expression",
    " iex",
)


@dataclass
class StartupEntry:
    name: str
    source: str
    command: str
    target: str
    score: int
    severity: str
    reasons: list[str] = field(default_factory=list)
    signature_valid: bool = False
    publisher: str | None = None
    target_exists: bool = False
    auto_quarantine_eligible: bool = False


def _expand_windows_environment(value: str) -> str:
    expanded = os.path.expandvars(value)
    return re.sub(
        r"%([^%]+)%",
        lambda match: os.environ.get(match.group(1), match.group(0)),
        expanded,
    )


def extract_executable_path(command: str) -> str:
    """Extract the first executable/script target without executing the command."""
    value = _expand_windows_environment(command.strip())
    if not value:
        return ""

    quoted = re.match(r'^\s*"([^"]+)"', value)
    if quoted:
        return quoted.group(1).strip()

    unquoted = re.match(
        r"^\s*(.+?\.(?:exe|com|bat|cmd|ps1|vbs|js|scr|lnk))(?=\s|$)",
        value,
        flags=re.IGNORECASE,
    )
    if unquoted:
        return unquoted.group(1).strip()

    # Keep the first token only as a conservative fallback; never shell-parse or execute it.
    token = value.split(maxsplit=1)[0]
    return token.strip('"').strip()


def assess_startup_entry(
    name: str,
    source: str,
    command: str,
    target: str,
    *,
    target_exists: bool,
    signature_valid: bool,
    publisher: str | None = None,
) -> StartupEntry:
    normalized_target = (target or "").lower().replace("/", "\\")
    normalized_command = (command or "").lower()
    filename = normalized_target.rsplit("\\", 1)[-1]
    reasons: list[str] = []
    score = 0

    if target and is_exact_ioc_file(target):
        reasons.append("Точное совпадение известного IOC: имя файла и подозрительный каталог")
        score = 100

    suspicious_argument = next(
        (marker for marker in SUSPICIOUS_ARGUMENTS if marker in normalized_command),
        None,
    )
    if suspicious_argument:
        display_marker = "-EncodedCommand" if suspicious_argument == "-encodedcommand" else suspicious_argument.strip()
        reasons.append(f"Команда автозагрузки содержит подозрительный параметр: {display_marker}")
        score = max(score, 75)

    if target and not target_exists:
        reasons.append("Файл, указанный в автозагрузке, не найден")
        score = max(score, 20)

    writable_location = any(marker in normalized_target for marker in WRITABLE_MARKERS)
    known_signed_app = is_trusted_application(
        filename,
        target,
        publisher,
        signature_valid,
    )
    if known_signed_app:
        return StartupEntry(
            name, source, command, target, 0, "trusted",
            ["Подпись издателя действительна и путь соответствует известному приложению"],
            True, publisher, target_exists, False,
        )

    if writable_location and not signature_valid and target_exists:
        reasons.append("Неподписанный исполняемый файл запускается из пользовательской записываемой области")
        score = max(score, 40)
    elif signature_valid and publisher and not score:
        reasons.append("Цифровая подпись действительна; неизвестный издатель не считается IOC")

    if not reasons:
        reasons.append("Явных подозрительных признаков не обнаружено")

    severity = (
        "critical" if score >= 90
        else "high" if score >= 70
        else "medium" if score >= 35
        else "review" if score >= 20
        else "info"
    )
    return StartupEntry(
        name=name,
        source=source,
        command=command,
        target=target,
        score=min(score, 100),
        severity=severity,
        reasons=reasons,
        signature_valid=signature_valid,
        publisher=publisher,
        target_exists=target_exists,
        auto_quarantine_eligible=bool(target and is_exact_ioc_file(target)),
    )


def build_autostart_command(
    *,
    frozen: bool,
    executable: str,
    script: str | None = None,
) -> str:
    """Build a quoted HKCU Run command that starts minimized to the tray."""
    executable_path = str(Path(executable))
    if frozen:
        command = f'"{executable_path}"'
    else:
        if not script:
            raise ValueError("A script path is required for source-mode autostart")
        command = f'"{executable_path}" "{Path(script)}"'
    return f"{command} --background"


def set_run_at_logon(enabled: bool, command: str | None = None) -> None:
    """Write only this application's HKCU Run value; never edits machine-wide keys."""
    if os.name != "nt":
        raise OSError("Windows logon startup is available only on Windows")
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as key:
        if enabled:
            if not command:
                raise ValueError("An autostart command is required")
            if len(command) > 260:
                raise ValueError("The Windows Run command exceeds the 260-character registry limit")
            winreg.SetValueEx(key, APP_RUN_VALUE, 0, winreg.REG_SZ, command)
        else:
            try:
                winreg.DeleteValue(key, APP_RUN_VALUE)
            except FileNotFoundError:
                pass


def is_run_at_logon_enabled() -> bool:
    if os.name != "nt":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY, 0, winreg.KEY_READ) as key:
            winreg.QueryValueEx(key, APP_RUN_VALUE)
            return True
    except OSError:
        return False


def _resolve_shortcut(path: Path) -> str:
    if os.name != "nt":
        return ""
    environment = os.environ.copy()
    environment["LEDERG_SHORTCUT_PATH"] = str(path)
    script = (
        "$shell = New-Object -ComObject WScript.Shell; "
        "$shortcut = $shell.CreateShortcut($env:LEDERG_SHORTCUT_PATH); "
        "[Console]::Write($shortcut.TargetPath)"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
            env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return result.stdout.strip() if result.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        return ""


def _inspect_target(name: str, source: str, command: str, target: str) -> StartupEntry:
    path = Path(target) if target else Path()
    exists = bool(target and path.is_file())
    signature_valid = False
    publisher = None
    if exists and path.suffix.lower() == ".exe":
        signature_valid, publisher = get_authenticode_publisher(path)
    return assess_startup_entry(
        name, source, command, target,
        target_exists=exists,
        signature_valid=signature_valid,
        publisher=publisher,
    )


def scan_startup_entries() -> list[StartupEntry]:
    """Read current-user/machine Run keys and Startup folders; make no changes."""
    if os.name != "nt":
        return []

    import winreg

    entries: list[StartupEntry] = []
    registry_locations = [
        (winreg.HKEY_CURRENT_USER, RUN_KEY, "HKCU Run"),
        (winreg.HKEY_CURRENT_USER, RUN_KEY.replace("\\Run", "\\RunOnce"), "HKCU RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE, RUN_KEY, "HKLM Run"),
        (winreg.HKEY_LOCAL_MACHINE, RUN_KEY.replace("\\Run", "\\RunOnce"), "HKLM RunOnce"),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
            "HKLM Wow6432Node Run",
        ),
        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKCU Policies Run",
        ),
        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKLM Policies Run",
        ),
    ]

    for root, key_path, source in registry_locations:
        try:
            with winreg.OpenKey(root, key_path, 0, winreg.KEY_READ) as key:
                index = 0
                while True:
                    try:
                        value_name, command, _value_type = winreg.EnumValue(key, index)
                    except OSError:
                        break
                    index += 1
                    if not isinstance(command, str) or not command.strip():
                        continue
                    target = extract_executable_path(command)
                    entries.append(_inspect_target(value_name, source, command, target))
        except OSError:
            continue

    startup_folders = [
        (os.environ.get("APPDATA", ""), "Current-user Startup"),
        (os.environ.get("PROGRAMDATA", ""), "All-users Startup"),
    ]
    for base, source in startup_folders:
        if not base:
            continue
        folder = Path(base) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
        if not folder.is_dir():
            continue
        try:
            items = list(folder.iterdir())
        except OSError:
            continue
        for item in items:
            if item.suffix.lower() not in STARTUP_EXTENSIONS:
                continue
            target = _resolve_shortcut(item) if item.suffix.lower() == ".lnk" else str(item)
            if target:
                entries.append(_inspect_target(item.name, source, str(item), target))
            else:
                entries.append(StartupEntry(
                    item.name, source, str(item), "", 10, "info",
                    ["Ярлык найден; Windows не смог раскрыть его целевой путь"],
                    False, None, True, False,
                ))

    return sorted(entries, key=lambda entry: (entry.score, entry.name.lower()), reverse=True)
