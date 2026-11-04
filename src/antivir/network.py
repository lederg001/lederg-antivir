from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import os
import socket
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

import psutil

KNOWN_BAD_NAMES = {"svchost32.exe", "cloudsynchost.exe", "csyncwatch.exe"}
KNOWN_BAD_PATHS = ("\\windowshelper\\", "\\cloudsyncdata\\", "\\cloudsyncwatcher\\")
WRITABLE_MARKERS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\public\\")


@dataclass
class ConnectionAssessment:
    score: int
    severity: str
    reasons: list[str]
    auto_block_eligible: bool


@dataclass
class NetworkEvent:
    timestamp: str
    pid: int
    process_name: str
    process_path: str
    remote_address: str
    remote_port: int
    protocol: str
    status: str
    score: int
    severity: str
    reasons: list[str]
    auto_block_eligible: bool
    action: str = "Наблюдение"


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%")[0])
        return address.is_global
    except ValueError:
        return False


def assess_connection(
    process_name: str,
    process_path: str | None,
    remote_address: str,
    remote_port: int,
    status: str,
) -> ConnectionAssessment:
    normalized = (process_path or "").lower().replace("/", "\\")
    filename = Path(process_name or (process_path or "unknown")).name.lower()
    reasons: list[str] = []
    score = 0
    known_name = filename in KNOWN_BAD_NAMES
    known_path = any(marker in normalized for marker in KNOWN_BAD_PATHS)
    writable_execution = any(marker in normalized for marker in WRITABLE_MARKERS)

    if known_path:
        score += 45
        reasons.append("Известная подозрительная директория")
    if known_name:
        score += 45
        reasons.append("Имя совпадает с индикатором из предыдущего анализа")
    if writable_execution and filename.endswith((".exe", ".dll", ".scr")):
        score += 25
        reasons.append("Исполняемый файл запущен из пользовательской записываемой области")
    if status.upper() == "ESTABLISHED" and _is_public_ip(remote_address) and (known_name or known_path or writable_execution):
        score += 15
        reasons.append("Подозрительный процесс имеет активное внешнее соединение")

    score = min(score, 100)
    severity = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 35 else "info"
    # Auto-containment is deliberately restricted to exact, previously observed IOCs.
    eligible = bool(known_name and known_path and status.upper() == "ESTABLISHED" and _is_public_ip(remote_address))
    return ConnectionAssessment(score, severity, reasons, eligible)


def _windows_root() -> Path:
    return Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()


def _firewall_rule_name(executable: Path) -> str:
    rule_id = hashlib.sha256(str(executable.resolve()).casefold().encode("utf-8")).hexdigest()[:12]
    return f"LEDERG ANTIVIR Outbound {rule_id}"


def build_firewall_block_args(executable: Path) -> list[str]:
    executable = Path(executable).expanduser().resolve(strict=True)
    if not executable.is_file() or executable.suffix.lower() != ".exe":
        raise ValueError("Firewall containment requires an existing .exe file")
    try:
        executable.relative_to(_windows_root())
        raise ValueError("Blocking Windows system binaries is prohibited")
    except ValueError as exc:
        if str(exc) == "Blocking Windows system binaries is prohibited":
            raise
    name = _firewall_rule_name(executable)
    return [
        "advfirewall", "firewall", "add", "rule",
        f'name="{name}"', "dir=out", "action=block", f'program="{executable}"',
        "enable=yes", "profile=any",
    ]


def build_firewall_unblock_args(executable: Path) -> list[str]:
    # Do not require the executable to still exist; the firewall rule may outlive quarantine/removal.
    executable = Path(executable).expanduser().resolve()
    name = _firewall_rule_name(executable)
    return ["advfirewall", "firewall", "delete", "rule", f'name="{name}"']


def is_admin() -> bool:
    if os.name != "nt":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def block_process_outbound(executable: Path) -> str:
    if os.name != "nt":
        raise OSError("Windows Firewall containment is available only on Windows")
    if not is_admin():
        raise PermissionError("Run LEDERG ANTIVIR as Administrator to create a firewall rule")
    command = ["netsh.exe", *build_firewall_block_args(executable)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "netsh failed").strip())
    return "Исходящие соединения процесса заблокированы правилом Windows Firewall"


def unblock_process_outbound(executable: Path) -> str:
    if os.name != "nt":
        raise OSError("Windows Firewall containment is available only on Windows")
    if not is_admin():
        raise PermissionError("Run LEDERG ANTIVIR as Administrator to remove a firewall rule")
    command = ["netsh.exe", *build_firewall_unblock_args(executable)]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False,
                            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    if result.returncode != 0:
        raise OSError((result.stderr or result.stdout or "netsh failed").strip())
    return "Правило блокировки удалено"


class NetworkMonitor:
    """Polls connection metadata; it does not sniff, decrypt, or store packet contents."""

    def __init__(self, callback: Callable[[NetworkEvent], None], interval: float = 2.5):
        self.callback = callback
        self.interval = max(1.0, interval)
        self.auto_block = False
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[tuple, float] = {}
        self.last_error: str | None = None

    @property
    def running(self) -> bool:
        return bool(self._thread and self._thread.is_alive())

    def start(self) -> None:
        if self.running:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="LEDERG-NetworkMonitor", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3)

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
                self.last_error = None
            except Exception as exc:
                self.last_error = str(exc)
            self._stop.wait(self.interval)

    def poll_once(self) -> list[NetworkEvent]:
        now = time.monotonic()
        current: list[NetworkEvent] = []
        connections = psutil.net_connections(kind="inet")
        self._seen = {key: timestamp for key, timestamp in self._seen.items() if now - timestamp < 90}
        for conn in connections:
            is_udp = conn.type == socket.SOCK_DGRAM
            if not conn.pid or not conn.raddr:
                continue
            # UDP sockets generally have no TCP-like ESTABLISHED state; connected UDP
            # endpoints are included when the OS reports a remote address.
            if not is_udp and conn.status != psutil.CONN_ESTABLISHED:
                continue
            remote_ip = getattr(conn.raddr, "ip", None) or conn.raddr[0]
            remote_port = getattr(conn.raddr, "port", None) or conn.raddr[1]
            if not _is_public_ip(str(remote_ip)):
                continue
            try:
                process = psutil.Process(conn.pid)
                process_name = process.name()
                try:
                    process_path = process.exe()
                except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                    process_path = ""
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                continue

            key = (conn.pid, str(remote_ip), int(remote_port), str(conn.type))
            if key in self._seen:
                continue
            self._seen[key] = now
            assessment = assess_connection(process_name, process_path, str(remote_ip), int(remote_port), conn.status)
            protocol = "UDP" if is_udp else "TCP"
            event = NetworkEvent(
                datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S"),
                conn.pid, process_name, process_path, str(remote_ip), int(remote_port),
                protocol, conn.status, assessment.score, assessment.severity,
                assessment.reasons, assessment.auto_block_eligible,
            )
            if self.auto_block and event.auto_block_eligible:
                try:
                    event.action = block_process_outbound(Path(process_path))
                except Exception as exc:
                    event.action = f"Автоблокировка не выполнена: {exc}"
            current.append(event)
            self.callback(event)
        return current
