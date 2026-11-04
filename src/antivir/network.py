from __future__ import annotations

import ctypes
import hashlib
import ipaddress
import os
import socket
import subprocess
import threading
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path, PureWindowsPath
from typing import Callable

import psutil

from .core import is_exact_ioc_file, quarantine_file
from .behavior import assess_process_behavior

KNOWN_BAD_NAMES = {"svchost32.exe", "cloudsynchost.exe", "csyncwatch.exe"}
KNOWN_BAD_PATHS = ("\\windowshelper\\", "\\cloudsyncdata\\", "\\cloudsyncwatcher\\")
WRITABLE_MARKERS = ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\public\\")
PROTECTED_PROCESS_NAMES = {"winws.exe", "zapret.exe", "cloudflarewarp.exe", "warp-svc.exe", "warp-cli.exe"}

# Trust is granted only when the executable is in its normal installation tree
# AND Windows reports a valid Authenticode signature from the expected publisher.
TRUSTED_APP_RULES = {
    "opera.exe": {
        "paths": ("\\appdata\\local\\programs\\opera\\", "\\program files\\opera\\"),
        "publishers": ("opera software", "opera norway"),
    },
    "discord.exe": {
        "paths": ("\\appdata\\local\\discord\\app-", "\\program files\\discord\\"),
        "publishers": ("discord inc",),
    },
    "chrome.exe": {
        "paths": ("\\appdata\\local\\google\\chrome\\application\\", "\\program files\\google\\chrome\\application\\"),
        "publishers": ("google llc",),
    },
    "msedge.exe": {
        "paths": ("\\program files (x86)\\microsoft\\edge\\application\\", "\\program files\\microsoft\\edge\\application\\"),
        "publishers": ("microsoft corporation",),
    },
    "firefox.exe": {
        "paths": ("\\program files\\mozilla firefox\\", "\\appdata\\local\\mozilla firefox\\"),
        "publishers": ("mozilla corporation",),
    },
    "brave.exe": {
        "paths": ("\\appdata\\local\\bravesoftware\\brave-browser\\application\\", "\\program files\\bravesoftware\\brave-browser\\application\\"),
        "publishers": ("brave software",),
    },
    "steam.exe": {
        "paths": ("\\program files (x86)\\steam\\", "\\program files\\steam\\"),
        "publishers": ("valve corp",),
    },
    "spotify.exe": {
        "paths": ("\\appdata\\roaming\\spotify\\", "\\program files\\spotify\\"),
        "publishers": ("spotify ab",),
    },
    "telegram.exe": {
        "paths": ("\\appdata\\roaming\\telegram desktop\\", "\\program files\\telegram desktop\\"),
        "publishers": ("telegram",),
    },
    "slack.exe": {
        "paths": ("\\appdata\\local\\slack\\app-", "\\program files\\slack\\"),
        "publishers": ("slack technologies", "salesforce"),
    },
    "zoom.exe": {
        "paths": ("\\appdata\\roaming\\zoom\\bin\\", "\\program files\\zoom\\bin\\"),
        "publishers": ("zoom video communications",),
    },
    "signal.exe": {
        "paths": ("\\appdata\\local\\programs\\signal-desktop\\", "\\program files\\signal\\"),
        "publishers": ("signal messenger",),
    },
    "onedrive.exe": {
        "paths": ("\\appdata\\local\\microsoft\\onedrive\\", "\\program files\\microsoft onedrive\\"),
        "publishers": ("microsoft corporation",),
    },
    "dropbox.exe": {
        "paths": ("\\program files\\dropbox\\client\\", "\\appdata\\local\\dropbox\\client\\"),
        "publishers": ("dropbox, inc", "dropbox inc"),
    },
}

_signature_cache: dict[str, tuple[float, int, bool, str | None]] = {}
_signature_cache_lock = threading.Lock()


@dataclass
class ConnectionAssessment:
    score: int
    severity: str
    reasons: list[str]
    auto_block_eligible: bool
    trusted_application: bool = False


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
    trusted_application: bool = False


def _is_public_ip(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value.split("%")[0])
        return address.is_global
    except ValueError:
        return False


def _filename(value: str) -> str:
    return PureWindowsPath(value or "").name.lower()


def is_trusted_application(
    process_name: str,
    process_path: str | None,
    publisher: str | None,
    signature_valid: bool,
) -> bool:
    filename = _filename(process_name or process_path or "")
    rule = TRUSTED_APP_RULES.get(filename)
    if not rule or not signature_valid or not publisher or not process_path:
        return False
    normalized_path = process_path.lower().replace("/", "\\")
    normalized_publisher = publisher.casefold()
    return (
        any(token in normalized_path for token in rule["paths"])
        and any(token in normalized_publisher for token in rule["publishers"])
    )


def get_authenticode_publisher(executable: str | Path) -> tuple[bool, str | None]:
    """Read the signer of a Windows executable and cache the result by path+mtime."""
    path = Path(executable)
    if os.name != "nt" or not path.is_file():
        return False, None
    try:
        modified_ns = path.stat().st_mtime_ns
    except OSError:
        return False, None
    key = str(path.resolve()).casefold()
    now = time.monotonic()
    with _signature_cache_lock:
        cached = _signature_cache.get(key)
        if cached and cached[0] > now and cached[1] == modified_ns:
            return cached[2], cached[3]

    environment = os.environ.copy()
    environment["LEDERG_SIGNED_FILE"] = str(path.resolve())
    script = (
        "$signature = Get-AuthenticodeSignature -LiteralPath $env:LEDERG_SIGNED_FILE; "
        "if ($signature.Status -eq 'Valid' -and $null -ne $signature.SignerCertificate) "
        "{ $signature.SignerCertificate.Subject }"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=8, check=False, env=environment,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        publisher = result.stdout.strip() if result.returncode == 0 else ""
        valid = bool(publisher)
        value = (valid, publisher or None)
    except (OSError, subprocess.SubprocessError):
        value = (False, None)

    with _signature_cache_lock:
        _signature_cache[key] = (now + (600 if value[0] else 90), modified_ns, value[0], value[1])
    return value


def assess_connection(
    process_name: str,
    process_path: str | None,
    remote_address: str,
    remote_port: int,
    status: str,
    publisher: str | None = None,
    signature_valid: bool = False,
) -> ConnectionAssessment:
    normalized = (process_path or "").lower().replace("/", "\\")
    filename = _filename(process_name or process_path or "unknown")
    if is_trusted_application(process_name, process_path, publisher, signature_valid):
        return ConnectionAssessment(
            0, "trusted", ["Доверенное приложение: действительная подпись и ожидаемый путь установки"],
            False, True,
        )

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
    eligible = bool(
        known_name and known_path and status.upper() == "ESTABLISHED"
        and _is_public_ip(remote_address)
    )
    return ConnectionAssessment(score, severity, reasons, eligible, False)


def _windows_root() -> Path:
    return Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve()


def _firewall_rule_name(executable: Path) -> str:
    rule_id = hashlib.sha256(str(executable.resolve()).casefold().encode("utf-8")).hexdigest()[:12]
    return f"LEDERG ANTIVIR Outbound {rule_id}"


def build_firewall_block_args(executable: Path) -> list[str]:
    executable = Path(executable).expanduser().resolve(strict=True)
    if not executable.is_file() or executable.suffix.lower() != ".exe":
        raise ValueError("Firewall containment requires an existing .exe file")
    if executable.name.casefold() in PROTECTED_PROCESS_NAMES:
        raise ValueError("Blocking WARP/Zapret network components is prohibited")
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
    executable = Path(executable).expanduser().resolve()
    if executable.name.casefold() in PROTECTED_PROCESS_NAMES:
        raise ValueError("Changing rules for WARP/Zapret network components is prohibited")
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
    """Poll connection metadata; no packet payload inspection or HTTPS decryption."""

    def __init__(
        self,
        callback: Callable[[NetworkEvent], None],
        interval: float = 2.5,
        quarantine_dir: Path | None = None,
    ):
        self.callback = callback
        self.interval = max(1.0, interval)
        self.auto_block = False
        self.auto_quarantine = False
        self.quarantine_dir = Path(quarantine_dir) if quarantine_dir else None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen: dict[tuple, float] = {}
        self._auto_contained: set[str] = set()
        self._cpu_samples: dict[int, deque[float]] = {}
        self._behavior_seen: dict[tuple[int, str], tuple[float, int]] = {}
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

    def _trusted_signature(self, process_name: str, process_path: str) -> tuple[bool, str | None]:
        if process_name.casefold() not in TRUSTED_APP_RULES or not process_path:
            return False, None
        return get_authenticode_publisher(process_path)

    def _auto_contain(self, event: NetworkEvent) -> str:
        path = Path(event.process_path)
        path_key = str(path).casefold()
        if path_key in self._auto_contained:
            return "Объект уже обработан автозащитой"
        if not is_exact_ioc_file(path):
            return "Автоизоляция запрещена: нет точного совпадения IOC"
        actions: list[str] = []
        try:
            actions.append(block_process_outbound(path))
        except Exception as exc:
            actions.append(f"Блокировка сети не выполнена: {exc}")
        try:
            process = psutil.Process(event.pid)
            process.terminate()
            process.wait(timeout=3)
            actions.append("Вредоносный процесс остановлен")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            actions.append("Процесс уже завершился")
        except Exception as exc:
            actions.append(f"Остановка процесса не выполнена: {exc}")
        if self.quarantine_dir is not None:
            try:
                item = quarantine_file(path, self.quarantine_dir)
                actions.append(f"Файл помещён в карантин · SHA256 {item.sha256[:16]}…")
            except Exception as exc:
                actions.append(f"Карантин не выполнен: {exc}")
        self._auto_contained.add(path_key)
        return " · ".join(actions)

    def _auto_contain_behavior(self, pid: int, process_path: str) -> str:
        """Contain only a high-confidence miner: outbound block + terminate, never auto-delete."""
        if not process_path:
            return "Автоблокировка пропущена: путь процесса недоступен"
        executable = Path(process_path)
        if executable.suffix.lower() != ".exe" or executable.name.casefold() in PROTECTED_PROCESS_NAMES:
            return "Автоблокировка пропущена: защищённый или неподдерживаемый процесс"
        try:
            resolved = executable.resolve(strict=True)
            resolved.relative_to(_windows_root())
            return "Автоблокировка пропущена: системный каталог Windows"
        except ValueError:
            pass
        except OSError as exc:
            return f"Автоблокировка пропущена: файл недоступен ({exc})"

        actions: list[str] = []
        try:
            actions.append(block_process_outbound(resolved))
        except Exception as exc:
            actions.append(f"Правило Firewall не создано: {exc}")
        try:
            process = psutil.Process(pid)
            current_path = process.exe()
            if os.path.normcase(os.path.abspath(current_path)) != os.path.normcase(os.path.abspath(str(resolved))):
                actions.append("Остановка отменена: PID уже принадлежит другому процессу")
            else:
                process.terminate()
                process.wait(timeout=3)
                actions.append("Процесс майнера остановлен")
        except (psutil.NoSuchProcess, psutil.ZombieProcess):
            actions.append("Процесс уже завершился")
        except Exception as exc:
            actions.append(f"Остановка процесса не выполнена: {exc}")
        return " · ".join(actions)

    def _scan_process_behavior(self, ports_by_pid: dict[int, set[int]], now: float) -> list[NetworkEvent]:
        events: list[NetworkEvent] = []
        live_pids: set[int] = set()
        for process in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
            try:
                info = process.info
                pid = int(info.get("pid") or process.pid)
                name = str(info.get("name") or "")
                if not name:
                    continue
                live_pids.add(pid)
                cpu = float(process.cpu_percent(interval=None))
                samples = self._cpu_samples.setdefault(pid, deque(maxlen=4))
                samples.append(cpu)
                sustained = len(samples) == 4 and sum(value >= 60.0 for value in samples) >= 3
                path = str(info.get("exe") or "")
                command_line = " ".join(info.get("cmdline") or [])
                assessment = assess_process_behavior(
                    name, path, command_line,
                    cpu_sustained=sustained,
                    network_ports=ports_by_pid.get(pid, set()),
                )
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError, TypeError, ValueError):
                continue

            if assessment.category == "none" or assessment.score < 35:
                continue
            key = (pid, assessment.category)
            previous = self._behavior_seen.get(key)
            if previous and now - previous[0] < 90 and assessment.score <= previous[1] + 10:
                continue
            self._behavior_seen[key] = (now, assessment.score)

            action = "Поведенческие признаки требуют проверки"
            if self.auto_block and assessment.auto_block_eligible:
                action = self._auto_contain_behavior(pid, path)

            event = NetworkEvent(
                datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S"),
                pid,
                name,
                path,
                "Поведенческий анализ",
                0,
                "BEHAVIOR",
                assessment.category.upper(),
                assessment.score,
                assessment.severity,
                assessment.reasons,
                assessment.auto_block_eligible,
                action,
                False,
            )
            events.append(event)
            self.callback(event)

        stale_pids = set(self._cpu_samples) - live_pids
        for pid in stale_pids:
            self._cpu_samples.pop(pid, None)
        self._behavior_seen = {
            key: value for key, value in self._behavior_seen.items()
            if now - value[0] < 600
        }
        return events

    def poll_once(self) -> list[NetworkEvent]:
        now = time.monotonic()
        current: list[NetworkEvent] = []
        connections = psutil.net_connections(kind="inet")
        ports_by_pid: dict[int, set[int]] = {}
        for connection in connections:
            if not connection.pid or not connection.raddr:
                continue
            remote_port = getattr(connection.raddr, "port", None) or connection.raddr[1]
            ports_by_pid.setdefault(int(connection.pid), set()).add(int(remote_port))
        self._seen = {key: timestamp for key, timestamp in self._seen.items() if now - timestamp < 90}
        for conn in connections:
            is_udp = conn.type == socket.SOCK_DGRAM
            if not conn.pid or not conn.raddr:
                continue
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
            signature_valid, publisher = self._trusted_signature(process_name, process_path)
            assessment = assess_connection(
                process_name, process_path, str(remote_ip), int(remote_port), conn.status,
                publisher=publisher, signature_valid=signature_valid,
            )
            protocol = "UDP" if is_udp else "TCP"
            event = NetworkEvent(
                datetime.now(timezone.utc).astimezone().strftime("%H:%M:%S"),
                conn.pid, process_name, process_path, str(remote_ip), int(remote_port),
                protocol, conn.status, assessment.score, assessment.severity,
                assessment.reasons, assessment.auto_block_eligible,
                "Доверенное приложение" if assessment.trusted_application else "Наблюдение",
                assessment.trusted_application,
            )
            if self.auto_block and event.auto_block_eligible:
                try:
                    event.action = (
                        self._auto_contain(event) if self.auto_quarantine
                        else block_process_outbound(Path(process_path))
                    )
                except Exception as exc:
                    event.action = f"Автозащита не завершена: {exc}"
            current.append(event)
            self.callback(event)
        current.extend(self._scan_process_behavior(ports_by_pid, now))
        return current
