from __future__ import annotations

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from dataclasses import dataclass


@dataclass(frozen=True)
class SysmonEvent:
    event_id: int
    record_id: int
    timestamp: str
    data: dict[str, str]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_sysmon_events(xml_text: str) -> list[SysmonEvent]:
    """Parse wevtutil XML output without executing or trusting event field values."""
    source = (xml_text or "").strip()
    if not source:
        return []
    source = re.sub(r"^<\?xml[^>]*\?>", "", source, flags=re.IGNORECASE).strip()
    if not source.startswith("<"):
        return []
    if _local_name(ET.fromstring(source).tag) == "Event":
        root = ET.fromstring(source)
        nodes = [root]
    else:
        root = ET.fromstring(source)
        nodes = [node for node in root.iter() if _local_name(node.tag) == "Event"]

    parsed: list[SysmonEvent] = []
    for node in nodes:
        system = next((child for child in node if _local_name(child.tag) == "System"), None)
        if system is None:
            continue
        event_id = record_id = 0
        timestamp = ""
        for child in system:
            name = _local_name(child.tag)
            if name == "EventID" and child.text:
                event_id = int(child.text)
            elif name == "EventRecordID" and child.text:
                record_id = int(child.text)
            elif name == "TimeCreated":
                timestamp = child.attrib.get("SystemTime", "")
        fields: dict[str, str] = {}
        for event_data in node.iter():
            if _local_name(event_data.tag) != "Data":
                continue
            field_name = event_data.attrib.get("Name", "")
            if field_name:
                fields[field_name] = event_data.text or ""
        if event_id and record_id:
            parsed.append(SysmonEvent(event_id, record_id, timestamp, fields))
    return parsed


def _basename(path: str) -> str:
    return (path or "").replace("/", "\\").rsplit("\\", 1)[-1].casefold()


def assess_sysmon_event(event: SysmonEvent):
    """Classify useful Sysmon telemetry; this sensor never auto-terminates processes."""
    from .behavior import BehaviorAssessment, _severity

    data = {key.casefold(): value for key, value in event.data.items()}
    score = 0
    category = "none"
    reasons: list[str] = []

    if event.event_id == 10:
        source = data.get("sourceimage", "")
        target = data.get("targetimage", "")
        target_name = _basename(target)
        source_name = _basename(source)
        if target_name == "lsass.exe" and source_name not in {"msmpeng.exe", "csfalconservice.exe"}:
            category, score = "credential_access", 90
            reasons.append("Sysmon Event 10: процесс обращался к памяти LSASS")
        elif target_name in {"chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe"} and source_name != target_name:
            category, score = "credential_access", 65
            reasons.append("Sysmon Event 10: сторонний процесс обращался к процессу браузера")
            if any(token in source.casefold() for token in ("\\temp\\", "\\downloads\\", "\\public\\")):
                score += 20
                reasons.append("Источник доступа запущен из временного или общедоступного каталога")

    elif event.event_id == 1:
        image = data.get("image", "")
        command = data.get("commandline", "").casefold()
        suspicious = (
            "-encodedcommand", " -enc ", "-windowstyle hidden", " -w hidden",
            "mshta.exe http", "regsvr32.exe /s", "rundll32.exe javascript:",
            "bitsadmin /transfer", "frombase64string", "downloadstring(",
            "davwwwroot", "invoke-expression",
        )
        matched = [marker for marker in suspicious if marker in command]
        if matched:
            category, score = "suspicious_execution", min(90, 45 + 15 * len(matched))
            reasons.append("Sysmon Event 1: подозрительные параметры или LOLBin в командной строке")
        if any(token in image.casefold() for token in ("\\appdata\\local\\temp\\", "\\downloads\\")):
            if category == "none":
                category, score = "suspicious_execution", 35
            else:
                score = min(100, score + 10)
            reasons.append("Процесс запущен из Temp или Downloads")

    elif event.event_id == 3:
        image = data.get("image", "")
        destination = data.get("destinationhostname", "").casefold()
        port = data.get("destinationport", "")
        pool_ports = {"3333", "3334", "4444", "5555", "7777", "8888", "9999", "14444", "3032"}
        pool_hints = ("supportxmr", "moneroocean", "nanopool", "2miners", "hashvault", "herominers", "f2pool")
        if port in pool_ports or any(hint in destination for hint in pool_hints):
            category, score = "network", 45
            reasons.append("Sysmon Event 3: сетевое соединение совпало с типичным признаком mining-pool")
            if any(token in image.casefold() for token in ("\\temp\\", "\\downloads\\", "\\public\\")):
                score += 15
                reasons.append("Сетевой процесс запущен из нестандартного пользовательского каталога")

    elif event.event_id == 11:
        target = data.get("targetfilename", "").casefold()
        if "\\start menu\\programs\\startup\\" in target and target.endswith((".exe", ".dll", ".vbs", ".js", ".ps1")):
            category, score = "persistence", 55
            reasons.append("Sysmon Event 11: создан исполняемый файл или скрипт в папке автозагрузки")

    return BehaviorAssessment(category, min(score, 100), _severity(min(score, 100)), reasons, False)


class SysmonReader:
    """Incrementally read recent Sysmon events via wevtutil; Sysmon is never installed or changed."""

    CHANNEL = "Microsoft-Windows-Sysmon/Operational"
    QUERY = "*[System[(EventID=1 or EventID=3 or EventID=10 or EventID=11)]]"

    def __init__(self, *, runner=subprocess.run, max_records: int = 100):
        self.runner = runner
        self.max_records = max(10, min(int(max_records), 500))
        self.last_record_id: int | None = None
        self.available = False
        self.last_error: str | None = None

    def read_new(self) -> list[SysmonEvent]:
        if os.name != "nt":
            self.available = False
            self.last_error = "Sysmon telemetry доступна только в Windows"
            return []
        command = [
            "wevtutil.exe", "qe", self.CHANNEL,
            f"/q:{self.QUERY}", f"/c:{self.max_records}", "/rd:true", "/f:xml",
        ]
        try:
            result = self.runner(
                command, capture_output=True, text=True, timeout=8, check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            self.available = False
            self.last_error = str(exc)
            return []
        if result.returncode != 0:
            self.available = False
            self.last_error = (result.stderr or result.stdout or "Sysmon event channel unavailable").strip()
            return []

        self.available = True
        self.last_error = None
        events = parse_sysmon_events(result.stdout)
        if not events:
            return []
        newest = max(event.record_id for event in events)
        if self.last_record_id is None:
            self.last_record_id = newest
            return []
        fresh = sorted(
            (event for event in events if event.record_id > self.last_record_id),
            key=lambda event: event.record_id,
        )
        self.last_record_id = max(self.last_record_id, newest)
        return fresh
