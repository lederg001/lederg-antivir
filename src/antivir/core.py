from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .behavior import STEALER_NAMES, assess_stealer_script, is_miner_artifact_name

@dataclass
class ScanResult:
    path: Path
    sha256: str
    score: int
    reasons: list[str]
    quarantined_path: Path | None = None

@dataclass
class QuarantineItem:
    path: Path
    metadata: Path
    sha256: str

SUSPICIOUS_PATHS = ("\\windowshelper\\", "\\cloudsyncdata\\", "\\cloudsyncwatcher\\", "\\sys_")
SUSPICIOUS_NAMES = ("svchost32.exe", "cloudsynchost.exe", "csyncwatch.exe")
PROTECTED_ROOTS = (
    Path(os.environ.get("SystemRoot", r"C:\Windows")).resolve(),
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")).resolve(),
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")).resolve(),
)

def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def analyze_file(path: Path) -> ScanResult:
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        raise FileNotFoundError(path)
    normalized = str(path).lower().replace("/", "\\")
    reasons: list[str] = []
    score = 0
    matched_path = next((token for token in SUSPICIOUS_PATHS if token in normalized), None)
    if matched_path:
        reasons.append(f"Подозрительный маркер пути: {matched_path.strip(chr(92))}")
        score += 55
    if path.name.lower() in SUSPICIOUS_NAMES:
        reasons.append(f"Имя совпадает с индикатором: {path.name}")
        score += 60
    if path.suffix.lower() in {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1"}:
        if "appdata" in normalized or "temp" in normalized:
            reasons.append("Исполняемый файл в пользовательской временной области")
            score += 15

    if path.suffix.lower() == ".exe" and is_miner_artifact_name(path.name):
        reasons.append("Имя файла совпадает с распространённым криптомайнером; нужна проверка процесса и сетевой активности")
        score = max(score, 55)
    if path.suffix.lower() == ".exe" and path.name.casefold() in STEALER_NAMES:
        reasons.append("Имя файла совпадает с отслеживаемым семейством инфостиллеров; требуется поведенческая проверка")
        score = max(score, 60)

    if path.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js"}:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as stream:
                content = stream.read(1_500_000)
            behavior = assess_stealer_script(content)
            if behavior.score >= 35:
                reasons.extend(behavior.reasons)
                score = max(score, behavior.score)
        except OSError:
            pass

    return ScanResult(path, _sha256(path), min(score, 100), reasons)


def should_auto_quarantine(result: ScanResult) -> bool:
    """Allow automatic quarantine only for exact IOC files or high-confidence scripts in user-writable areas."""
    path = Path(result.path).expanduser().resolve()
    if is_exact_ioc_file(path):
        return True
    if result.score < 90 or path.suffix.casefold() not in {".ps1", ".bat", ".cmd", ".vbs", ".js"}:
        return False
    normalized = str(path).casefold().replace("/", "\\")
    writable = any(marker in normalized for marker in ("\\appdata\\", "\\temp\\", "\\downloads\\", "\\public\\"))
    return writable and not _is_protected(path)


def is_exact_ioc_file(path: Path | str) -> bool:
    """Return True only for an exact known filename in a known malicious directory."""
    value = str(path).lower().replace("/", "\\")
    filename = value.rsplit("\\", 1)[-1]
    return (
        filename in SUSPICIOUS_NAMES
        and filename.endswith(".exe")
        and any(marker in value for marker in SUSPICIOUS_PATHS)
    )


def _is_protected(path: Path) -> bool:
    resolved = path.resolve()
    for root in PROTECTED_ROOTS:
        try:
            resolved.relative_to(root)
            return True
        except ValueError:
            pass
    return False

def quarantine_file(source: Path, quarantine_dir: Path) -> QuarantineItem:
    source = Path(source).expanduser().resolve()
    if _is_protected(source):
        raise ValueError("Protected system/program path is not allowed")
    if not source.is_file():
        raise FileNotFoundError(source)
    quarantine_dir = Path(quarantine_dir).expanduser().resolve()
    quarantine_dir.mkdir(parents=True, exist_ok=True)
    digest = _sha256(source)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = source.name.replace("..", "_")
    destination = quarantine_dir / f"{stamp}_{digest[:12]}_{safe_name}.quarantined"
    metadata = destination.with_suffix(destination.suffix + ".json")
    # Move atomically on same volume; copy+verify when volumes differ.
    try:
        shutil.move(str(source), str(destination))
    except OSError:
        with source.open("rb") as src, destination.open("xb") as dst:
            shutil.copyfileobj(src, dst)
        if _sha256(destination) != digest:
            destination.unlink(missing_ok=True)
            raise IOError("Quarantine copy hash verification failed")
        source.unlink()
    if _sha256(destination) != digest:
        shutil.move(str(destination), str(source))
        raise IOError("Quarantine hash verification failed; original restored")
    record = {"original_path": str(source), "quarantined_path": str(destination), "sha256": digest,
              "created_utc": datetime.now(timezone.utc).isoformat(), "state": "quarantined"}
    metadata.write_text(json.dumps(record, ensure_ascii=False, indent=2), encoding="utf-8")
    return QuarantineItem(destination, metadata, digest)

def restore_file(quarantined_path: Path, metadata_path: Path, destination: Path) -> Path:
    quarantined_path = Path(quarantined_path).resolve()
    metadata_path = Path(metadata_path).resolve()
    destination = Path(destination).expanduser().resolve()
    if not quarantined_path.is_file() or not metadata_path.is_file():
        raise FileNotFoundError("Quarantine entry or metadata is missing")
    record = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected = record.get("sha256")
    if _sha256(quarantined_path) != expected:
        raise ValueError("Quarantine item hash mismatch; restore blocked")
    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(quarantined_path), str(destination))
    metadata_path.unlink()
    return destination
