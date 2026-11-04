from src.antivir.startup import (
    assess_startup_entry,
    build_autostart_command,
    extract_executable_path,
)


def test_extract_executable_path_from_quoted_path_with_spaces():
    command = r'"C:\Program Files\Example App\agent.exe" --silent'
    assert extract_executable_path(command) == r"C:\Program Files\Example App\agent.exe"


def test_extract_executable_path_from_unquoted_command():
    command = r"C:\Users\tester\AppData\Local\Temp\agent.exe -silent"
    assert extract_executable_path(command) == r"C:\Users\tester\AppData\Local\Temp\agent.exe"


def test_encoded_powershell_startup_entry_is_high_risk():
    result = assess_startup_entry(
        name="Update Service",
        source="HKCU Run",
        command="powershell.exe -NoProfile -WindowStyle Hidden -EncodedCommand SQBFAFgA",
        target=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        target_exists=True,
        signature_valid=True,
        publisher="Microsoft Corporation",
    )
    assert result.score >= 70
    assert result.severity in {"high", "critical"}
    assert any("EncodedCommand" in reason for reason in result.reasons)


def test_exact_known_stealer_ioc_in_startup_is_critical():
    result = assess_startup_entry(
        name="Windows Helper",
        source="HKCU Run",
        command=r'"C:\Users\tester\AppData\Roaming\WindowsHelper\svchost32.exe"',
        target=r"C:\Users\tester\AppData\Roaming\WindowsHelper\svchost32.exe",
        target_exists=True,
        signature_valid=False,
    )
    assert result.score == 100
    assert result.severity == "critical"


def test_signed_standard_application_is_not_flagged_for_starting_with_windows():
    result = assess_startup_entry(
        name="Discord",
        source="HKCU Run",
        command=r'"C:\Users\tester\AppData\Local\Discord\Update.exe" --processStart Discord.exe',
        target=r"C:\Program Files\Discord\Discord.exe",
        target_exists=True,
        signature_valid=True,
        publisher="Discord Inc.",
    )
    assert result.score == 0
    assert result.severity == "trusted"


def test_unsigned_executable_from_temp_startup_is_reviewed_not_auto_killed():
    result = assess_startup_entry(
        name="Updater",
        source="HKCU Run",
        command=r"C:\Users\tester\AppData\Local\Temp\updater.exe",
        target=r"C:\Users\tester\AppData\Local\Temp\updater.exe",
        target_exists=True,
        signature_valid=False,
    )
    assert result.score >= 35
    assert result.severity == "medium"
    assert result.auto_quarantine_eligible is False


def test_missing_startup_target_is_reported():
    result = assess_startup_entry(
        name="Old app",
        source="HKCU Run",
        command=r'"C:\Program Files\Old App\old.exe"',
        target=r"C:\Program Files\Old App\old.exe",
        target_exists=False,
        signature_valid=False,
    )
    assert result.score > 0
    assert any("не найден" in reason.lower() for reason in result.reasons)


def test_autostart_command_quotes_executable_and_requests_hidden_launch():
    command = build_autostart_command(
        frozen=True,
        executable=r"C:\Program Files\LEDERG\LEDERG-ANTIVIR.exe",
    )
    assert command == r'"C:\Program Files\LEDERG\LEDERG-ANTIVIR.exe" --background'


def test_autostart_command_supports_python_source_launch():
    command = build_autostart_command(
        frozen=False,
        executable=r"C:\Python312\pythonw.exe",
        script=r"C:\LEDERG\app.py",
    )
    assert command == r'"C:\Python312\pythonw.exe" "C:\LEDERG\app.py" --background'



def test_own_lederg_autostart_entry_is_protected_from_self_detection():
    result = assess_startup_entry(
        name="LEDERG ANTIVIR",
        source="HKCU Run",
        command=r'"C:\Users\tester\AppData\Local\LEDERG\LEDERG-ANTIVIR.exe" --background',
        target=r"C:\Users\tester\AppData\Local\LEDERG\LEDERG-ANTIVIR.exe",
        target_exists=True,
        signature_valid=False,
        own_application=True,
    )

    assert result.score == 0
    assert result.severity == "trusted"
    assert result.auto_quarantine_eligible is False
    assert any("собственное приложение" in reason.lower() for reason in result.reasons)



def test_self_autostart_requires_our_exact_name_and_executable(monkeypatch, tmp_path):
    from src.antivir import startup

    executable = tmp_path / "LEDERG-ANTIVIR.exe"
    executable.write_bytes(b"test")
    monkeypatch.setattr(startup.sys, "executable", str(executable))
    monkeypatch.setattr(startup.sys, "frozen", True, raising=False)

    assert startup._is_our_autostart_entry(
        "LEDERG ANTIVIR",
        f'"{executable}" --background',
        str(executable),
    )
    assert not startup._is_our_autostart_entry(
        "Other updater",
        f'"{executable}" --background',
        str(executable),
    )
    assert not startup._is_our_autostart_entry(
        "LEDERG ANTIVIR",
        r'"C:\\Temp\\fake.exe" --background',
        r"C:\\Temp\\fake.exe",
    )
