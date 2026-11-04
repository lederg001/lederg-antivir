import json

from src.antivir.defender import build_scan_command, parse_defender_status


def test_parse_defender_status_reports_realtime_and_engine_mode():
    payload = json.dumps({
        "AntivirusEnabled": True,
        "RealTimeProtectionEnabled": True,
        "AMRunningMode": "Normal",
        "AntivirusSignatureLastUpdated": "2026-11-04T10:00:00Z",
    })
    status = parse_defender_status(payload)
    assert status.antivirus_enabled is True
    assert status.realtime_enabled is True
    assert status.running_mode == "Normal"


def test_parse_defender_status_handles_disabled_or_missing_fields():
    status = parse_defender_status('{"AntivirusEnabled": false}')
    assert status.antivirus_enabled is False
    assert status.realtime_enabled is False
    assert status.running_mode == "Unknown"


def test_custom_scan_command_uses_environment_path_not_shell_interpolation():
    command = build_scan_command("CustomScan")
    assert command[-1] == "Start-MpScan -ScanType CustomScan -ScanPath $env:LEDERG_SCAN_PATH"
    assert "LEDERG_SCAN_PATH" not in " ".join(command[:-1])


def test_full_scan_command_requests_full_scan():
    command = build_scan_command("FullScan")
    assert command[-1] == "Start-MpScan -ScanType FullScan"


def test_scan_type_is_validated():
    try:
        build_scan_command("DeleteAll")
    except ValueError:
        pass
    else:
        raise AssertionError("unknown Defender scan type must be rejected")
