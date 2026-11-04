from pathlib import Path

from src.antivir.network import assess_connection, build_firewall_block_args, build_firewall_unblock_args
from src.antivir.threat_intel import TRACKED_FAMILIES


def test_known_suspicious_artifact_making_public_connection_is_critical():
    result = assess_connection(
        process_name="svchost32.exe",
        process_path=r"C:\Users\tester\AppData\Roaming\WindowsHelper\svchost32.exe",
        remote_address="1.1.1.1",
        remote_port=443,
        status="ESTABLISHED",
    )

    assert result.score >= 80
    assert result.severity == "critical"
    assert result.reasons
    assert result.auto_block_eligible is True


def test_normal_program_files_process_is_not_flagged_by_default():
    result = assess_connection(
        process_name="browser.exe",
        process_path=r"C:\Program Files\Browser\browser.exe",
        remote_address="8.8.8.8",
        remote_port=443,
        status="ESTABLISHED",
    )

    assert result.score < 50
    assert result.auto_block_eligible is False


def test_private_network_connection_is_not_treated_as_internet_exfiltration():
    result = assess_connection(
        process_name="agent.exe",
        process_path=r"C:\Users\tester\AppData\Local\Temp\agent.exe",
        remote_address="192.168.1.10",
        remote_port=443,
        status="ESTABLISHED",
    )

    assert result.score < 80
    assert result.auto_block_eligible is False


def test_firewall_rule_is_program_scoped_and_outbound_only(tmp_path):
    executable = tmp_path / "sample.exe"
    executable.write_bytes(b"test")
    args = build_firewall_block_args(executable)

    assert "dir=out" in args
    assert "action=block" in args
    assert any(str(executable.resolve()) in item for item in args)
    assert "dir=in" not in args


def test_family_catalog_is_transparent_and_referenced():
    assert {"Vidar", "LummaC2", "Rhadamanthys", "StealC", "RedLine"}.issubset(
        {family["name"] for family in TRACKED_FAMILIES}
    )
    assert all(family["source"] for family in TRACKED_FAMILIES)



def test_firewall_refuses_to_change_warp_or_zapret_process_rules(tmp_path):
    protected = tmp_path / "winws.exe"
    protected.write_bytes(b"test")
    try:
        build_firewall_block_args(protected)
    except ValueError as exc:
        assert "WARP/Zapret" in str(exc)
    else:
        raise AssertionError("WARP/Zapret process block must be refused")


def test_firewall_rule_can_be_removed_after_executable_is_gone(tmp_path):
    executable = tmp_path / "former-app.exe"
    executable.write_bytes(b"test")
    blocked_args = build_firewall_block_args(executable)
    executable.unlink()
    remove_args = build_firewall_unblock_args(executable)

    assert any("Outbound" in item for item in blocked_args)
    assert "delete" in remove_args
    assert "name=" in remove_args[-1]


def test_signed_opera_installed_in_expected_directory_is_trusted():
    result = assess_connection(
        process_name="opera.exe",
        process_path=r"C:\Users\tester\AppData\Local\Programs\Opera\opera.exe",
        remote_address="185.26.182.11",
        remote_port=443,
        status="ESTABLISHED",
        publisher="CN=Opera Software AS, O=Opera Norway AS",
        signature_valid=True,
    )
    assert result.score == 0
    assert result.trusted_application is True
    assert result.auto_block_eligible is False


def test_signed_discord_installed_in_expected_directory_is_trusted():
    result = assess_connection(
        process_name="Discord.exe",
        process_path=r"C:\Users\tester\AppData\Local\Discord\app-1.0.9000\Discord.exe",
        remote_address="162.159.128.233",
        remote_port=443,
        status="ESTABLISHED",
        publisher="CN=Discord Inc.",
        signature_valid=True,
    )
    assert result.score == 0
    assert result.trusted_application is True


def test_unsigned_discord_named_executable_is_not_trusted():
    result = assess_connection(
        process_name="Discord.exe",
        process_path=r"C:\Users\tester\AppData\Local\Temp\Discord.exe",
        remote_address="162.159.128.233",
        remote_port=443,
        status="ESTABLISHED",
    )
    assert result.trusted_application is False
    assert result.score > 0


def test_signed_opera_in_unexpected_path_is_not_trusted():
    result = assess_connection(
        process_name="opera.exe",
        process_path=r"C:\Users\tester\AppData\Local\Temp\opera.exe",
        remote_address="185.26.182.11",
        remote_port=443,
        status="ESTABLISHED",
        publisher="CN=Opera Software AS, O=Opera Norway AS",
        signature_valid=True,
    )
    assert result.trusted_application is False
    assert result.score > 0


def test_signed_steam_in_expected_program_files_path_is_trusted():
    result = assess_connection(
        process_name="steam.exe",
        process_path=r"C:\Program Files (x86)\Steam\Steam.exe",
        remote_address="155.133.248.34",
        remote_port=443,
        status="ESTABLISHED",
        publisher="CN=Valve Corp.",
        signature_valid=True,
    )
    assert result.trusted_application is True
    assert result.score == 0


def test_common_domain_reference_catalogue_contains_major_user_services():
    from src.antivir.threat_intel import COMMON_SERVICE_DOMAINS

    domains = {domain for service in COMMON_SERVICE_DOMAINS for domain in service["domains"]}
    assert {"opera.com", "discord.com", "discord.gg", "google.com", "microsoft.com"} <= domains
