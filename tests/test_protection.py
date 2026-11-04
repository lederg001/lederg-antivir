import json

from src.antivir.protection import parse_firewall_profiles


def test_firewall_profiles_are_reported_on_only_when_every_profile_is_enabled():
    enabled, count = parse_firewall_profiles(json.dumps([
        {"Name": "Domain", "Enabled": True},
        {"Name": "Private", "Enabled": True},
        {"Name": "Public", "Enabled": True},
    ]))
    assert enabled is True
    assert count == 3


def test_firewall_profiles_report_attention_when_one_profile_is_disabled():
    enabled, count = parse_firewall_profiles(json.dumps([
        {"Name": "Domain", "Enabled": True},
        {"Name": "Private", "Enabled": False},
        {"Name": "Public", "Enabled": True},
    ]))
    assert enabled is False
    assert count == 3


def test_firewall_profile_parser_handles_empty_payload():
    enabled, count = parse_firewall_profiles("[]")
    assert enabled is None
    assert count == 0
