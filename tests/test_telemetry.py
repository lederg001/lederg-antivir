from src.antivir.telemetry import SysmonEvent, assess_sysmon_event, parse_sysmon_events


def test_parse_sysmon_xml_extracts_event_id_record_and_named_fields():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System><EventID>10</EventID><EventRecordID>42</EventRecordID>
        <TimeCreated SystemTime="2026-11-04T10:00:00.000Z" /></System>
      <EventData>
        <Data Name="SourceImage">C:\\Users\\Public\\updater.exe</Data>
        <Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>
        <Data Name="SourceProcessId">1234</Data>
      </EventData>
    </Event>"""
    events = parse_sysmon_events(xml)

    assert len(events) == 1
    assert events[0].event_id == 10
    assert events[0].record_id == 42
    assert events[0].data["SourceImage"].endswith("updater.exe")
    assert events[0].data["TargetImage"].endswith("lsass.exe")


def test_sysmon_process_access_to_lsass_is_high_risk_but_never_auto_kills():
    event = SysmonEvent(
        event_id=10,
        record_id=1,
        timestamp="2026-11-04T10:00:00Z",
        data={
            "SourceImage": r"C:\Users\Public\updater.exe",
            "TargetImage": r"C:\Windows\System32\lsass.exe",
            "SourceProcessId": "1234",
        },
    )

    result = assess_sysmon_event(event)

    assert result.category == "credential_access"
    assert result.score >= 80
    assert result.auto_block_eligible is False


def test_sysmon_network_event_to_mining_port_is_signal_not_verdict():
    event = SysmonEvent(
        event_id=3,
        record_id=2,
        timestamp="2026-11-04T10:00:00Z",
        data={"Image": r"C:\Users\Public\service.exe", "DestinationIp": "203.0.113.8",
              "DestinationPort": "3333", "Protocol": "tcp"},
    )

    result = assess_sysmon_event(event)

    assert result.category == "network"
    assert result.score >= 35
    assert result.auto_block_eligible is False


def test_sysmon_event_without_suspicious_indicators_is_ignored():
    event = SysmonEvent(
        event_id=3,
        record_id=3,
        timestamp="2026-11-04T10:00:00Z",
        data={"Image": r"C:\Program Files\Browser\browser.exe",
              "DestinationIp": "203.0.113.8", "DestinationPort": "443", "Protocol": "tcp"},
    )

    result = assess_sysmon_event(event)

    assert result.category == "none"
    assert result.score == 0


def test_sysmon_dns_query_for_known_pool_is_a_behavior_signal():
    event = SysmonEvent(
        event_id=22,
        record_id=4,
        timestamp="2026-11-04T10:00:00Z",
        data={"Image": r"C:\\Users\\Public\\service.exe", "QueryName": "pool.supportxmr.com"},
    )

    result = assess_sysmon_event(event)

    assert result.category == "network"
    assert result.score >= 55
    assert result.auto_block_eligible is False


def test_sysmon_registry_run_key_change_is_persistence_signal():
    event = SysmonEvent(
        event_id=13,
        record_id=5,
        timestamp="2026-11-04T10:00:00Z",
        data={"Image": r"C:\\Users\\Public\\updater.exe",
              "TargetObject": r"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater"},
    )

    result = assess_sysmon_event(event)

    assert result.category == "persistence"
    assert result.score >= 55
    assert result.auto_block_eligible is False
