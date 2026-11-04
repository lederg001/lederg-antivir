from __future__ import annotations

from dataclasses import dataclass
from pathlib import PureWindowsPath


MINER_NAMES = {
    "xmrig.exe", "xmrig", "minerd.exe", "minerd", "cpuminer.exe", "cpuminer",
    "ethminer.exe", "ethminer", "phoenixminer.exe", "nbminer.exe", "lolminer.exe",
    "t-rex.exe", "gminer.exe", "srbminer.exe", "teamredminer.exe",
    "nanominer.exe", "wildrig.exe", "bminer.exe", "kawpowminer.exe",
}
STEALER_NAMES = {
    "redline.exe", "vidar.exe", "rhadamanthys.exe", "stealc.exe", "lumma.exe",
    "agenttesla.exe", "raccoon.exe", "formbook.exe", "xloader.exe",
    "strelastealer.exe", "risepro.exe", "meduzastealer.exe",
}

MINER_ARGUMENTS = (
    "stratum+tcp://", "stratum+ssl://", "--pool", " -o stratum", "--wallet",
    "--coin", "--algo", "--donate-level", "randomx", "cryptonight", "ethash",
    "kawpow", "autolykos", "progpow", "rx/0", "monero",
)
MINER_POOL_HINTS = (
    "supportxmr.com", "moneroocean.stream", "nanopool.org", "2miners.com",
    "hashvault.pro", "herominers.com", "miningpoolhub.com", "f2pool.com",
    "pool.minexmr.com",
)
MINING_PORTS = {3333, 3334, 4444, 5555, 7777, 8888, 9999, 14444, 3032}

BROWSER_STORE_MARKERS = (
    "login data", "cookies", "local state", "web data", "logins.json",
    "key4.db", "chrome\\user data", "opera software", "firefox\\profiles",
    "discord\\local storage", "telegram desktop\\tdata", "leveldb",
    "wallet", "extension state",
)
DECRYPTION_MARKERS = (
    "cryptunprotectdata", "protecteddata.unprotect", "dpapi", "oscrypt",
    "decrypt", "aesgcm", "master_key", "unprotect",
)
COLLECTION_MARKERS = (
    "sqlite3", "sqlite.connect", "shutil.copy", "copyfile", "zipfile",
    "tarfile", "7z", "leveldb",
)
EXFILTRATION_MARKERS = (
    "requests.post", "httpx.post", "invoke-restmethod", "webclient.upload",
    "uploadfile", "discord.com/api/webhooks", "socket.create_connection",
    "urlopen", "telegram.org", "api.telegram.org", "curl",
)


@dataclass
class BehaviorAssessment:
    category: str
    score: int
    severity: str
    reasons: list[str]
    auto_block_eligible: bool = False


def _severity(score: int) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 35:
        return "medium"
    return "info"


def assess_stealer_script(content: str) -> BehaviorAssessment:
    """Detect combinations of browser-store access, decryption and data transfer markers."""
    sample = (content or "")[:1_500_000].casefold()
    browser = [marker for marker in BROWSER_STORE_MARKERS if marker in sample]
    decryption = [marker for marker in DECRYPTION_MARKERS if marker in sample]
    collection = [marker for marker in COLLECTION_MARKERS if marker in sample]
    exfiltration = [marker for marker in EXFILTRATION_MARKERS if marker in sample]

    score = 0
    reasons: list[str] = []
    if browser:
        score += 35
        reasons.append("Обнаружены обращения к хранилищам браузера, cookies или профилям")
    if decryption:
        score += 25
        reasons.append("Обнаружены признаки расшифровки/доступа к защищённым данным")
    if collection:
        score += 15
        reasons.append("Обнаружены признаки сбора или упаковки локальных данных")
    if exfiltration:
        score += 30
        reasons.append("Обнаружены признаки отправки данных во внешнюю сеть")

    score = min(score, 100)
    if not browser or score < 35:
        return BehaviorAssessment("none", score, _severity(score), reasons, False)
    return BehaviorAssessment("stealer", score, _severity(score), reasons, False)


def assess_process_behavior(
    process_name: str,
    process_path: str | None,
    command_line: str,
    *,
    cpu_sustained: bool,
    network_ports: set[int] | None = None,
) -> BehaviorAssessment:
    """Correlate miner names, stratum/pool arguments, sustained CPU and pool ports."""
    filename = PureWindowsPath(process_name or process_path or "").name.casefold()
    command = (command_line or "").casefold()
    ports = network_ports or set()
    reasons: list[str] = []

    known_name = filename in MINER_NAMES or filename.startswith(("xmrig-", "cpuminer-"))
    command_match = any(marker in command for marker in MINER_ARGUMENTS)
    pool_hint = any(marker in command for marker in MINER_POOL_HINTS)
    pool_connection = bool(ports & MINING_PORTS)

    score = 0
    if known_name:
        score += 30
        reasons.append("Имя процесса совпадает с известным семейством/исполняемым файлом майнера")
    if command_match:
        score += 35
        reasons.append("Командная строка содержит параметры алгоритма или протокола mining-pool")
    if cpu_sustained:
        score += 25
        reasons.append("Процесс устойчиво потребляет высокий процент CPU в нескольких замерах")
    if pool_hint or pool_connection:
        score += 25
        reasons.append("Обнаружен адрес или типичный порт соединения с mining-pool")

    score = min(score, 100)
    qualifies = (
        score >= 80
        and cpu_sustained
        and (known_name or command_match)
        and (pool_hint or pool_connection)
    )
    if score >= 35:
        return BehaviorAssessment("miner", score, _severity(score), reasons, qualifies)

    stealer = assess_stealer_script(command)
    if filename in STEALER_NAMES:
        stealer.score = max(stealer.score, 50)
        stealer.category = "stealer"
        stealer.severity = _severity(stealer.score)
        stealer.reasons.append("Имя процесса совпадает с известным семейством инфостиллеров")
    return stealer


def is_miner_artifact_name(filename: str) -> bool:
    value = PureWindowsPath(filename or "").name.casefold()
    return value in MINER_NAMES or value.startswith(("xmrig-", "cpuminer-"))
