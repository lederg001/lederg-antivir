from dataclasses import dataclass

@dataclass
class DefenderStatus:
    antivirus_enabled: bool
    realtime_enabled: bool
    running_mode: str
