"""Transparent, source-linked coverage notes; not a malware-signature database."""
TRACKED_FAMILIES = [
    {"name": "Vidar", "platform": "Windows", "note": "Credential, browser and wallet theft; HTTP(S) C2 is documented.", "source": "https://attack.mitre.org/software/S9050/"},
    {"name": "LummaC2", "platform": "Windows", "note": "Infostealer observed in 2025-2026 threat reporting.", "source": "https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-ai-hype-in-social-engineering/"},
    {"name": "Rhadamanthys", "platform": "Windows", "note": "Reported among prevalent infostealer families in 2025 telemetry.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "StealC", "platform": "Windows", "note": "Included in 2025 credential-theft reporting.", "source": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
    {"name": "RedLine", "platform": "Windows", "note": "Legacy family still present in stolen-credential telemetry.", "source": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
    {"name": "Raccoon Stealer", "platform": "Windows", "note": "Included in 2025 credential-theft reporting.", "source": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
    {"name": "MetaStealer", "platform": "Windows", "note": "Observed in 2025 infostealer infrastructure reporting.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Acreed", "platform": "Windows", "note": "Appears in recent weekly infostealer reporting.", "source": "https://intel.threadlinqs.com/threat/TL-2026-5041"},
    {"name": "Warden Stealer", "platform": "Windows", "note": "Appears in recent weekly infostealer reporting.", "source": "https://intel.threadlinqs.com/threat/TL-2026-5041"},
    {"name": "Remus", "platform": "Windows", "note": "Appears in recent weekly infostealer reporting.", "source": "https://intel.threadlinqs.com/threat/TL-2026-5041"},
]

COMMON_BEHAVIORS = [
    "Execution from user-writable AppData or Temp locations",
    "Suspicious persistence or masquerading as a Windows component",
    "Browser credential and session-cookie access",
    "Unexpected outbound network connections from an unusual executable",
    "Process injection or tampering (requires endpoint telemetry such as Sysmon)",
]

SOURCES = [
    {"name": "MITRE ATT&CK — Vidar", "url": "https://attack.mitre.org/software/S9050/"},
    {"name": "Microsoft Security Blog — 2026 campaigns", "url": "https://www.microsoft.com/en-us/security/blog/2026/06/08/ai-brands-as-bait-how-threat-actors-are-using-ai-hype-in-social-engineering/"},
    {"name": "Recorded Future — 2025 Year in Review", "url": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Outpost24 — Breached Password Report 2026", "url": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
]
