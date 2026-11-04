"""Source-linked infostealer coverage and defensive guidance.

This catalogue is context for triage, not a live IOC feed or a malware signature engine.
"""
TRACKED_FAMILIES = [
    {"name": "Vidar", "platform": "Windows", "note": "Steals browser data, credentials, wallets and files; observed use of HTTPS, DNS and masquerading.", "source": "https://attack.mitre.org/software/S9050/"},
    {"name": "LummaC2", "platform": "Windows", "note": "Infostealer-as-a-service; observed in 2025 stealer activity and ClickFix delivery campaigns.", "source": "https://redcanary.com/threat-detection-report/trends/info-stealers/"},
    {"name": "Rhadamanthys", "platform": "Windows", "note": "Infostealer-as-a-service; tracked in 2025 threat reporting.", "source": "https://redcanary.com/threat-detection-report/trends/info-stealers/"},
    {"name": "StealC", "platform": "Windows", "note": "Credential and browser-data theft family; included in recent credential theft reporting.", "source": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
    {"name": "RedLine", "platform": "Windows", "note": "Credential and information stealer; historical family remains relevant to incident triage.", "source": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
    {"name": "Raccoon Stealer", "platform": "Windows", "note": "Credential, browser and wallet theft family.", "source": "https://marketing.outpost24.com/hubfs/BreachedPasswordsReport_Updated_Final_EN.pdf"},
    {"name": "MetaStealer", "platform": "Windows", "note": "Credential stealer included in recent threat reporting.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "RisePro", "platform": "Windows", "note": "Windows infostealer tracked in previous threat reporting; activity rankings can shift.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Meduza Stealer", "platform": "Windows", "note": "Tracked in 2025 infostealer-panel reporting; activity changed after reported law-enforcement action.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "SalatStealer", "platform": "Windows", "note": "Go-based infostealer described as targeting browser credentials, wallet data and session information.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Unam Web Panel", "platform": "Windows / MaaS", "note": "Among the most frequently detected infostealer panels in the 2025 Recorded Future review.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "SvcStealer", "platform": "Windows", "note": "Appeared among 2025 infostealer-panel detections.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Cyber Stealer", "platform": "Windows", "note": "Appeared among 2025 infostealer-panel detections.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Amatera Stealer", "platform": "Windows", "note": "Appeared among 2025 infostealer-panel detections.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Fickle Stealer", "platform": "Windows", "note": "Appeared among 2025 infostealer-panel detections.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "GhostSpy", "platform": "Windows", "note": "Appeared among 2025 infostealer-panel detections.", "source": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "XLoader / Formbook", "platform": "Windows", "note": "Steals data from web browsers, email clients and FTP applications; can use Run keys for persistence.", "source": "https://attack.mitre.org/software/S1207/"},
    {"name": "Agent Tesla", "platform": "Windows", "note": "Spyware / credential theft malware; uses web and mail protocols and may establish startup persistence.", "source": "https://attack.mitre.org/software/S0331/"},
    {"name": "StrelaStealer", "platform": "Windows", "note": "Focuses on harvesting email credentials from clients such as Outlook and Thunderbird.", "source": "https://attack.mitre.org/software/S1183/"},
    {"name": "Acreed", "platform": "Windows", "note": "Tracked in recent community threat reporting; family-specific signatures are not included in this application.", "source": "https://intel.threadlinqs.com/threat/TL-2026-5041"},
    {"name": "Warden Stealer", "platform": "Windows", "note": "Tracked in recent community threat reporting; family-specific signatures are not included in this application.", "source": "https://intel.threadlinqs.com/threat/TL-2026-5041"},
    {"name": "Remus", "platform": "Windows", "note": "Tracked in recent community threat reporting; family-specific signatures are not included in this application.", "source": "https://intel.threadlinqs.com/threat/TL-2026-5041"},
    {"name": "Atomic Stealer", "platform": "macOS", "note": "macOS infostealer; included as cross-platform threat context, not a Windows signature.", "source": "https://redcanary.com/threat-detection-report/trends/info-stealers/"},
    {"name": "Poseidon", "platform": "macOS", "note": "macOS infostealer tracked in 2025 reporting; informational coverage only.", "source": "https://redcanary.com/threat-detection-report/trends/info-stealers/"},
    {"name": "MacSync", "platform": "macOS", "note": "macOS infostealer tracked in 2025 reporting; informational coverage only.", "source": "https://redcanary.com/threat-detection-report/trends/info-stealers/"},
]

COMMON_BEHAVIORS = [
    "Browser password, cookie, autofill and wallet-store discovery (ATT&CK T1555.003)",
    "Session-cookie theft and reuse without a password (ATT&CK T1539)",
    "LSASS memory access and credential dumping (ATT&CK T1003.001)",
    "Unexpected Run-key or Startup-folder persistence (ATT&CK T1547.001)",
    "Obfuscated PowerShell or script execution (ATT&CK T1059.001)",
    "Encrypted HTTP(S) or DNS command-and-control traffic (ATT&CK T1071)",
    "Archiving collected data before exfiltration (ATT&CK T1560)",
    "Exfiltration through web services or cloud storage (ATT&CK T1567)",
    "Process injection, hollowing or suspicious access to browser processes",
    "ClickFix / fake CAPTCHA / paste-and-run social engineering delivery",
    "Replay of stolen authenticated sessions after MFA (ATT&CK T1550.004)",
    "Browser-profile access combined with DPAPI/AES decryption and outbound transfer",
    "Credential theft via browser extensions, injected scripts or process-memory access",
    "Mining behavior correlation: sustained CPU + miner arguments + pool connection (T1496.001)",
    "Persistence of miners through Run keys, scheduled tasks, WMI or services",
]

ATTACK_TECHNIQUES = [
    {"id": "T1555.003", "name": "Credentials from Web Browsers", "url": "https://attack.mitre.org/techniques/T1555/003/"},
    {"id": "T1539", "name": "Steal Web Session Cookie", "url": "https://attack.mitre.org/techniques/T1539/"},
    {"id": "T1003.001", "name": "LSASS Memory", "url": "https://attack.mitre.org/techniques/T1003/001/"},
    {"id": "T1547.001", "name": "Registry Run Keys / Startup Folder", "url": "https://attack.mitre.org/techniques/T1547/001/"},
    {"id": "T1059.001", "name": "PowerShell", "url": "https://attack.mitre.org/techniques/T1059/001/"},
    {"id": "T1071.001", "name": "Web Protocols", "url": "https://attack.mitre.org/techniques/T1071/001/"},
    {"id": "T1567.002", "name": "Exfiltration to Cloud Storage", "url": "https://attack.mitre.org/techniques/T1567/002/"},
    {"id": "T1550.004", "name": "Web Session Cookie", "url": "https://attack.mitre.org/techniques/T1550/004/"},
    {"id": "T1185", "name": "Browser Session Hijacking", "url": "https://attack.mitre.org/techniques/T1185/"},
    {"id": "T1056.003", "name": "Web Portal Capture", "url": "https://attack.mitre.org/techniques/T1056/003/"},
    {"id": "T1496", "name": "Resource Hijacking", "url": "https://attack.mitre.org/techniques/T1496/"},
    {"id": "T1496.001", "name": "Compute Hijacking", "url": "https://attack.mitre.org/techniques/T1496/001/"},
]

TRACKED_MINER_TOOLS = [
    {"name": "XMRig", "note": "Legitimate open-source RandomX/CryptoNight miner that is also frequently repurposed in cryptojacking. Name alone is not treated as proof of compromise."},
    {"name": "CPUMiner / minerd", "note": "CPU mining software; unexpected background execution with pool traffic and sustained CPU is suspicious."},
    {"name": "T-Rex Miner", "note": "GPU mining software; its presence can be legitimate, so LEDERG correlates command-line and process behavior."},
    {"name": "PhoenixMiner", "note": "GPU mining software; a filename match alone never triggers automatic termination."},
    {"name": "NBMiner / lolMiner", "note": "GPU mining tools; unexpected execution, pool configuration and sustained resource use are correlated."},
    {"name": "GMiner / SRBMiner", "note": "Mining software families monitored through process arguments, CPU activity and network indicators."},
    {"name": "TeamRedMiner / NanoMiner", "note": "Mining tools whose command-line patterns and pool connections can be part of behavioral triage."},
]

PROTECTION_GUIDANCE = [
    {"title": "Microsoft Defender real-time protection", "detail": "Keep real-time protection and cloud-delivered protection enabled. Use LEDERG to start on-demand scans, not to replace Defender.", "source": "https://learn.microsoft.com/en-us/defender-endpoint/run-scan-microsoft-defender-antivirus"},
    {"title": "LSA protection and Credential Guard", "detail": "Use Windows LSA protection / Credential Guard where supported to reduce credential theft from LSASS. Check compatibility before changing system policy.", "source": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection"},
    {"title": "ASR: block credential stealing from LSASS", "detail": "Microsoft documents an Attack Surface Reduction rule for LSASS credential theft. Test policy first; LSA protection may already provide equivalent protection and ASR audit can be noisy.", "source": "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"},
    {"title": "Sysmon endpoint telemetry", "detail": "Optional Sysmon events 1, 3, 10, 11 and 22 can provide process, network, process-access, file-create and DNS-query context. Sysmon is not installed or configured by LEDERG.", "source": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files"},
    {"title": "Valid Authenticode signatures", "detail": "A valid signature is useful for reducing false positives when combined with the expected install path. A signature alone does not prove software is safe.", "source": "https://learn.microsoft.com/powershell/module/microsoft.powershell.security/get-authenticodesignature"},
    {"title": "Session-theft response", "detail": "A stolen authenticated session cookie can let an attacker reuse an already authenticated session and bypass some MFA prompts. It does not reveal the current one-time code or the second factor itself. After suspected infection, use a clean device to revoke all active sessions, sign out all devices, rotate passwords and review recovery methods.", "source": "https://attack.mitre.org/techniques/T1539/"},
    {"title": "Phishing-resistant MFA", "detail": "Prefer passkeys or FIDO2 security keys where supported. MFA reduces account takeover risk, but session-token theft still requires session revocation and endpoint cleanup.", "source": "https://attack.mitre.org/techniques/T1550/004/"},
    {"title": "Updates and multi-factor authentication", "detail": "Keep browsers and password managers updated; use phishing-resistant MFA where available and review stored passwords and active sessions after a suspected infection.", "source": "https://attack.mitre.org/techniques/T1555/"},
]


COMMON_SERVICE_DOMAINS = [
    {"service": "Opera", "domains": ["opera.com"]},
    {"service": "Discord", "domains": ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media"]},
    {"service": "Google / Chrome", "domains": ["google.com", "googleapis.com", "gstatic.com"]},
    {"service": "Microsoft / Windows / Office", "domains": ["microsoft.com", "microsoftonline.com", "office.com", "live.com", "windows.net"]},
    {"service": "Mozilla / Firefox", "domains": ["mozilla.org", "firefox.com"]},
    {"service": "Brave", "domains": ["brave.com"]},
    {"service": "Telegram", "domains": ["telegram.org", "t.me", "telegram.me", "telegram-cdn.org"]},
    {"service": "Steam", "domains": ["steampowered.com", "steamcommunity.com", "steamstatic.com"]},
    {"service": "Spotify", "domains": ["spotify.com", "scdn.co"]},
    {"service": "Slack", "domains": ["slack.com", "slack-edge.com"]},
    {"service": "Zoom", "domains": ["zoom.us"]},
]

THREAT_FEEDS = [
    {"name": "MalwareBazaar", "type": "Known malware file hashes and metadata", "url": "https://bazaar.abuse.ch/api/", "auth": "Community API key required"},
    {"name": "ThreatFox", "type": "Malware-related indicators of compromise", "url": "https://threatfox.abuse.ch/api/", "auth": "Community API key required"},
    {"name": "URLhaus", "type": "Malware distribution URLs and host indicators", "url": "https://urlhaus.abuse.ch/api/", "auth": "Community API key required"},
]

SOURCES = [
    {"name": "MITRE ATT&CK — Vidar", "url": "https://attack.mitre.org/software/S9050/"},
    {"name": "MITRE ATT&CK — XLoader / Formbook", "url": "https://attack.mitre.org/software/S1207/"},
    {"name": "MITRE ATT&CK — Agent Tesla", "url": "https://attack.mitre.org/software/S0331/"},
    {"name": "MITRE ATT&CK — StrelaStealer", "url": "https://attack.mitre.org/software/S1183/"},
    {"name": "MITRE ATT&CK — Steal Web Session Cookie (T1539)", "url": "https://attack.mitre.org/techniques/T1539/"},
    {"name": "MITRE ATT&CK — Web Session Cookie (T1550.004)", "url": "https://attack.mitre.org/techniques/T1550/004/"},
    {"name": "MITRE ATT&CK — Session Cookie Detection (DET0074)", "url": "https://attack.mitre.org/detectionstrategies/DET0074/"},
    {"name": "MITRE ATT&CK — Resource Hijacking (DET0267)", "url": "https://attack.mitre.org/detectionstrategies/DET0267/"},
    {"name": "MITRE ATT&CK — Compute Hijacking (DET0540)", "url": "https://attack.mitre.org/detectionstrategies/DET0540/"},
    {"name": "Recorded Future — 2025 Year in Review", "url": "https://assets.recordedfuture.com/insikt-report-pdfs/2026/cta-2026-0319.pdf"},
    {"name": "Red Canary — Info Stealers 2025", "url": "https://redcanary.com/threat-detection-report/trends/info-stealers/"},
    {"name": "abuse.ch / Spamhaus — malware intelligence feeds", "url": "https://abusech-docs.spamhaus.com/api-reference"},
    {"name": "Microsoft — ASR rules reference", "url": "https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference"},
    {"name": "Microsoft — Sysmon event reference", "url": "https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-configuration-files"},
]
