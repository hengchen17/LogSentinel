# -*- coding: utf-8 -*-
"""
rules.py
========
所有威脅偵測特徵集中於此，方便日後擴充或調整，不需改動主程式邏輯。
可依需求自行新增分類、正則表達式或調整閾值。
"""
import re

# ============================================================
# 1. URL / Payload 特徵比對規則 (不區分大小寫)
#    每個分類回傳一個 compiled regex，符合即判定為該類型攻擊
# ============================================================
THREAT_PATTERNS = {
    "SQL Injection": re.compile(
        r"(union\s+select|select.+from|insert\s+into|update\s+.+set|"
        r"drop\s+table|' or '1'='1|'\s*or\s*1\s*=\s*1|--\s|;--|/\*.*\*/|"
        r"xp_cmdshell|sleep\(\d+\)|benchmark\()",
        re.IGNORECASE,
    ),
    "XSS": re.compile(
        r"(<script|javascript:|onerror\s*=|onload\s*=|<img[^>]+src\s*=|"
        r"alert\(|document\.cookie|<iframe|%3cscript)",
        re.IGNORECASE,
    ),
    "Path Traversal": re.compile(
        r"(\.\./|\.\.%2f|%2e%2e%2f|%2e%2e/|/etc/passwd|/etc/shadow|"
        r"boot\.ini|win\.ini|\.\.\\)",
        re.IGNORECASE,
    ),
    "Command Injection": re.compile(
        r"(;\s*(cat|ls|whoami|id|uname|wget|curl)\b|\|\s*(cat|ls|whoami|id)\b|"
        r"`.*`|\$\(.*\)|&&\s*(cat|ls|whoami))",
        re.IGNORECASE,
    ),
    "Sensitive File Access": re.compile(
        r"(\.env$|\.git/config|\.ssh/id_rsa|wp-config\.php|\.htpasswd|"
        r"web\.config|phpinfo\.php)",
        re.IGNORECASE,
    ),
}

# ============================================================
# 2. 已知惡意 / 掃描工具 User-Agent 關鍵字
# ============================================================
MALICIOUS_UA_KEYWORDS = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirbuster",
    "acunetix", "nessus", "wpscan", "havij", "libwww-perl", "zgrab",
    "python-requests", "hydra",
]

# ============================================================
# 3. 目錄掃描 (Scanner) 偵測閾值
#    在 SCAN_WINDOW 秒內，同一 IP 觸發超過 SCAN_THRESHOLD 次 404
# ============================================================
SCAN_WINDOW = 10       # 單位：秒
SCAN_THRESHOLD = 3     # 觸發警告的 404 次數

# ============================================================
# 4. 暴力破解 / 高頻請求偵測閾值
#    在 BRUTE_FORCE_WINDOW 秒內，同一 IP 對敏感路徑請求超過門檻
# ============================================================
BRUTE_FORCE_WINDOW = 60
BRUTE_FORCE_THRESHOLD = 10
BRUTE_FORCE_PATHS = ("/login", "/wp-login.php", "/admin", "/api/auth", "/signin")

# ============================================================
# 5. 嚴重程度顏色對應 (供報告使用)
# ============================================================
SEVERITY_COLOR = {
    "critical": "#dc2626",
    "high": "#ef4444",
    "medium": "#eab308",
    "low": "#3b82f6",
}

CATEGORY_SEVERITY = {
    "SQL Injection": "critical",
    "Command Injection": "critical",
    "XSS": "high",
    "Path Traversal": "high",
    "Sensitive File Access": "medium",
    "Scanner": "medium",
    "Brute Force": "high",
    "Malicious UA": "low",
}
