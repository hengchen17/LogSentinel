# -*- coding: utf-8 -*-
"""
analyzer.py
===========
核心偵測引擎：逐行比對規則、彙整每個 IP 的行為，
並在讀檔結束後計算掃描器 / 暴力破解等「時間窗口型」攻擊。
"""
import urllib.parse
from collections import defaultdict

from . import rules
from . import parser


class AnalysisResult:
    """保存單次分析所產出的所有結果，供 reporter 使用"""

    def __init__(self):
        self.total_lines = 0
        self.parsed_lines = 0
        self.alerts_by_category = defaultdict(list)   # {category: [alert, ...]}
        self.ip_threat_score = defaultdict(int)        # {ip: score}
        self.malformed_lines = 0

    def add_alert(self, category, alert):
        self.alerts_by_category[category].append(alert)
        severity = rules.CATEGORY_SEVERITY.get(category, "low")
        weight = {"critical": 10, "high": 5, "medium": 3, "low": 1}.get(severity, 1)
        self.ip_threat_score[alert["ip"]] += weight

    @property
    def total_alerts(self):
        return sum(len(v) for v in self.alerts_by_category.values())

    def top_ips(self, n=10):
        return sorted(self.ip_threat_score.items(), key=lambda x: x[1], reverse=True)[:n]


def run_analysis(log_file, progress_callback=None):
    """
    分析指定的日誌檔，回傳 AnalysisResult。
    progress_callback(current_line, total_lines) 可選，用於更新進度條。
    """
    result = AnalysisResult()

    total = parser.count_lines(log_file)
    ip_404_records = defaultdict(list)
    ip_sensitive_hits = defaultdict(list)  # 用於暴力破解偵測

    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for idx, line in enumerate(f, 1):
            result.total_lines += 1
            if progress_callback and idx % 200 == 0:
                progress_callback(idx, total)

            data = parser.parse_line(line)
            if not data:
                result.malformed_lines += 1
                continue

            result.parsed_lines += 1
            ip = data["ip"]
            url = data["url"]
            agent = data.get("agent", "-")
            status_str = data["status"]
            log_time = parser.parse_log_time(data["time"])

            try:
                status = int(status_str)
            except ValueError:
                status = 0

            decoded_url = urllib.parse.unquote(url)

            # 1. URL / Payload 特徵比對 (SQLi, XSS, Path Traversal, Command Injection, Sensitive File)
            #    不再於命中第一個分類後 break：單一 request 可能同時攜帶多種攻擊特徵
            #    (例如 SQLi payload 又指向敏感檔案路徑)，逐一記錄才能反映真實風險，
            #    並在下方額外標記為「複合攻擊」以提高其威脅分數。
            matched_categories = []
            for category, pattern in rules.THREAT_PATTERNS.items():
                if pattern.search(decoded_url):
                    result.add_alert(category, {
                        "line": idx,
                        "ip": ip,
                        "time": data["time"],
                        "payload": decoded_url,
                        "status": status,
                    })
                    matched_categories.append(category)

            if len(matched_categories) >= rules.COMPOUND_ATTACK_MIN_CATEGORIES:
                result.add_alert("Compound Attack", {
                    "line": idx,
                    "ip": ip,
                    "time": data["time"],
                    "payload": f"{decoded_url}  [{' + '.join(matched_categories)}]",
                    "status": status,
                })

            # 2. 惡意 User-Agent
            agent_lower = agent.lower()
            for keyword in rules.MALICIOUS_UA_KEYWORDS:
                if keyword in agent_lower:
                    result.add_alert("Malicious UA", {
                        "line": idx,
                        "ip": ip,
                        "time": data["time"],
                        "payload": f"{keyword} -> {agent}",
                        "status": status,
                    })
                    break

            # 3. 收集 404，供掃描器偵測
            if status == 404 and log_time:
                ip_404_records[ip].append(log_time)

            # 4. 收集敏感路徑請求，供暴力破解偵測
            if log_time and any(decoded_url.startswith(p) for p in rules.BRUTE_FORCE_PATHS):
                ip_sensitive_hits[ip].append(log_time)

    if progress_callback:
        progress_callback(total, total)

    _detect_scanner(result, ip_404_records)
    _detect_brute_force(result, ip_sensitive_hits)

    return result


def _sliding_window_max_count(times, window_seconds):
    """
    找出 window_seconds 秒內最多發生的事件次數。

    以雙指標(two-pointer)取代原本的雙層迴圈：
    times 已依時間排序後單調不減，因此 left 指標只會隨 right 前進而前進，
    整體只會各自走過陣列一次，時間複雜度由 O(n^2) 降為 O(n log n)
    (瓶頸落在排序；掃描本身是 O(n))。當單一 IP 觸發大量事件
    (例如真的被掃描攻擊灌爆 log)時效能提升會很明顯。
    """
    times = sorted(times)
    best = 0
    left = 0
    for right in range(len(times)):
        while (times[right] - times[left]).total_seconds() > window_seconds:
            left += 1
        best = max(best, right - left + 1)
    return best


def _detect_scanner(result, ip_404_records):
    for ip, times in ip_404_records.items():
        max_count = _sliding_window_max_count(times, rules.SCAN_WINDOW)
        if max_count >= rules.SCAN_THRESHOLD:
            result.add_alert("Scanner", {
                "ip": ip,
                "event_count": len(times),
                "message": f"在 {rules.SCAN_WINDOW} 秒內觸發了 {max_count} 次 404，疑似目錄掃描行為",
            })


def _detect_brute_force(result, ip_sensitive_hits):
    for ip, times in ip_sensitive_hits.items():
        max_count = _sliding_window_max_count(times, rules.BRUTE_FORCE_WINDOW)
        if max_count >= rules.BRUTE_FORCE_THRESHOLD:
            result.add_alert("Brute Force", {
                "ip": ip,
                "event_count": len(times),
                "message": f"在 {rules.BRUTE_FORCE_WINDOW} 秒內對登入/敏感路徑發出 {max_count} 次請求，疑似暴力破解",
            })
