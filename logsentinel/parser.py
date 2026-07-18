# -*- coding: utf-8 -*-
"""
parser.py
=========
負責將 Nginx / Apache 存取日誌逐行解析為結構化資料。
同時支援標準 Common Log Format (CLF) 與 Combined Log Format
(多了 Referer 與 User-Agent 欄位)。
"""
import re
from datetime import datetime

# Combined Log Format：CLF 欄位 + 可選的 referer / user-agent
LOG_LINE_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


def parse_log_time(time_str):
    """將 Log 的時間字串轉換為 datetime 物件，失敗時回傳 None"""
    try:
        time_clean = time_str.split(" ")[0]
        return datetime.strptime(time_clean, "%d/%b/%Y:%H:%M:%S")
    except (ValueError, IndexError):
        return None


def parse_line(line):
    """解析單行 Log，成功傳回 dict，失敗傳回 None"""
    line = line.strip()
    if not line:
        return None
    match = LOG_LINE_REGEX.match(line)
    if not match:
        return None
    data = match.groupdict()
    # Combined format 沒有 referer/agent 時給預設值，避免下游 KeyError
    data["referer"] = data.get("referer") or "-"
    data["agent"] = data.get("agent") or "-"
    return data


def count_lines(filepath):
    """快速計算檔案總行數，用於進度條顯示真實進度"""
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for _ in f)
