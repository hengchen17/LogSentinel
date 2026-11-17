# -*- coding: utf-8 -*-
"""
tests/test_analyzer.py
=======================
針對本次修改的兩個項目撰寫測試：
1. _sliding_window_max_count 的正確性 (與原本 O(n^2) 版本行為一致)
   以及在大量事件下的效能。
2. 複合攻擊 (Compound Attack) 偵測：單一 request 同時命中多種
   威脅特徵時，應個別記錄每個分類，並額外產生一筆 Compound Attack 警報。

執行方式：
    pip install pytest
    pytest tests/ -v
"""
import time
from datetime import datetime, timedelta

import pytest

from logsentinel import analyzer, rules


# ------------------------------------------------------------------
# 1. 滑動窗口演算法
# ------------------------------------------------------------------

def _naive_sliding_window_max_count(times, window_seconds):
    """保留原本 O(n^2) 實作，作為正確性比對的基準 (ground truth)"""
    times = sorted(times)
    best = 0
    for i in range(len(times)):
        count = 0
        for j in range(i, len(times)):
            if (times[j] - times[i]).total_seconds() <= window_seconds:
                count += 1
            else:
                break
        best = max(best, count)
    return best


def test_sliding_window_empty():
    assert analyzer._sliding_window_max_count([], 10) == 0


def test_sliding_window_single_event():
    base = datetime(2026, 1, 1, 0, 0, 0)
    assert analyzer._sliding_window_max_count([base], 10) == 1


def test_sliding_window_matches_naive_on_random_bursts():
    """隨機產生多組事件時間，比對新舊實作是否一致"""
    import random
    random.seed(42)
    base = datetime(2026, 1, 1, 0, 0, 0)

    for _ in range(20):
        times = [base + timedelta(seconds=random.randint(0, 120)) for _ in range(50)]
        window = random.choice([5, 10, 30, 60])
        expected = _naive_sliding_window_max_count(times, window)
        actual = analyzer._sliding_window_max_count(times, window)
        assert actual == expected, f"window={window} times={times}"


def test_sliding_window_detects_burst_within_threshold():
    base = datetime(2026, 1, 1, 0, 0, 0)
    # 10 秒內連續 5 次 404 -> 應偵測到 5
    times = [base + timedelta(seconds=i) for i in range(5)]
    assert analyzer._sliding_window_max_count(times, 10) == 5


def test_sliding_window_performance_on_large_input():
    """
    大量事件（模擬單一 IP 被灌爆 log）情境下，
    優化後的版本應該在合理時間內完成（舊版 O(n^2) 在 n=5000 時會明顯變慢）。
    """
    base = datetime(2026, 1, 1, 0, 0, 0)
    times = [base + timedelta(milliseconds=i * 10) for i in range(5000)]  # 50 秒內 5000 筆

    start = time.perf_counter()
    result = analyzer._sliding_window_max_count(times, 10)
    elapsed = time.perf_counter() - start

    assert result > 0
    assert elapsed < 1.0, f"優化後仍花費 {elapsed:.2f}s，可能未正確套用雙指標邏輯"


# ------------------------------------------------------------------
# 2. 複合攻擊偵測
# ------------------------------------------------------------------

def _make_log_line(ip, url, status=200, ua="Mozilla/5.0"):
    return (
        f'{ip} - - [10/Aug/2026:12:00:00 +0800] '
        f'"GET {url} HTTP/1.1" {status} 512 "-" "{ua}"\n'
    )


def test_single_category_still_recorded_normally(tmp_path):
    """只命中一種攻擊特徵時，行為應與修改前一致：不產生 Compound Attack"""
    log_file = tmp_path / "single.log"
    # log 的 URL 欄位不能含真正的空白字元，這裡用 %20 模擬瀏覽器/客戶端會做的
    # URL 編碼，analyzer 內部會用 urllib.parse.unquote 還原成 "1' OR '1'='1"
    log_file.write_text(_make_log_line("1.1.1.1", "/?id=1%27%20OR%20%271%27=%271"), encoding="utf-8")

    result = analyzer.run_analysis(str(log_file))

    assert "SQL Injection" in result.alerts_by_category
    assert "Compound Attack" not in result.alerts_by_category


def test_compound_attack_detected_when_multiple_categories_match(tmp_path):
    """
    構造一個同時符合 SQL Injection 與 Sensitive File Access 特徵的 payload，
    應該同時記錄兩個分類的警報，並額外產生一筆 Compound Attack。
    """
    log_file = tmp_path / "compound.log"
    # 同時命中 Path Traversal ("../") 與 Sensitive File Access (".env" 結尾)
    # 這也是實務上常見的複合攻擊手法：用目錄遍歷繞到 .env 等敏感檔案
    payload_url = "/static/../../../.env"
    log_file.write_text(_make_log_line("2.2.2.2", payload_url), encoding="utf-8")

    result = analyzer.run_analysis(str(log_file))

    assert "Path Traversal" in result.alerts_by_category
    assert "Sensitive File Access" in result.alerts_by_category
    assert "Compound Attack" in result.alerts_by_category
    assert len(result.alerts_by_category["Compound Attack"]) == 1

    compound_alert = result.alerts_by_category["Compound Attack"][0]
    assert compound_alert["ip"] == "2.2.2.2"
    assert "Path Traversal" in compound_alert["payload"]
    assert "Sensitive File Access" in compound_alert["payload"]


def test_compound_attack_increases_ip_threat_score(tmp_path):
    """複合攻擊的 IP 威脅分數應高於只命中單一分類的情況"""
    single_log = tmp_path / "single.log"
    single_log.write_text(_make_log_line("3.3.3.1", "/?id=1%27%20OR%20%271%27=%271"), encoding="utf-8")

    compound_log = tmp_path / "compound.log"
    compound_log.write_text(
        _make_log_line("3.3.3.2", "/static/../../../.env"),
        encoding="utf-8",
    )

    single_result = analyzer.run_analysis(str(single_log))
    compound_result = analyzer.run_analysis(str(compound_log))

    single_score = single_result.ip_threat_score["3.3.3.1"]
    compound_score = compound_result.ip_threat_score["3.3.3.2"]

    assert compound_score > single_score


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
