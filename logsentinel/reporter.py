# -*- coding: utf-8 -*-
"""
reporter.py
===========
將 AnalysisResult 轉換成一份美化、互動式的 HTML 資安報告
(Tailwind CSS + Chart.js，純前端渲染，離線也可開啟查看，僅圖表/字型需連網 CDN)。
"""
import json
from datetime import datetime

from . import rules

CATEGORY_COLORS = {
    "SQL Injection": "#ef4444",
    "XSS": "#f97316",
    "Path Traversal": "#eab308",
    "Command Injection": "#dc2626",
    "Sensitive File Access": "#a855f7",
    "Malicious UA": "#3b82f6",
    "Scanner": "#facc15",
    "Brute Force": "#ec4899",
}


def _severity_badge(category):
    severity = rules.CATEGORY_SEVERITY.get(category, "low")
    color = rules.SEVERITY_COLOR.get(severity, "#6b7280")
    return severity, color


def generate_html_report(result, output_file="report.html", log_file_name=""):
    """依 AnalysisResult 產生單一自包含的 HTML 報告檔"""

    categories = list(result.alerts_by_category.keys())
    category_counts = {c: len(result.alerts_by_category[c]) for c in categories}
    safe_count = max(0, result.parsed_lines - result.total_alerts)

    top_ips = result.top_ips(10)

    # 各分類的表格資料（URL / Payload 類型 vs 事件型）
    payload_categories = [c for c in categories if c not in ("Scanner", "Brute Force")]
    event_categories = [c for c in categories if c in ("Scanner", "Brute Force")]

    payload_rows = []
    for cat in payload_categories:
        severity, color = _severity_badge(cat)
        for a in result.alerts_by_category[cat]:
            payload_rows.append({
                "category": cat,
                "severity": severity,
                "color": color,
                "line": a.get("line", "-"),
                "ip": a.get("ip", "-"),
                "time": a.get("time", "-"),
                "payload": a.get("payload", "-"),
            })

    event_rows = []
    for cat in event_categories:
        severity, color = _severity_badge(cat)
        for a in result.alerts_by_category[cat]:
            event_rows.append({
                "category": cat,
                "severity": severity,
                "color": color,
                "ip": a.get("ip", "-"),
                "event_count": a.get("event_count", "-"),
                "message": a.get("message", "-"),
            })

    chart_labels = categories + (["安全連線"] if safe_count else [])
    chart_data = [category_counts[c] for c in categories] + ([safe_count] if safe_count else [])
    chart_colors = [CATEGORY_COLORS.get(c, "#6b7280") for c in categories] + (["#22c55e"] if safe_count else [])

    top_ip_labels = [ip for ip, _ in top_ips]
    top_ip_scores = [score for _, score in top_ips]

    payload_json = json.dumps(payload_rows, ensure_ascii=False)
    event_json = json.dumps(event_rows, ensure_ascii=False)

    stat_cards = "".join(f"""
            <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-sm border-l-4"
                 style="border-left-color: {CATEGORY_COLORS.get(cat, '#6b7280')}">
                <p class="text-xs text-gray-400 font-medium truncate">{cat}</p>
                <p class="text-2xl font-bold mt-2" style="color: {CATEGORY_COLORS.get(cat, '#e5e7eb')}">{category_counts[cat]}</p>
            </div>""" for cat in categories)

    html_template = f"""<!DOCTYPE html>
<html lang="zh-TW">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LogSentinel 資安威脅分析報告</title>
    <link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>🛡️</text></svg>">
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {{ font-family: 'Segoe UI', 'Noto Sans TC', sans-serif; }}
        ::-webkit-scrollbar {{ height: 8px; width: 8px; }}
        ::-webkit-scrollbar-thumb {{ background: #4b5563; border-radius: 4px; }}
        .badge {{ display: inline-block; padding: 2px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; color: #0b0f19; }}
    </style>
</head>
<body class="bg-gray-900 text-gray-100 min-h-screen">
    <nav class="bg-gray-800/80 backdrop-blur border-b border-gray-700 py-4 px-8 shadow-md sticky top-0 z-20">
        <div class="max-w-7xl mx-auto flex flex-wrap justify-between items-center gap-2">
            <h1 class="text-xl font-bold text-red-500 tracking-wider">🛡️ LogSentinel IDS 分析報告</h1>
            <div class="text-sm text-gray-400 flex gap-4">
                <span>來源檔案：<span class="text-gray-200">{log_file_name or '未指定'}</span></span>
                <span>生成時間：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            </div>
        </div>
    </nav>

    <main class="max-w-7xl mx-auto px-4 py-8 sm:px-6 lg:px-8">

        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-sm">
                <p class="text-xs text-gray-400 font-medium">總分析日誌行數</p>
                <p class="text-2xl font-bold text-blue-400 mt-2">{result.total_lines}</p>
            </div>
            <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-sm">
                <p class="text-xs text-gray-400 font-medium">成功解析行數</p>
                <p class="text-2xl font-bold text-indigo-400 mt-2">{result.parsed_lines}</p>
            </div>
            <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-sm">
                <p class="text-xs text-gray-400 font-medium">總威脅事件數</p>
                <p class="text-2xl font-bold text-red-400 mt-2">{result.total_alerts}</p>
            </div>
            <div class="bg-gray-800 p-5 rounded-xl border border-gray-700 shadow-sm">
                <p class="text-xs text-gray-400 font-medium">安全 / 正常連線</p>
                <p class="text-2xl font-bold text-green-400 mt-2">{safe_count}</p>
            </div>
        </div>

        <div class="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            {stat_cards if stat_cards else '<p class="text-green-400 col-span-4">✔ 未偵測到任何分類威脅</p>'}
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
            <div class="bg-gray-800 p-6 rounded-xl border border-gray-700 lg:col-span-1 flex flex-col items-center">
                <h3 class="text-md font-semibold text-gray-200 mb-4 self-start">威脅類型分佈</h3>
                <div class="w-full max-w-[260px]"><canvas id="threatChart"></canvas></div>
            </div>
            <div class="bg-gray-800 p-6 rounded-xl border border-gray-700 lg:col-span-2">
                <h3 class="text-md font-semibold text-gray-200 mb-4">高風險來源 IP Top 10 (威脅分數)</h3>
                <div class="h-72"><canvas id="ipChart"></canvas></div>
            </div>
        </div>

        <div class="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden mb-8">
            <div class="px-6 py-4 border-b border-gray-700 flex flex-wrap justify-between items-center gap-3">
                <h3 class="text-md font-semibold text-red-400">🚨 攻擊 Payload 偵測紀錄 ({len(payload_rows)})</h3>
                <div class="flex gap-2">
                    <input id="payloadSearch" type="text" placeholder="搜尋 IP / Payload..."
                           class="bg-gray-900 border border-gray-700 rounded-lg px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-red-500 w-56">
                    <button onclick="exportCSV('payload')" class="bg-gray-700 hover:bg-gray-600 text-xs px-3 py-1.5 rounded-lg text-gray-200">匯出 CSV</button>
                </div>
            </div>
            <div class="overflow-x-auto max-h-[420px] overflow-y-auto">
                <table class="min-w-full divide-y divide-gray-700 text-left text-sm text-gray-300">
                    <thead class="bg-gray-900 text-gray-400 uppercase text-xs sticky top-0">
                        <tr>
                            <th class="px-6 py-3">類型</th>
                            <th class="px-6 py-3">行號</th>
                            <th class="px-6 py-3">來源 IP</th>
                            <th class="px-6 py-3">時間</th>
                            <th class="px-6 py-3">可疑 Payload</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700" id="payload-table-body"></tbody>
                </table>
            </div>
        </div>

        <div class="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
            <div class="px-6 py-4 border-b border-gray-700 flex flex-wrap justify-between items-center gap-3">
                <h3 class="text-md font-semibold text-yellow-400">⚠️ 行為型異常紀錄 (掃描 / 暴力破解) ({len(event_rows)})</h3>
                <button onclick="exportCSV('event')" class="bg-gray-700 hover:bg-gray-600 text-xs px-3 py-1.5 rounded-lg text-gray-200">匯出 CSV</button>
            </div>
            <div class="overflow-x-auto">
                <table class="min-w-full divide-y divide-gray-700 text-left text-sm text-gray-300">
                    <thead class="bg-gray-900 text-gray-400 uppercase text-xs">
                        <tr>
                            <th class="px-6 py-3">類型</th>
                            <th class="px-6 py-3">來源 IP</th>
                            <th class="px-6 py-3">觸發次數</th>
                            <th class="px-6 py-3">判定說明</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-gray-700" id="event-table-body"></tbody>
                </table>
            </div>
        </div>
    </main>

    <footer class="text-center py-8 text-xs text-gray-500 border-t border-gray-800 mt-12">
        <p>Generated by LogSentinel Analyser Engine · <a href="https://github.com/" class="underline hover:text-gray-300">github.com</a></p>
    </footer>

    <script>
        const payloadData = {payload_json};
        const eventData = {event_json};

        function severityBadge(sev, color) {{
            return `<span class="badge" style="background:${{color}}">${{sev.toUpperCase()}}</span>`;
        }}

        function renderPayloadTable(rows) {{
            const body = document.getElementById('payload-table-body');
            if (rows.length === 0) {{
                body.innerHTML = `<tr><td colspan="5" class="px-6 py-4 text-center text-green-400">✔ 未偵測到任何攻擊 Payload</td></tr>`;
                return;
            }}
            body.innerHTML = rows.map(item => `<tr>
                <td class="px-6 py-4">${{severityBadge(item.severity, item.color)}}<div class="text-xs text-gray-400 mt-1">${{item.category}}</div></td>
                <td class="px-6 py-4 font-mono text-gray-500">${{item.line}}</td>
                <td class="px-6 py-4 text-cyan-400 font-semibold">${{item.ip}}</td>
                <td class="px-6 py-4 text-gray-400">${{item.time}}</td>
                <td class="px-6 py-4 font-mono text-red-300 bg-gray-900 rounded px-2 py-1 select-all inline-block break-all">${{item.payload}}</td>
            </tr>`).join('');
        }}

        function renderEventTable(rows) {{
            const body = document.getElementById('event-table-body');
            if (rows.length === 0) {{
                body.innerHTML = `<tr><td colspan="4" class="px-6 py-4 text-center text-green-400">✔ 未偵測到異常行為</td></tr>`;
                return;
            }}
            body.innerHTML = rows.map(item => `<tr>
                <td class="px-6 py-4">${{severityBadge(item.severity, item.color)}}<div class="text-xs text-gray-400 mt-1">${{item.category}}</div></td>
                <td class="px-6 py-4 text-cyan-400 font-semibold">${{item.ip}}</td>
                <td class="px-6 py-4 text-yellow-500 font-bold">${{item.event_count}} 次</td>
                <td class="px-6 py-4 text-gray-400">${{item.message}}</td>
            </tr>`).join('');
        }}

        renderPayloadTable(payloadData);
        renderEventTable(eventData);

        document.getElementById('payloadSearch').addEventListener('input', (e) => {{
            const q = e.target.value.toLowerCase();
            const filtered = payloadData.filter(r =>
                r.ip.toLowerCase().includes(q) || r.payload.toLowerCase().includes(q) || r.category.toLowerCase().includes(q));
            renderPayloadTable(filtered);
        }});

        function exportCSV(which) {{
            const rows = which === 'payload' ? payloadData : eventData;
            if (!rows.length) return;
            const headers = Object.keys(rows[0]).filter(k => k !== 'color');
            const csv = [headers.join(',')].concat(
                rows.map(r => headers.map(h => `"${{String(r[h]).replace(/"/g, '""')}}"`).join(','))
            ).join('\\n');
            const blob = new Blob([csv], {{ type: 'text/csv;charset=utf-8;' }});
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `logsentinel_${{which}}.csv`;
            a.click();
            URL.revokeObjectURL(url);
        }}

        new Chart(document.getElementById('threatChart').getContext('2d'), {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(chart_labels, ensure_ascii=False)},
                datasets: [{{ data: {json.dumps(chart_data)}, backgroundColor: {json.dumps(chart_colors)}, borderWidth: 0 }}]
            }},
            options: {{ plugins: {{ legend: {{ position: 'bottom', labels: {{ color: '#d1d5db', boxWidth: 12 }} }} }} }}
        }});

        new Chart(document.getElementById('ipChart').getContext('2d'), {{
            type: 'bar',
            data: {{
                labels: {json.dumps(top_ip_labels)},
                datasets: [{{
                    label: '威脅分數',
                    data: {json.dumps(top_ip_scores)},
                    backgroundColor: '#f43f5e',
                    borderRadius: 6,
                }}]
            }},
            options: {{
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                scales: {{
                    x: {{ grid: {{ color: '#374151' }}, ticks: {{ color: '#9ca3af' }} }},
                    y: {{ grid: {{ display: false }}, ticks: {{ color: '#9ca3af' }} }}
                }},
                plugins: {{ legend: {{ display: false }} }}
            }}
        }});
    </script>
</body>
</html>
"""
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html_template)
    return output_file
