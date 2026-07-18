# -*- coding: utf-8 -*-
"""
cli.py
======
LogSentinel 命令列進入點，負責參數解析、進度顯示與終端機報告輸出。
"""
import argparse
import sys
import webbrowser

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, BarColumn, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from . import analyzer, rules

console = Console()


def parse_args(argv=None):
    p = argparse.ArgumentParser(
        prog="logsentinel",
        description="🛡️ LogSentinel - Nginx / Apache 存取日誌威脅分析與入侵偵測工具",
    )
    p.add_argument("logfile", nargs="?", default="sample_logs/mock_access.log",
                    help="要分析的日誌檔案路徑 (預設: sample_logs/mock_access.log)")
    p.add_argument("-o", "--output", default="report.html",
                    help="輸出 HTML 報告檔名 (預設: report.html)")
    p.add_argument("--open", action="store_true",
                    help="分析完成後自動用瀏覽器開啟報告")
    p.add_argument("--quiet", action="store_true",
                    help="僅輸出摘要，不列出完整威脅表格")
    return p.parse_args(argv)


def _print_summary_table(title, style, rows, columns):
    table = Table(show_header=True, header_style=f"bold {style}", box=None)
    for col, width in columns:
        table.add_column(col, width=width)
    for row in rows:
        table.add_row(*row)
    console.print(f"\n[bold {style}]{title}[/bold {style}]")
    console.print(table)


def main(argv=None):
    args = parse_args(argv)

    console.print(
        Panel.fit(
            "[bold red]🛡️ LogSentinel[/bold red] [dim]v2.0[/dim]\n"
            "[dim]惡意流量分析與入侵偵測系統 — SQLi / XSS / Path Traversal / Scanner / Brute Force[/dim]",
            border_style="magenta",
        )
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        transient=True,
    ) as progress:
        task = progress.add_task("[cyan]解析日誌檔案...[/cyan]", total=None)

        def on_progress(current, total):
            if progress.tasks[0].total is None and total:
                progress.update(task, total=total)
            progress.update(task, completed=current)

        try:
            result = analyzer.run_analysis(args.logfile, progress_callback=on_progress)
        except FileNotFoundError:
            console.print(f"[bold red]❌ 錯誤：找不到日誌檔 {args.logfile}[/bold red]")
            sys.exit(1)

    console.print(
        f"[green]✔ 完成：共 {result.total_lines} 行，成功解析 {result.parsed_lines} 行，"
        f"偵測到 {result.total_alerts} 個威脅事件。[/green]"
    )

    if not args.quiet:
        for category, alerts in result.alerts_by_category.items():
            if category in ("Scanner", "Brute Force"):
                rows = [(a["ip"], f"{a['event_count']} 次", a["message"]) for a in alerts]
                _print_summary_table(f"⚠️ [{category}]", "yellow", rows,
                                      [("來源 IP", 16), ("次數", 8), ("判定說明", None)])
            else:
                rows = [(str(a["line"]), a["ip"], a["time"], a["payload"][:80]) for a in alerts]
                _print_summary_table(f"🚨 [{category}]", "red", rows,
                                      [("行號", 6), ("來源 IP", 16), ("時間", 22), ("Payload", None)])

        if not result.alerts_by_category:
            console.print("\n[green]✔ 未偵測到任何威脅，日誌狀態正常。[/green]")

        top_ips = result.top_ips(5)
        if top_ips:
            rows = [(ip, str(score)) for ip, score in top_ips]
            _print_summary_table("🔥 高風險來源 IP Top 5", "magenta", rows,
                                  [("來源 IP", 20), ("威脅分數", None)])

    from . import reporter
    output_path = reporter.generate_html_report(result, args.output, log_file_name=args.logfile)
    console.print(f"\n[bold green]✨ 報告已產生：{output_path}[/bold green]\n")

    if args.open:
        webbrowser.open(output_path)


if __name__ == "__main__":
    main()
