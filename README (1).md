# 🛡️ LogSentinel

**輕量級 Nginx / Apache 存取日誌威脅分析與入侵偵測工具**

以純 Python 撰寫，無需資料庫或第三方服務。輸入一份 access log，
即可自動偵測 SQL Injection、XSS、路徑遍歷、指令注入、敏感檔案存取、
惡意掃描工具與暴力破解等攻擊行為，並產出一份美觀、可互動的 HTML 分析報告。

![CI](https://github.com/hengchen17/LogSentinel/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

---

## ✨ 功能特色

- **多種攻擊偵測**：SQL Injection、XSS、Path Traversal、Command Injection、
  敏感檔案存取（`.env`、`.git/config` 等）
- **複合攻擊 (Compound Attack) 標記**：單一請求同時命中多種攻擊特徵時
  （例如路徑遍歷繞到 `.env`），會額外標記為複合攻擊並提高該 IP 的威脅分數，
  避免低估組合式攻擊手法的風險
- **行為型偵測**：時間窗口式目錄掃描器偵測（雙指標演算法，O(n log n)）、
  暴力破解 (brute-force) 偵測
- **惡意 UA 識別**：內建 sqlmap / nikto / nmap 等常見掃描工具特徵庫
- **威脅分數排名**：自動彙整每個來源 IP 的威脅分數，找出最危險的攻擊者
- **美化終端輸出**：以 [rich](https://github.com/Textualize/rich) 呈現進度條與彩色表格
- **互動式 HTML 報告**：Tailwind CSS + Chart.js，含分類圖表、Top IP 長條圖、
  即時搜尋、CSV 匯出
- **規則可擴充**：所有偵測特徵集中於 `logsentinel/rules.py`，新增規則不需改動主程式
- **支援標準日誌格式**：Nginx / Apache 的 Common 與 Combined Log Format

## 📁 專案結構

```
logsentinel/
├── logsentinel/
│   ├── __init__.py
│   ├── rules.py         # 攻擊特徵、UA 黑名單、閾值設定
│   ├── parser.py        # 日誌解析 (Common / Combined Log Format)
│   ├── analyzer.py       # 核心偵測引擎
│   ├── reporter.py       # HTML 報告產生器
│   └── cli.py            # 命令列進入點
├── sample_logs/
│   └── mock_access.log   # 含攻擊樣本的模擬日誌，方便直接體驗
├── tests/
│   └── test_analyzer.py  # 滑動窗口效能/正確性、複合攻擊偵測等單元測試
├── run.py                 # 執行進入點
├── requirements.txt
└── .github/workflows/ci.yml
```

## 🚀 快速開始

```bash
# 1. 安裝相依套件
pip install -r requirements.txt

# 2. 用內建的模擬日誌試跑（含 SQLi / XSS / 掃描器等攻擊樣本）
python run.py sample_logs/mock_access.log

# 3. 分析你自己的 Nginx / Apache access log
python run.py /var/log/nginx/access.log -o my_report.html --open
```

### 命令列參數

| 參數 | 說明 | 預設值 |
|---|---|---|
| `logfile` | 要分析的日誌檔路徑 | `sample_logs/mock_access.log` |
| `-o, --output` | 輸出的 HTML 報告檔名 | `report.html` |
| `--open` | 分析完成後自動用瀏覽器開啟報告 | 關閉 |
| `--quiet` | 終端機只顯示摘要，不列出完整表格 | 關閉 |

## 🔧 自訂偵測規則

所有規則都定義在 `logsentinel/rules.py`，例如新增一組正則表達式即可擴充分類：

```python
THREAT_PATTERNS["Log4Shell"] = re.compile(r"\$\{jndi:(ldap|rmi)://", re.IGNORECASE)
```

掃描器與暴力破解的靈敏度也可直接調整：

```python
SCAN_WINDOW = 10          # 10 秒內
SCAN_THRESHOLD = 3        # 超過 3 次 404 視為掃描行為
BRUTE_FORCE_THRESHOLD = 10
```

## 🧪 執行測試

```bash
pip install pytest
pytest tests/ -v
```

涵蓋滑動窗口演算法的正確性與效能、以及複合攻擊判定邏輯。

## 📤 上傳到 GitHub

```bash
cd logsentinel
git init
git add .
git commit -m "Initial commit: LogSentinel v2.0"
git branch -M main
git remote add origin https://github.com/<你的帳號>/<你的repo>.git
git push -u origin main
```

> 若尚未建立遠端 repo，先到 GitHub 建立一個空的 repository（不要初始化 README），
> 再貼上系統提供的 `git remote add origin ...` 指令即可。

## ⚠️ 使用聲明

本工具僅用於分析你自己擁有或已獲授權管理之伺服器日誌，屬於**防禦性**資安工具，
不含任何攻擊或漏洞利用功能。請遵守當地法律與相關資安規範。

## 📄 授權

[MIT License](LICENSE)
