# Security Audit Tool (SAT)

Bộ công cụ audit bảo mật Linux theo hướng **defensive**: quét máy local, chấm rủi ro, xuất báo cáo, và có thể tự động remediation các lỗi an toàn.

> Repository này có code chính trong thư mục `sat/`.

---

## 1) SAT làm được gì?

- Quét nhiều lớp bảo mật hệ thống (port, privilege, file permission, secrets, cấu hình SSH/sysctl, CVE, Docker, systemd, user, ...)
- Tính risk score + phân loại severity
- Xuất báo cáo terminal/JSON/HTML
- Baseline & drift detection (so thay đổi theo thời gian)
- Tích hợp AI để tóm tắt rủi ro, attack chain
- Tích hợp Telegram alert / polling bot
- Hỗ trợ remediation (`--fix`, `--dry-run`)

---

## 2) Cấu trúc repo

```text
security_audit_tool/
├── sat/                    # core source code + modules + tests
│   ├── main.py            # CLI entrypoint
│   ├── ...
│   └── README.md          # tài liệu chuyên sâu của SAT
├── Makefile
├── CHANGELOG.md
├── CONTRIBUTING.md
└── README.md              # file này
```

Tài liệu chuyên sâu (đầy đủ module + API):
- `sat/README.md`

---

## 3) Cài đặt nhanh

### Yêu cầu
- Linux
- Python 3.10+

### Cài bằng Make (khuyến nghị)

```bash
git clone https://github.com/nmhuei/security_audit_tool.git
cd security_audit_tool

make venv
source .venv/bin/activate
```

### Cài thủ công

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r sat/requirements.txt
```

### (Tuỳ chọn) cài tool ngoài để scan sâu hơn

```bash
sudo apt-get install -y lynis nmap chkrootkit rkhunter trivy aide nikto
```

---

## 4) Cách dùng nhanh (most useful)

> Tất cả lệnh chạy trong thư mục `sat/`.

```bash
cd sat
```

### Quét cơ bản

```bash
python3 main.py scan
```

### Quét sâu

```bash
python3 main.py scan --deep
```

### Remediation

```bash
python3 main.py scan --fix --dry-run   # chỉ preview
python3 main.py scan --fix             # apply thật
```

### Baseline / Drift

```bash
python3 main.py scan --save-baseline
python3 main.py diff
```

### Xem help đầy đủ

```bash
python3 main.py --help
python3 main.py scan --help
```

---

## 5) Telegram & Scheduler

### Telegram

```bash
# gửi 1 lần
python3 main.py telegram --token "BOT_TOKEN" --chat-id "CHAT_ID" --mode once

# bot polling (/scan, /report)
python3 main.py telegram --token "BOT_TOKEN" --chat-id "CHAT_ID" --mode poll
```

### Lên lịch quét

```bash
python3 main.py schedule install --freq daily
python3 main.py schedule status

# hoặc backend cron
python3 main.py schedule install --backend cron
```

---

## 6) Cấu hình AI provider (tuỳ chọn)

Set bằng `.env` hoặc biến môi trường:

```bash
# Anthropic
ANTHROPIC_API_KEY=...

# OpenAI
OPENAI_API_KEY=...

# Ollama
OLLAMA_HOST=http://localhost:11434

# Gemini
GOOGLE_API_KEY=...
```

---

## 7) Luồng đề xuất cho production

1. `scan --deep` để lấy baseline đầu tiên
2. fix an toàn bằng `--fix --dry-run` rồi `--fix`
3. lưu baseline (`--save-baseline`)
4. cài scheduler quét định kỳ
5. bật Telegram alert nếu cần thông báo realtime

---

## 8) Development

```bash
make test
make test-cov
make lint
make check
```

---

## 9) Lưu ý an toàn

- Tool này thiết kế cho **defensive auditing**
- Quét local machine, không phải framework tấn công
- Khi remediation liên quan root/system service: luôn chạy dry-run trước
- Với finding kiểu rootkit, cần manual incident response thay vì auto-fix

---

## 10) Link nhanh

- Tài liệu chi tiết: `sat/README.md`
- Đóng góp: `CONTRIBUTING.md`
- Changelog: `CHANGELOG.md`
- License: `LICENSE`
