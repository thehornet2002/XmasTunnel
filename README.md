# XmasTunnel 🎄
### Secure AES-256-GCM Encrypted TCP Tunnel with Low-Level Packet & Flag Inspection Engine

---

## معرفی پروژه (Project Overview)

پروژه **XmasTunnel** یک سامانه ماژولار و مهندسی‌شده کلاینت-سرور برای ایجاد **تونل‌های TCP رمزنگاری‌شده با AES-256-GCM** همراه با ماژول اختصاصی **کنترل و تحلیل بسته‌های سطح پایین شبکه و فلگ‌های هدر TCP** (`FIN, SYN, RST, PSH, ACK, URG, ECE, CWR`) است.

این نرم‌افزار با تفکیک کامل پشته انتقال قابل اتکا از دسترسی سطح پایین شبکه پیاده‌سازی شده و از کتابخانه‌های استاندارد رمزنگاری و استانداردهای RFC برای محاسبه Checksum و مدیریت بسته استفاده می‌کند.

---

## ساختار پروژه (Directory Structure)

```
XmasTunnel/
├── xmastunnel/
│   ├── crypto/                 # لایه رمزنگاری و مدیریت کلید
│   │   ├── aes_gcm.py          # پیاده‌سازی AES-256-GCM و تایید اصالت تگ
│   │   ├── kdf.py              # مشتق‌سازی کلید با HKDF-SHA256 و PBKDF2
│   │   └── nonce_manager.py    # مدیریت Nonce بدون تکرار و پنجره ضد بازپخش (Anti-Replay)
│   ├── protocol/               # پروتکل داخلی و ماشین حالت
│   │   ├── frame.py            # قاب‌بندی ۲۴ بایتی باینری و بافر جریان
│   │   └── state_machine.py    # ماشین حالت پروتکل مستقل از فلگ‌های TCP
│   ├── transport/              # لایه انتقال شبکه
│   │   └── tcp_transport.py    # سوکت‌های TCP با TCP_NODELAY، محدودساز نرخ و Timeout
│   ├── session/                # مدیریت نشست‌ها
│   │   ├── session.py          # فرآیند Handshake چهار مرحله‌ای و چرخش کلید
│   │   └── session_manager.py  # مدیریت چرخه حیات نشست‌ها و انقضای نشست‌های غیرفعال
│   ├── packet_engine/          # موتور سطح پایین بسته‌ها و فلگ‌های TCP
│   │   ├── flags.py            # بیت‌ماسک فلگ‌های TCP و پروفایل‌های آزمایشی
│   │   ├── checksum.py         # الگوریتم چک‌سام RFC 1071 و Pseudo-Header
│   │   ├── packet.py           # هدرهای IPv4/TCP و اعتبارسنجی بسته‌های خام
│   │   └── raw_engine.py       # موتور بسته‌های خام و تحلیل محدودیت‌های سیستم‌عامل
│   ├── config/                 # تنظیمات و لاگینگ امن
│   │   ├── config.py           # کلاس‌های پیکربندی کلاینت، سرور و آزمون
│   │   └── logger.py           # لاگر با فیلتر خودکار کلیدها و داده‌های حساس
│   ├── server.py               # سرور اصلی تونل
│   ├── client.py               # کلاینت اصلی تونل
│   └── cli.py                  # رابط خط فرمان (CLI)
├── tests/                      # آزمون‌های واحد، یکپارچگی و امنیتی
│   ├── test_crypto.py
│   ├── test_protocol.py
│   ├── test_session.py
│   ├── test_transport.py
│   ├── test_packet_engine.py
│   └── test_integration.py
├── docs/                       # مستندات فنی
│   ├── ARCHITECTURE.md
│   ├── PROTOCOL.md
│   ├── LOW_LEVEL_NETWORKING.md
│   └── SECURITY.md
├── scripts/                    # اسکریپت‌های آماده راه‌اندازی برای لینوکس و ویندوز
│   ├── install_ubuntu.sh       # اسکریپت نصب یک‌دستوری در اوبونتو
│   ├── server_ubuntu.sh        # راه‌اندازی خودکار سرور در اوبونتو
│   ├── client_ubuntu.sh        # راه‌اندازی خودکار کلاینت در اوبونتو
│   ├── server_windows.ps1      # راه‌اندازی خودکار سرور در ویندوز (PowerShell)
│   ├── client_windows.ps1      # راه‌اندازی خودکار کلاینت در ویندوز (PowerShell)
│   ├── server_windows.bat      # لانچر سریع سرور ویندوز
│   └── client_windows.bat      # لانچر سریع کلاینت ویندوز
├── install.sh                  # اسکریپت نصب یک‌دستوری سیستم با venv و دسترسی‌های لینوکس
├── requirements.txt
├── config_server.json
└── config_client.json
```

---

## نیازمندی‌ها و نصب (Installation)

### نصب با یک دستور در سرور و کلاینت اوبونتو (One-Command Installer):

این دستور به طور خودکار وابستگی‌های سیستمی (`python3-venv`, `pip`, `libcap2-bin`) را نصب کرده، محیط ایزوله `venv` را می‌سازد، وابستگی‌ها را نصب نموده، قابلیت‌های `CAP_NET_RAW` لینوکس را تنظیم می‌کند و دستورات سیستمی سراسری (`xmastunnel`, `xmastunnel-server`, `xmastunnel-client`) و سرویس systemd را اضافه می‌کند:

```bash
sudo bash install.sh
```

یا در صورتی که فایل را از گیت‌هاب مستقیم می‌گیرید:
```bash
curl -fsSL https://raw.githubusercontent.com/<USER>/XmasTunnel/main/install.sh | sudo bash
```

پس از نصب، می‌توانید از هر جای سیستم مستقیماً دستورات زیر را استفاده کنید:
```bash
# در سرور:
xmastunnel-server 8443

# در کلاینت:
xmastunnel-client <SERVER_IP> 8443 "<KEY>" --xmas-probe
```

---

### نصب دستی (Manual Installation):

این پروژه از **Python 3.11+** استفاده می‌کند. وابستگی‌ها را با دستور زیر نصب کنید:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## اسکریپت‌های اجرای سریع (Quick Launch Scripts)

### در اوبونتو / لینوکس (Ubuntu):

**راه‌اندازی سرور:**
```bash
chmod +x scripts/*.sh
./scripts/server_ubuntu.sh [HOST] [PORT] [KEY]
# مثال بدون پارامتر (پورت ۸۴۴۳ با تولید خودکار کلید):
./scripts/server_ubuntu.sh
```

**اجرای کلاینت:**
```bash
./scripts/client_ubuntu.sh [SERVER_IP] [PORT] [KEY]
# مثال با دریافت تعاملی آدرس و کلید:
./scripts/client_ubuntu.sh
```

### در ویندوز (Windows):

**راه‌اندازی سرور (PowerShell یا دوبار کلیک روی `server_windows.bat`):**
```powershell
.\scripts\server_windows.ps1 -Port 8443
```

**اجرای کلاینت (PowerShell یا دوبار کلیک روی `client_windows.bat`):**
```powershell
.\scripts\client_windows.ps1 -Server 127.0.0.1 -Port 8443 -Key "<SERVER_KEY>" -XmasProbe
```

---

## راهنمای استفاده (Usage Guide)

### ۱. تولید کلید تصادفی ۲۵۶ بیتی (Generate PSK)

```bash
python -m xmastunnel gen-key
```

### ۲. راه‌اندازی سرور (Start Server)

با اجرای سرور بدون کلید، یک کلید تصادفی امن تولید و در ترمینال نمایش داده می‌شود:

```bash
python -m xmastunnel server --host 0.0.0.0 --port 8443
```

یا با تعیین کلید اختصاصی:

```bash
python -m xmastunnel server -p 8443 --key "65b0e79f33883a727ffd1a51ed12901a24aa1c2aea466f820bc42516110e2f2b"
```

### ۳. اتصال کلاینت (Connect Client)

**حالت ارسال پیام متنی یک‌باره:**
```bash
python -m xmastunnel client -s 127.0.0.1 -p 8443 --key "<SERVER_KEY>" --send "Hello Secure Tunnel"
```

**بررسی تاخیر ارتباط (Ping/Pong):**
```bash
python -m xmastunnel client -s 127.0.0.1 -p 8443 --key "<SERVER_KEY>" --ping 5
```

**حالت تعاملی دوطرفه:**
```bash
python -m xmastunnel client -s 127.0.0.1 -p 8443 --key "<SERVER_KEY>"
```

### ۴. آزمایش و بررسی فلگ‌های سطح پایین TCP (Packet Engine)

**اجرای ماتریس آزمایشی تمام پروفایل‌ها (Xmas Tree, SYN, NULL, ALL FLAGS):**
```bash
python -m xmastunnel test-flags --matrix
```

**ساخت و آزمایش بسته دلخواه با ترکیب فلگ‌ها:**
```bash
python -m xmastunnel test-flags --flags "FIN,URG,PSH" --src-port 54321 --dst-port 8443
```

---

## گزارش تست‌ها (Test Suite Report)

تمام ۲۱ آزمون در فایل‌های زیر بدون خطا پاس شده‌اند:

```bash
pytest tests -v
```

```
tests/test_crypto.py::test_aes_gcm_encrypt_decrypt_roundtrip PASSED
tests/test_crypto.py::test_aes_gcm_tamper_detection PASSED
tests/test_crypto.py::test_psk_generation_and_detection PASSED
tests/test_crypto.py::test_kdf_derivation_deterministic PASSED
tests/test_crypto.py::test_nonce_manager_monotonic PASSED
tests/test_crypto.py::test_replay_protection_window PASSED
tests/test_integration.py::test_full_tunnel_integration_and_rekey PASSED
tests/test_integration.py::test_client_wrong_psk_rejected PASSED
tests/test_packet_engine.py::test_flag_parsing_and_str PASSED
tests/test_packet_engine.py::test_checksum_algorithm PASSED
tests/test_packet_engine.py::test_raw_tcp_packet_craft_and_parse PASSED
tests/test_packet_engine.py::test_flag_matrix_execution PASSED
tests/test_protocol.py::test_frame_pack_unpack_roundtrip PASSED
tests/test_protocol.py::test_frame_parser_fragmentation PASSED
tests/test_protocol.py::test_frame_parser_multiple_frames_in_buffer PASSED
tests/test_protocol.py::test_protocol_state_machine_valid_and_invalid PASSED
tests/test_session.py::test_handshake_flow_success PASSED
tests/test_session.py::test_handshake_bad_psk_failure PASSED
tests/test_session.py::test_session_data_encryption_and_anti_replay PASSED
tests/test_session.py::test_session_manager PASSED
tests/test_transport.py::test_tcp_transport_streaming PASSED

============================= 21 passed in 0.65s ==============================
```
