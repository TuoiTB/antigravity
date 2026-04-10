# 🔐 BÁO CÁO KIỂM THỬ BẢO MẬT — API Cấu hình tích hợp Email

> **Module:** Quản lý cấu hình tích hợp Email
> **Endpoint:** `PUT /iam-be/api/v1/integration-config/EMAIL/019d42a4-3f51-7894-a25f-f38a3d38b6a1`
> **Base URL:** `https://ubck-iam-api.viettelsoftware.com`
> **Ngày thực hiện:** 2026-04-09
> **Người thực hiện:** QA Automation
> **Framework:** Playwright (TypeScript) — API Testing
> **Loại kiểm thử:** Security Testing — SSRF & URL Validation (OWASP Top 10)

---

## 📊 Tổng quan kết quả

| Chỉ số | Số lượng |
|---|---|
| Tổng số test case | 22 |
| ✅ PASS | 1 |
| ❌ FAIL (BUG) | 21 |
| ⏭️ SKIP | 0 |
| Thời gian chạy | ~14.6 giây |

> [!CAUTION]
> **21/22 test case FAIL** xác nhận API **không có bất kỳ validation SSRF nào ở Backend**. Mọi URL độc hại đều được lưu thành công vào database với `resultCode: 200, errorCode: "0000"`.

---

## 📋 Chi tiết từng test case

---

### TC-01 — Chặn URL localhost ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-01 |
| **Loại** | [A10:2021] SSRF |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://localhost:8080` |

**Request body:**
```json
{ "type": "EMAIL", "status": "ACTIVE", "url": "http://localhost:8080", "method": "PUT" }
```

**Kết quả thực tế — Response 200 OK:**
```json
{
  "httpStatus": "OK",
  "errorCode": "0000",
  "resultCode": 200,
  "data": { "config": { "url": "http://localhost:8080", "method": "PUT" } }
}
```

**Kết quả kỳ vọng:** HTTP `400` kèm message "URL không hợp lệ"

**Mô tả bug:** API lưu thành công URL trỏ đến localhost — có thể lợi dụng để request vào service nội bộ.

**Khuyến nghị fix:** Validate URL không thuộc dải `localhost`, `127.0.0.1`, `::1` trước khi lưu.

---

### TC-02 — Chặn địa chỉ loopback 127.0.0.1 ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-02 |
| **Loại** | [A10:2021] SSRF |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://127.0.0.1` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://127.0.0.1", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400` — reject loopback address

**Mô tả bug:** IP loopback không bị chặn — attacker truy cập service nội bộ trên server.

**Khuyến nghị fix:** Resolve IP, kiểm tra và reject nếu thuộc `127.0.0.0/8`.

---

### TC-03 — Chặn private IP (192.168.x.x) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-03 |
| **Loại** | [A10:2021] SSRF |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://192.168.1.1` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://192.168.1.1", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400` — reject private IP range

**Mô tả bug:** Dải `192.168.0.0/16` không bị chặn — attacker có thể scan mạng nội bộ.

**Khuyến nghị fix:** Reject các dải IP RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`.

---

### TC-04 — Chặn private IP (10.x.x.x) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-04 |
| **Loại** | [A10:2021] SSRF |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://10.0.0.1` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://10.0.0.1", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** Áp dụng blocklist private IP theo RFC 1918.

---

### TC-05 — Chặn private IP (172.16.x.x) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-05 |
| **Loại** | [A10:2021] SSRF |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://172.16.0.1` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://172.16.0.1", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** Block dải `172.16.0.0/12`.

---

### TC-06 — Chặn cloud metadata endpoint ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-06 |
| **Loại** | [A10:2021] SSRF — Cloud Metadata |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://169.254.169.254/latest/meta-data` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://169.254.169.254/latest/meta-data", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** IP metadata AWS/GCP/Azure. Nếu server chạy trên cloud, attacker có thể lấy cloud credentials.

**Khuyến nghị fix:** Block dải `169.254.0.0/16`. **Ưu tiên cao nhất.**

---

### TC-07 — Chặn SSRF qua redirect ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-07 |
| **Loại** | [A10:2021] SSRF via Redirect |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://httpbin.org/redirect-to?url=http://localhost:8080` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://httpbin.org/redirect-to?url=http://localhost:8080", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** BE không follow redirect chain. URL bề ngoài hợp lệ nhưng đích đến là internal.

**Khuyến nghị fix:** Follow redirect khi validate, kiểm tra URL đích sau khi redirect.

---

### TC-08 — Chặn protocol `file://` ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-08 |
| **Loại** | [A10:2021] Protocol Injection |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `file:///etc/passwd` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "file:///etc/passwd", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** Protocol `file://` cho phép đọc file hệ thống nếu server thực thi request.

**Khuyến nghị fix:** Whitelist protocol — chỉ cho phép `https://`.

---

### TC-09 — Chặn protocol `ftp://` ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-09 |
| **Loại** | [A10:2021] Protocol Injection |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `ftp://example.com` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "ftp://example.com", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** Chỉ cho phép scheme `https`.

---

### TC-10 — Chặn protocol `gopher://` ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-10 |
| **Loại** | [A10:2021] Protocol Injection |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `gopher://127.0.0.1` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "gopher://127.0.0.1", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** `gopher` protocol có thể gửi arbitrary TCP data tới internal ports — rất nguy hiểm.

**Khuyến nghị fix:** Chỉ cho phép scheme `https`.

---

### TC-11 — Chỉ cho phép HTTPS (Chặn HTTP) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-11 |
| **Loại** | [A02:2021] Cryptographic Failures |
| **Mức độ** | 🟠 HIGH |
| **URL test** | `http://example.com` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://example.com", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** HTTP không mã hóa được chấp nhận — dữ liệu trao đổi có thể bị intercept.

**Khuyến nghị fix:** Bắt buộc URL phải bắt đầu bằng `https://`.

---

### TC-12 — Chặn quét port SSH (22) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-12 |
| **Loại** | [A10:2021] SSRF Port Scan |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `http://localhost:22` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://localhost:22", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** Attacker probe SSH port trên server thông qua API này.

---

### TC-13 — Chặn quét port MySQL (3306) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-13 |
| **Loại** | [A10:2021] SSRF Port Scan |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `http://localhost:3306` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://localhost:3306", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** Xác định được database port đang mở.

---

### TC-14 — Chặn quét port Redis (6379) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-14 |
| **Loại** | [A10:2021] SSRF Port Scan |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `http://localhost:6379` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://localhost:6379", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** Redis port exposed — có thể kết hợp gopher protocol tấn công Redis.

---

### TC-15 — Chặn IP encode Decimal ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-15 |
| **Loại** | [A10:2021] SSRF Bypass — IP Encoding |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `http://2130706433` (= `127.0.0.1` dạng decimal) |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://2130706433", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** BE không normalize IP — attacker bypass bằng IP dạng decimal.

**Khuyến nghị fix:** Dùng `InetAddress.getByName()` để resolve về IP chuẩn trước khi validate.

---

### TC-16 — Chặn IP encode Hex ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-16 |
| **Loại** | [A10:2021] SSRF Bypass — IP Encoding |
| **Mức độ** | 🔴 HIGH |
| **URL test** | `http://0x7f000001` (= `127.0.0.1` dạng hex) |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://0x7f000001", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** Resolve IP về dạng dotted-decimal trước khi kiểm tra blocklist.

---

### TC-17 — Chặn bypass URL encoding (`%2f`) ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-17 |
| **Loại** | [A10:2021] SSRF Bypass — URL Encoding |
| **Mức độ** | 🟡 MEDIUM |
| **URL test** | `http://127.0.0.1%2f` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://127.0.0.1%2f", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** URL decode trước khi validate, sau đó kiểm tra blocklist.

---

### TC-18 — Chặn bypass NULL byte ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-18 |
| **Loại** | [A10:2021] SSRF Bypass — Null Byte |
| **Mức độ** | 🟡 MEDIUM |
| **URL test** | `http://localhost%00.example.com` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://localhost%00.example.com", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** Strip/reject URL chứa `%00`, `\0` hoặc control characters.

---

### TC-19 — Chặn domain không có trong whitelist ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-19 |
| **Loại** | [A05:2021] Security Misconfiguration |
| **Mức độ** | 🟡 MEDIUM |
| **URL test** | `http://evil.com` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://evil.com", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Khuyến nghị fix:** Implement domain whitelist — chỉ cho phép domain đã được phê duyệt.

---

### TC-20 — Chặn truy cập internal service ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-20 |
| **Loại** | [A09:2021] Security Logging Failures |
| **Mức độ** | 🟡 MEDIUM |
| **URL test** | `http://internal-service/admin` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://internal-service/admin", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400`

**Mô tả bug:** Tên service nội bộ được lưu và có thể lộ qua response/log.

**Khuyến nghị fix:** Block non-public domain, không log full URL trong error response.

---

### TC-BlindSSRF — Kiểm tra Blind SSRF qua webhook.site ❌ FAIL

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-BlindSSRF |
| **Loại** | [A10:2021] Blind SSRF |
| **Mức độ** | 🔴 CRITICAL |
| **URL test** | `http://webhook.site/019d42a4-3f51-7894-a25f-f38a3d38b6a1` |

**Kết quả thực tế — Response 200 OK:**
```json
{ "data": { "config": { "url": "http://webhook.site/019d42a4-...", "method": "PUT" } } }
```

**Kết quả kỳ vọng:** HTTP `400` — BE không lưu URL và không gửi request ra ngoài

> [!CAUTION]
> Cần verify thêm tại webhook.site xem BE có thực sự gửi HTTP request ra ngoài không. Nếu có → **BUG CRITICAL mức độ cao nhất**.

**Khuyến nghị fix:** Validate và reject URL trước khi lưu. Không thực hiện outbound request trong quá trình save config.

---

### TC-Positive — Cho phép URL HTTPS hợp lệ ✅ PASS

| Trường | Nội dung |
|---|---|
| **Mã TC** | TC-Positive |
| **Loại** | Happy Path |
| **URL test** | `https://mail.google.com/api/v1` |

**Kết quả thực tế:** HTTP `200 OK` ✅ — Đúng behavior.

---

## 🛠️ Khuyến nghị Fix cho Backend Team

> [!IMPORTANT]
> Implement validation layer URL tại BE trước khi lưu config:

```
validate(url):
  1. Parse URL → reject nếu parse lỗi
  2. Kiểm tra scheme → chỉ cho phép "https"
  3. Strip/reject control chars: %00, \0, %2f bypass
  4. Resolve hostname → IP thực (xử lý decimal/hex/encoding)
  5. Kiểm tra IP blocklist:
     - 127.0.0.0/8       (loopback)
     - 10.0.0.0/8        (private RFC1918)
     - 172.16.0.0/12     (private RFC1918)
     - 192.168.0.0/16    (private RFC1918)
     - 169.254.0.0/16    (link-local / cloud metadata)
     - ::1               (IPv6 loopback)
  6. Kiểm tra domain whitelist
  7. Follow redirect → validate URL đích cuối cùng
```

| Thư viện Java gợi ý | Mục đích |
|---|---|
| `java.net.InetAddress.getByName()` | Resolve IP từ hostname |
| `java.net.URI` | Parse và normalize URL |
| Custom blocklist validator | Kiểm tra IP range |

---

## 📁 Thông tin thực thi

| Mục | Giá trị |
|---|---|
| Script | `integration_email_security.spec.ts` |
| Config | `playwright.config.ts` |
| Thư mục | `.agent/security test iam/` |
| Lệnh | `npx playwright test integration_email_security.spec.ts --reporter=line` |
| Thời gian chạy | 14.6 giây |
| Ngày | 2026-04-09 08:31 ICT |
