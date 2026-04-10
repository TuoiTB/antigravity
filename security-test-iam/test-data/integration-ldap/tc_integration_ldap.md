# Test Cases — Security LDAP Integration Config
**API:** `PUT /iam-be/api/v1/integration-config/LDAP/{id}`
**Base URL:** `https://ubck-iam-api.viettelsoftware.com`
**Ngày soạn:** 2026-04-09

---

## SECTION 1 — SSRF: connectionUrl

| Mã TC | OWASP | Danh mục | Mức độ | connectionUrl test | Kết quả kỳ vọng |
|-------|-------|----------|--------|-------------------|-----------------|
| TC-SSRF-01 | A10:2021 | SSRF | CRITICAL | `ldap://localhost:389` | 400 — Reject |
| TC-SSRF-02 | A10:2021 | SSRF | CRITICAL | `ldap://127.0.0.1` | 400 — Reject |
| TC-SSRF-03 | A10:2021 | SSRF | CRITICAL | `ldap://192.168.1.1:389` | 400 — Reject |
| TC-SSRF-04 | A10:2021 | SSRF | CRITICAL | `ldap://10.0.0.1:389` | 400 — Reject |
| TC-SSRF-05 | A10:2021 | SSRF | CRITICAL | `ldap://172.16.0.1:389` | 400 — Reject |
| TC-SSRF-06 | A10:2021 | SSRF - Cloud Metadata | CRITICAL | `ldap://169.254.169.254` | 400 — Reject |
| TC-BSSRF-01 | A10:2021 | Blind SSRF | CRITICAL | `ldap://webhook.site/...` | 400 — Reject |

## SECTION 2 — Protocol Injection: connectionUrl

| Mã TC | OWASP | Danh mục | Mức độ | connectionUrl test | Kết quả kỳ vọng |
|-------|-------|----------|--------|-------------------|-----------------|
| TC-PROTO-01 | A10:2021 | Protocol Injection | HIGH | `http://example.com` | 400 — Chỉ cho phép ldap/ldaps |
| TC-PROTO-02 | A10:2021 | Protocol Injection | HIGH | `https://example.com` | 400 — Chỉ cho phép ldap/ldaps |
| TC-PROTO-03 | A10:2021 | Protocol Injection | HIGH | `file:///etc/passwd` | 400 — Reject |
| TC-PROTO-04 | A10:2021 | Protocol Injection | HIGH | `gopher://127.0.0.1` | 400 — Reject |
| TC-PROTO-05 | A10:2021 | Protocol Injection | HIGH | `ftp://example.com` | 400 — Reject |
| TC-PROTO-06 | A10:2021 | Input Validation | MEDIUM | `not-a-url` | 400 — Reject |
| TC-PROTO-07 | A10:2021 | Input Validation | MEDIUM | `` (empty string) | 400 — Reject |

## SECTION 3 — IP Encoding Bypass: connectionUrl

| Mã TC | OWASP | Danh mục | Mức độ | connectionUrl test | Kết quả kỳ vọng |
|-------|-------|----------|--------|-------------------|-----------------|
| TC-BYPASS-01 | A10:2021 | SSRF Bypass - IP Decimal | HIGH | `ldap://2130706433` | 400 — Normalize và reject |
| TC-BYPASS-02 | A10:2021 | SSRF Bypass - IP Hex | HIGH | `ldap://0x7f000001` | 400 — Normalize và reject |
| TC-BYPASS-03 | A10:2021 | SSRF Bypass - URL Encoding | MEDIUM | `ldap://127.0.0.1%2f` | 400 — Decode và reject |
| TC-BYPASS-04 | A10:2021 | SSRF Bypass - Null Byte | MEDIUM | `ldap://localhost%00.example.com` | 400 — Reject |

## SECTION 4 — Port Scan qua SSRF

| Mã TC | OWASP | Danh mục | Mức độ | connectionUrl test | Kết quả kỳ vọng |
|-------|-------|----------|--------|-------------------|-----------------|
| TC-PORT-01 | A10:2021 | SSRF Port Scan | HIGH | `ldap://localhost:22` | 400 — Reject |
| TC-PORT-02 | A10:2021 | SSRF Port Scan | HIGH | `ldap://localhost:3306` | 400 — Reject |
| TC-PORT-03 | A10:2021 | SSRF Port Scan | HIGH | `ldap://localhost:6379` | 400 — Reject |
| TC-PORT-04 | A10:2021 | SSRF Port Scan | HIGH | `ldap://localhost:8080` | 400 — Reject |

## SECTION 5 — LDAP Injection: bindDn

| Mã TC | OWASP | Danh mục | Mức độ | Payload | Kết quả kỳ vọng |
|-------|-------|----------|--------|---------|-----------------|
| TC-INJ-01 | A03:2021 | LDAP Injection | CRITICAL | `cn=*)(|(cn=*` | 400 — Reject meta-chars |
| TC-INJ-02 | A03:2021 | LDAP Injection | CRITICAL | `cn=admin,dc=ubck,dc=local)(objectClass=*` | 400 — Reject |
| TC-INJ-03 | A03:2021 | LDAP Injection | HIGH | `cn=admin\x00,...` | 400 — Reject null byte |
| TC-INJ-04 | A03:2021 | LDAP Injection | HIGH | `*` | 400 — Reject wildcard |
| TC-INJ-05 | A03:2021 | LDAP Injection | MEDIUM | `cn=admin+dc=evil,...` | 400 — Reject special DN chars |

## SECTION 6 — LDAP Injection: userDn

| Mã TC | OWASP | Danh mục | Mức độ | Payload | Kết quả kỳ vọng |
|-------|-------|----------|--------|---------|-----------------|
| TC-INJ-06 | A03:2021 | LDAP Injection | CRITICAL | `ou=users,...)(objectClass=*` | 400 — Reject |
| TC-INJ-07 | A03:2021 | LDAP Injection | CRITICAL | `*(objectClass=*)` | 400 — Reject |
| TC-INJ-08 | A03:2021 | LDAP Injection | HIGH | `ou=users,...\r\ndc=evil` | 400 — Reject CRLF |

## SECTION 7 — LDAP Injection: Attributes

| Mã TC | OWASP | Danh mục | Mức độ | Field | Payload | Kết quả kỳ vọng |
|-------|-------|----------|--------|-------|---------|-----------------|
| TC-INJ-09 | A03:2021 | LDAP Injection | HIGH | usernameLdapAttribute | `uid)(objectClass=*` | 400 |
| TC-INJ-10 | A03:2021 | LDAP Injection | HIGH | rdnLdapAttribute | `*(|(objectClass=*))` | 400 |
| TC-INJ-11 | A03:2021 | LDAP Injection | MEDIUM | uuidLdapAttribute | `entryUUID\x00` | 400 |
| TC-INJ-12 | A03:2021 | LDAP Injection | HIGH | userObjectClass | `inetOrgPerson)(objectClass=*` | 400 |

## SECTION 8 — XSS trong string fields

| Mã TC | OWASP | Danh mục | Mức độ | Field | Payload | Kết quả kỳ vọng |
|-------|-------|----------|--------|-------|---------|-----------------|
| TC-XSS-01 | A03:2021 | XSS | HIGH | bindDn | `<script>alert(1)</script>` | 400 |
| TC-XSS-02 | A03:2021 | XSS | HIGH | userDn | `"><img src=x onerror=alert(1)>` | 400 |
| TC-XSS-03 | A03:2021 | XSS | MEDIUM | userObjectClass | `';alert('xss');'` | 400 |

## SECTION 9 — Field Validation

| Mã TC | OWASP | Danh mục | Mức độ | Kịch bản | Kết quả kỳ vọng |
|-------|-------|----------|--------|----------|-----------------|
| TC-VAL-01 | A10:2021 | Input Validation | HIGH | Thiếu connectionUrl | 400 — Required field |
| TC-VAL-02 | A10:2021 | Input Validation | MEDIUM | connectionUrl 2000+ ký tự | 400 — Maxlength |
| TC-VAL-03 | A10:2021 | Input Validation | MEDIUM | bindDn 2000+ ký tự | 400 — Maxlength |
| TC-VAL-04 | A10:2021 | Input Validation | MEDIUM | enableStartTls = string | 400/422 — Type mismatch |
| TC-VAL-05 | A10:2021 | Input Validation | MEDIUM | bindType = INVALID_TYPE | 400 — Enum violation |

## SECTION 10 — Happy Path

| Mã TC | Kịch bản | connectionUrl | Kết quả kỳ vọng |
|-------|---------|---------------|-----------------|
| TC-POS-01 | LDAP hợp lệ — ldaps:// + TLS | `ldaps://ldap.example.com:636` | 200 (hoặc 401 nếu token hết hạn) |
| TC-POS-02 | LDAP hợp lệ — ldap:// | `ldap://ldap.example.com:389` | 200 (hoặc 401 nếu token hết hạn) |
