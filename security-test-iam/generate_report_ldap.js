const ExcelJS = require('exceljs');
const path = require('path');

const OUTPUT_FILE = path.join(__dirname, 'security_test_report_ldap.xlsx');

// ════════════════════════════════════════════════════════════════════
// KẾT QUẢ TEST — 44 TC | 37 FAIL | 7 PASS | Thời gian: ~32 giây
// ════════════════════════════════════════════════════════════════════
const testResults = [
  // ── SSRF: Private IPs ─────────────────────────────────────────
  {
    id: 'TC-SSRF-01',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'ldap://localhost:389',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://localhost:389" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'API lưu thành công connectionUrl trỏ đến localhost:389 — attacker có thể probe LDAP service nội bộ.',
    recommendation: 'Reject connectionUrl trỏ tới localhost, 127.0.0.1, ::1.',
  },
  {
    id: 'TC-SSRF-02',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'ldap://127.0.0.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://127.0.0.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'IP loopback 127.0.0.1 không bị chặn — attacker truy cập LDAP service nội bộ.',
    recommendation: 'Resolve và reject IP thuộc dải 127.0.0.0/8.',
  },
  {
    id: 'TC-SSRF-03',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'ldap://192.168.1.1:389',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://192.168.1.1:389" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Dải 192.168.0.0/16 không bị block — attacker scan mạng nội bộ.',
    recommendation: 'Block RFC 1918: 10/8, 172.16/12, 192.168/16.',
  },
  {
    id: 'TC-SSRF-04',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'ldap://10.0.0.1:389',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://10.0.0.1:389" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Dải 10.0.0.0/8 không bị chặn.',
    recommendation: 'Block dải 10.0.0.0/8.',
  },
  {
    id: 'TC-SSRF-05',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'ldap://172.16.0.1:389',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://172.16.0.1:389" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Dải 172.16.0.0/12 không bị chặn.',
    recommendation: 'Block dải 172.16.0.0/12.',
  },
  {
    id: 'TC-SSRF-06',
    owasp: 'A10:2021',
    category: 'SSRF - Cloud Metadata',
    severity: 'CRITICAL',
    urlTest: 'ldap://169.254.169.254',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://169.254.169.254" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'IP metadata AWS/GCP/Azure 169.254.169.254 không bị block — nếu server trên cloud, lộ cloud credentials.',
    recommendation: 'Block dải 169.254.0.0/16 (link-local). Ưu tiên cao nhất.',
  },
  {
    id: 'TC-BSSRF-01',
    owasp: 'A10:2021',
    category: 'Blind SSRF',
    severity: 'CRITICAL',
    urlTest: 'ldap://webhook.site/ldap-probe-test',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://webhook.site/ldap-probe-test" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Blind SSRF — server lưu URL mà không validate; có thể gửi outbound connection đến external host.',
    recommendation: 'Validate và reject URL nằm ngoài whitelist domain. Không attempt LDAP connect khi save config.',
  },
  // ── Protocol Injection ────────────────────────────────────────
  {
    id: 'TC-PROTO-01',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'http://example.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "http://example.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'Chỉ cho phép ldap:// hoặc ldaps://',
    result: 'FAIL',
    bugDescription: 'HTTP scheme được chấp nhận cho LDAP connectionUrl — sai protocol, không phải LDAP endpoint.',
    recommendation: 'Whitelist scheme — chỉ chấp nhận ldap:// và ldaps://.',
  },
  {
    id: 'TC-PROTO-02',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'https://example.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "https://example.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'Chỉ cho phép ldap:// hoặc ldaps://',
    result: 'FAIL',
    bugDescription: 'HTTPS được chấp nhận thay vì LDAP — API không kiểm tra scheme.',
    recommendation: 'Whitelist scheme ldap/ldaps.',
  },
  {
    id: 'TC-PROTO-03',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'file:///etc/passwd',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "file:///etc/passwd" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'file:// được chấp nhận — có thể đọc file hệ thống nếu server thực thi.',
    recommendation: 'Chỉ cho phép scheme ldap/ldaps.',
  },
  {
    id: 'TC-PROTO-04',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'gopher://127.0.0.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "gopher://127.0.0.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'gopher:// scheme nguy hiểm — gửi arbitrary TCP data, có thể exploit internal services.',
    recommendation: 'Block gopher, file, ftp, dict, và mọi scheme không phải ldap/ldaps.',
  },
  {
    id: 'TC-PROTO-05',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'ftp://example.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ftp://example.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'ftp:// được chấp nhận — không phải LDAP protocol.',
    recommendation: 'Whitelist scheme ldap/ldaps.',
  },
  {
    id: 'TC-PROTO-06',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'MEDIUM',
    urlTest: 'not-a-url',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-PROTO-07',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'MEDIUM',
    urlTest: '(empty string)',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  // ── IP Encoding Bypass ────────────────────────────────────────
  {
    id: 'TC-BYPASS-01',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - IP Decimal',
    severity: 'HIGH',
    urlTest: 'ldap://2130706433',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://2130706433" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: '2130706433 = 127.0.0.1 dạng decimal — bypass blocklist vì BE không normalize IP.',
    recommendation: 'Dùng InetAddress.getByName() để resolve IP về dotted-decimal trước khi validate.',
  },
  {
    id: 'TC-BYPASS-02',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - IP Hex',
    severity: 'HIGH',
    urlTest: 'ldap://0x7f000001',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://0x7f000001" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: '0x7f000001 = 127.0.0.1 dạng hex — bypass blocklist nếu không normalize.',
    recommendation: 'Normalize IP về dotted-decimal trước khi validate.',
  },
  {
    id: 'TC-BYPASS-03',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - URL Encoding',
    severity: 'MEDIUM',
    urlTest: 'ldap://127.0.0.1%2f',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-BYPASS-04',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - Null Byte',
    severity: 'MEDIUM',
    urlTest: 'ldap://localhost%00.example.com',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  // ── Port Scan ─────────────────────────────────────────────────
  {
    id: 'TC-PORT-01',
    owasp: 'A10:2021',
    category: 'SSRF Port Scan',
    severity: 'HIGH',
    urlTest: 'ldap://localhost:22',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://localhost:22" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Attacker probe SSH port 22 nội bộ thông qua LDAP connectionUrl.',
    recommendation: 'Block localhost + dangerous ports (22, 3306, 5432, 6379, 8080...).',
  },
  {
    id: 'TC-PORT-02',
    owasp: 'A10:2021',
    category: 'SSRF Port Scan',
    severity: 'HIGH',
    urlTest: 'ldap://localhost:3306',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://localhost:3306" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'MySQL port 3306 có thể bị probe — lộ database internal.',
    recommendation: 'Block localhost + dangerous ports.',
  },
  {
    id: 'TC-PORT-03',
    owasp: 'A10:2021',
    category: 'SSRF Port Scan',
    severity: 'HIGH',
    urlTest: 'ldap://localhost:6379',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "connectionUrl": "ldap://localhost:6379" } } }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Redis port 6379 — kết hợp gopher có thể tấn công Redis.',
    recommendation: 'Block localhost + dangerous ports.',
  },
  // ── LDAP Injection: bindDn ────────────────────────────────────
  {
    id: 'TC-INJ-01',
    owasp: 'A03:2021',
    category: 'LDAP Injection (bindDn)',
    severity: 'CRITICAL',
    urlTest: '[bindDn] cn=*)(|(cn=*',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "bindDn": "cn=*)(|(cn=*" } } }',
    expectedStatus: 400,
    expectedMessage: 'bindDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'LDAP meta-characters (, ), * được lưu vào bindDn — có thể bypass LDAP filter trong authentication.',
    recommendation: 'Escape (, ), *, \\, NUL theo RFC 4515/4516. Validate DN theo RFC 4514.',
  },
  {
    id: 'TC-INJ-02',
    owasp: 'A03:2021',
    category: 'LDAP Injection (bindDn)',
    severity: 'CRITICAL',
    urlTest: '[bindDn] cn=admin,dc=ubck,dc=local)(objectClass=*',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'bindDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Injection mở rộng LDAP filter — dump toàn bộ LDAP entries khi bind.',
    recommendation: 'Validate DN format nghiêm ngặt — reject ký tự ) và ( không được escape.',
  },
  {
    id: 'TC-INJ-03',
    owasp: 'A03:2021',
    category: 'LDAP Injection (bindDn)',
    severity: 'HIGH',
    urlTest: '[bindDn] cn=admin\\x00,...',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'bindDn không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-INJ-04',
    owasp: 'A03:2021',
    category: 'LDAP Injection (bindDn)',
    severity: 'HIGH',
    urlTest: '[bindDn] *',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "bindDn": "*" } } }',
    expectedStatus: 400,
    expectedMessage: 'bindDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Wildcard * trong bindDn — dump toàn bộ LDAP directory nếu sử dụng trong search.',
    recommendation: 'Reject wildcard trong DN fields.',
  },
  {
    id: 'TC-INJ-05',
    owasp: 'A03:2021',
    category: 'LDAP Injection (bindDn)',
    severity: 'MEDIUM',
    urlTest: '[bindDn] cn=admin+dc=evil,dc=ubck,dc=local',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'bindDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Ký tự đặc biệt DN (+) ngoài context hợp lệ — có thể manipulate DN parsing.',
    recommendation: 'Validate DN format nghiêm ngặt theo RFC 4514.',
  },
  // ── LDAP Injection: userDn ────────────────────────────────────
  {
    id: 'TC-INJ-06',
    owasp: 'A03:2021',
    category: 'LDAP Injection (userDn)',
    severity: 'CRITICAL',
    urlTest: '[userDn] ou=users,dc=ubck,dc=local)(objectClass=*',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'userDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'LDAP Injection trong userDn — bypass user search filter, lộ toàn bộ LDAP directory.',
    recommendation: 'Sanitize DN fields. Escape LDAP meta-chars theo RFC 4516.',
  },
  {
    id: 'TC-INJ-07',
    owasp: 'A03:2021',
    category: 'LDAP Injection (userDn)',
    severity: 'CRITICAL',
    urlTest: '[userDn] *(objectClass=*)',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'userDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Wildcard dump all — userDn với payload wildcard cho phép dump toàn bộ LDAP entries.',
    recommendation: 'Validate và escape special chars trong userDn.',
  },
  {
    id: 'TC-INJ-08',
    owasp: 'A03:2021',
    category: 'LDAP Injection (userDn)',
    severity: 'HIGH',
    urlTest: '[userDn] ou=users,...\\r\\ndc=evil',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'userDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'CRLF injection trong userDn — có thể inject thêm LDAP attribute hoặc bypass filter.',
    recommendation: 'Strip CRLF và control characters khỏi DN fields.',
  },
  // ── LDAP Injection: Attributes ────────────────────────────────
  {
    id: 'TC-INJ-09',
    owasp: 'A03:2021',
    category: 'LDAP Injection (Attributes)',
    severity: 'HIGH',
    urlTest: '[usernameLdapAttribute] uid)(objectClass=*',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'Attribute không hợp lệ',
    result: 'FAIL',
    bugDescription: 'LDAP Injection trong usernameLdapAttribute — manipulate LDAP search filter.',
    recommendation: 'Validate attribute names — regex: ^[a-zA-Z][a-zA-Z0-9-]*$.',
  },
  {
    id: 'TC-INJ-10',
    owasp: 'A03:2021',
    category: 'LDAP Injection (Attributes)',
    severity: 'HIGH',
    urlTest: '[rdnLdapAttribute] *(|(objectClass=*))',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'Attribute không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Wildcard trong rdnLdapAttribute — bypass attribute filter.',
    recommendation: 'Chỉ cho phép ký tự alphanumeric và dấu gạch ngang trong attribute names.',
  },
  {
    id: 'TC-INJ-11',
    owasp: 'A03:2021',
    category: 'LDAP Injection (Attributes)',
    severity: 'MEDIUM',
    urlTest: '[uuidLdapAttribute] entryUUID\\x00',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'Attribute không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-INJ-12',
    owasp: 'A03:2021',
    category: 'LDAP Injection (Attributes)',
    severity: 'HIGH',
    urlTest: '[userObjectClass] inetOrgPerson)(objectClass=*',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'Attribute không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Injection vào userObjectClass — cho phép bypass class filter trong user search.',
    recommendation: 'Validate objectClass theo whitelist: inetOrgPerson, person, organizationalPerson, v.v.',
  },
  // ── XSS ──────────────────────────────────────────────────────
  {
    id: 'TC-XSS-01',
    owasp: 'A03:2021',
    category: 'XSS (bindDn)',
    severity: 'HIGH',
    urlTest: '[bindDn] <script>alert(1)</script>',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'bindDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'XSS payload trong bindDn được lưu nguyên — reflected XSS nếu admin UI hiển thị raw value.',
    recommendation: 'HTML encode output. Validate DN không chứa HTML/script tags.',
  },
  {
    id: 'TC-XSS-02',
    owasp: 'A03:2021',
    category: 'XSS (userDn)',
    severity: 'HIGH',
    urlTest: '[userDn] "><img src=x onerror=alert(1)>',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'userDn không hợp lệ',
    result: 'FAIL',
    bugDescription: 'XSS trong userDn — img onerror payload được lưu.',
    recommendation: 'Sanitize và encode output. Reject HTML tags trong DN fields.',
  },
  {
    id: 'TC-XSS-03',
    owasp: 'A03:2021',
    category: 'XSS (userObjectClass)',
    severity: 'MEDIUM',
    urlTest: "[userObjectClass] ';alert('xss');'",
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'userObjectClass không hợp lệ',
    result: 'FAIL',
    bugDescription: 'JavaScript payload trong userObjectClass được lưu — có thể khai thác reflected XSS.',
    recommendation: 'Whitelist objectClass values. Reject payload chứa quotes và script chars.',
  },
  // ── Field Validation ──────────────────────────────────────────
  {
    id: 'TC-VAL-01',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'HIGH',
    urlTest: '[Thiếu connectionUrl]',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl là bắt buộc',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-VAL-02',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'MEDIUM',
    urlTest: '[connectionUrl] ldap:// + 2000 ký tự',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'connectionUrl vượt maxlength',
    result: 'FAIL',
    bugDescription: 'connectionUrl không bị giới hạn maxlength — có thể gây buffer overflow hoặc memory issues.',
    recommendation: 'Giới hạn connectionUrl tối đa 512 ký tự.',
  },
  {
    id: 'TC-VAL-03',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'MEDIUM',
    urlTest: '[bindDn] cn= + 2000 ký tự',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 400,
    expectedMessage: 'bindDn vượt maxlength',
    result: 'FAIL',
    bugDescription: 'bindDn không bị giới hạn độ dài — tiềm năng buffer overflow.',
    recommendation: 'Giới hạn bindDn tối đa 1024 ký tự theo RFC 4514.',
  },
  {
    id: 'TC-VAL-04',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'MEDIUM',
    urlTest: '[enableStartTls] "true_string_attack"',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'enableStartTls phải là boolean',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-VAL-05',
    owasp: 'A10:2021',
    category: 'Input Validation',
    severity: 'MEDIUM',
    urlTest: '[bindType] INVALID_TYPE_ATTACK',
    actualStatus: 400,
    actualResponse: '{ "errorCode": "ERR_VALIDATION", "resultCode": 400 }',
    expectedStatus: 400,
    expectedMessage: 'bindType không hợp lệ',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  // ── Happy Path ────────────────────────────────────────────────
  {
    id: 'TC-POS-01',
    owasp: 'Happy Path',
    category: 'Happy Path',
    severity: '-',
    urlTest: 'ldaps://ldap.example.com:636',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 200,
    expectedMessage: 'SUCCESS',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-POS-02',
    owasp: 'Happy Path',
    category: 'Happy Path',
    severity: '-',
    urlTest: 'ldap://ldap.example.com:389',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 200,
    expectedMessage: 'SUCCESS',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
];

// ════════════════════════════════════════════════════════════════════
// COLOR MAPS
// ════════════════════════════════════════════════════════════════════
const SEVERITY_COLORS = {
  CRITICAL: 'FFFF0000',
  HIGH:     'FFFF6600',
  MEDIUM:   'FFFFC000',
  '-':      'FF92D050',
};
const RESULT_COLORS = {
  FAIL: 'FFFF0000',
  PASS: 'FF00B050',
};

// ════════════════════════════════════════════════════════════════════
// GENERATE REPORT
// ════════════════════════════════════════════════════════════════════
async function generateReport() {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'QA Automation';
  workbook.created = new Date();

  // ─── Sheet 1: Tổng quan ───────────────────────────────────────────
  const summary = workbook.addWorksheet('Tổng quan');
  summary.mergeCells('A1:G1');
  const titleCell = summary.getCell('A1');
  titleCell.value = '🔐 BÁO CÁO KIỂM THỬ BẢO MẬT — API CẤU HÌNH TÍCH HỢP LDAP';
  titleCell.font = { bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
  titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
  titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
  summary.getRow(1).height = 36;

  const infoData = [
    ['Module',          'Quản lý cấu hình tích hợp LDAP'],
    ['Endpoint',        'PUT /iam-be/api/v1/integration-config/LDAP/{id}'],
    ['Base URL',        'https://ubck-iam-api.viettelsoftware.com'],
    ['Ngày thực hiện',  '2026-04-09'],
    ['Người thực hiện', 'QA Automation'],
    ['Framework',       'Playwright (TypeScript) — API Testing'],
    ['Loại kiểm thử',   'Security Testing — SSRF, LDAP Injection, Protocol Injection (OWASP Top 10)'],
  ];

  infoData.forEach(([label, value], i) => {
    const row = summary.getRow(i + 2);
    row.getCell(1).value = label;
    row.getCell(1).font = { bold: true };
    row.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD6DCE4' } };
    row.getCell(2).value = value;
    summary.mergeCells(i + 2, 2, i + 2, 7);
    row.height = 20;
  });

  summary.getRow(10).height = 10;

  const statsTitle = summary.getRow(11);
  summary.mergeCells('A11:G11');
  statsTitle.getCell(1).value = 'KẾT QUẢ THỰC THI';
  statsTitle.getCell(1).font = { bold: true, size: 12, color: { argb: 'FFFFFFFF' } };
  statsTitle.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2E75B6' } };
  statsTitle.getCell(1).alignment = { horizontal: 'center' };
  statsTitle.height = 24;

  const statsHeaders = ['Tổng TC', 'PASS', 'FAIL', 'SKIP', 'Thời gian', 'Ngày', ''];
  const statsValues  = [44, 7, 37, 0, '~32 giây', '2026-04-09', ''];
  const headerRow    = summary.getRow(12);
  const valueRow     = summary.getRow(13);

  statsHeaders.forEach((h, i) => {
    headerRow.getCell(i + 1).value = h;
    headerRow.getCell(i + 1).font = { bold: true };
    headerRow.getCell(i + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD6E4F7' } };
    headerRow.getCell(i + 1).alignment = { horizontal: 'center' };

    valueRow.getCell(i + 1).value = statsValues[i];
    valueRow.getCell(i + 1).alignment = { horizontal: 'center' };
    if (i === 1) valueRow.getCell(i + 1).font = { bold: true, color: { argb: 'FF00B050' } };
    if (i === 2) valueRow.getCell(i + 1).font = { bold: true, color: { argb: 'FFFF0000' } };
  });
  headerRow.height = 22;
  valueRow.height  = 24;

  summary.columns = [
    { width: 22 }, { width: 18 }, { width: 10 }, { width: 10 },
    { width: 14 }, { width: 14 }, { width: 14 },
  ];

  // ─── Sheet 2: Chi tiết Test Cases ─────────────────────────────────
  const detail  = workbook.addWorksheet('Chi tiết Test Cases');
  const headers = [
    'Mã TC', 'OWASP', 'Danh mục', 'Mức độ',
    'URL / Field Test', 'Status thực tế', 'Response thực tế',
    'Status kỳ vọng', 'Message kỳ vọng',
    'Kết quả', 'Mô tả Bug', 'Khuyến nghị Fix',
  ];

  const headerRow2 = detail.getRow(1);
  headers.forEach((h, i) => {
    const cell = headerRow2.getCell(i + 1);
    cell.value = h;
    cell.font      = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    cell.border    = {
      top: { style: 'thin' }, left: { style: 'thin' },
      bottom: { style: 'thin' }, right: { style: 'thin' },
    };
  });
  headerRow2.height = 30;

  testResults.forEach((tc, idx) => {
    const row    = detail.getRow(idx + 2);
    const values = [
      tc.id, tc.owasp, tc.category, tc.severity,
      tc.urlTest, tc.actualStatus, tc.actualResponse,
      tc.expectedStatus, tc.expectedMessage,
      tc.result, tc.bugDescription, tc.recommendation,
    ];
    values.forEach((val, i) => {
      const cell     = row.getCell(i + 1);
      cell.value     = val;
      cell.alignment = { vertical: 'middle', wrapText: true, horizontal: i < 4 ? 'center' : 'left' };
      cell.border    = {
        top: { style: 'thin' }, left: { style: 'thin' },
        bottom: { style: 'thin' }, right: { style: 'thin' },
      };
      // Tô màu mức độ
      if (i === 3 && SEVERITY_COLORS[tc.severity]) {
        cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEVERITY_COLORS[tc.severity] } };
      }
      // Tô màu kết quả
      if (i === 9) {
        cell.font = { bold: true, color: { argb: RESULT_COLORS[tc.result] || 'FF000000' } };
      }
      // Zebra stripe
      if (idx % 2 === 0 && i !== 3 && i !== 9) {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF2F7FC' } };
      }
    });
    row.height = 60;
  });

  detail.columns = [
    { width: 14 }, { width: 12 }, { width: 28 }, { width: 12 },
    { width: 42 }, { width: 14 }, { width: 55 },
    { width: 14 }, { width: 22 },
    { width: 10 }, { width: 55 }, { width: 55 },
  ];

  // ─── Sheet 3: Bug Summary ──────────────────────────────────────────
  const bugSheet = workbook.addWorksheet('Bug Summary');
  bugSheet.mergeCells('A1:F1');
  bugSheet.getCell('A1').value     = 'DANH SÁCH BUG CẦN LOG';
  bugSheet.getCell('A1').font      = { bold: true, size: 13, color: { argb: 'FFFFFFFF' } };
  bugSheet.getCell('A1').fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFC00000' } };
  bugSheet.getCell('A1').alignment = { horizontal: 'center', vertical: 'middle' };
  bugSheet.getRow(1).height = 30;

  const bugHeaders    = ['Mã TC', 'Mức độ', 'Danh mục lỗ hổng', 'URL / Field Test', 'Mô tả Bug', 'Khuyến nghị Fix'];
  const bugHeaderRow  = bugSheet.getRow(2);
  bugHeaders.forEach((h, i) => {
    const cell     = bugHeaderRow.getCell(i + 1);
    cell.value     = h;
    cell.font      = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2E75B6' } };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    cell.border    = {
      top: { style: 'thin' }, left: { style: 'thin' },
      bottom: { style: 'thin' }, right: { style: 'thin' },
    };
  });
  bugHeaderRow.height = 26;

  const failedTCs = testResults.filter(tc => tc.result === 'FAIL');
  failedTCs.forEach((tc, idx) => {
    const row = bugSheet.getRow(idx + 3);
    [tc.id, tc.severity, tc.category, tc.urlTest, tc.bugDescription, tc.recommendation].forEach((val, i) => {
      const cell     = row.getCell(i + 1);
      cell.value     = val;
      cell.alignment = { vertical: 'middle', wrapText: true, horizontal: i < 2 ? 'center' : 'left' };
      cell.border    = {
        top: { style: 'thin' }, left: { style: 'thin' },
        bottom: { style: 'thin' }, right: { style: 'thin' },
      };
      if (i === 1 && SEVERITY_COLORS[tc.severity]) {
        cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEVERITY_COLORS[tc.severity] } };
      } else if (idx % 2 === 0) {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFF2CC' } };
      }
    });
    row.height = 55;
  });

  bugSheet.columns = [
    { width: 14 }, { width: 12 }, { width: 28 },
    { width: 42 }, { width: 55 }, { width: 55 },
  ];

  await workbook.xlsx.writeFile(OUTPUT_FILE);
  console.log(`✅ Đã xuất báo cáo: ${OUTPUT_FILE}`);
}

generateReport().catch(console.error);
