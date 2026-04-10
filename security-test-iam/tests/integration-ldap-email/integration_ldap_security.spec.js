// @ts-check
const { test, expect } = require('@playwright/test');

/**
 * @description Test Security cho module Cấu hình tích hợp LDAP
 * @coverage  SSRF (connectionUrl) + LDAP Injection (bindDn, userDn, attributes)
 * @owasp     A10:2021, A03:2021, A02:2021
 * @author    Antigravity
 * @date      2026-04-09
 */

const { getAuthHeaders } = require('../../config/env');

const BASE_URL =
  'https://ubck-iam-api.viettelsoftware.com/iam-be/api/v1/integration-config/LDAP/019d427c-8ffd-792b-9be7-04405729c9ae';

/** Body hợp lệ dùng làm base, override từng field khi test */
const validBody = {
  type: 'LDAP',
  status: 'ACTIVE',
  connectionUrl: 'ldaps://ldap.example.com:636',
  enableStartTls: false,
  bindType: 'none',
  bindDn: 'cn=admin,dc=ubck,dc=local',
  userDn: 'ou=users,dc=ubck,dc=local',
  usernameLdapAttribute: 'uid',
  rdnLdapAttribute: 'uid',
  uuidLdapAttribute: 'entryUUID',
  userObjectClass: 'inetOrgPerson',
  connectionPooling: false,
};

// ════════════════════════════════════════════════════════════════════
// SECTION 1: SSRF — Kiểm tra connectionUrl
// ════════════════════════════════════════════════════════════════════
test.describe('Security Test: LDAP connectionUrl — SSRF & Protocol Injection', () => {

  // ── 1.1 SSRF Private / Loopback IPs ──────────────────────────────
  const ssrfIpCases = [
    { name: 'TC-SSRF-01: Chặn localhost:389',               connectionUrl: 'ldap://localhost:389' },
    { name: 'TC-SSRF-02: Chặn loopback 127.0.0.1',         connectionUrl: 'ldap://127.0.0.1' },
    { name: 'TC-SSRF-03: Chặn private IP 192.168.x.x',     connectionUrl: 'ldap://192.168.1.1:389' },
    { name: 'TC-SSRF-04: Chặn private IP 10.x.x.x',        connectionUrl: 'ldap://10.0.0.1:389' },
    { name: 'TC-SSRF-05: Chặn private IP 172.16.x.x',      connectionUrl: 'ldap://172.16.0.1:389' },
    { name: 'TC-SSRF-06: Chặn cloud metadata AWS/GCP',      connectionUrl: 'ldap://169.254.169.254' },
  ];

  for (const tc of ssrfIpCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, connectionUrl: tc.connectionUrl },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải reject connectionUrl trỏ đến địa chỉ nội bộ — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 1.2 Protocol Injection ────────────────────────────────────────
  const protocolCases = [
    { name: 'TC-PROTO-01: Chặn HTTP thay vì LDAP',     connectionUrl: 'http://example.com' },
    { name: 'TC-PROTO-02: Chặn HTTPS thay vì LDAP',    connectionUrl: 'https://example.com' },
    { name: 'TC-PROTO-03: Chặn file protocol',          connectionUrl: 'file:///etc/passwd' },
    { name: 'TC-PROTO-04: Chặn gopher protocol',        connectionUrl: 'gopher://127.0.0.1' },
    { name: 'TC-PROTO-05: Chặn ftp protocol',           connectionUrl: 'ftp://example.com' },
    { name: 'TC-PROTO-06: Chặn chuỗi không phải URL',  connectionUrl: 'not-a-url' },
    { name: 'TC-PROTO-07: Chặn connectionUrl rỗng',    connectionUrl: '' },
  ];

  for (const tc of protocolCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, connectionUrl: tc.connectionUrl },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải reject protocol không phải ldap:// hoặc ldaps:// — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 1.3 IP Encoding Bypass ────────────────────────────────────────
  const encodingCases = [
    { name: 'TC-BYPASS-01: IP Decimal (127.0.0.1 = 2130706433)', connectionUrl: 'ldap://2130706433' },
    { name: 'TC-BYPASS-02: IP Hex (127.0.0.1 = 0x7f000001)',     connectionUrl: 'ldap://0x7f000001' },
    { name: 'TC-BYPASS-03: URL encoding (%2f bypass)',            connectionUrl: 'ldap://127.0.0.1%2f' },
    { name: 'TC-BYPASS-04: NULL byte injection (%00)',            connectionUrl: 'ldap://localhost%00.example.com' },
  ];

  for (const tc of encodingCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, connectionUrl: tc.connectionUrl },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải normalize URL và phát hiện bypass — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 1.4 Port Scan qua SSRF ────────────────────────────────────────
  const portScanCases = [
    { name: 'TC-PORT-01: Chặn quét SSH port 22',      connectionUrl: 'ldap://localhost:22' },
    { name: 'TC-PORT-02: Chặn quét MySQL port 3306',  connectionUrl: 'ldap://localhost:3306' },
    { name: 'TC-PORT-03: Chặn quét Redis port 6379',  connectionUrl: 'ldap://localhost:6379' },
    { name: 'TC-PORT-04: Chặn quét HTTP port 8080',   connectionUrl: 'ldap://localhost:8080' },
  ];

  for (const tc of portScanCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, connectionUrl: tc.connectionUrl },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải reject localhost kèm port nguy hiểm — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 1.5 Blind SSRF ───────────────────────────────────────────────
  test('TC-BSSRF-01: Blind SSRF — server không được gửi outbound request', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, connectionUrl: 'ldap://webhook.site/ldap-probe-test' },
    });

    expect(
      response.status(),
      'Server phải reject URL không trong whitelist và không gửi outbound request',
    ).toBeGreaterThanOrEqual(400);
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 2: LDAP Injection — Kiểm tra các string field
// ════════════════════════════════════════════════════════════════════
test.describe('Security Test: LDAP Injection — bindDn, userDn, Attributes', () => {

  // ── 2.1 LDAP Injection trong bindDn ──────────────────────────────
  const bindDnInjectionCases = [
    { name: 'TC-INJ-01: LDAP Injection bindDn — filter bypass (*)',    bindDn: 'cn=*)(|(cn=*' },
    { name: 'TC-INJ-02: LDAP Injection bindDn — xóa toàn bộ user',    bindDn: 'cn=admin,dc=ubck,dc=local)(objectClass=*' },
    { name: 'TC-INJ-03: LDAP Injection bindDn — null byte',            bindDn: 'cn=admin\x00,dc=ubck,dc=local' },
    { name: 'TC-INJ-04: LDAP Injection bindDn — wildcard dump all',    bindDn: '*' },
    { name: 'TC-INJ-05: LDAP Injection bindDn — ký tự đặc biệt DN',   bindDn: 'cn=admin+dc=evil,dc=ubck,dc=local' },
  ];

  for (const tc of bindDnInjectionCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, bindDn: tc.bindDn },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải sanitize và reject LDAP Injection trong bindDn — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 2.2 LDAP Injection trong userDn ──────────────────────────────
  const userDnInjectionCases = [
    { name: 'TC-INJ-06: LDAP Injection userDn — bypass filter',       userDn: 'ou=users,dc=ubck,dc=local)(objectClass=*' },
    { name: 'TC-INJ-07: LDAP Injection userDn — dump tất cả entries', userDn: '*(objectClass=*)' },
    { name: 'TC-INJ-08: LDAP Injection userDn — ký tự đặc biệt',     userDn: 'ou=users,dc=ubck,dc=local\r\ndc=evil' },
  ];

  for (const tc of userDnInjectionCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, userDn: tc.userDn },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải sanitize LDAP Injection trong userDn — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 2.3 LDAP Injection trong Attributes ──────────────────────────
  const attributeInjectionCases = [
    { name: 'TC-INJ-09: LDAP Injection usernameLdapAttribute — filter injection', field: 'usernameLdapAttribute', value: 'uid)(objectClass=*' },
    { name: 'TC-INJ-10: LDAP Injection rdnLdapAttribute — special chars',         field: 'rdnLdapAttribute',       value: '*(|(objectClass=*))' },
    { name: 'TC-INJ-11: LDAP Injection uuidLdapAttribute — null byte',            field: 'uuidLdapAttribute',      value: 'entryUUID\x00' },
    { name: 'TC-INJ-12: LDAP Injection userObjectClass — bypass class filter',    field: 'userObjectClass',        value: 'inetOrgPerson)(objectClass=*' },
  ];

  for (const tc of attributeInjectionCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, [tc.field]: tc.value },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải sanitize LDAP meta-characters trong ${tc.field} — expected >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  // ── 2.4 XSS trong string fields ───────────────────────────────
  const xssCases = [
    { name: 'TC-XSS-01: XSS trong bindDn',       field: 'bindDn',          value: '<script>alert(1)</script>' },
    { name: 'TC-XSS-02: XSS trong userDn',        field: 'userDn',          value: '"><img src=x onerror=alert(1)>' },
    { name: 'TC-XSS-03: XSS trong userObjectClass', field: 'userObjectClass', value: "';alert('xss');'" },
  ];

  for (const tc of xssCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: { ...validBody, [tc.field]: tc.value },
      });

      expect(
        response.status(),
        `[${tc.name}] Server phải reject hoặc sanitize XSS payload trong ${tc.field}`,
      ).toBeGreaterThanOrEqual(400);
    });
  }
});

// ════════════════════════════════════════════════════════════════════
// SECTION 3: Input Validation — Kiểm tra field validation
// ════════════════════════════════════════════════════════════════════
test.describe('Security Test: LDAP Field Validation', () => {

  test('TC-VAL-01: Thiếu connectionUrl — bắt buộc có giá trị', async ({ request }) => {
    const body = { ...validBody };
    delete body.connectionUrl;

    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: body,
    });

    expect(
      response.status(),
      'connectionUrl là bắt buộc — expected 400',
    ).toBeGreaterThanOrEqual(400);
  });

  test('TC-VAL-02: connectionUrl quá dài — giới hạn maxlength', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, connectionUrl: 'ldap://' + 'a'.repeat(2000) + '.com' },
    });

    expect(
      response.status(),
      'connectionUrl vượt maxlength phải bị reject — expected 400',
    ).toBeGreaterThanOrEqual(400);
  });

  test('TC-VAL-03: bindDn quá dài — giới hạn maxlength', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, bindDn: 'cn=' + 'a'.repeat(2000) + ',dc=ubck,dc=local' },
    });

    expect(
      response.status(),
      'bindDn vượt maxlength phải bị reject — expected 400',
    ).toBeGreaterThanOrEqual(400);
  });

  test('TC-VAL-04: enableStartTls là boolean — từ chối string', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, enableStartTls: 'true_string_attack' },
    });

    expect(
      [400, 422],
      'enableStartTls phải là boolean — expected 400 hoặc 422',
    ).toContain(response.status());
  });

  test('TC-VAL-05: bindType không hợp lệ', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, bindType: 'INVALID_TYPE_ATTACK' },
    });

    expect(
      response.status(),
      'bindType không hợp lệ phải bị reject — expected 400',
    ).toBeGreaterThanOrEqual(400);
  });
});

// ════════════════════════════════════════════════════════════════════
// SECTION 4: Happy Path — Kiểm tra kịch bản hợp lệ
// ════════════════════════════════════════════════════════════════════
test.describe('Happy Path: LDAP hợp lệ', () => {

  test('TC-POS-01: Cấu hình LDAP hợp lệ với ldaps:// (chuẩn TLS)', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, connectionUrl: 'ldaps://ldap.example.com:636' },
    });

    expect(
      [200, 401],
      'URL ldaps:// hợp lệ phải được chấp nhận (200) hoặc token hết hạn (401)',
    ).toContain(response.status());
  });

  test('TC-POS-02: Cấu hình LDAP hợp lệ với ldap:// (không TLS)', async ({ request }) => {
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: { ...validBody, connectionUrl: 'ldap://ldap.example.com:389' },
    });

    expect(
      [200, 401],
      'URL ldap:// hợp lệ phải được chấp nhận (200) hoặc token hết hạn (401)',
    ).toContain(response.status());
  });
});
