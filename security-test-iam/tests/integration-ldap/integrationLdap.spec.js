// @ts-check
const { test, expect } = require('@playwright/test');
const { createIntegrationLdapApi } = require('../../api/integrationLdap.api');

/**
 * @description Security Test — Integration LDAP API
 * @owasp     A10:2021 (SSRF), A03:2021 (Injection), A02:2021 (Cryptographic Failures)
 * @author    Antigravity
 */

test.describe('Integration LDAP API — Security Tests', () => {

  /** @type {ReturnType<typeof createIntegrationLdapApi>} */
  let api;

  test.beforeEach(({ request }) => {
    api = createIntegrationLdapApi(request);
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 1: SSRF — connectionUrl
  // ════════════════════════════════════════════════════════════════
  test.describe('SSRF — field connectionUrl', () => {

    const ssrfCases = [
      { name: 'TC-SSRF-01: Chặn localhost:389',                   connectionUrl: 'ldap://localhost:389' },
      { name: 'TC-SSRF-02: Chặn loopback 127.0.0.1',             connectionUrl: 'ldap://127.0.0.1' },
      { name: 'TC-SSRF-03: Chặn private IP 192.168.x.x',         connectionUrl: 'ldap://192.168.1.1:389' },
      { name: 'TC-SSRF-04: Chặn private IP 10.x.x.x',            connectionUrl: 'ldap://10.0.0.1:389' },
      { name: 'TC-SSRF-05: Chặn private IP 172.16.x.x',          connectionUrl: 'ldap://172.16.0.1:389' },
      { name: 'TC-SSRF-06: Chặn cloud metadata AWS/GCP',          connectionUrl: 'ldap://169.254.169.254' },
      { name: 'TC-BSSRF-01: Blind SSRF qua webhook.site',         connectionUrl: 'ldap://webhook.site/ldap-probe' },
    ];

    for (const tc of ssrfCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, connectionUrl: tc.connectionUrl });
        expect(res.status(), `[${tc.name}] IP nội bộ/private phải bị chặn`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 2: Protocol Injection — connectionUrl
  // ════════════════════════════════════════════════════════════════
  test.describe('Protocol Injection — connectionUrl', () => {

    const protocolCases = [
      { name: 'TC-PROTO-01: Chặn HTTP thay vì LDAP',    connectionUrl: 'http://example.com' },
      { name: 'TC-PROTO-02: Chặn HTTPS thay vì LDAP',   connectionUrl: 'https://example.com' },
      { name: 'TC-PROTO-03: Chặn file protocol',         connectionUrl: 'file:///etc/passwd' },
      { name: 'TC-PROTO-04: Chặn gopher protocol',       connectionUrl: 'gopher://127.0.0.1' },
      { name: 'TC-PROTO-05: Chặn ftp protocol',          connectionUrl: 'ftp://example.com' },
      { name: 'TC-PROTO-06: Chuỗi không phải URL',       connectionUrl: 'not-a-url' },
      { name: 'TC-PROTO-07: connectionUrl rỗng',         connectionUrl: '' },
    ];

    for (const tc of protocolCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, connectionUrl: tc.connectionUrl });
        expect(res.status(), `[${tc.name}] Protocol không hợp lệ phải bị chặn`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 3: IP Encoding Bypass & Port Scan
  // ════════════════════════════════════════════════════════════════
  test.describe('IP Encoding Bypass & Port Scan', () => {

    const bypassCases = [
      { name: 'TC-BYPASS-01: IP Decimal (2130706433)',         connectionUrl: 'ldap://2130706433' },
      { name: 'TC-BYPASS-02: IP Hex (0x7f000001)',             connectionUrl: 'ldap://0x7f000001' },
      { name: 'TC-BYPASS-03: URL encoding (%2f)',              connectionUrl: 'ldap://127.0.0.1%2f' },
      { name: 'TC-BYPASS-04: NULL byte injection (%00)',       connectionUrl: 'ldap://localhost%00.example.com' },
      { name: 'TC-PORT-01: Chặn quét SSH port 22',            connectionUrl: 'ldap://localhost:22' },
      { name: 'TC-PORT-02: Chặn quét MySQL port 3306',        connectionUrl: 'ldap://localhost:3306' },
      { name: 'TC-PORT-03: Chặn quét Redis port 6379',        connectionUrl: 'ldap://localhost:6379' },
      { name: 'TC-PORT-04: Chặn quét HTTP port 8080',         connectionUrl: 'ldap://localhost:8080' },
    ];

    for (const tc of bypassCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, connectionUrl: tc.connectionUrl });
        expect(res.status(), `[${tc.name}] Bypass attempt phải bị chặn`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 4: LDAP Injection — bindDn, userDn, Attributes
  // ════════════════════════════════════════════════════════════════
  test.describe('LDAP Injection — bindDn', () => {

    const bindDnCases = [
      { name: 'TC-INJ-01: Filter bypass (*)',     bindDn: 'cn=*)(|(cn=*' },
      { name: 'TC-INJ-02: Xóa toàn bộ user',     bindDn: 'cn=admin,dc=ubck,dc=local)(objectClass=*' },
      { name: 'TC-INJ-03: Null byte',             bindDn: 'cn=admin\x00,dc=ubck,dc=local' },
      { name: 'TC-INJ-04: Wildcard dump all',     bindDn: '*' },
      { name: 'TC-INJ-05: Ký tự đặc biệt DN',    bindDn: 'cn=admin+dc=evil,dc=ubck,dc=local' },
    ];

    for (const tc of bindDnCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, bindDn: tc.bindDn });
        expect(res.status(), `[${tc.name}] LDAP Injection trong bindDn phải bị reject`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  test.describe('LDAP Injection — userDn & Attributes', () => {

    const userDnCases = [
      { name: 'TC-INJ-06: userDn — bypass filter',       field: 'userDn',                value: 'ou=users,dc=ubck,dc=local)(objectClass=*' },
      { name: 'TC-INJ-07: userDn — dump all entries',     field: 'userDn',                value: '*(objectClass=*)' },
      { name: 'TC-INJ-08: userDn — CRLF injection',       field: 'userDn',                value: 'ou=users,dc=ubck,dc=local\r\ndc=evil' },
      { name: 'TC-INJ-09: usernameLdapAttribute',         field: 'usernameLdapAttribute', value: 'uid)(objectClass=*' },
      { name: 'TC-INJ-10: rdnLdapAttribute',              field: 'rdnLdapAttribute',       value: '*(|(objectClass=*))' },
      { name: 'TC-INJ-11: uuidLdapAttribute — null byte', field: 'uuidLdapAttribute',      value: 'entryUUID\x00' },
      { name: 'TC-INJ-12: userObjectClass — bypass',      field: 'userObjectClass',        value: 'inetOrgPerson)(objectClass=*' },
    ];

    for (const tc of userDnCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, [tc.field]: tc.value });
        expect(res.status(), `[${tc.name}] LDAP Injection phải bị reject`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  test.describe('XSS — string fields', () => {

    const xssCases = [
      { name: 'TC-XSS-01: XSS trong bindDn',         field: 'bindDn',          value: '<script>alert(1)</script>' },
      { name: 'TC-XSS-02: XSS trong userDn',          field: 'userDn',          value: '"><img src=x onerror=alert(1)>' },
      { name: 'TC-XSS-03: XSS trong userObjectClass', field: 'userObjectClass', value: "';alert('xss');'" },
    ];

    for (const tc of xssCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, [tc.field]: tc.value });
        expect(res.status(), `[${tc.name}] XSS payload phải bị reject`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 5: Input Validation
  // ════════════════════════════════════════════════════════════════
  test.describe('Input Validation', () => {

    test('TC-VAL-01: Thiếu connectionUrl', async () => {
      const body = { ...api.validBody };
      delete body.connectionUrl;
      const res = await api.update(body);
      expect(res.status(), 'connectionUrl là bắt buộc').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-02: connectionUrl quá dài (2000 ký tự)', async () => {
      const res = await api.update({ ...api.validBody, connectionUrl: 'ldap://' + 'a'.repeat(2000) + '.com' });
      expect(res.status(), 'connectionUrl vượt maxlength phải bị reject').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-03: bindDn quá dài (2000 ký tự)', async () => {
      const res = await api.update({ ...api.validBody, bindDn: 'cn=' + 'a'.repeat(2000) + ',dc=ubck,dc=local' });
      expect(res.status(), 'bindDn vượt maxlength phải bị reject').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-04: enableStartTls là string thay vì boolean', async () => {
      const res = await api.update({ ...api.validBody, enableStartTls: 'true_string_attack' });
      expect([400, 422], 'enableStartTls phải là boolean').toContain(res.status());
    });

    test('TC-VAL-05: bindType không hợp lệ', async () => {
      const res = await api.update({ ...api.validBody, bindType: 'INVALID_TYPE_ATTACK' });
      expect(res.status(), 'bindType không hợp lệ phải bị reject').toBeGreaterThanOrEqual(400);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 6: Authorization
  // ════════════════════════════════════════════════════════════════
  test.describe('Authorization — Token validation', () => {

    test('TC-AUTH-01: Không có Authorization header', async () => {
      const res = await api.updateWithToken(api.validBody, null);
      expect(res.status(), 'Không có token phải trả 401').toBe(401);
    });

    test('TC-AUTH-02: Token giả mạo — chữ ký sai', async () => {
      const res = await api.updateWithToken(
        api.validBody,
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhdHRhY2tlciJ9.FAKE_SIGNATURE',
      );
      expect(res.status(), 'Token giả mạo phải trả 401').toBe(401);
    });

    test('TC-AUTH-03: Token là chuỗi rác', async () => {
      const res = await api.updateWithToken(api.validBody, 'INVALID_TOKEN_STRING');
      expect(res.status(), 'Token rác phải trả 401').toBe(401);
    });

    test('TC-AUTH-04: Token rỗng — Bearer không có giá trị', async () => {
      const res = await api.updateWithToken(api.validBody, '');
      expect([400, 401], 'Token rỗng phải bị reject').toContain(res.status());
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 7: Happy Path
  // ════════════════════════════════════════════════════════════════
  test.describe('Happy Path', () => {

    test('TC-POS-01: ldaps:// hợp lệ (TLS)', async () => {
      const res = await api.update({ ...api.validBody, connectionUrl: 'ldaps://ldap.example.com:636' });
      expect([200, 401], 'ldaps:// hợp lệ phải trả 200 hoặc 401').toContain(res.status());
    });

    test('TC-POS-02: ldap:// hợp lệ (không TLS)', async () => {
      const res = await api.update({ ...api.validBody, connectionUrl: 'ldap://ldap.example.com:389' });
      expect([200, 401], 'ldap:// hợp lệ phải trả 200 hoặc 401').toContain(res.status());
    });
  });
});
