// @ts-check
const { test, expect } = require('@playwright/test');
const { createIntegrationEmailApi } = require('../../api/integrationEmail.api');

/**
 * @description Security Test — Integration Email API
 * @owasp     A10:2021 (SSRF), A07:2021 (Auth Failures)
 * @author    Antigravity
 */

test.describe('Integration Email API — Security Tests', () => {

  /** @type {ReturnType<typeof createIntegrationEmailApi>} */
  let api;

  test.beforeEach(({ request }) => {
    api = createIntegrationEmailApi(request);
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 1: SSRF — Kiểm tra URL field
  // ════════════════════════════════════════════════════════════════
  test.describe('SSRF & Protocol Injection — field url', () => {

    const ssrfCases = [
      { name: 'TC-SSRF-01: Chặn localhost',                          url: 'http://localhost:8080' },
      { name: 'TC-SSRF-02: Chặn loopback 127.0.0.1',                url: 'http://127.0.0.1' },
      { name: 'TC-SSRF-03: Chặn private IP 192.168.x.x',            url: 'http://192.168.1.1' },
      { name: 'TC-SSRF-04: Chặn private IP 10.x.x.x',               url: 'http://10.0.0.1' },
      { name: 'TC-SSRF-05: Chặn private IP 172.16.x.x',             url: 'http://172.16.0.1' },
      { name: 'TC-SSRF-06: Chặn cloud metadata endpoint',            url: 'http://169.254.169.254/latest/meta-data' },
      { name: 'TC-SSRF-07: Chặn SSRF qua redirect',                  url: 'http://httpbin.org/redirect-to?url=http://localhost:8080' },
      { name: 'TC-SSRF-08: Blind SSRF qua webhook.site',             url: 'http://webhook.site/019d42a4-3f51-7894-a25f-f38a3d38b6a1' },
      { name: 'TC-PROTO-01: Chặn protocol file://',                  url: 'file:///etc/passwd' },
      { name: 'TC-PROTO-02: Chặn protocol ftp://',                   url: 'ftp://example.com' },
      { name: 'TC-PROTO-03: Chặn protocol gopher://',                url: 'gopher://127.0.0.1' },
      { name: 'TC-PROTO-04: Chỉ cho phép HTTPS — chặn HTTP',        url: 'http://example.com' },
      { name: 'TC-PORT-01: Chặn quét SSH port 22',                   url: 'http://localhost:22' },
      { name: 'TC-PORT-02: Chặn quét MySQL port 3306',               url: 'http://localhost:3306' },
      { name: 'TC-PORT-03: Chặn quét Redis port 6379',               url: 'http://localhost:6379' },
      { name: 'TC-BYPASS-01: Chặn IP Decimal (2130706433)',          url: 'http://2130706433' },
      { name: 'TC-BYPASS-02: Chặn IP Hex (0x7f000001)',              url: 'http://0x7f000001' },
      { name: 'TC-BYPASS-03: Chặn URL encoding (%2f)',               url: 'http://127.0.0.1%2f' },
      { name: 'TC-BYPASS-04: Chặn NULL byte (%00)',                  url: 'http://localhost%00.example.com' },
      { name: 'TC-WLIST-01: Chặn domain ngoài whitelist',            url: 'http://evil.com' },
      { name: 'TC-WLIST-02: Chặn truy cập internal service',         url: 'http://internal-service/admin' },
    ];

    for (const tc of ssrfCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, url: tc.url });
        expect(res.status(), `[${tc.name}] URL nguy hiểm phải bị chặn — expected >= 400`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 2: Authorization
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

    test('TC-AUTH-05: Sai auth scheme — Basic thay vì Bearer', async () => {
      const res = await api.update(api.validBody, {
        Authorization: 'Basic YWRtaW46cGFzc3dvcmQ=',
        'Content-Type': 'application/json',
      });
      expect(res.status(), 'Basic auth scheme phải bị reject').toBe(401);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 3: Happy Path
  // ════════════════════════════════════════════════════════════════
  test.describe('Happy Path', () => {

    test('TC-POS-01: URL HTTPS hợp lệ — phải được chấp nhận', async () => {
      const res = await api.update({ ...api.validBody, url: 'https://mail.google.com/api/v1' });
      expect([200, 401], 'URL hợp lệ phải trả 200 hoặc 401 (token hết hạn)').toContain(res.status());
    });
  });
});
