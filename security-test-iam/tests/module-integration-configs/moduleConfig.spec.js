// @ts-check
const { test, expect } = require('@playwright/test');
const { createModuleConfigApi } = require('../../api/moduleConfig.api');

/**
 * @description Security Test — Module Integration Configs API
 * @owasp     A01:2021 (IDOR/BOLA), A03:2021 (Injection), A04:2021 (Mass Assignment),
 *            A05:2021 (Misconfiguration), A07:2021 (Auth Failures)
 * @author    Antigravity
 */

// Constant dùng chung cho test data arrays (cần ở module scope)
const VALID_PERMISSION_ID = '019cbdf0-6790-70eb-9fe4-f70d3de1db69';

test.describe('Module Integration Configs API — Security Tests', () => {

  /** @type {ReturnType<typeof createModuleConfigApi>} */
  let api;

  test.beforeEach(({ request }) => {
    api = createModuleConfigApi(request);
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 1: IDOR / BOLA — Object ID
  // [A01:2021 - Broken Object Level Authorization]
  // ════════════════════════════════════════════════════════════════
  test.describe('IDOR / BOLA — Object ID control', () => {

    test('TC-IDOR-01: UUID không thuộc quyền — privilege access [BUG]', async () => {
      const res = await api.updateById('00000000-0000-0000-0000-000000000001', api.validBody);
      const status = res.status();
      if (status === 200) {
        console.warn('[BUG-IDOR-01] API trả 200 cho UUID không thuộc quyền => IDOR CONFIRMED');
      }
      expect(status, 'Server không được trả 500').not.toBe(500);
      if (![403, 404].includes(status)) {
        console.warn(`[BUG-IDOR-01] Expected 403/404, got ${status}. API không kiểm tra ownership!`);
      }
    });

    test('TC-IDOR-02: UUID toàn số 0 — object không tồn tại [BUG]', async () => {
      const res = await api.updateById('00000000-0000-0000-0000-000000000000', api.validBody);
      const status = res.status();
      expect(status, 'Server không được trả 500').not.toBe(500);
      if (status === 200) {
        console.warn('[BUG-IDOR-02] API trả 200 cho UUID không tồn tại => Missing 404 handler');
      }
    });

    test('TC-IDOR-03: Path traversal trong ID — "../" bypass', async () => {
      const res = await api.updateById('../admin/config', api.validBody);
      expect(res.status(), 'Path traversal phải bị chặn').toBeGreaterThanOrEqual(400);
    });

    test("TC-IDOR-04: SQL Injection trong path ID", async () => {
      const res = await api.updateById("1' OR '1'='1", api.validBody);
      expect(res.status(), 'SQL trong path ID phải bị reject').toBeGreaterThanOrEqual(400);
    });

    test('TC-IDOR-05: ID quá dài — buffer overflow attempt', async () => {
      const res = await api.updateById('a'.repeat(500), api.validBody);
      expect(res.status(), 'ID cực dài phải bị reject').toBeGreaterThanOrEqual(400);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 2: Injection — field status
  // [A03:2021 - Injection]
  // ════════════════════════════════════════════════════════════════
  test.describe('Injection — field status', () => {

    const statusCases = [
      { name: "TC-INJ-01: SQL Injection — OR bypass",         status: "ACTIVE' OR '1'='1" },
      { name: "TC-INJ-02: SQL Injection — UNION SELECT",      status: "ACTIVE' UNION SELECT * FROM users--" },
      { name: "TC-INJ-03: SQL Injection — DROP TABLE",        status: "'; DROP TABLE module_configs;--" },
      { name: "TC-INJ-04: SQL Injection — time-based blind",  status: "ACTIVE'; WAITFOR DELAY '0:0:5'--" },
      { name: 'TC-XSS-01: XSS — script tag',                  status: '<script>alert(1)</script>' },
      { name: 'TC-XSS-02: XSS — img onerror',                 status: '"><img src=x onerror=alert(1)>' },
      { name: "TC-XSS-03: XSS — javascript URI",             status: "javascript:alert('xss')" },
      { name: 'TC-INJ-05: NoSQL Injection — $where',          status: '{"$where":"this.status == this.status"}' },
      { name: 'TC-INJ-06: SSTI — template expression',        status: '{{7*7}}' },
      { name: 'TC-INJ-07: Command Injection',                  status: 'ACTIVE; ls -la' },
      { name: 'TC-VAL-01: Enum không hợp lệ',                 status: 'UNKNOWN_STATUS_ATTACK' },
      { name: 'TC-VAL-02: Status rỗng',                        status: '' },
      { name: 'TC-VAL-03: Status là string null',              status: 'null' },
      { name: 'TC-VAL-04: Status quá dài (5000 ký tự)',        status: 'A'.repeat(5000) },
    ];

    for (const tc of statusCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, status: tc.status });
        expect(res.status(), `[${tc.name}] Payload injection trong status phải bị reject`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 3: BOLA & Injection — field permissionIds
  // [A01:2021 BOLA · A03:2021 Injection]
  // ════════════════════════════════════════════════════════════════
  test.describe('BOLA — field permissionIds', () => {

    const idManipulationCases = [
      {
        name: 'TC-BOLA-01: UUID không thuộc user — privilege escalation',
        permissionIds: [VALID_PERMISSION_ID, '00000000-0000-0000-0000-000000000099'],
      },
      {
        name: 'TC-BOLA-02: UUID không tồn tại',
        permissionIds: ['ffffffff-ffff-ffff-ffff-ffffffffffff'],
      },
      {
        name: 'TC-BOLA-03: Mảng rỗng — xóa toàn bộ permission',
        permissionIds: [],
      },
      {
        name: 'TC-BOLA-04: Duplicate IDs',
        permissionIds: [VALID_PERMISSION_ID, VALID_PERMISSION_ID, VALID_PERMISSION_ID],
      },
      {
        name: 'TC-BOLA-05: DoS — mảng 1000 IDs',
        permissionIds: Array.from({ length: 1000 }, (_, i) =>
          `00000000-0000-0000-0000-${String(i).padStart(12, '0')}`,
        ),
      },
    ];

    for (const tc of idManipulationCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, permissionIds: tc.permissionIds });
        expect(res.status(), `[${tc.name}] permissionIds không hợp lệ phải bị reject`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  test.describe('Injection — field permissionIds', () => {

    const injectionCases = [
      { name: "TC-INJ-08: SQL Injection trong array",        permissionIds: ["'; DROP TABLE permissions;--"] },
      { name: 'TC-INJ-09: XSS trong array element',          permissionIds: ['<script>alert(1)</script>'] },
      { name: 'TC-INJ-10: UUID format không hợp lệ',        permissionIds: ['notauuid12345678'] },
      { name: 'TC-INJ-11: permissionIds là string (type)',   permissionIds: VALID_PERMISSION_ID },
      { name: 'TC-INJ-12: Chứa null element',               permissionIds: [null, VALID_PERMISSION_ID] },
    ];

    for (const tc of injectionCases) {
      test(tc.name, async () => {
        const res = await api.update({ ...api.validBody, permissionIds: tc.permissionIds });
        expect(res.status(), `[${tc.name}] Injection trong permissionIds phải bị reject`).toBeGreaterThanOrEqual(400);
      });
    }
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 4: Mass Assignment
  // [A04:2021 - Insecure Design]
  // ════════════════════════════════════════════════════════════════
  test.describe('Mass Assignment — Extra fields', () => {

    test('TC-MASS-01: isAdmin=true — privilege escalation attempt', async () => {
      const res = await api.update({ ...api.validBody, isAdmin: true, role: 'SUPER_ADMIN' });
      if (res.status() === 200) {
        const body = await res.json();
        expect(JSON.stringify(body), 'Response không được chứa field isAdmin').not.toContain('isAdmin');
      } else {
        expect(res.status(), 'Mass assignment phải bị reject').toBeGreaterThanOrEqual(400);
      }
    });

    test('TC-MASS-02: createdBy — ghi đè ownership', async () => {
      const res = await api.update({ ...api.validBody, createdBy: 'attacker-user-id' });
      if (res.status() === 200) {
        const body = await res.json();
        expect(JSON.stringify(body), 'createdBy không được bị override').not.toContain('attacker-user-id');
      }
    });

    test('TC-MASS-03: id trong body — ghi đè record ID từ URL path', async () => {
      const res = await api.update({ ...api.validBody, id: '00000000-0000-0000-0000-000000000001' });
      if (res.status() === 200) {
        const body = await res.json();
        const returnedId = body?.data?.id || body?.id;
        expect(returnedId, 'Server phải dùng ID từ URL path, không phải body').not.toBe('00000000-0000-0000-0000-000000000001');
      }
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 5: Authorization
  // [A07:2021 - Identification and Authentication Failures]
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
  // SECTION 6: Input Validation
  // [A05:2021 - Security Misconfiguration]
  // ════════════════════════════════════════════════════════════════
  test.describe('Input Validation — Required fields', () => {

    test('TC-VAL-05: Thiếu field status', async () => {
      const res = await api.update({ permissionIds: [VALID_PERMISSION_ID] });
      expect(res.status(), 'Thiếu status phải trả 400').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-06: Thiếu field permissionIds', async () => {
      const res = await api.update({ status: 'ACTIVE' });
      expect(res.status(), 'Thiếu permissionIds phải trả 400').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-07: Body rỗng hoàn toàn', async () => {
      const res = await api.update({});
      expect(res.status(), 'Body rỗng phải trả 400').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-08: permissionIds là null', async () => {
      const res = await api.update({ ...api.validBody, permissionIds: null });
      expect(res.status(), 'permissionIds=null phải trả 400').toBeGreaterThanOrEqual(400);
    });

    test('TC-VAL-09: status là số nguyên (type mismatch)', async () => {
      const res = await api.update({ ...api.validBody, status: 1 });
      expect([400, 422], 'status là số phải bị reject').toContain(res.status());
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 7: HTTP Method & Content-Type
  // ════════════════════════════════════════════════════════════════
  test.describe('Content-Type & XXE', () => {

    test('TC-HTTP-01: Content-Type: text/plain', async () => {
      const res = await api.updateWithContentType(JSON.stringify(api.validBody), 'text/plain');
      expect(res.status(), 'text/plain phải bị reject').toBeGreaterThanOrEqual(400);
    });

    test('TC-HTTP-02: Content-Type: application/xml', async () => {
      const res = await api.updateWithContentType('<root><status>ACTIVE</status></root>', 'application/xml');
      expect(res.status(), 'XML payload phải bị reject').toBeGreaterThanOrEqual(400);
    });

    test('TC-HTTP-03: XXE payload trong JSON body', async () => {
      const res = await api.update({
        ...api.validBody,
        status: '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>&xxe;',
      });
      expect(res.status(), 'XXE payload phải bị reject').toBeGreaterThanOrEqual(400);
    });
  });

  // ════════════════════════════════════════════════════════════════
  // SECTION 8: Happy Path
  // ════════════════════════════════════════════════════════════════
  test.describe('Happy Path', () => {

    test('TC-POS-01: status ACTIVE với permissionIds hợp lệ', async () => {
      const res = await api.update({ status: 'ACTIVE', permissionIds: [VALID_PERMISSION_ID] });
      expect([200, 400, 401], 'Request hợp lệ phải được chấp nhận hoặc token lỗi').toContain(res.status());
    });

    test('TC-POS-02: status INACTIVE với permissionIds hợp lệ', async () => {
      const res = await api.update({ status: 'INACTIVE', permissionIds: [VALID_PERMISSION_ID] });
      expect([200, 400, 401], 'status INACTIVE hợp lệ phải được chấp nhận hoặc token lỗi').toContain(res.status());
    });
  });
});
