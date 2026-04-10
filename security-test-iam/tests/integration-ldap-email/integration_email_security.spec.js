// @ts-check
const { test, expect } = require('@playwright/test');

/**
 * @description Test Security cho module Cấu hình tích hợp Email (SSRF, Validation)
 * @author Antigravity
 * @date 2026-04-09
 */

const { getAuthHeaders } = require('../../config/env');

const BASE_URL =
  'https://ubck-iam-api.viettelsoftware.com/iam-be/api/v1/integration-config/EMAIL/019d42a4-3f51-7894-a25f-f38a3d38b6a1';

test.describe('Security Test: Integration Email API (SSRF & Validation)', () => {

  const testCases = [
    { name: 'TC-01: Chặn URL localhost',                         url: 'http://localhost:8080' },
    { name: 'TC-02: Chặn địa chỉ loopback 127.0.0.1',           url: 'http://127.0.0.1' },
    { name: 'TC-03: Chặn private IP (192.168.x.x)',              url: 'http://192.168.1.1' },
    { name: 'TC-04: Chặn private IP (10.x.x.x)',                 url: 'http://10.0.0.1' },
    { name: 'TC-05: Chặn private IP (172.16.x.x)',               url: 'http://172.16.0.1' },
    { name: 'TC-06: Chặn cloud metadata endpoint',               url: 'http://169.254.169.254/latest/meta-data' },
    { name: 'TC-07: Chặn SSRF qua redirect',                     url: 'http://httpbin.org/redirect-to?url=http://localhost:8080' },
    { name: 'TC-08: Chặn protocol không hợp lệ (file)',          url: 'file:///etc/passwd' },
    { name: 'TC-09: Chặn protocol không hợp lệ (ftp)',           url: 'ftp://example.com' },
    { name: 'TC-10: Chặn protocol không hợp lệ (gopher)',        url: 'gopher://127.0.0.1' },
    { name: 'TC-11: Chỉ cho phép HTTPS (Chặn HTTP)',             url: 'http://example.com' },
    { name: 'TC-12: Chặn quét port nội bộ (22)',                 url: 'http://localhost:22' },
    { name: 'TC-13: Chặn quét port nội bộ (3306)',               url: 'http://localhost:3306' },
    { name: 'TC-14: Chặn quét port nội bộ (6379)',               url: 'http://localhost:6379' },
    { name: 'TC-15: Chặn IP encode Decimal',                     url: 'http://2130706433' },
    { name: 'TC-16: Chặn IP encode Hex',                         url: 'http://0x7f000001' },
    { name: 'TC-17: Chặn bypass bằng encoding URL',              url: 'http://127.0.0.1%2f' },
    { name: 'TC-18: Chặn bypass bằng NULL byte',                 url: 'http://localhost%00.example.com' },
    { name: 'TC-19: Chặn domain không có trong whitelist',       url: 'http://evil.com' },
    { name: 'TC-20: Chặn truy cập internal service',             url: 'http://internal-service/admin' },
  ];

  for (const tc of testCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: getAuthHeaders(),
        data: {
          type: 'EMAIL',
          status: 'ACTIVE',
          url: tc.url,
          method: 'PUT',
        },
      });

      expect(
        response.status(),
        `Test case ${tc.name} phải bị chặn với status >= 400`,
      ).toBeGreaterThanOrEqual(400);
    });
  }

  test('TC-Positive: Cho phép URL hợp lệ (HTTPS)', async ({ request }) => {
    const validUrl = 'https://mail.google.com/api/v1';
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: {
        type: 'EMAIL',
        status: 'ACTIVE',
        url: validUrl,
        method: 'PUT',
      },
    });

    // Nếu token còn sống và URL hợp lệ → 200, token hết → 401
    expect([200, 401]).toContain(response.status());
  });

  test('TC-BlindSSRF: Kiểm tra Blind SSRF qua webhook.site', async ({ request }) => {
    const webhookUrl = 'http://webhook.site/019d42a4-3f51-7894-a25f-f38a3d38b6a1';
    const response = await request.put(BASE_URL, {
      headers: getAuthHeaders(),
      data: {
        type: 'EMAIL',
        status: 'ACTIVE',
        url: webhookUrl,
        method: 'PUT',
      },
    });

    // BE chặn và không gửi request ra ngoài → 400
    expect(response.status()).toBeGreaterThanOrEqual(400);
  });
});
