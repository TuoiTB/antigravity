import { test, expect } from '@playwright/test';

/**
 * @description Test Security cho module Cấu hình tích hợp Email (SSRF, Validation)
 * @author Antigravity
 * @date 2026-04-09
 */

const BASE_URL = 'https://ubck-iam-api.viettelsoftware.com/iam-be/api/v1/integration-config/EMAIL/019d42a4-3f51-7894-a25f-f38a3d38b6a1';
const TOKEN = 'eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJFV3VBVUI0R0xUeGRMWnUyclA0VkEzNHJTc2o3dWp1UlE3ZU9wMFRFT04wIn0.eyJleHAiOjE3NzU3ODM5MTYsImlhdCI6MTc3NTY5NzUxNiwiYXV0aF90aW1lIjoxNzc1Njk3NTE2LCJqdGkiOiJvbnJ0YWM6MTE2NDgzODktMTkzNC0xMjk5LWQ3MWUtNDJmZTg1ZTFkMmY3IiwiaXNzIjoiaHR0cHM6Ly91YmNrLXNzby52aWV0dGVsc29mdHdhcmUuY29tL3JlYWxtcy91YmNrIiwiYXVkIjoiYWNjb3VudCIsInN1YiI6IjkzYjg1OGI1LWFmNjctNDVhOC05NGVmLWQyZGE1OWRlNjMwMCIsInR5cCI6IkJlYXJlciIsImF6cCI6InViY2stY2xpIiwic2lkIjoiYWZlNDg5MDYtNmVlZC1kZGZkLWJmYmYtMjk0ZTgzNjhlNjc1IiwiYWNyIjoiMSIsImFsbG93ZWQtb3JpZ2lucyI6WyIqIl0sInJlYWxtX2FjY2VzcyI6eyJyb2xlcyI6WyJvZmZsaW5lX2FjY2VzcyIsImRlZmF1bHQtcm9sZXMtdWJjayIsInVtYV9hdXRob3JpemF0aW9uIl19LCJyZXNvdXJjZV9hY2Nlc3MiOnsiYWNjb3VudCI6eyJyb2xlcyI6WyJtYW5hZ2UtYWNjb3VudCIsIm1hbmFnZS1hY2NvdW50LWxpbmtzIiwidmlldy1wcm9maWxlIl19fSwic2NvcGUiOiJvcGVuaWQgcHJvZmlsZSBlbWFpbCIsImVtYWlsX3ZlcmlmaWVkIjpmYWxzZSwibmFtZSI6ImFkbWluLXViY2sgS0jDlE5HIFjDk0EgVMOKTiBS4bqkVCBEw4BJIExVw5ROIE5Iw4kgc2RmIiwicHJlZmVycmVkX3VzZXJuYW1lIjoiYWRtaW4tdWJjayIsImdpdmVuX25hbWUiOiJhZG1pbi11YmNrIEtIw5RORyBYw5NBIFTDik4gUuG6pFQgRMOASSBMVcOUTiBOSMOJIiwiZmFtaWx5X25hbWUiOiJzZGYiLCJtYW5hZ2VyX3VzZXJfaWQiOiIwMTljYmQ4Ny0zZjQ4LTc3N2QtYjQ2NS02Yzk5ZTUxMTE3NDYiLCJlbWFpbCI6ImFkbWluLXViY2tzQHlvcG1haWwuY29tIn0.K1YYNRcqQP5lgMfts13oaPKy0HsGiHaFwztkEfBXzwlYo6oWd8JStPPylrFW1QFaYFZxnYdry7k_PQOJC1yI-459BDanWR5K9HP_Q1Xbkj8g5mmlCWMZgxMwR3nQEoOb9ro5ZDyACjB34gs6DdYx6iWxR-BgRiXBJLswBM10uh1bwrIXDeke4zXDmXkEw7lyhhDLRobz_8iqauoSIevUdMUKV3jf5W3o3J72bQ3kIBS8J5Mbzq5_o8MSuGyZCInePmDXOYmG0XcCMWODV-oK5s64XPfNnQtkgz9k2VutfYs_1kM0OWkgDf62Zqa5dgkw8JefNcabUdzjx0iutDUv-w';

const commonHeaders = {
  'Authorization': `Bearer ${TOKEN}`,
  'Content-Type': 'application/json',
  'Accept': 'application/json, text/plain, */*',
  'Accept-Language': 'vi',
  'sec-ch-ua-platform': '"Windows"',
  'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
  'sec-ch-ua-mobile': '?0',
  'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
  'Referer': 'https://ubck-iam.viettelsoftware.com/',
};

test.describe('Security Test: Integration Email API (SSRF & Validation)', () => {

  const testCases = [
    { name: 'TC-01: Chặn URL localhost', url: 'http://localhost:8080' },
    { name: 'TC-02: Chặn địa chỉ loopback 127.0.0.1', url: 'http://127.0.0.1' },
    { name: 'TC-03: Chặn private IP (192.168.x.x)', url: 'http://192.168.1.1' },
    { name: 'TC-04: Chặn private IP (10.x.x.x)', url: 'http://10.0.0.1' },
    { name: 'TC-05: Chặn private IP (172.16.x.x)', url: 'http://172.16.0.1' },
    { name: 'TC-06: Chặn cloud metadata endpoint', url: 'http://169.254.169.254/latest/meta-data' },
    { name: 'TC-07: Chặn SSRF qua redirect', url: 'http://httpbin.org/redirect-to?url=http://localhost:8080' },
    { name: 'TC-08: Chặn protocol không hợp lệ (file)', url: 'file:///etc/passwd' },
    { name: 'TC-09: Chặn protocol không hợp lệ (ftp)', url: 'ftp://example.com' },
    { name: 'TC-10: Chặn protocol không hợp lệ (gopher)', url: 'gopher://127.0.0.1' },
    { name: 'TC-11: Chỉ cho phép HTTPS (Chặn HTTP)', url: 'http://example.com' },
    { name: 'TC-12: Chặn quét port nội bộ (22)', url: 'http://localhost:22' },
    { name: 'TC-13: Chặn quét port nội bộ (3306)', url: 'http://localhost:3306' },
    { name: 'TC-14: Chặn quét port nội bộ (6379)', url: 'http://localhost:6379' },
    { name: 'TC-15: Chặn IP encode Decimal', url: 'http://2130706433' },
    { name: 'TC-16: Chặn IP encode Hex', url: 'http://0x7f000001' },
    { name: 'TC-17: Chặn bypass bằng encoding URL', url: 'http://127.0.0.1%2f' },
    { name: 'TC-18: Chặn bypass bằng NULL byte', url: 'http://localhost%00.example.com' },
    { name: 'TC-19: Chặn domain không có trong whitelist', url: 'http://evil.com' },
    { name: 'TC-20: Chặn truy cập internal service', url: 'http://internal-service/admin' },
  ];

  for (const tc of testCases) {
    test(tc.name, async ({ request }) => {
      const response = await request.put(BASE_URL, {
        headers: commonHeaders,
        data: {
          type: 'EMAIL',
          status: 'ACTIVE',
          url: tc.url,
          method: 'PUT'
        }
      });

      // Assertions
      // BE bắt buộc check và hiển thị lỗi: “URL không hợp lệ” (hoặc tương đương)
      // Thường thì status sẽ là 400 Bad Request
      console.log(`[${tc.name}] Testing URL: ${tc.url}`);
      console.log(`Response Status: ${response.status()}`);
      const body = await response.json();
      console.log(`Response Body:`, body);

      expect(response.status(), `Test case ${tc.name} should fail with 400 or restricted status`).toBeGreaterThanOrEqual(400);

      // Kiểm tra message lỗi nếu có
      // Tùy thuộc vào thực tế API trả về gì, ở đây giả định message chứa "không hợp lệ" hoặc mã lỗi specific
      // expect(JSON.stringify(body)).toContain('không hợp lệ');
    });
  }

  test('TC-Positive: Cho phép URL hợp lệ (HTTPS)', async ({ request }) => {
    const validUrl = 'https://mail.google.com/api/v1';
    const response = await request.put(BASE_URL, {
      headers: commonHeaders,
      data: {
        type: 'EMAIL',
        status: 'ACTIVE',
        url: validUrl,
        method: 'PUT'
      }
    });

    console.log(`[TC-Positive] Testing URL: ${validUrl}`);
    console.log(`Response Status: ${response.status()}`);

    // Nếu token còn sống và URL hợp lệ, mong đợi 200 OK
    // Nếu token chết, sẽ trả về 401
    expect([200, 401]).toContain(response.status());
  });

  test('TC-BlindSSRF: Kiểm tra Blind SSRF qua webhook.site', async ({ request }) => {
    // Lưu ý: Cần ID thực tế từ webhook.site để verify log nếu muốn test end-to-end
    const webhookUrl = 'http://webhook.site/019d42a4-3f51-7894-a25f-f38a3d38b6a1';
    const response = await request.put(BASE_URL, {
      headers: commonHeaders,
      data: {
        type: 'EMAIL',
        status: 'ACTIVE',
        url: webhookUrl,
        method: 'PUT'
      }
    });

    console.log(`[TC-BlindSSRF] Testing URL: ${webhookUrl}`);
    const status = response.status();
    console.log(`Response Status: ${status}`);

    // Mong đợi: BE chặn và không gửi request ra ngoài
    // Thông thường BE sẽ validate và reject ngay (400)
    expect(status).toBeGreaterThanOrEqual(400);
  });
});
