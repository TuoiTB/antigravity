/**
 * @description SSRF Attack Payloads dùng chung cho mọi API có URL field.
 * Import bộ payload này vào bất kỳ test spec nào cần kiểm tra SSRF.
 */

export interface SsrfPayload {
  name: string;
  url: string;
  owasp: string;
  category: string;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
}

export const SSRF_PAYLOADS: SsrfPayload[] = [
  // ── SSRF: Private / Loopback IPs ──────────────────────────────────
  { name: 'TC-SSRF-01: Chặn URL localhost', url: 'http://localhost:8080', owasp: 'A10:2021', category: 'SSRF', severity: 'CRITICAL' },
  { name: 'TC-SSRF-02: Chặn loopback 127.0.0.1', url: 'http://127.0.0.1', owasp: 'A10:2021', category: 'SSRF', severity: 'CRITICAL' },
  { name: 'TC-SSRF-03: Chặn private IP 192.168.x.x', url: 'http://192.168.1.1', owasp: 'A10:2021', category: 'SSRF', severity: 'CRITICAL' },
  { name: 'TC-SSRF-04: Chặn private IP 10.x.x.x', url: 'http://10.0.0.1', owasp: 'A10:2021', category: 'SSRF', severity: 'CRITICAL' },
  { name: 'TC-SSRF-05: Chặn private IP 172.16.x.x', url: 'http://172.16.0.1', owasp: 'A10:2021', category: 'SSRF', severity: 'CRITICAL' },

  // ── SSRF: Cloud Metadata ───────────────────────────────────────────
  { name: 'TC-SSRF-06: Chặn cloud metadata AWS/GCP/Azure', url: 'http://169.254.169.254/latest/meta-data', owasp: 'A10:2021', category: 'SSRF - Cloud Metadata', severity: 'CRITICAL' },

  // ── SSRF via Redirect ──────────────────────────────────────────────
  { name: 'TC-SSRF-07: Chặn SSRF qua redirect', url: 'http://httpbin.org/redirect-to?url=http://localhost:8080', owasp: 'A10:2021', category: 'SSRF via Redirect', severity: 'CRITICAL' },

  // ── Blind SSRF ────────────────────────────────────────────────────
  { name: 'TC-SSRF-08: Kiểm tra Blind SSRF qua webhook.site', url: 'http://webhook.site/test-probe', owasp: 'A10:2021', category: 'Blind SSRF', severity: 'CRITICAL' },

  // ── Protocol Injection ────────────────────────────────────────────
  { name: 'TC-PROTO-01: Chặn protocol file://', url: 'file:///etc/passwd', owasp: 'A10:2021', category: 'Protocol Injection', severity: 'HIGH' },
  { name: 'TC-PROTO-02: Chặn protocol ftp://', url: 'ftp://example.com', owasp: 'A10:2021', category: 'Protocol Injection', severity: 'HIGH' },
  { name: 'TC-PROTO-03: Chặn protocol gopher://', url: 'gopher://127.0.0.1', owasp: 'A10:2021', category: 'Protocol Injection', severity: 'HIGH' },

  // ── HTTPS Required ────────────────────────────────────────────────
  { name: 'TC-HTTPS-01: Chỉ cho phép HTTPS (reject HTTP)', url: 'http://example.com', owasp: 'A02:2021', category: 'Cryptographic Failures', severity: 'HIGH' },

  // ── SSRF Port Scan ────────────────────────────────────────────────
  { name: 'TC-PORT-01: Chặn quét SSH port 22', url: 'http://localhost:22', owasp: 'A10:2021', category: 'SSRF Port Scan', severity: 'HIGH' },
  { name: 'TC-PORT-02: Chặn quét MySQL port 3306', url: 'http://localhost:3306', owasp: 'A10:2021', category: 'SSRF Port Scan', severity: 'HIGH' },
  { name: 'TC-PORT-03: Chặn quét Redis port 6379', url: 'http://localhost:6379', owasp: 'A10:2021', category: 'SSRF Port Scan', severity: 'HIGH' },

  // ── IP Encoding Bypass ────────────────────────────────────────────
  { name: 'TC-BYPASS-01: Chặn IP Decimal (127.0.0.1 = 2130706433)', url: 'http://2130706433', owasp: 'A10:2021', category: 'SSRF Bypass - IP Decimal', severity: 'HIGH' },
  { name: 'TC-BYPASS-02: Chặn IP Hex (127.0.0.1 = 0x7f000001)', url: 'http://0x7f000001', owasp: 'A10:2021', category: 'SSRF Bypass - IP Hex', severity: 'HIGH' },

  // ── URL Encoding Bypass ───────────────────────────────────────────
  { name: 'TC-BYPASS-03: Chặn bypass bằng URL encoding (%2f)', url: 'http://127.0.0.1%2f', owasp: 'A10:2021', category: 'SSRF Bypass - URL Encoding', severity: 'MEDIUM' },
  { name: 'TC-BYPASS-04: Chặn bypass bằng NULL byte (%00)', url: 'http://localhost%00.example.com', owasp: 'A10:2021', category: 'SSRF Bypass - Null Byte', severity: 'MEDIUM' },

  // ── Domain Whitelist ──────────────────────────────────────────────
  { name: 'TC-WLIST-01: Chặn domain không trong whitelist', url: 'http://evil.com', owasp: 'A05:2021', category: 'Security Misconfiguration', severity: 'MEDIUM' },
  { name: 'TC-WLIST-02: Chặn truy cập internal service', url: 'http://internal-service/admin', owasp: 'A09:2021', category: 'Security Logging Failures', severity: 'MEDIUM' },
];
