const ExcelJS = require('exceljs');
const path = require('path');

const OUTPUT_FILE = path.join(__dirname, 'security_test_report.xlsx');

const testResults = [
  {
    id: 'TC-01',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'http://localhost:8080',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://localhost:8080" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'API lưu thành công URL trỏ đến localhost — có thể lợi dụng để request vào service nội bộ.',
    recommendation: 'Validate URL không thuộc dải localhost, 127.0.0.1, ::1 trước khi lưu.',
  },
  {
    id: 'TC-02',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'http://127.0.0.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://127.0.0.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'IP loopback 127.0.0.1 không bị chặn — attacker truy cập service nội bộ trên server.',
    recommendation: 'Resolve IP, reject nếu thuộc dải 127.0.0.0/8.',
  },
  {
    id: 'TC-03',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'http://192.168.1.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://192.168.1.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Dải 192.168.0.0/16 không bị chặn — attacker có thể scan mạng nội bộ.',
    recommendation: 'Reject các dải IP RFC 1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16.',
  },
  {
    id: 'TC-04',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'http://10.0.0.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://10.0.0.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Dải 10.0.0.0/8 không bị chặn.',
    recommendation: 'Áp dụng blocklist private IP theo RFC 1918.',
  },
  {
    id: 'TC-05',
    owasp: 'A10:2021',
    category: 'SSRF',
    severity: 'CRITICAL',
    urlTest: 'http://172.16.0.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://172.16.0.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Dải 172.16.0.0/12 không bị chặn.',
    recommendation: 'Block dải 172.16.0.0/12.',
  },
  {
    id: 'TC-06',
    owasp: 'A10:2021',
    category: 'SSRF - Cloud Metadata',
    severity: 'CRITICAL',
    urlTest: 'http://169.254.169.254/latest/meta-data',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://169.254.169.254/latest/meta-data" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'IP metadata AWS/GCP/Azure. Nếu server chạy trên cloud, attacker lấy được cloud credentials.',
    recommendation: 'Block dải 169.254.0.0/16 (link-local). Ưu tiên cao nhất.',
  },
  {
    id: 'TC-07',
    owasp: 'A10:2021',
    category: 'SSRF via Redirect',
    severity: 'CRITICAL',
    urlTest: 'http://httpbin.org/redirect-to?url=http://localhost:8080',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://httpbin.org/redirect-to?url=http://localhost:8080" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'BE không follow redirect chain. URL ngoài trông hợp lệ nhưng đích đến là internal.',
    recommendation: 'Follow redirect khi validate, kiểm tra URL đích sau khi redirect.',
  },
  {
    id: 'TC-08',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'file:///etc/passwd',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "file:///etc/passwd" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Protocol file:// cho phép đọc file hệ thống nếu server thực thi request.',
    recommendation: 'Whitelist scheme — chỉ cho phép https://.',
  },
  {
    id: 'TC-09',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'ftp://example.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "ftp://example.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Protocol ftp:// được chấp nhận.',
    recommendation: 'Chỉ cho phép scheme https.',
  },
  {
    id: 'TC-10',
    owasp: 'A10:2021',
    category: 'Protocol Injection',
    severity: 'HIGH',
    urlTest: 'gopher://127.0.0.1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "gopher://127.0.0.1" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Protocol gopher:// có thể gửi arbitrary TCP data tới internal ports — rất nguy hiểm.',
    recommendation: 'Chỉ cho phép scheme https.',
  },
  {
    id: 'TC-11',
    owasp: 'A02:2021',
    category: 'Cryptographic Failures',
    severity: 'HIGH',
    urlTest: 'http://example.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://example.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'Chỉ cho phép HTTPS',
    result: 'FAIL',
    bugDescription: 'HTTP không mã hóa được chấp nhận — dữ liệu trao đổi có thể bị intercept.',
    recommendation: 'Bắt buộc URL phải bắt đầu bằng https://.',
  },
  {
    id: 'TC-12',
    owasp: 'A10:2021',
    category: 'SSRF Port Scan',
    severity: 'HIGH',
    urlTest: 'http://localhost:22',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://localhost:22" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Attacker có thể probe SSH port (22) trên server thông qua API này.',
    recommendation: 'Block localhost kết hợp với block port nguy hiểm.',
  },
  {
    id: 'TC-13',
    owasp: 'A10:2021',
    category: 'SSRF Port Scan',
    severity: 'HIGH',
    urlTest: 'http://localhost:3306',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://localhost:3306" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Xác định được MySQL database port (3306) đang mở.',
    recommendation: 'Block localhost kết hợp với block port nguy hiểm.',
  },
  {
    id: 'TC-14',
    owasp: 'A10:2021',
    category: 'SSRF Port Scan',
    severity: 'HIGH',
    urlTest: 'http://localhost:6379',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://localhost:6379" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Redis port (6379) exposed — kết hợp gopher protocol tấn công Redis.',
    recommendation: 'Block localhost kết hợp với block port nguy hiểm.',
  },
  {
    id: 'TC-15',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - IP Encoding',
    severity: 'HIGH',
    urlTest: 'http://2130706433',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://2130706433" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'BE không normalize IP — 2130706433 = 127.0.0.1 dạng decimal. Attacker bypass blocklist.',
    recommendation: 'Dùng InetAddress.getByName() để resolve về IP chuẩn trước khi validate.',
  },
  {
    id: 'TC-16',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - IP Encoding',
    severity: 'HIGH',
    urlTest: 'http://0x7f000001',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://0x7f000001" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'BE không normalize IP — 0x7f000001 = 127.0.0.1 dạng hex.',
    recommendation: 'Resolve IP về dotted-decimal trước khi kiểm tra blocklist.',
  },
  {
    id: 'TC-17',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - URL Encoding',
    severity: 'MEDIUM',
    urlTest: 'http://127.0.0.1%2f',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://127.0.0.1%2f" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'URL encoding bypass (%2f) — BE không decode trước khi validate.',
    recommendation: 'URL decode trước khi validate, kiểm tra sau khi normalize.',
  },
  {
    id: 'TC-18',
    owasp: 'A10:2021',
    category: 'SSRF Bypass - Null Byte',
    severity: 'MEDIUM',
    urlTest: 'http://localhost%00.example.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://localhost%00.example.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Null byte injection (%00) — BE không phát hiện.',
    recommendation: 'Strip/reject URL chứa %00, \\0 hoặc control characters.',
  },
  {
    id: 'TC-19',
    owasp: 'A05:2021',
    category: 'Security Misconfiguration',
    severity: 'MEDIUM',
    urlTest: 'http://evil.com',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://evil.com" } } }',
    expectedStatus: 400,
    expectedMessage: 'Domain không được phép',
    result: 'FAIL',
    bugDescription: 'Domain không trong whitelist vẫn được chấp nhận.',
    recommendation: 'Implement domain whitelist — chỉ cho phép domain đã được phê duyệt.',
  },
  {
    id: 'TC-20',
    owasp: 'A09:2021',
    category: 'Security Logging Failures',
    severity: 'MEDIUM',
    urlTest: 'http://internal-service/admin',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://internal-service/admin" } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Tên internal service lộ qua response/log.',
    recommendation: 'Block non-public domain, không log full URL trong error response.',
  },
  {
    id: 'TC-BlindSSRF',
    owasp: 'A10:2021',
    category: 'Blind SSRF',
    severity: 'CRITICAL',
    urlTest: 'http://webhook.site/019d42a4-3f51-7894-a25f-f38a3d38b6a1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200, "data": { "config": { "url": "http://webhook.site/..." } } }',
    expectedStatus: 400,
    expectedMessage: 'URL không hợp lệ',
    result: 'FAIL',
    bugDescription: 'Blind SSRF — URL được lưu, cần verify thêm xem BE có gửi outbound request không. Nếu có → BUG CRITICAL cao nhất.',
    recommendation: 'Validate và reject URL trước khi lưu. Không thực hiện outbound request trong quá trình save config.',
  },
  {
    id: 'TC-Positive',
    owasp: 'Happy Path',
    category: 'Happy Path',
    severity: '-',
    urlTest: 'https://mail.google.com/api/v1',
    actualStatus: 200,
    actualResponse: '{ "errorCode": "0000", "resultCode": 200 }',
    expectedStatus: 200,
    expectedMessage: 'SUCCESS',
    result: 'PASS',
    bugDescription: '-',
    recommendation: '-',
  },
];

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

async function generateReport() {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'QA Automation';
  workbook.created = new Date();

  // ─── Sheet 1: Summary ──────────────────────────────────────────────
  const summary = workbook.addWorksheet('Tổng quan');
  summary.mergeCells('A1:G1');
  const titleCell = summary.getCell('A1');
  titleCell.value = '🔐 BÁO CÁO KIỂM THỬ BẢO MẬT — API CẤU HÌNH TÍCH HỢP EMAIL';
  titleCell.font = { bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
  titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
  titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
  summary.getRow(1).height = 36;

  const infoData = [
    ['Module', 'Quản lý cấu hình tích hợp Email'],
    ['Endpoint', 'PUT /iam-be/api/v1/integration-config/EMAIL/{id}'],
    ['Base URL', 'https://ubck-iam-api.viettelsoftware.com'],
    ['Ngày thực hiện', '2026-04-09'],
    ['Người thực hiện', 'QA Automation'],
    ['Framework', 'Playwright (TypeScript) — API Testing'],
    ['Loại kiểm thử', 'Security Testing — SSRF & URL Validation (OWASP Top 10)'],
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
  const statsValues = [22, 1, 21, 0, '14.6 giây', '2026-04-09', ''];
  const headerRow = summary.getRow(12);
  const valueRow  = summary.getRow(13);
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
  valueRow.height = 24;

  summary.columns = [
    { width: 22 }, { width: 18 }, { width: 10 }, { width: 10 },
    { width: 14 }, { width: 14 }, { width: 14 },
  ];

  // ─── Sheet 2: Chi tiết test cases ─────────────────────────────────
  const detail = workbook.addWorksheet('Chi tiết Test Cases');
  const headers = [
    'Mã TC', 'OWASP', 'Danh mục', 'Mức độ',
    'URL Test', 'Status thực tế', 'Response thực tế',
    'Status kỳ vọng', 'Message kỳ vọng',
    'Kết quả', 'Mô tả Bug', 'Khuyến nghị Fix',
  ];
  const headerRow2 = detail.getRow(1);
  headers.forEach((h, i) => {
    const cell = headerRow2.getCell(i + 1);
    cell.value = h;
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    cell.border = {
      top: { style: 'thin' }, left: { style: 'thin' },
      bottom: { style: 'thin' }, right: { style: 'thin' },
    };
  });
  headerRow2.height = 30;

  testResults.forEach((tc, idx) => {
    const row = detail.getRow(idx + 2);
    const values = [
      tc.id, tc.owasp, tc.category, tc.severity,
      tc.urlTest, tc.actualStatus, tc.actualResponse,
      tc.expectedStatus, tc.expectedMessage,
      tc.result, tc.bugDescription, tc.recommendation,
    ];
    values.forEach((val, i) => {
      const cell = row.getCell(i + 1);
      cell.value = val;
      cell.alignment = { vertical: 'middle', wrapText: true, horizontal: i < 4 ? 'center' : 'left' };
      cell.border = {
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
    { width: 14 }, { width: 12 }, { width: 24 }, { width: 12 },
    { width: 42 }, { width: 14 }, { width: 55 },
    { width: 14 }, { width: 20 },
    { width: 10 }, { width: 55 }, { width: 55 },
  ];

  // ─── Sheet 3: Bug Summary ──────────────────────────────────────────
  const bugSheet = workbook.addWorksheet('Bug Summary');
  bugSheet.mergeCells('A1:F1');
  bugSheet.getCell('A1').value = 'DANH SÁCH BUG CẦN LOG';
  bugSheet.getCell('A1').font = { bold: true, size: 13, color: { argb: 'FFFFFFFF' } };
  bugSheet.getCell('A1').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFC00000' } };
  bugSheet.getCell('A1').alignment = { horizontal: 'center', vertical: 'middle' };
  bugSheet.getRow(1).height = 30;

  const bugHeaders = ['Mã TC', 'Mức độ', 'Danh mục lỗ hổng', 'URL Test', 'Mô tả Bug', 'Khuyến nghị Fix'];
  const bugHeaderRow = bugSheet.getRow(2);
  bugHeaders.forEach((h, i) => {
    const cell = bugHeaderRow.getCell(i + 1);
    cell.value = h;
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2E75B6' } };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    cell.border = {
      top: { style: 'thin' }, left: { style: 'thin' },
      bottom: { style: 'thin' }, right: { style: 'thin' },
    };
  });
  bugHeaderRow.height = 26;

  const failedTCs = testResults.filter(tc => tc.result === 'FAIL');
  failedTCs.forEach((tc, idx) => {
    const row = bugSheet.getRow(idx + 3);
    [tc.id, tc.severity, tc.category, tc.urlTest, tc.bugDescription, tc.recommendation].forEach((val, i) => {
      const cell = row.getCell(i + 1);
      cell.value = val;
      cell.alignment = { vertical: 'middle', wrapText: true, horizontal: i < 2 ? 'center' : 'left' };
      cell.border = {
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
