const ExcelJS = require('exceljs');
const path    = require('path');

const OUTPUT_FILE = path.join(__dirname, 'security_test_report_module_config.xlsx');

// ════════════════════════════════════════════════════════════════════
// TEST RESULTS — sẽ cập nhật actualStatus/result sau khi chạy test
// ════════════════════════════════════════════════════════════════════
const testResults = [
  // ── SECTION 1: IDOR / BOLA ───────────────────────────────────────
  {
    id: 'TC-IDOR-01', owasp: 'A01:2021', category: 'IDOR / BOLA', severity: 'CRITICAL',
    urlTest: 'PUT .../00000000-0000-0000-0000-000000000001',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 403, expectedMessage: 'Không có quyền truy cập resource',
    result: 'SKIP',
    bugDescription: 'Attacker thay đổi UUID trên path để truy cập cấu hình của đối tượng khác — nếu server không kiểm tra ownership sẽ bị IDOR.',
    recommendation: 'Validate ownership: user chỉ được sửa config thuộc quyền quản lý của mình.',
  },
  {
    id: 'TC-IDOR-02', owasp: 'A01:2021', category: 'IDOR / BOLA', severity: 'CRITICAL',
    urlTest: 'PUT .../00000000-0000-0000-0000-000000000000',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 404, expectedMessage: 'Object không tồn tại',
    result: 'SKIP',
    bugDescription: 'UUID không tồn tại — server phải trả 404, không được trả 500.',
    recommendation: 'Handle not found gracefully — return 404 với message rõ ràng.',
  },
  {
    id: 'TC-IDOR-03', owasp: 'A01:2021', category: 'IDOR - Path Traversal', severity: 'HIGH',
    urlTest: 'PUT .../../../admin/config',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Invalid ID format',
    result: 'SKIP',
    bugDescription: 'Path traversal trong ID — bypass route restriction.',
    recommendation: 'Validate ID format — chỉ chấp nhận UUID v4 pattern.',
  },
  {
    id: 'TC-IDOR-04', owasp: 'A01:2021', category: 'IDOR - SQL in Path', severity: 'HIGH',
    urlTest: "PUT .../1' OR '1'='1",
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Invalid ID format',
    result: 'SKIP',
    bugDescription: 'SQL Injection trong path parameter ID.',
    recommendation: 'Validate UUID format nghiêm ngặt — regex UUID v4.',
  },
  {
    id: 'TC-IDOR-05', owasp: 'A01:2021', category: 'IDOR - Buffer Overflow', severity: 'MEDIUM',
    urlTest: 'PUT .../aaa...500 ký tự',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Invalid ID format',
    result: 'SKIP',
    bugDescription: 'ID quá dài — tiềm năng buffer overflow.',
    recommendation: 'Limit path parameter length trước khi xử lý.',
  },
  // ── SECTION 2: Injection — status ───────────────────────────────
  {
    id: 'TC-INJ-01', owasp: 'A03:2021', category: 'SQL Injection (status)', severity: 'CRITICAL',
    urlTest: "[status] ACTIVE' OR '1'='1",
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'SQL Injection trong field status — bypass enum validation để thao túng query.',
    recommendation: 'Validate status chỉ nhận giá trị enum: ACTIVE, INACTIVE.',
  },
  {
    id: 'TC-INJ-02', owasp: 'A03:2021', category: 'SQL Injection (status)', severity: 'CRITICAL',
    urlTest: "[status] ACTIVE' UNION SELECT * FROM users--",
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'UNION SELECT trong status — lộ dữ liệu từ table khác.',
    recommendation: 'Sử dụng Prepared Statements. Validate enum nghiêm ngặt.',
  },
  {
    id: 'TC-INJ-03', owasp: 'A03:2021', category: 'SQL Injection (status)', severity: 'CRITICAL',
    urlTest: "[status] '; DROP TABLE module_configs;--",
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'DROP TABLE injection — xóa toàn bộ cấu hình module.',
    recommendation: 'Không interpolate string trực tiếp vào SQL. Whitelist enum values.',
  },
  {
    id: 'TC-XSS-01', owasp: 'A03:2021', category: 'XSS (status)', severity: 'HIGH',
    urlTest: '[status] <script>alert(1)</script>',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'XSS payload trong status — phản chiếu lại nếu UI render raw value.',
    recommendation: 'Validate status là enum. HTML encode output.',
  },
  {
    id: 'TC-XSS-02', owasp: 'A03:2021', category: 'XSS (status)', severity: 'HIGH',
    urlTest: '[status] "><img src=x onerror=alert(1)>',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'XSS img onerror — bypass filter nếu không sanitize đúng.',
    recommendation: 'Whitelist enum: ACTIVE, INACTIVE.',
  },
  {
    id: 'TC-INJ-05', owasp: 'A03:2021', category: 'NoSQL Injection (status)', severity: 'HIGH',
    urlTest: '[status] {"$where":"this.status == this.status"}',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'NoSQL Injection — nếu backend dùng MongoDB có thể bypass query.',
    recommendation: 'Validate và sanitize input trước khi query. Dùng ODM parameterized queries.',
  },
  {
    id: 'TC-INJ-06', owasp: 'A03:2021', category: 'Template Injection (status)', severity: 'HIGH',
    urlTest: '[status] {{7*7}}',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'SSTI — nếu server dùng template engine, {{7*7}} có thể trả về 49.',
    recommendation: 'Không truyền user input vào template engine.',
  },
  {
    id: 'TC-INJ-07', owasp: 'A03:2021', category: 'Command Injection (status)', severity: 'HIGH',
    urlTest: '[status] ACTIVE; ls -la',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'Command injection — nếu status được xử lý qua shell.',
    recommendation: 'Whitelist enum values. Không truyền input vào shell commands.',
  },
  {
    id: 'TC-VAL-01', owasp: 'A05:2021', category: 'Enum Validation (status)', severity: 'MEDIUM',
    urlTest: '[status] UNKNOWN_STATUS_ATTACK',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'Status nhận giá trị ngoài enum — server phải validate nghiêm ngặt.',
    recommendation: 'Validate status theo enum: [ACTIVE, INACTIVE].',
  },
  {
    id: 'TC-VAL-02', owasp: 'A05:2021', category: 'Enum Validation (status)', severity: 'MEDIUM',
    urlTest: '[status] (empty string)',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'Status rỗng — phải bị validate.',
    recommendation: 'Thêm @NotBlank validation.',
  },
  {
    id: 'TC-VAL-04', owasp: 'A05:2021', category: 'Input Validation (status)', severity: 'MEDIUM',
    urlTest: '[status] A x 5000 ký tự',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status vượt maxlength',
    result: 'SKIP',
    bugDescription: 'Status không bị giới hạn maxlength — tiềm năng buffer overflow.',
    recommendation: 'Giới hạn status tối đa 20 ký tự.',
  },
  // ── SECTION 3: BOLA — permissionIds ─────────────────────────────
  {
    id: 'TC-BOLA-01', owasp: 'A01:2021', category: 'BOLA (permissionIds)', severity: 'CRITICAL',
    urlTest: '[permissionIds] + UUID không thuộc user',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 403, expectedMessage: 'Không có quyền thêm permission này',
    result: 'SKIP',
    bugDescription: 'Attacker thêm permissionId không thuộc phạm vi quyền của mình — privilege escalation.',
    recommendation: 'Validate mỗi permissionId — chỉ cho phép IDs thuộc scope của user/module.',
  },
  {
    id: 'TC-BOLA-02', owasp: 'A01:2021', category: 'BOLA (permissionIds)', severity: 'CRITICAL',
    urlTest: '[permissionIds] UUID không tồn tại',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'permissionId không tồn tại',
    result: 'SKIP',
    bugDescription: 'UUID không hợp lệ được chấp nhận — server không verify existence.',
    recommendation: 'Validate existence của mỗi permissionId trong DB.',
  },
  {
    id: 'TC-BOLA-03', owasp: 'A01:2021', category: 'BOLA (permissionIds)', severity: 'HIGH',
    urlTest: '[permissionIds] [] (mảng rỗng)',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'permissionIds không được rỗng',
    result: 'SKIP',
    bugDescription: 'Xóa toàn bộ permissions bằng mảng rỗng — có thể lock system.',
    recommendation: 'Validate permissionIds.length > 0 nếu là bắt buộc, hoặc có confirm flow.',
  },
  {
    id: 'TC-BOLA-04', owasp: 'A01:2021', category: 'BOLA (permissionIds)', severity: 'LOW',
    urlTest: '[permissionIds] Duplicate IDs',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Duplicate permissionIds',
    result: 'SKIP',
    bugDescription: 'Duplicate IDs trong mảng — server phải deduplicate hoặc reject.',
    recommendation: 'Deduplicate IDs trước khi lưu.',
  },
  {
    id: 'TC-BOLA-05', owasp: 'A05:2021', category: 'DoS (permissionIds)', severity: 'MEDIUM',
    urlTest: '[permissionIds] Mảng 1000 phần tử',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'permissionIds vượt giới hạn',
    result: 'SKIP',
    bugDescription: 'Mảng cực lớn — gây load DB cao, tiềm năng DoS.',
    recommendation: 'Giới hạn permissionIds.length (ví dụ: tối đa 100).',
  },
  // ── SECTION 3: Injection — permissionIds ────────────────────────
  {
    id: 'TC-INJ-08', owasp: 'A03:2021', category: 'SQL Injection (permissionIds)', severity: 'CRITICAL',
    urlTest: "[permissionIds] [\"'; DROP TABLE permissions;--\"]",
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'UUID format không hợp lệ',
    result: 'SKIP',
    bugDescription: 'SQL Injection trong permissionIds array.',
    recommendation: 'Validate UUID format cho mỗi element. Dùng Prepared Statements.',
  },
  {
    id: 'TC-INJ-09', owasp: 'A03:2021', category: 'XSS (permissionIds)', severity: 'HIGH',
    urlTest: '[permissionIds] ["<script>alert(1)</script>"]',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'UUID format không hợp lệ',
    result: 'SKIP',
    bugDescription: 'XSS trong permissionIds element.',
    recommendation: 'Validate UUID format — regex: ^[0-9a-f-]{36}$.',
  },
  {
    id: 'TC-INJ-10', owasp: 'A03:2021', category: 'Input Validation (permissionIds)', severity: 'MEDIUM',
    urlTest: '[permissionIds] ["notauuid12345678"]',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'UUID format không hợp lệ',
    result: 'SKIP',
    bugDescription: 'Non-UUID string được chấp nhận — không validate format.',
    recommendation: 'Strict UUID v4 validation cho mỗi element.',
  },
  // ── SECTION 4: Mass Assignment ───────────────────────────────────
  {
    id: 'TC-MASS-01', owasp: 'A04:2021', category: 'Mass Assignment', severity: 'HIGH',
    urlTest: '[body] + isAdmin:true, role:"SUPER_ADMIN"',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Field không được phép',
    result: 'SKIP',
    bugDescription: 'Mass assignment — thêm field isAdmin, role ngoài schema; nếu server không filter có thể leo thang quyền.',
    recommendation: 'Dùng DTO whitelist. Ignore hoặc reject field ngoài schema.',
  },
  {
    id: 'TC-MASS-02', owasp: 'A04:2021', category: 'Mass Assignment', severity: 'HIGH',
    urlTest: '[body] + createdBy:"attacker"',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Field không được phép',
    result: 'SKIP',
    bugDescription: 'Override createdBy/ownerId — ghi đè ownership của record.',
    recommendation: 'createdBy phải được lấy từ token, không từ request body.',
  },
  {
    id: 'TC-MASS-03', owasp: 'A04:2021', category: 'Mass Assignment', severity: 'HIGH',
    urlTest: '[body] + id: "other-UUID"',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Không được override ID',
    result: 'SKIP',
    bugDescription: 'id trong body override ID từ URL path — ghi đè record khác.',
    recommendation: 'Luôn dùng ID từ path parameter, bỏ qua id trong body.',
  },
  // ── SECTION 5: Authorization ─────────────────────────────────────
  {
    id: 'TC-AUTH-01', owasp: 'A07:2021', category: 'Authorization', severity: 'CRITICAL',
    urlTest: '[No Authorization header]',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 401, expectedMessage: 'Unauthorized',
    result: 'SKIP',
    bugDescription: 'Không có token — server phải reject ngay lập tức.',
    recommendation: 'Bắt buộc Bearer token cho mọi PUT endpoint.',
  },
  {
    id: 'TC-AUTH-02', owasp: 'A07:2021', category: 'Authorization', severity: 'CRITICAL',
    urlTest: '[Bearer] token giả — chữ ký sai',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 401, expectedMessage: 'Unauthorized - Invalid token',
    result: 'SKIP',
    bugDescription: 'JWT token với chữ ký giả mạo — server phải verify signature.',
    recommendation: 'Verify JWT signature với public key. Reject token invalid.',
  },
  {
    id: 'TC-AUTH-03', owasp: 'A07:2021', category: 'Authorization', severity: 'CRITICAL',
    urlTest: '[Bearer] INVALID_TOKEN_STRING',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 401, expectedMessage: 'Unauthorized',
    result: 'SKIP',
    bugDescription: 'Token là chuỗi rác — phải bị từ chối.',
    recommendation: 'Validate JWT format trước khi parse.',
  },
  {
    id: 'TC-AUTH-04', owasp: 'A07:2021', category: 'Authorization', severity: 'HIGH',
    urlTest: '[Bearer] (empty)',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 401, expectedMessage: 'Unauthorized',
    result: 'SKIP',
    bugDescription: 'Token rỗng sau Bearer — server phải reject.',
    recommendation: 'Validate token không rỗng.',
  },
  {
    id: 'TC-AUTH-05', owasp: 'A07:2021', category: 'Authorization', severity: 'HIGH',
    urlTest: '[Basic] YWRtaW46cGFzc3dvcmQ=',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 401, expectedMessage: 'Unauthorized',
    result: 'SKIP',
    bugDescription: 'Sai scheme Basic thay vì Bearer — server không được chấp nhận.',
    recommendation: 'Chỉ chấp nhận Bearer token. Reject Basic auth.',
  },
  // ── SECTION 6: Field Validation ──────────────────────────────────
  {
    id: 'TC-VAL-05', owasp: 'A05:2021', category: 'Input Validation', severity: 'MEDIUM',
    urlTest: '[Thiếu status]',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status là bắt buộc',
    result: 'SKIP',
    bugDescription: 'Thiếu field bắt buộc status.',
    recommendation: '@NotNull, @NotBlank cho status.',
  },
  {
    id: 'TC-VAL-06', owasp: 'A05:2021', category: 'Input Validation', severity: 'MEDIUM',
    urlTest: '[Thiếu permissionIds]',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'permissionIds là bắt buộc',
    result: 'SKIP',
    bugDescription: 'Thiếu field permissionIds.',
    recommendation: '@NotNull, @NotEmpty cho permissionIds.',
  },
  {
    id: 'TC-VAL-07', owasp: 'A05:2021', category: 'Input Validation', severity: 'MEDIUM',
    urlTest: '[body] {}',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Thiếu field bắt buộc',
    result: 'SKIP',
    bugDescription: 'Body rỗng — server phải validate và trả lỗi rõ ràng.',
    recommendation: 'Validate toàn bộ required fields.',
  },
  {
    id: 'TC-VAL-08', owasp: 'A05:2021', category: 'Input Validation', severity: 'MEDIUM',
    urlTest: '[permissionIds] null',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'permissionIds là bắt buộc',
    result: 'SKIP',
    bugDescription: 'permissionIds = null — server phải reject.',
    recommendation: '@NotNull cho permissionIds.',
  },
  {
    id: 'TC-VAL-09', owasp: 'A05:2021', category: 'Input Validation', severity: 'MEDIUM',
    urlTest: '[status] 1 (số nguyên)',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status phải là string',
    result: 'SKIP',
    bugDescription: 'Type mismatch — status là số nguyên thay vì string.',
    recommendation: 'Validate type của status.',
  },
  // ── SECTION 7: HTTP Method & Content-Type ────────────────────────
  {
    id: 'TC-HTTP-01', owasp: 'A05:2021', category: 'Content-Type', severity: 'LOW',
    urlTest: 'Content-Type: text/plain',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Unsupported Content-Type',
    result: 'SKIP',
    bugDescription: 'text/plain Content-Type — server phải chỉ chấp nhận application/json.',
    recommendation: 'Enforce Content-Type: application/json.',
  },
  {
    id: 'TC-HTTP-02', owasp: 'A05:2021', category: 'Content-Type', severity: 'LOW',
    urlTest: 'Content-Type: application/xml',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'Unsupported Content-Type',
    result: 'SKIP',
    bugDescription: 'XML Content-Type — phải bị reject.',
    recommendation: 'Restrict to application/json.',
  },
  {
    id: 'TC-HTTP-03', owasp: 'A03:2021', category: 'XXE', severity: 'HIGH',
    urlTest: '[status] <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 400, expectedMessage: 'status không hợp lệ',
    result: 'SKIP',
    bugDescription: 'XXE payload trong status field.',
    recommendation: 'Validate enum. Disable XML processing nếu không cần.',
  },
  // ── Happy Path ────────────────────────────────────────────────────
  {
    id: 'TC-POS-01', owasp: 'Happy Path', category: 'Happy Path', severity: '-',
    urlTest: 'status: ACTIVE + valid permissionIds',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 200, expectedMessage: 'SUCCESS',
    result: 'SKIP',
    bugDescription: '-',
    recommendation: '-',
  },
  {
    id: 'TC-POS-02', owasp: 'Happy Path', category: 'Happy Path', severity: '-',
    urlTest: 'status: INACTIVE + valid permissionIds',
    actualStatus: null, actualResponse: 'Chưa chạy',
    expectedStatus: 200, expectedMessage: 'SUCCESS',
    result: 'SKIP',
    bugDescription: '-',
    recommendation: '-',
  },
];

// ════════════════════════════════════════════════════════════════════
const SEVERITY_COLORS = {
  CRITICAL: 'FFFF0000',
  HIGH:     'FFFF6600',
  MEDIUM:   'FFFFC000',
  LOW:      'FF70AD47',
  '-':      'FF92D050',
};
const RESULT_COLORS = {
  FAIL: 'FFFF0000',
  PASS: 'FF00B050',
  SKIP: 'FF808080',
};

async function generateReport() {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'QA Automation';
  workbook.created = new Date();

  // ─── Sheet 1: Tổng quan ───────────────────────────────────────────
  const summary = workbook.addWorksheet('Tổng quan');
  summary.mergeCells('A1:G1');
  const titleCell = summary.getCell('A1');
  titleCell.value = '🔐 BÁO CÁO KIỂM THỬ BẢO MẬT — API MODULE INTEGRATION CONFIGS';
  titleCell.font      = { bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
  titleCell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
  titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
  summary.getRow(1).height = 36;

  const totalTC = testResults.length;
  const passTC  = testResults.filter(t => t.result === 'PASS').length;
  const failTC  = testResults.filter(t => t.result === 'FAIL').length;
  const skipTC  = testResults.filter(t => t.result === 'SKIP').length;

  const infoData = [
    ['Module',          'Quản lý Module Integration Configs'],
    ['Endpoint',        'PUT /iam-be/api/v1/module-integration-configs/{id}'],
    ['Base URL',        'https://ubck-iam-api.viettelsoftware.com'],
    ['Ngày thực hiện',  new Date().toISOString().split('T')[0]],
    ['Người thực hiện', 'QA Automation'],
    ['Framework',       'Playwright (TypeScript) — API Testing'],
    ['Loại kiểm thử',   'Security Testing — IDOR/BOLA, Injection, Mass Assignment, Authorization (OWASP Top 10)'],
  ];

  infoData.forEach(([label, value], i) => {
    const row = summary.getRow(i + 2);
    row.getCell(1).value = label;
    row.getCell(1).font  = { bold: true };
    row.getCell(1).fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD6DCE4' } };
    row.getCell(2).value = value;
    summary.mergeCells(i + 2, 2, i + 2, 7);
    row.height = 20;
  });

  summary.getRow(10).height = 10;

  summary.mergeCells('A11:G11');
  summary.getCell('A11').value = 'KẾT QUẢ THỰC THI';
  summary.getCell('A11').font  = { bold: true, size: 12, color: { argb: 'FFFFFFFF' } };
  summary.getCell('A11').fill  = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2E75B6' } };
  summary.getCell('A11').alignment = { horizontal: 'center' };
  summary.getRow(11).height = 24;

  const statsHeaders = ['Tổng TC', 'PASS', 'FAIL', 'SKIP', 'Thời gian', 'Ngày', ''];
  const statsValues  = [totalTC, passTC, failTC, skipTC, 'Chưa chạy', new Date().toISOString().split('T')[0], ''];

  const headerRow = summary.getRow(12);
  const valueRow  = summary.getRow(13);
  statsHeaders.forEach((h, i) => {
    headerRow.getCell(i + 1).value     = h;
    headerRow.getCell(i + 1).font      = { bold: true };
    headerRow.getCell(i + 1).fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD6E4F7' } };
    headerRow.getCell(i + 1).alignment = { horizontal: 'center' };
    valueRow.getCell(i + 1).value      = statsValues[i];
    valueRow.getCell(i + 1).alignment  = { horizontal: 'center' };
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
    cell.value     = h;
    cell.font      = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    cell.border    = { top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' } };
  });
  headerRow2.height = 30;

  testResults.forEach((tc, idx) => {
    const row    = detail.getRow(idx + 2);
    const values = [
      tc.id, tc.owasp, tc.category, tc.severity,
      tc.urlTest, tc.actualStatus ?? '-', tc.actualResponse,
      tc.expectedStatus, tc.expectedMessage,
      tc.result, tc.bugDescription, tc.recommendation,
    ];
    values.forEach((val, i) => {
      const cell     = row.getCell(i + 1);
      cell.value     = val;
      cell.alignment = { vertical: 'middle', wrapText: true, horizontal: i < 4 ? 'center' : 'left' };
      cell.border    = { top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' } };
      if (i === 3 && SEVERITY_COLORS[tc.severity]) {
        cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEVERITY_COLORS[tc.severity] } };
      }
      if (i === 9) {
        cell.font = { bold: true, color: { argb: RESULT_COLORS[tc.result] || 'FF000000' } };
      }
      if (idx % 2 === 0 && i !== 3 && i !== 9) {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF2F7FC' } };
      }
    });
    row.height = 60;
  });

  detail.columns = [
    { width: 14 }, { width: 12 }, { width: 30 }, { width: 12 },
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

  const bugHeaders   = ['Mã TC', 'Mức độ', 'Danh mục lỗ hổng', 'URL / Field Test', 'Mô tả Bug', 'Khuyến nghị Fix'];
  const bugHeaderRow = bugSheet.getRow(2);
  bugHeaders.forEach((h, i) => {
    const cell     = bugHeaderRow.getCell(i + 1);
    cell.value     = h;
    cell.font      = { bold: true, color: { argb: 'FFFFFFFF' } };
    cell.fill      = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2E75B6' } };
    cell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
    cell.border    = { top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' } };
  });
  bugHeaderRow.height = 26;

  const failedTCs = testResults.filter(tc => tc.result === 'FAIL');
  if (failedTCs.length === 0) {
    bugSheet.getRow(3).getCell(1).value = 'Chưa có kết quả — chạy test trước để cập nhật';
    bugSheet.getRow(3).getCell(1).font  = { italic: true, color: { argb: 'FF808080' } };
  } else {
    failedTCs.forEach((tc, idx) => {
      const row = bugSheet.getRow(idx + 3);
      [tc.id, tc.severity, tc.category, tc.urlTest, tc.bugDescription, tc.recommendation].forEach((val, i) => {
        const cell     = row.getCell(i + 1);
        cell.value     = val;
        cell.alignment = { vertical: 'middle', wrapText: true, horizontal: i < 2 ? 'center' : 'left' };
        cell.border    = { top: { style: 'thin' }, left: { style: 'thin' }, bottom: { style: 'thin' }, right: { style: 'thin' } };
        if (i === 1 && SEVERITY_COLORS[tc.severity]) {
          cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEVERITY_COLORS[tc.severity] } };
        } else if (idx % 2 === 0) {
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFF2CC' } };
        }
      });
      row.height = 55;
    });
  }

  bugSheet.columns = [
    { width: 14 }, { width: 12 }, { width: 30 },
    { width: 42 }, { width: 55 }, { width: 55 },
  ];

  await workbook.xlsx.writeFile(OUTPUT_FILE);
  console.log(`✅ Đã xuất báo cáo: ${OUTPUT_FILE}`);
}

generateReport().catch(console.error);
