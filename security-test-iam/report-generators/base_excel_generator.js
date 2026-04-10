const ExcelJS = require('exceljs');
const path = require('path');

/**
 * @description Generic Excel report generator cho Security Test
 * Nhận vào: testResults + reportMeta → xuất file Excel 3 sheet.
 * 
 * Usage:
 *   node scripts/generate_excel_report.js --api integration-email
 *   node scripts/generate_excel_report.js --api integration-sms
 */

const SEVERITY_COLORS = {
  CRITICAL: 'FFFF0000',
  HIGH: 'FFFF6600',
  MEDIUM: 'FFFFC000',
  LOW: 'FF92D050',
  '-': 'FFD9D9D9',
};

const RESULT_COLORS = {
  FAIL: 'FFFF0000',
  PASS: 'FF00B050',
  SKIP: 'FFFFC000',
};

/**
 * @param {Object} options
 * @param {Array}  options.testResults   - Mảng test result objects
 * @param {Object} options.reportMeta    - Metadata cho summary sheet
 * @param {string} options.outputFile    - Đường dẫn file output
 */
async function generateSecurityReport({ testResults, reportMeta, outputFile }) {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = 'QA Automation - Security Test';
  workbook.created = new Date();

  // ─── Sheet 1: Tổng quan ───────────────────────────────────────────
  const summary = workbook.addWorksheet('Tổng quan');
  summary.mergeCells('A1:G1');
  const titleCell = summary.getCell('A1');
  titleCell.value = `🔐 BÁO CÁO KIỂM THỬ BẢO MẬT — ${reportMeta.module.toUpperCase()}`;
  titleCell.font = { bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
  titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1F3864' } };
  titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
  summary.getRow(1).height = 36;

  const infoData = [
    ['Module', reportMeta.module],
    ['Endpoint', reportMeta.endpoint],
    ['Base URL', reportMeta.baseUrl],
    ['Ngày thực hiện', reportMeta.date],
    ['Người thực hiện', reportMeta.tester],
    ['Framework', reportMeta.framework],
    ['Loại kiểm thử', reportMeta.testType],
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

  // Stats
  const statsTitle = summary.getRow(11);
  summary.mergeCells('A11:G11');
  statsTitle.getCell(1).value = 'KẾT QUẢ THỰC THI';
  statsTitle.getCell(1).font = { bold: true, size: 12, color: { argb: 'FFFFFFFF' } };
  statsTitle.getCell(1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF2E75B6' } };
  statsTitle.getCell(1).alignment = { horizontal: 'center' };
  statsTitle.height = 24;

  const total = testResults.length;
  const passed = testResults.filter(t => t.result === 'PASS').length;
  const failed = testResults.filter(t => t.result === 'FAIL').length;
  const skipped = testResults.filter(t => t.result === 'SKIP').length;

  const statsHeaders = ['Tổng TC', 'PASS', 'FAIL', 'SKIP', 'Ngày', '', ''];
  const statsValues = [total, passed, failed, skipped, reportMeta.date, '', ''];
  const headerRow = summary.getRow(12);
  const valueRow = summary.getRow(13);

  statsHeaders.forEach((h, i) => {
    headerRow.getCell(i + 1).value = h;
    headerRow.getCell(i + 1).font = { bold: true };
    headerRow.getCell(i + 1).fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD6E4F7' } };
    headerRow.getCell(i + 1).alignment = { horizontal: 'center' };
    valueRow.getCell(i + 1).value = statsValues[i];
    valueRow.getCell(i + 1).alignment = { horizontal: 'center' };
    if (i === 1) valueRow.getCell(i + 1).font = { bold: true, color: { argb: 'FF00B050' } };
    if (i === 2) valueRow.getCell(i + 1).font = { bold: true, color: { argb: 'FFFF0000' } };
    if (i === 3) valueRow.getCell(i + 1).font = { bold: true, color: { argb: 'FFFFC000' } };
  });
  headerRow.height = 22;
  valueRow.height = 24;

  summary.columns = [
    { width: 22 }, { width: 18 }, { width: 10 }, { width: 10 },
    { width: 14 }, { width: 14 }, { width: 14 },
  ];

  // ─── Sheet 2: Chi tiết Test Cases ─────────────────────────────────
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
      if (i === 3 && SEVERITY_COLORS[tc.severity]) {
        cell.font = { bold: true, color: { argb: 'FFFFFFFF' } };
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: SEVERITY_COLORS[tc.severity] } };
      }
      if (i === 9) {
        cell.font = { bold: true, color: { argb: RESULT_COLORS[tc.result] || 'FF000000' } };
      }
      if (idx % 2 === 0 && i !== 3 && i !== 9) {
        if (!cell.fill || cell.fill.fgColor?.argb !== SEVERITY_COLORS[tc.severity]) {
          cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF2F7FC' } };
        }
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

  testResults
    .filter(tc => tc.result === 'FAIL')
    .forEach((tc, idx) => {
      const row = bugSheet.getRow(idx + 3);
      [tc.id, tc.severity, tc.category, tc.urlTest, tc.bugDescription, tc.recommendation].forEach(
        (val, i) => {
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
          } else if (idx % 2 === 0 && i !== 1) {
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFF2CC' } };
          }
        }
      );
      row.height = 55;
    });

  bugSheet.columns = [
    { width: 14 }, { width: 12 }, { width: 28 },
    { width: 42 }, { width: 55 }, { width: 55 },
  ];

  await workbook.xlsx.writeFile(outputFile);
  console.log(`✅ Đã xuất báo cáo: ${outputFile}`);
}

module.exports = { generateSecurityReport };
