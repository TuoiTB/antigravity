---
name: Flaky Test Analyzer
description: Skill phân tích và khắc phục các automation test không ổn định (flaky tests), xác định root cause và đề xuất fix.
---

# Flaky Test Analyzer (Công cụ Phân tích Test không ổn định)

Mục tiêu: Xác định và khắc phục các kịch bản kiểm thử tự động (automation tests) hoạt động không ổn định.

---

## Khi nào cần sử dụng

Sử dụng skill này khi:

- Một ca kiểm thử (test case) lúc Pass lúc Fail một cách ngẫu nhiên.
- Kết quả kiểm thử không nhất quán giữa các lần chạy khác nhau.
- Quy trình CI/CD có kết quả kiểm thử không đáng tin cậy.

---

## Trách nhiệm

Phát hiện và phân tích các Flaky Test gây ra bởi:

- **Locator không ổn định:** (Sử dụng dynamic classes, xpath theo vị trí tuyệt đối).
- **Vấn đề về thời gian (Timing issues):** (Race conditions, trang tải chậm hoặc phản hồi trễ).
- **Sử dụng Wait sai cách:** (Dùng hard sleep/fixed delay thay vì smart waits).
- **Phụ thuộc vào môi trường:** (Dữ liệu không được dọn dẹp sau khi chạy, dịch vụ bên ngoài bị gián đoạn).
- **Xung đột dữ liệu (Test data conflicts):** (Dùng chung dữ liệu giữa các luồng test chạy song song).

---

## Quy trình phân tích (Analysis Workflow)

1. **Detect (Phát hiện)** — Xác định test case bị lỗi và tái hiện lại lỗi đó.
2. **Inspect (Kiểm tra)** — Đọc log lỗi, stack traces và xem ảnh chụp màn hình (screenshots).
3. **Classify (Phân loại)** — Phân nhóm nguyên nhân gốc rễ (locator / timing / dữ liệu / môi trường).
4. **Fix (Khắc phục)** — Áp dụng chiến lược sửa lỗi phù hợp.
5. **Verify (Xác minh)** — Chạy lại bộ test nhiều lần để xác nhận độ ổn định.

---

## Các nguyên nhân Flaky phổ biến & Cách khắc phục

### 1. Locator không ổn định (Unstable Locator)

**Vấn đề:**
```
//div[3]/button
.css-1n2xyz-btn
```

**Khắc phục:** Thay thế bằng locator ổn định theo thứ tự ưu tiên trong `.agent/rules/locator_strategy.md`:
- `id`, `data-testid`, `name`, `css selector` (ổn định), `xpath` (tương đối).

---

### 2. Vấn đề về thời gian (Timing Issues)

**Vấn đề:**
```java
Thread.sleep(3000);       // Chờ đợi cứng — RẤT TỆ
page.waitForTimeout(2000); // Trễ cố định — RẤT TỆ
```

**Khắc phục:** Sử dụng smart waits (chờ đợi thông minh) như quy định trong `.agent/rules/selenium_rules.md` và `.agent/rules/playwright_rules.md`:
```java
// Selenium
WebDriverWait wait = new WebDriverWait(driver, Duration.ofSeconds(10));
wait.until(ExpectedConditions.visibilityOfElementLocated(By.id("result")));

// Playwright
await expect(page.getByRole('button', { name: 'Submit' })).toBeVisible();
```

---

### 3. Xung đột dữ liệu (Test Data Conflicts)

**Vấn đề:** Các bài test dùng chung dữ liệu có thể thay đổi → khi chạy song song sẽ gây xung đột.

**Khắc phục:** Sử dụng dữ liệu ngẫu nhiên, duy nhất và có khả năng truy vết (traceable):
```
<testName>_<timestamp>@test.com
```

---

## Danh sách kiểm tra độ ổn định (Stability Checklist)

Sau khi sửa một flaky test, hãy xác nhận:

- [ ] Locator là duy nhất và ổn định kể cả khi load lại trang.
- [ ] Không sử dụng hard sleep hoặc fixed delays (trễ cố định).
- [ ] Dữ liệu test là duy nhất và có tính xác định (deterministic).
- [ ] Test case độc lập (không phụ thuộc vào kết quả của các test case khác).
- [ ] Test case vượt qua ít nhất 5 lần chạy liên tiếp.

---

## Quy tắc tham chiếu (Rules References)

Agent BẮT BUỘC tuân thủ các quy tắc sau khi phân tích flaky tests:

- `.agent/rules/locator_strategy.md` — Quy tắc ổn định Locator.
- `.agent/rules/automation_rules.md` — Best practices chung về automation.
- `.agent/rules/selenium_rules.md` — Chiến lược wait trong Selenium.
- `.agent/rules/playwright_rules.md` — Cơ chế tự động đợi (auto-waiting) của Playwright.