---
name: Locator Healer Agent
description: Skill tự động phát hiện và sửa chữa locators bị hỏng khi automation tests fail do thay đổi DOM.
---

# Locator Healer Agent (Công cụ Phục hồi Locator)

Mục tiêu: Tự động sửa chữa các locator bị hỏng khi các kịch bản automation test bị thất bại.

---

## Khi nào cần sử dụng

Sử dụng skill này khi:

- Test bị fail với lỗi "element not found" (không tìm thấy phần tử) hoặc "element detached" (phần tử bị tách khỏi DOM).
- Giao diện người dùng (UI) đã thay đổi và các locator cũ không còn hoạt động.
- Sau khi triển khai frontend (deployment) làm thay đổi cấu trúc DOM.

---

## Nhiệm vụ

Khi một locator bị hỏng:

1. Kiểm tra DOM hiện tại hoặc cấu trúc phân cấp UI.
2. So sánh locator cũ với cấu trúc trang hiện tại.
3. Xác định các thuộc tính đã được cập nhật.
4. Tạo một locator thay thế.
5. Chạy lại test để xác minh việc sửa lỗi.

---

## Chiến lược phát hiện (Detection Strategy)

Một locator được coi là bị hỏng khi:

- Không tìm thấy phần tử (`NoSuchElementException` / `TimeoutError`).
- Phần tử bị tách rời khỏi DOM (Stale/Detached).
- Bộ chọn (Selector) không khớp với bất kỳ phần tử nào.
- Bộ chọn khớp sai phần tử (khác nội dung text hoặc vị trí).

---

## Quy trình phục hồi (Healing Workflow)

### Bước 1: Phân tích lỗi
- Đọc nhật ký lỗi (error log) để xác định chính xác locator nào bị hỏng.
- Xác định file Page Object và số dòng tương ứng.

### Bước 2: Kiểm tra DOM hiện tại
- Mở trang web bằng các công cụ MCP.
- Điều hướng đến đúng trạng thái (UI state) mà test đã bị fail.
- Kiểm tra vùng mục tiêu trong DOM.

### Bước 3: Tìm Locator thay thế
Thử các phương án theo thứ tự ưu tiên:

1. Thuộc tính Accessibility (`aria-label`, `role`).
2. `data-testid` / `data-test`.
3. `id` (nếu ổn định, không phải ID tự sinh).
4. Locator semantic (Playwright `getByRole`, `getByLabel`).
5. `css selector` (các thuộc tính ổn định).
6. `xpath` (tương đối, không dùng vị trí tuyệt đối).

### Bước 4: Xác thực & Thay thế
- Xác minh locator mới khớp duy nhất (exactly one) với phần tử mục tiêu.
- Xác minh phần tử đó là chính xác (kiểm tra text, vị trí, hành vi).
- Thay thế locator hỏng trong class Page Object.
- Chạy lại kịch bản test.

---

## Phân biệt với Smart Locator Agent

| Khía cạnh | Locator Healer | Smart Locator |
|-----------|---------------|---------------|
| **Kích hoạt** | Khi test thất bại (Phản ứng) | Khi có phần tử mới (Chủ động) |
| **Đầu vào** | Locator hỏng + log lỗi | Phần tử HTML/DOM |
| **Mục tiêu** | Sửa locator hiện có | Tạo locator mới |
| **Quy trình** | Lỗi → Kiểm tra → Thay thế → Xác minh | Kiểm tra → Tạo mới → Xác thực |

---

## Xác minh (Verification)

Sau khi phục hồi:

- [ ] Locator phải khớp duy nhất một phần tử.
- [ ] Phần tử là mục tiêu chính xác (xác minh text/thuộc tính).
- [ ] Kịch bản test phải chạy vượt qua (Pass) thành công.
- [ ] Locator ổn định sau khi tải lại trang.

---

## Quy tắc tham chiếu (Rules References)

- `.agent/rules/locator_strategy.md` — Bản đồ ưu tiên locator.
- `.agent/rules/automation_rules.md` — Các nguyên tắc chung về automation.
