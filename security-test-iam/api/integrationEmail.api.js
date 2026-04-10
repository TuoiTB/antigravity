// @ts-check
/**
 * @file integrationEmail.api.js
 * @description API Client Object cho module Cấu hình tích hợp Email.
 *
 * Pattern: mỗi API module có 1 client object chứa toàn bộ method gọi API.
 * Test spec chỉ import client, không biết về URL hay headers — giữ DRY.
 */

const { getAuthHeaders } = require('../config/env');

const BASE_URL =
  'https://ubck-iam-api.viettelsoftware.com/iam-be/api/v1/integration-config/EMAIL/019d42a4-3f51-7894-a25f-f38a3d38b6a1';

/**
 * Tạo API Client cho Integration Email endpoint.
 * @param {import('@playwright/test').APIRequestContext} request - Playwright request context
 */
const createIntegrationEmailApi = (request) => ({

  /**
   * Gọi PUT endpoint với body và headers tuỳ chỉnh.
   * @param {object} data - Request body
   * @param {object} [overrideHeaders] - Override headers (dùng khi test auth failures)
   */
  update(data, overrideHeaders) {
    const headers = overrideHeaders ?? getAuthHeaders();
    return request.put(BASE_URL, { headers, data });
  },

  /**
   * Gọi PUT với token tuỳ chỉnh (test authorization).
   * @param {string|null} token - Bearer token; null = bỏ Authorization header
   */
  updateWithToken(data, token) {
    const headers = { ...getAuthHeaders() };
    if (token === null) {
      delete headers['Authorization'];
    } else {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return request.put(BASE_URL, { headers, data });
  },

  /** Body hợp lệ dùng làm base trong test cases */
  validBody: {
    type: 'EMAIL',
    status: 'ACTIVE',
    url: 'https://mail.google.com/api/v1',
    method: 'PUT',
  },
});

module.exports = { createIntegrationEmailApi };
