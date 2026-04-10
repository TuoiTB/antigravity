// @ts-check
/**
 * @file moduleConfig.api.js
 * @description API Client Object cho module Module Integration Configs.
 *
 * Pattern: mỗi API module có 1 client object chứa toàn bộ method gọi API.
 * Test spec chỉ import client, không biết về URL hay headers — giữ DRY.
 */

const { getAuthHeaders } = require('../config/env');

const BASE_URL  = 'https://ubck-iam-api.viettelsoftware.com';
const ENDPOINT  = '/iam-be/api/v1/module-integration-configs';
const RECORD_ID = '019d5127-6c4d-7372-aa19-12d7e8d28df3';
const API_URL   = `${BASE_URL}${ENDPOINT}/${RECORD_ID}`;

/** Permission ID hợp lệ lấy từ curl mẫu */
const VALID_PERMISSION_ID = '019cbdf0-6790-70eb-9fe4-f70d3de1db69';

/**
 * Tạo API Client cho Module Integration Configs endpoint.
 * @param {import('@playwright/test').APIRequestContext} request
 */
const createModuleConfigApi = (request) => ({

  /**
   * Gọi PUT endpoint với record ID mặc định.
   * @param {object} data - Request body
   * @param {object} [overrideHeaders] - Override headers (dùng khi test auth failures)
   */
  update(data, overrideHeaders) {
    const headers = overrideHeaders ?? getAuthHeaders();
    return request.put(API_URL, { headers, data });
  },

  /**
   * Gọi PUT với record ID tuỳ chỉnh (dùng khi test IDOR/BOLA).
   * @param {string} id - Record ID trên path
   * @param {object} data
   * @param {object} [overrideHeaders]
   */
  updateById(id, data, overrideHeaders) {
    const headers = overrideHeaders ?? getAuthHeaders();
    return request.put(`${BASE_URL}${ENDPOINT}/${id}`, { headers, data });
  },

  /**
   * Gọi PUT với token tuỳ chỉnh (test authorization).
   * @param {object} data
   * @param {string|null} token - null = bỏ Authorization header hoàn toàn
   */
  updateWithToken(data, token) {
    const headers = { ...getAuthHeaders() };
    if (token === null) {
      delete headers['Authorization'];
    } else {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return request.put(API_URL, { headers, data });
  },

  /**
   * Gọi PUT với Content-Type tuỳ chỉnh (test Content-Type enforcement).
   * @param {object|string} data
   * @param {string} contentType
   */
  updateWithContentType(data, contentType) {
    return request.put(API_URL, {
      headers: { ...getAuthHeaders(), 'Content-Type': contentType },
      data,
    });
  },

  /** Body hợp lệ dùng làm base trong test cases */
  validBody: {
    status: 'ACTIVE',
    permissionIds: [VALID_PERMISSION_ID],
  },

  /** Permission ID hợp lệ để reference trong test data */
  VALID_PERMISSION_ID,

  /** Base URL và Endpoint để build custom paths trong IDOR tests */
  BASE_URL,
  ENDPOINT,
});

module.exports = { createModuleConfigApi };
