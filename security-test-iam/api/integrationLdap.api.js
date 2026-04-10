// @ts-check
/**
 * @file integrationLdap.api.js
 * @description API Client Object cho module Cấu hình tích hợp LDAP.
 *
 * Pattern: mỗi API module có 1 client object chứa toàn bộ method gọi API.
 * Test spec chỉ import client, không biết về URL hay headers — giữ DRY.
 */

const { getAuthHeaders } = require('../config/env');

const BASE_URL =
  'https://ubck-iam-api.viettelsoftware.com/iam-be/api/v1/integration-config/LDAP/019d427c-8ffd-792b-9be7-04405729c9ae';

/**
 * Tạo API Client cho Integration LDAP endpoint.
 * @param {import('@playwright/test').APIRequestContext} request
 */
const createIntegrationLdapApi = (request) => ({

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
   * @param {object} data - Request body
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

  /**
   * Gọi PUT với Content-Type tuỳ chỉnh.
   * @param {object|string} data
   * @param {string} contentType
   */
  updateWithContentType(data, contentType) {
    return request.put(BASE_URL, {
      headers: { ...getAuthHeaders(), 'Content-Type': contentType },
      data,
    });
  },

  /** Body hợp lệ dùng làm base trong test cases */
  validBody: {
    type: 'LDAP',
    status: 'ACTIVE',
    connectionUrl: 'ldaps://ldap.example.com:636',
    enableStartTls: false,
    bindType: 'none',
    bindDn: 'cn=admin,dc=ubck,dc=local',
    userDn: 'ou=users,dc=ubck,dc=local',
    usernameLdapAttribute: 'uid',
    rdnLdapAttribute: 'uid',
    uuidLdapAttribute: 'entryUUID',
    userObjectClass: 'inetOrgPerson',
    connectionPooling: false,
  },
});

module.exports = { createIntegrationLdapApi };
