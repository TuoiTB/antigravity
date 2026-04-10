/**
 * @file env.js
 * @description Cấu hình môi trường chung cho Security Test Suite.
 * Thay đổi TOKEN tại config/auth.js khi token hết hạn.
 */

const { TOKEN } = require('./auth');

const ENV = {
  BASE_URL: process.env.BASE_URL || 'https://ubck-iam-api.viettelsoftware.com',
  TOKEN,
};

/**
 * Trả về headers chuẩn cho mọi API request bảo mật.
 * @param {string} [token] - Override token nếu muốn dùng token khác ENV.TOKEN
 * @returns {Record<string, string>}
 */
function getAuthHeaders(token) {
  const bearerToken = token || ENV.TOKEN;
  return {
    Authorization: `Bearer ${bearerToken}`,
    'Content-Type': 'application/json',
    Accept: 'application/json, text/plain, */*',
    'Accept-Language': 'vi',
    'sec-ch-ua-platform': '"Windows"',
    'sec-ch-ua': '"Chromium";v="146", "Not-A.Brand";v="24", "Google Chrome";v="146"',
    'sec-ch-ua-mobile': '?0',
    'User-Agent':
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36',
    Referer: 'https://ubck-iam.viettelsoftware.com/',
  };
}

module.exports = { ENV, getAuthHeaders };
