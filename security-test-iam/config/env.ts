/**
 * @description Cấu hình môi trường chung cho Security Test Suite
 * Thay đổi TOKEN và BASE_URL tại đây cho mỗi lần chạy test.
 */

export const ENV = {
  BASE_URL: process.env.BASE_URL || 'https://ubck-iam-api.viettelsoftware.com',
  TOKEN: process.env.TOKEN || '',
};

export function getAuthHeaders(token?: string): Record<string, string> {
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
