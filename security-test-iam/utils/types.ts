/**
 * @description Interface và type chung cho Security Test reporting
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | '-';
export type TestResult = 'PASS' | 'FAIL' | 'SKIP';

export interface SecurityTestCase {
  id: string;
  owasp: string;
  category: string;
  severity: Severity;
  urlTest: string;
  actualStatus: number;
  actualResponse: string;
  expectedStatus: number;
  expectedMessage: string;
  result: TestResult;
  bugDescription: string;
  recommendation: string;
}

export interface ReportMeta {
  module: string;
  endpoint: string;
  baseUrl: string;
  date: string;
  tester: string;
  framework: string;
  testType: string;
}
