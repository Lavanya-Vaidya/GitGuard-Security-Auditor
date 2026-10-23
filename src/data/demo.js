export const repositories = [
  { name: 'acme/platform-api', owner: 'acme', visibility: 'Private', audits: 18, latest: '12 min ago', status: 'Connected' },
  { name: 'acme/web-client', owner: 'acme', visibility: 'Private', audits: 12, latest: '1 hr ago', status: 'Connected' },
  { name: 'northstar/infra', owner: 'northstar', visibility: 'Public', audits: 7, latest: 'Yesterday', status: 'Connected' },
];

export const audits = [
  { id: 'api-284', repo: 'acme/platform-api', number: 284, title: 'Add account recovery endpoint', author: 'Maya Chen', initials: 'MC', status: 'Completed', sha: 'a81f3d2', scanned: '12 min ago', timestamp: Date.now() - 12 * 60000, findings: { critical: 1, high: 2, medium: 3, low: 1 }, url: 'https://github.com/acme/platform-api/pull/284', summary: 'The recovery flow accepts an untrusted account identifier without an ownership check. Add authorization before issuing a reset token.' },
  { id: 'web-119', repo: 'acme/web-client', number: 119, title: 'Update markdown rendering pipeline', author: 'Jordan Lee', initials: 'JL', status: 'Completed', sha: 'c4b09e1', scanned: '1 hr ago', timestamp: Date.now() - 60 * 60000, findings: { critical: 0, high: 1, medium: 2, low: 0 }, url: 'https://github.com/acme/web-client/pull/119' },
  { id: 'infra-72', repo: 'northstar/infra', number: 72, title: 'Rotate service health checks', author: 'Sam Rivera', initials: 'SR', status: 'Completed', sha: '90de7ac', scanned: '3 hrs ago', timestamp: Date.now() - 3 * 3600000, findings: { critical: 0, high: 0, medium: 1, low: 2 }, url: 'https://github.com/northstar/infra/pull/72' },
  { id: 'api-283', repo: 'acme/platform-api', number: 283, title: 'Cache organization permissions', author: 'Ari Patel', initials: 'AP', status: 'Completed', sha: '729bc10', scanned: 'Yesterday', timestamp: Date.now() - 24 * 3600000, findings: { critical: 0, high: 0, medium: 0, low: 0 }, url: 'https://github.com/acme/platform-api/pull/283' },
  { id: 'web-118', repo: 'acme/web-client', number: 118, title: 'Add invite acceptance screen', author: 'Maya Chen', initials: 'MC', status: 'Completed', sha: 'ef552d4', scanned: 'Oct 19', timestamp: Date.now() - 3 * 86400000, findings: { critical: 0, high: 1, medium: 0, low: 1 }, url: 'https://github.com/acme/web-client/pull/118' },
  { id: 'infra-71', repo: 'northstar/infra', number: 71, title: 'Pin base image versions', author: 'Jordan Lee', initials: 'JL', status: 'Completed', sha: '829a14f', scanned: 'Oct 18', timestamp: Date.now() - 4 * 86400000, findings: { critical: 0, high: 0, medium: 0, low: 0 }, url: 'https://github.com/northstar/infra/pull/71' },
];

export const findings = [
  { id: 'f1', auditId: 'api-284', repo: 'acme/platform-api', pr: 284, severity: 'critical', category: 'Authorization', title: 'Account recovery lacks an ownership check', file: 'src/routes/recovery.ts', line: 42, cwe: 'CWE-862', explanation: 'The request uses the supplied accountId to create a recovery token without confirming that the requester can act on that account.', fix: 'Verify the account ownership or use a verified email challenge before creating a recovery token.', status: 'Open' },
  { id: 'f2', auditId: 'api-284', repo: 'acme/platform-api', pr: 284, severity: 'high', category: 'Secrets exposure', title: 'Recovery token included in application logs', file: 'src/services/recovery.ts', line: 88, cwe: 'CWE-532', explanation: 'Logging the token exposes a credential to anyone with access to centralized application logs.', fix: 'Remove the token from log fields and log only a request identifier.', status: 'Open' },
  { id: 'f3', auditId: 'api-284', repo: 'acme/platform-api', pr: 284, severity: 'high', category: 'Injection', title: 'Untrusted value interpolated into query', file: 'src/db/accounts.ts', line: 106, cwe: 'CWE-89', explanation: 'The account lookup interpolates a user controlled value into the query string.', fix: 'Use a parameterized query and pass the identifier as a bound parameter.', status: 'Open' },
  { id: 'f4', auditId: 'web-119', repo: 'acme/web-client', pr: 119, severity: 'high', category: 'Injection', title: 'Raw HTML rendered from markdown input', file: 'src/render/markdown.tsx', line: 67, cwe: 'CWE-79', explanation: 'Raw HTML from markdown is inserted into the page without sanitization, allowing script injection.', fix: 'Sanitize generated HTML with a maintained allowlist before rendering.', status: 'Open' },
  { id: 'f5', auditId: 'api-284', repo: 'acme/platform-api', pr: 284, severity: 'medium', category: 'Insecure configuration', title: 'Recovery link accepts an unbounded redirect', file: 'src/routes/recovery.ts', line: 57, cwe: 'CWE-601', explanation: 'The redirect target is not restricted to an approved origin.', fix: 'Allow only relative paths or validate against an explicit trusted host list.', status: 'Open' },
  { id: 'f6', auditId: 'infra-72', repo: 'northstar/infra', pr: 72, severity: 'low', category: 'Dependency risk', title: 'Health endpoint reveals runtime version', file: 'deploy/healthcheck.yaml', line: 31, cwe: 'CWE-200', explanation: 'The health response includes unnecessary runtime details.', fix: 'Return a minimal health status without version metadata.', status: 'Open' },
];

export const activity = [
  { type: 'critical', text: 'Critical issue found in', target: 'PR #284 · platform-api', time: '12 min ago', auditId: 'api-284' },
  { type: 'success', text: 'Security scan completed for', target: 'PR #119 · web-client', time: '1 hr ago', auditId: 'web-119' },
  { type: 'success', text: 'No critical findings in', target: 'PR #72 · northstar/infra', time: '3 hrs ago', auditId: 'infra-72' },
  { type: 'resolved', text: 'Audit completed for', target: 'PR #283 · platform-api', time: 'Yesterday', auditId: 'api-283' },
];

export const trend = [
  { day: 'Oct 16', critical: 3, high: 8, medium: 12 }, { day: 'Oct 17', critical: 2, high: 7, medium: 10 },
  { day: 'Oct 18', critical: 4, high: 9, medium: 13 }, { day: 'Oct 19', critical: 2, high: 6, medium: 9 },
  { day: 'Oct 20', critical: 3, high: 8, medium: 11 }, { day: 'Oct 21', critical: 1, high: 5, medium: 8 },
  { day: 'Oct 22', critical: 1, high: 3, medium: 6 },
];
