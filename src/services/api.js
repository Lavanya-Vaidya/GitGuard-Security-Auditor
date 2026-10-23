import { audits, findings, repositories } from '../data/demo.js';

const baseUrl = import.meta.env.VITE_API_BASE_URL?.trim().replace(/\/$/, '');
export const demoMode = !baseUrl;

async function request(path) {
  if (!baseUrl) return null;
  const tokenProvider = window.GITGUARD_AUTH?.getAccessToken;
  if (typeof tokenProvider !== 'function') {
    throw new Error('Sign in through the configured identity provider to load private audit data.');
  }
  const token = await tokenProvider();
  if (typeof token !== 'string' || !token.trim()) {
    throw new Error('No valid dashboard access token is available. Sign in again.');
  }
  const response = await fetch(`${baseUrl}${path}`, {
    headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
    cache: 'no-store',
  });
  if (!response.ok) throw new Error(`Dashboard API returned ${response.status}.`);
  return response.json();
}

function requiredArray(value, name) {
  if (!Array.isArray(value)) throw new Error(`Dashboard API response must include a ${name} array.`);
  return value;
}

function normalizeAudit(audit) {
  if (!audit || typeof audit !== 'object') throw new Error('Dashboard API returned an invalid audit record.');
  let rawDetails = audit.findingDetails ?? audit.findings;
  if (typeof rawDetails === 'string') {
    try { rawDetails = JSON.parse(rawDetails); } catch { throw new Error('Audit findings must be valid JSON.'); }
  }
  const findingDetails = Array.isArray(rawDetails)
    ? rawDetails
    : Object.entries(rawDetails && typeof rawDetails === 'object' ? rawDetails : {}).flatMap(([file, entries]) =>
      Array.isArray(entries) ? entries.map(entry => ({ ...entry, file: entry.file ?? file })) : []);
  const counts = audit.counts || (rawDetails && !Array.isArray(rawDetails) && Object.values(rawDetails).every(value => typeof value === 'number') ? rawDetails : {});
  const timestamp = Number(audit.timestamp ?? 0) * (Number(audit.timestamp ?? 0) < 1e12 ? 1000 : 1);
  return {
    ...audit,
    id: String(audit.id ?? `${audit.repo ?? audit.repository ?? 'repo'}-${audit.number ?? audit.pr_number ?? audit.commit_sha ?? ''}`),
    repo: String(audit.repo ?? audit.repository ?? ''),
    number: Number(audit.number ?? audit.pr_number ?? 0),
    title: audit.title == null ? '' : String(audit.title),
    author: audit.author == null ? '' : String(audit.author),
    initials: audit.initials == null ? '' : String(audit.initials),
    status: String(audit.status ?? 'Unknown').toLowerCase() === 'completed' ? 'Completed' : String(audit.status ?? 'Unknown'),
    sha: String(audit.sha ?? audit.commit_sha ?? ''),
    scanned: String(audit.scanned ?? (timestamp ? new Date(timestamp).toLocaleString() : 'Unknown')),
    timestamp,
    findings: Object.fromEntries(['critical', 'high', 'medium', 'low'].map(s => [s, Number(counts[s] ?? 0)])),
    findingDetails: findingDetails.map((finding, index) => normalizeFinding({
      ...finding,
      id: finding.id ?? `${audit.id ?? audit.commit_sha ?? 'audit'}-${index}`,
      auditId: audit.id ?? `${audit.repo ?? audit.repository ?? 'repo'}-${audit.number ?? audit.pr_number ?? audit.commit_sha ?? ''}`,
      repo: finding.repo ?? audit.repo ?? audit.repository,
      pr: finding.pr ?? audit.number ?? audit.pr_number,
    })),
  };
}

function normalizeFinding(finding) {
  if (!finding || typeof finding !== 'object') throw new Error('Dashboard API returned an invalid finding record.');
  return { ...finding, id: String(finding.id ?? `${finding.repo ?? ''}-${finding.pr ?? finding.pr_number ?? ''}-${finding.file ?? finding.path ?? ''}-${finding.line ?? ''}`), auditId: String(finding.auditId ?? finding.audit_id ?? ''), repo: String(finding.repo ?? finding.repository ?? ''), pr: Number(finding.pr ?? finding.pr_number ?? 0), severity: String(finding.severity ?? 'medium').toLowerCase(), title: String(finding.title ?? 'Security finding'), file: String(finding.file ?? finding.path ?? ''), line: Number(finding.line ?? 0), category: finding.category ? String(finding.category) : 'Uncategorized', status: finding.status ? String(finding.status) : 'Unspecified' };
}

function normalizeRepository(repo) {
  if (!repo || typeof repo !== 'object') throw new Error('Dashboard API returned an invalid repository record.');
  const latestTimestamp = Number(repo.latestTimestamp ?? 0);
  return {
    ...repo,
    name: String(repo.name ?? repo.repo ?? ''),
    owner: String(repo.owner ?? String(repo.name ?? '').split('/')[0] ?? ''),
    audits: Number(repo.audits ?? 0),
    status: String(repo.status ?? 'Unknown').toLowerCase() === 'completed' ? 'Completed' : String(repo.status ?? 'Unknown'),
    visibility: repo.visibility ? String(repo.visibility) : null,
    latest: repo.latest ?? (latestTimestamp ? new Date(latestTimestamp * (latestTimestamp < 1e12 ? 1000 : 1)).toLocaleString() : 'Unknown'),
  };
}

export async function getDashboardData() {
  if (!baseUrl) return { audits, findings, repositories, source: 'demo' };
  const pages = [];
  let nextToken;
  for (let page = 0; page < 5; page += 1) {
    const query = new URLSearchParams({ limit: '100' });
    if (nextToken) query.set('nextToken', nextToken);
    const data = await request(`/dashboard?${query}`);
    if (!data || typeof data !== 'object') throw new Error('Dashboard API returned an empty response.');
    pages.push(data);
    nextToken = data.nextToken || '';
    if (!nextToken) break;
  }
  return {
    audits: pages.flatMap(data => requiredArray(data.audits, 'audits')).map(normalizeAudit),
    findings: pages.flatMap(data => requiredArray(data.findings, 'findings')).map(normalizeFinding),
    repositories: mergeRepositories(pages.flatMap(data => requiredArray(data.repositories, 'repositories')).map(normalizeRepository)),
    hasMore: Boolean(nextToken),
    source: 'api',
  };
}

function mergeRepositories(repositories) {
  const merged = new Map();
  for (const repo of repositories) {
    const existing = merged.get(repo.name);
    if (!existing) merged.set(repo.name, { ...repo });
    else {
      existing.audits += repo.audits;
      if (Number(repo.latestTimestamp) > Number(existing.latestTimestamp)) {
        existing.latestTimestamp = repo.latestTimestamp;
        existing.status = repo.status;
      }
    }
  }
  return [...merged.values()];
}
export async function getAudit(id) {
  if (!baseUrl) return audits.find(a => a.id === id) ?? null;
  const data = await request(`/audits/${encodeURIComponent(id)}`);
  if (!data || typeof data !== 'object') throw new Error('Audit API returned an empty response.');
  return normalizeAudit(data);
}
