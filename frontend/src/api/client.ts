const API_BASE = import.meta.env.VITE_API_URL || '';

export class ApiError extends Error {
  status: number;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

export function getToken() {
  return localStorage.getItem('siem_token');
}

export function setToken(token: string | null) {
  if (token) {
    localStorage.setItem('siem_token', token);
  } else {
    localStorage.removeItem('siem_token');
  }
}

export function getTenantId() {
  return localStorage.getItem('siem_tenant_id') || '';
}

export function setTenantId(tenantId: string) {
  localStorage.setItem('siem_tenant_id', tenantId);
}

export async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getToken();
  const tenantId = getTenantId();
  const headers = new Headers(options.headers);
  headers.set('Content-Type', headers.get('Content-Type') || 'application/json');
  if (token) headers.set('Authorization', `Bearer ${token}`);
  if (tenantId) headers.set('X-Tenant-ID', tenantId);
  const response = await fetch(`${API_BASE}${path}`, { ...options, headers });
  if (!response.ok) {
    const text = await response.text();
    let detail = text;
    try {
      detail = JSON.parse(text).detail || text;
    } catch {
      detail = text || response.statusText;
    }
    throw new ApiError(response.status, detail);
  }
  if (response.status === 204) return undefined as T;
  const contentType = response.headers.get('content-type') || '';
  if (!contentType.includes('application/json')) return (await response.text()) as T;
  return response.json() as Promise<T>;
}
