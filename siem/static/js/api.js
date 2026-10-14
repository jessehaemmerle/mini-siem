// Zugriff auf die REST-API. Bei abgelaufener Anmeldung -> Login-Seite.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

let onUnauthorized = () => {};
export function setUnauthorizedHandler(fn) { onUnauthorized = fn; }

export async function api(path, { method = 'GET', body, params, signal } = {}) {
  let url = path;
  if (params) {
    const qs = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    }
    const s = qs.toString();
    if (s) url += (url.includes('?') ? '&' : '?') + s;
  }
  const headers = { 'X-SIEM': '1' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(url, {
      method, headers, signal, credentials: 'same-origin',
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
  } catch (e) {
    if (e.name === 'AbortError') throw e;
    throw new ApiError(0, 'Der Server ist nicht erreichbar. Läuft der Container?');
  }
  if (res.status === 401 && !path.startsWith('/api/auth/login')) {
    onUnauthorized();
    throw new ApiError(401, 'Bitte erneut anmelden');
  }
  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch { data = { detail: text }; }
  }
  if (!res.ok) {
    let msg = data?.detail ?? `Fehler ${res.status}`;
    if (Array.isArray(msg)) msg = msg.map((d) => d.msg).join('; ');
    throw new ApiError(res.status, msg);
  }
  return data;
}
