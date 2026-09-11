export const DEMO_PWD = import.meta.env.VITE_DEMO_PASSWORD || 'changeme123';
export const ADMIN_PWD = import.meta.env.VITE_ADMIN_PASSWORD || 'admin_changeme123';

export async function login(apiBase: string, subject: string, password: string = DEMO_PWD): Promise<string> {
  const res = await fetch(`${apiBase}/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, password }),
  });
  if (!res.ok) throw new Error(`login failed for ${subject}: ${res.status}`);
  const data = await res.json();
  return data.access_token as string;
}

export async function registerThrowaway(apiBase: string): Promise<{ subject: string; token: string }> {
  const subject = `probe_${Math.random().toString(36).slice(2, 10)}`;
  const res = await fetch(`${apiBase}/auth/register`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ subject, password: DEMO_PWD, role: 'customer' }),
  });
  if (!res.ok) throw new Error(`throwaway registration failed: ${res.status}`);
  const token = await login(apiBase, subject, DEMO_PWD);
  return { subject, token };
}

export async function timedFetch(apiBase: string, path: string, init: RequestInit = {}): Promise<{ status: number; ms: number; body: any }> {
  const start = performance.now();
  const res = await fetch(`${apiBase}${path}`, init);
  const ms = Math.round(performance.now() - start);
  const body = await res.json().catch(() => ({}));
  return { status: res.status, ms, body };
}
