import axios from "axios";

const AUTH_URL =
  import.meta.env.VITE_AUTH_URL ?? "http://localhost:8000";

export interface AuthUser {
  user_id: string;
  email: string;
  role: string;
  tenant_id: string;
}

export interface MeResponse extends AuthUser {
  last_login: string | null;
}

export interface TokenPair {
  access_token: string;
  refresh_token: string;
  user: AuthUser;
}

export interface RefreshResponse {
  access_token: string;
  refresh_token: string;
}

// Dedicated axios instance — never carries a stale Bearer token.
export const authClient = axios.create({
  baseURL: AUTH_URL,
  timeout: 15000,
  headers: { "Content-Type": "application/json" },
});

export async function register(
  email: string,
  password: string,
  tenant_name: string,
): Promise<TokenPair> {
  const res = await authClient.post<TokenPair>("/auth/register", {
    email,
    password,
    tenant_name,
  });
  return res.data;
}

export async function login(
  email: string,
  password: string,
): Promise<TokenPair> {
  const res = await authClient.post<TokenPair>("/auth/login", {
    email,
    password,
  });
  return res.data;
}

export async function refresh(refresh_token: string): Promise<RefreshResponse> {
  const res = await authClient.post<RefreshResponse>("/auth/refresh", {
    refresh_token,
  });
  return res.data;
}

export async function logout(
  access_token: string,
  refresh_token: string,
): Promise<void> {
  await authClient.post(
    "/auth/logout",
    { refresh_token },
    { headers: { Authorization: `Bearer ${access_token}` } },
  );
}

export async function fetchMe(access_token: string): Promise<MeResponse> {
  const res = await authClient.get<MeResponse>("/auth/me", {
    headers: { Authorization: `Bearer ${access_token}` },
  });
  return res.data;
}
