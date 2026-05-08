import {apiClient, setAccessToken, setRefreshToken, clearTokens} from './client';
import type {AuthTokens} from '../types';

export async function login(email: string, password: string): Promise<AuthTokens> {
  const res = await apiClient.post<AuthTokens>('/auth/login', {email, password});
  await setAccessToken(res.data.access_token);
  await setRefreshToken(res.data.refresh_token);
  return res.data;
}

export async function logout(refreshToken: string): Promise<void> {
  try {
    await apiClient.post('/auth/logout', {refresh_token: refreshToken});
  } finally {
    await clearTokens();
  }
}

export async function getMe(): Promise<{user_id: string; email: string; role: string; tenant_id: string}> {
  const res = await apiClient.get('/auth/me');
  return res.data;
}
