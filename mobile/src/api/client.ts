import axios, {AxiosError, type InternalAxiosRequestConfig} from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as Keychain from 'react-native-keychain';

const BASE_URL_KEY = '@vigil/base_url';

let _baseUrl: string | null = null;

export async function getBaseUrl(): Promise<string> {
  if (_baseUrl) {
    return _baseUrl;
  }
  const cached = await AsyncStorage.getItem(BASE_URL_KEY);
  _baseUrl = cached || 'http://localhost:8000';
  return _baseUrl;
}

export async function setBaseUrl(url: string): Promise<void> {
  _baseUrl = url;
  await AsyncStorage.setItem(BASE_URL_KEY, url);
}

const KEYCHAIN_SERVICE_ACCESS = 'vigil-access-token';
const KEYCHAIN_SERVICE_REFRESH = 'vigil-refresh-token';

export async function setAccessToken(token: string): Promise<void> {
  await Keychain.setGenericPassword('access', token, {
    service: KEYCHAIN_SERVICE_ACCESS,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function setRefreshToken(token: string): Promise<void> {
  await Keychain.setGenericPassword('refresh', token, {
    service: KEYCHAIN_SERVICE_REFRESH,
    accessible: Keychain.ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
  });
}

export async function getAccessToken(): Promise<string | null> {
  const creds = await Keychain.getGenericPassword({service: KEYCHAIN_SERVICE_ACCESS});
  return creds ? creds.password : null;
}

export async function getRefreshToken(): Promise<string | null> {
  const creds = await Keychain.getGenericPassword({service: KEYCHAIN_SERVICE_REFRESH});
  return creds ? creds.password : null;
}

export async function clearTokens(): Promise<void> {
  await Keychain.resetGenericPassword({service: KEYCHAIN_SERVICE_ACCESS});
  await Keychain.resetGenericPassword({service: KEYCHAIN_SERVICE_REFRESH});
}

export async function decodeJwtPayload(token: string): Promise<Record<string, unknown> | null> {
  try {
    const part = token.split('.')[1];
    const padded = part + '='.repeat((4 - (part.length % 4)) % 4);
    const json = decodeBase64Url(padded);
    return JSON.parse(json);
  } catch {
    return null;
  }
}

function decodeBase64Url(s: string): string {
  // RN doesn't have atob in older versions; fall back to manual decode.
  if (typeof atob === 'function') {
    return atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  }
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
  let str = s.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const c of str) {
    const v = chars.indexOf(c);
    if (v === -1) continue;
    buffer = (buffer << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out += String.fromCharCode((buffer >> bits) & 0xff);
    }
  }
  return out;
}

export const apiClient = axios.create({timeout: 15000});

apiClient.interceptors.request.use(async config => {
  if (!config.baseURL) {
    config.baseURL = await getBaseUrl();
  }
  const token = await getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  config.headers['Content-Type'] = 'application/json';
  return config;
});

type Retry = InternalAxiosRequestConfig & {_retry?: boolean};

apiClient.interceptors.response.use(
  res => res,
  async (err: AxiosError) => {
    const original = err.config as Retry | undefined;
    if (err.response?.status === 401 && original && !original._retry) {
      original._retry = true;
      const refresh = await getRefreshToken();
      if (refresh) {
        try {
          const baseUrl = await getBaseUrl();
          const r = await axios.post(`${baseUrl}/auth/refresh`, {refresh_token: refresh});
          await setAccessToken(r.data.access_token);
          await setRefreshToken(r.data.refresh_token);
          original.headers = original.headers ?? {};
          original.headers.Authorization = `Bearer ${r.data.access_token}`;
          return apiClient(original);
        } catch {
          await clearTokens();
        }
      }
    }
    return Promise.reject(err);
  },
);

export const analystPortalClient = axios.create({timeout: 15000});

analystPortalClient.interceptors.request.use(async config => {
  if (!config.baseURL) {
    const base = await getBaseUrl();
    // Convention: replace :8000 → :8008. Fallback to inserted ANALYST_URL if needed.
    config.baseURL = base.replace(/:8000$/, ':8008');
  }
  const token = await getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  config.headers['Content-Type'] = 'application/json';
  return config;
});

export const attackStateClient = axios.create({timeout: 15000});

attackStateClient.interceptors.request.use(async config => {
  if (!config.baseURL) {
    const base = await getBaseUrl();
    config.baseURL = base.replace(/:8000$/, ':8002');
  }
  const token = await getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  config.headers['Content-Type'] = 'application/json';
  return config;
});
