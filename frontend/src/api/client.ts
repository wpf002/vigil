import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL ?? "http://localhost:8002";
const DEV_TENANT = import.meta.env.VITE_DEV_TENANT_ID ?? "default";

export const apiClient = axios.create({
  baseURL: API_URL,
  timeout: 15000,
  headers: {
    "Content-Type": "application/json",
  },
});

apiClient.interceptors.request.use((config) => {
  // Dev mode: send X-Tenant-Id when no real Clerk token is available.
  // Once Clerk is wired in, replace this with the JWT from useAuth().
  if (!config.headers.Authorization) {
    config.headers["X-Tenant-Id"] = DEV_TENANT;
  }
  return config;
});

apiClient.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response?.data?.error) {
      err.message = err.response.data.error;
    }
    return Promise.reject(err);
  },
);
