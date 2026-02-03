export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

export type ApiError = {
  status: number;
  message: string;
};

export async function apiRequest<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem("osint_token");
  const headers = new Headers(options.headers || {});
  if (!headers.has("Content-Type") && options.body) {
    headers.set("Content-Type", "application/json");
  }
  if (token) {
    headers.set("Authorization", `Bearer ${token}`);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers,
  });

  if (response.status === 401) {
    localStorage.removeItem("osint_token");
    window.dispatchEvent(new CustomEvent("osint:unauthorized"));
  }

  if (!response.ok) {
    let message = response.statusText;
    try {
      const data = await response.json();
      message = data.detail || data.message || message;
    } catch {
      // ignore
    }
    throw { status: response.status, message } as ApiError;
  }

  if (response.status === 204) {
    return {} as T;
  }

  return response.json() as Promise<T>;
}
