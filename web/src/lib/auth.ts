export function isAuthenticated(): boolean {
  return Boolean(localStorage.getItem("osint_token"));
}

export function setToken(token: string) {
  localStorage.setItem("osint_token", token);
}

export function clearToken() {
  localStorage.removeItem("osint_token");
}
