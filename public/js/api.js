
const API = "";  // same origin

function getToken() {
  return localStorage.getItem("lb_token") || "";
}
function setToken(t) {
  if (t) localStorage.setItem("lb_token", t);
  else localStorage.removeItem("lb_token");
}
function getAdminToken() {
  return localStorage.getItem("lb_admin_token") || "";
}
function setAdminToken(t) {
  if (t) localStorage.setItem("lb_admin_token", t);
  else localStorage.removeItem("lb_admin_token");
}

async function api(path, options = {}) {
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (options.auth === "customer") headers.Authorization = "Bearer " + getToken();
  if (options.auth === "admin") headers.Authorization = "Bearer " + getAdminToken();
  const res = await fetch(API + path, {
    method: options.method || "GET",
    headers,
    body: options.body ? JSON.stringify(options.body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function formatMoney(n) {
  return new Intl.NumberFormat("en-US", { style: "currency", currency: "USD" }).format(n || 0);
}

function requireCustomerPage() {
  if (!getToken()) { location.href = "login.html"; return false; }
  return true;
}
function requireAdminPage() {
  if (!getAdminToken()) { location.href = "admin-login.html"; return false; }
  return true;
}
