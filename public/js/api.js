const API = "";

function getToken() {
  return localStorage.getItem("lb_token") || localStorage.getItem("leads_customer_token") || "";
}
function setToken(t) {
  if (t) {
    localStorage.setItem("lb_token", t);
    localStorage.setItem("leads_customer_token", t);
  } else {
    localStorage.removeItem("lb_token");
    localStorage.removeItem("leads_customer_token");
  }
}
function getAdminToken() {
  return localStorage.getItem("lb_admin_token") || localStorage.getItem("leads_admin_token") || "";
}
function setAdminToken(t) {
  if (t) {
    localStorage.setItem("lb_admin_token", t);
    localStorage.setItem("leads_admin_token", t);
  } else {
    localStorage.removeItem("lb_admin_token");
    localStorage.removeItem("leads_admin_token");
  }
}

async function api(path, options) {
  options = options || {};
  const headers = Object.assign({ "Content-Type": "application/json" }, options.headers || {});
  if (options.auth === "customer") {
    const token = getToken();
    if (!token) {
      location.href = "login.html";
      throw new Error("Unauthorized");
    }
    headers.Authorization = "Bearer " + token;
  }
  if (options.auth === "admin") {
    const token = getAdminToken();
    if (!token) {
      location.href = "admin-login.html";
      throw new Error("Unauthorized");
    }
    headers.Authorization = "Bearer " + token;
  }
  const res = await fetch(API + path, {
    method: options.method || "GET",
    headers: headers,
    body: options.body ? JSON.stringify(options.body) : undefined,
  });
  const data = await res.json().catch(function () { return {}; });
  if (res.status === 401) {
    if (options.auth === "admin") setAdminToken("");
    else if (options.auth === "customer") setToken("");
  }
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
