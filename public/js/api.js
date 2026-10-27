function tokenKey(auth) {
  return auth === "admin" ? "leads_admin_token" : "leads_customer_token";
}

async function api(path, opts) {
  opts = opts || {};
  const headers = { "Content-Type": "application/json" };
  if (opts.auth) {
    const token = localStorage.getItem(tokenKey(opts.auth));
    if (!token) {
      if (opts.auth === "admin") location.href = "admin-login.html";
      else location.href = "/login";
      throw new Error("Unauthorized");
    }
    headers.Authorization = "Bearer " + token;
  }
  const res = await fetch(path, {
    method: opts.method || "GET",
    headers: headers,
    body: opts.body ? JSON.stringify(opts.body) : undefined,
  });
  let data = {};
  try {
    data = await res.json();
  } catch (e) {}
  if (res.status === 401) {
    localStorage.removeItem(tokenKey(opts.auth || "customer"));
    if (opts.auth === "admin") location.href = "admin-login.html";
    else location.href = "/login";
  }
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

function formatMoney(n) {
  return Number(n || 0).toLocaleString("en-US", { style: "currency", currency: "USD" });
}
