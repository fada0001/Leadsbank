
const express = require("express");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { db, init, nextAccountId } = require("./db");

init();

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "leads-bank-practice-secret-change-in-production";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function uid() {
  return "ID-" + Date.now() + "-" + Math.floor(Math.random() * 10000);
}

function createNotification(userId, email, title, body, type = "info") {
  const id = uid();
  const now = new Date().toISOString();
  db.prepare(`
    INSERT INTO notifications (id, user_id, email, title, body, type, is_read, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?)
  `).run(id, userId, email, title, body, type, now);
  return id;
}

function authCustomer(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "customer") return res.status(401).json({ error: "Unauthorized" });
    req.user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function authAdmin(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Unauthorized" });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    if (payload.role !== "admin") return res.status(401).json({ error: "Unauthorized" });
    req.admin = payload;
    next();
  } catch {
    return res.status(401).json({ error: "Unauthorized" });
  }
}

function publicUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    firstName: row.first_name,
    lastName: row.last_name,
    email: row.email,
    phone: row.phone,
    address: row.address,
    city: row.city,
    state: row.state,
    zip: row.zip,
    ssnLast4: row.ssn_last4,
    balance: row.balance,
    available: row.available,
    accountType: row.account_type,
    status: row.status,
    routingNumber: row.routing_number || "",
    accountNumber: row.account_number || "",
    createdAt: row.created_at
  };
}

// ========== AUTH ==========
app.post("/api/register", (req, res) => {
  try {
    const b = req.body || {};
    const required = ["firstName", "lastName", "email", "phone", "address", "city", "state", "zip", "ssnLast4", "password", "accountType"];
    for (const k of required) {
      if (!b[k] || String(b[k]).trim() === "") return res.status(400).json({ error: `Missing ${k}` });
    }
    if (String(b.password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    const email = String(b.email).trim().toLowerCase();
    const exists = db.prepare("SELECT id FROM users WHERE email = ?").get(email);
    if (exists) return res.status(400).json({ error: "An account with this email already exists" });

    const id = nextAccountId();
    const hash = bcrypt.hashSync(String(b.password), 10);
    const today = new Date().toISOString().slice(0, 10);
    const routing = require("./db").generateRouting();
    const acctNum = require("./db").generateAccountNumber();

    db.prepare(`
      INSERT INTO users (id, first_name, last_name, email, phone, address, city, state, zip, ssn_last4, password_hash, balance, available, account_type, status, routing_number, account_number, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, ?, 'active', ?, ?, ?)
    `).run(
      id,
      String(b.firstName).trim(),
      String(b.lastName).trim(),
      email,
      String(b.phone).trim(),
      String(b.address).trim(),
      String(b.city).trim(),
      String(b.state).trim(),
      String(b.zip).trim(),
      String(b.ssnLast4).trim(),
      hash,
      String(b.accountType).trim(),
      routing,
      acctNum,
      today
    );

    db.prepare("INSERT INTO transactions (user_id, date, description, amount, type) VALUES (?, ?, ?, ?, ?)").run(
      id, today, "Account Opened", 0, "credit"
    );

    createNotification(
      id,
      email,
      "Account Opened Successfully",
      `Welcome to Leads Bank! Your account has been created. Account Number: ${acctNum}, Routing: ${routing}.`,
      "registration"
    );

    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
    const token = jwt.sign({ role: "customer", email: user.email, id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", (req, res) => {
  try {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const password = String((req.body || {}).password || "");
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ error: "Invalid email or password" });
    }
    const token = jwt.sign({ role: "customer", email: user.email, id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Login failed" });
  }
});

app.post("/api/admin/login", (req, res) => {
  try {
    const username = String((req.body || {}).username || "").trim();
    const password = String((req.body || {}).password || "");
    const admin = db.prepare("SELECT * FROM admins WHERE username = ?").get(username);
    if (!admin || !bcrypt.compareSync(password, admin.password_hash)) {
      return res.status(401).json({ error: "Invalid admin credentials" });
    }
    const token = jwt.sign({ role: "admin", username }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Admin login failed" });
  }
});

// ========== CUSTOMER ==========
app.get("/api/me", authCustomer, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(req.user.email);
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(user) });
});

app.get("/api/me/transactions", authCustomer, (req, res) => {
  const rows = db.prepare("SELECT date, description AS desc, amount, type FROM transactions WHERE user_id = ? ORDER BY id ASC").all(req.user.id);
  res.json({ transactions: rows });
});

app.get("/api/me/requests", authCustomer, (req, res) => {
  const rows = db.prepare("SELECT id, request_type AS type, details, amount, status, date FROM transfer_requests WHERE email = ? ORDER BY created_at DESC").all(req.user.email);
  res.json({ requests: rows });
});

app.post("/api/me/add-funds-request", authCustomer, (req, res) => {
  try {
    const amount = parseFloat((req.body || {}).amount);
    const memo = String((req.body || {}).memo || "Add funds request").trim();
    if (!(amount > 0)) {
      return res.status(400).json({ error: "Invalid amount" });
    }
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO transfer_requests (id, user_id, email, user_name, request_type, details, amount, status, date, created_at)
      VALUES (?, ?, ?, ?, 'add_funds', ?, ?, 'pending', ?, ?)
    `).run(id, user.id, user.email, `${user.first_name} ${user.last_name}`, memo, amount, today, now);

    res.json({ ok: true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not submit add funds request" });
  }
});

app.post("/api/me/transfer-request", authCustomer, (req, res) => {
  try {
    const amount = parseFloat((req.body || {}).amount);
    const recipientName = String((req.body || {}).recipientName || "").trim();
    const recipientAcct = String((req.body || {}).recipientAcct || "").trim();
    const memo = String((req.body || {}).memo || "").trim();
    if (!recipientName || !recipientAcct || !(amount > 0)) {
      return res.status(400).json({ error: "Invalid transfer details" });
    }
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (amount > user.available) return res.status(400).json({ error: "Insufficient available balance" });

    const details = memo ? `${recipientName} (${recipientAcct}) — ${memo}` : `${recipientName} (${recipientAcct})`;
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO transfer_requests (id, user_id, email, user_name, details, amount, status, date, created_at)
      VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
    `).run(id, user.id, user.email, `${user.first_name} ${user.last_name}`, details, amount, today, now);

    res.json({ ok: true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not submit transfer request" });
  }
});

app.put("/api/me/profile", authCustomer, (req, res) => {
  try {
    const b = req.body || {};
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    const newEmail = String(b.email || user.email).trim().toLowerCase();
    if (newEmail !== user.email) {
      const taken = db.prepare("SELECT id FROM users WHERE email = ?").get(newEmail);
      if (taken) return res.status(400).json({ error: "That email is already in use" });
    }
    db.prepare(`
      UPDATE users SET first_name=?, last_name=?, email=?, phone=?, address=?, city=?, state=?, zip=?
      WHERE id=?
    `).run(
      String(b.firstName || user.first_name).trim(),
      String(b.lastName || user.last_name).trim(),
      newEmail,
      String(b.phone || user.phone).trim(),
      String(b.address || user.address).trim(),
      String(b.city || user.city).trim(),
      String(b.state || user.state).trim(),
      String(b.zip || user.zip).trim(),
      user.id
    );
    const updated = db.prepare("SELECT * FROM users WHERE id = ?").get(user.id);
    const token = jwt.sign({ role: "customer", email: updated.email, id: updated.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: publicUser(updated) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Profile update failed" });
  }
});

app.put("/api/me/password", authCustomer, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body || {};
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    if (!bcrypt.compareSync(String(currentPassword || ""), user.password_hash)) {
      return res.status(400).json({ error: "Current password is incorrect" });
    }
    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: "New password must be at least 8 characters" });
    }
    const hash = bcrypt.hashSync(String(newPassword), 10);
    db.prepare("UPDATE users SET password_hash = ? WHERE id = ?").run(hash, user.id);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Password update failed" });
  }
});

app.post("/api/me/messages", authCustomer, (req, res) => {
  try {
    const subject = String((req.body || {}).subject || "").trim();
    const body = String((req.body || {}).body || "").trim();
    if (!body) return res.status(400).json({ error: "Message required" });
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(req.user.id);
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO messages (id, email, user_id, user_name, from_role, subject, body, date, created_at, is_read)
      VALUES (?, ?, ?, ?, 'customer', ?, ?, ?, ?, 0)
    `).run(id, user.email, user.id, `${user.first_name} ${user.last_name}`, subject, body, today, now);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not send message" });
  }
});

app.get("/api/me/notifications", authCustomer, (req, res) => {
  const rows = db.prepare("SELECT id, title, body, type, is_read AS isRead, created_at AS createdAt FROM notifications WHERE user_id = ? ORDER BY created_at DESC").all(req.user.id);
  res.json({ notifications: rows });
});

app.post("/api/me/notifications/:id/read", authCustomer, (req, res) => {
  db.prepare("UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?").run(req.params.id, req.user.id);
  res.json({ ok: true });
});

app.post("/api/admin/notifications", authAdmin, (req, res) => {
  try {
    const { email, title, body } = req.body || {};
    if (!email || !title || !body) return res.status(400).json({ error: "email, title, and body required" });
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(String(email).trim().toLowerCase());
    if (!user) return res.status(404).json({ error: "Customer not found" });
    createNotification(user.id, user.email, String(title).trim(), String(body).trim(), "admin");
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Failed to send notification" });
  }
});

// ========== ADMIN ==========
app.get("/api/admin/stats", authAdmin, (req, res) => {
  const customers = db.prepare("SELECT COUNT(*) AS c FROM users").get().c;
  const deposits = db.prepare("SELECT COALESCE(SUM(balance),0) AS s FROM users").get().s;
  const pending = db.prepare("SELECT COUNT(*) AS c FROM transfer_requests WHERE status = 'pending'").get().c;
  const openMsg = db.prepare("SELECT COUNT(*) AS c FROM messages WHERE from_role = 'customer' AND is_read = 0").get().c;
  res.json({ customers, deposits, pending, openMsg });
});

app.get("/api/admin/customers", authAdmin, (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  let rows;
  if (q) {
    rows = db.prepare(`
      SELECT * FROM users WHERE
        lower(first_name || ' ' || last_name || ' ' || email || ' ' || id || ' ' || account_type) LIKE ?
      ORDER BY created_at DESC
    `).all("%" + q + "%");
  } else {
    rows = db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
  }
  res.json({ customers: rows.map(publicUser) });
});

app.get("/api/admin/customers/:email", authAdmin, (req, res) => {
  const user = db.prepare("SELECT * FROM users WHERE email = ?").get(String(req.params.email).toLowerCase());
  if (!user) return res.status(404).json({ error: "Not found" });
  const txs = db.prepare("SELECT date, description AS desc, amount, type FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 20").all(user.id);
  res.json({ user: publicUser(user), transactions: txs });
});

app.get("/api/admin/requests", authAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM transfer_requests ORDER BY created_at DESC").all();
  res.json({
    requests: rows.map(r => ({
      id: r.id,
      email: r.email,
      userId: r.user_id,
      userName: r.user_name,
      type: r.request_type || "transfer",
      details: r.details,
      amount: r.amount,
      status: r.status,
      date: r.date
    }))
  });
});

app.post("/api/admin/requests/:id/approve", authAdmin, (req, res) => {
  const r = db.prepare("SELECT * FROM transfer_requests WHERE id = ?").get(req.params.id);
  if (!r) return res.status(404).json({ error: "Request not found" });
  if (r.status !== "pending") return res.status(400).json({ error: "Already processed" });
  const user = db.prepare("SELECT * FROM users WHERE id = ?").get(r.user_id);
  if (!user) return res.status(404).json({ error: "Customer not found" });

  const today = new Date().toISOString().slice(0, 10);
  const isAddFunds = (r.request_type || "transfer") === "add_funds";

  if (isAddFunds) {
    const newBal = Math.round((user.balance + r.amount) * 100) / 100;
    const newAvail = Math.round((user.available + r.amount) * 100) / 100;
    const tx = db.transaction(() => {
      db.prepare("UPDATE users SET balance = ?, available = ? WHERE id = ?").run(newBal, newAvail, user.id);
      db.prepare("INSERT INTO transactions (user_id, date, description, amount, type) VALUES (?, ?, ?, ?, ?)").run(
        user.id, today, "Funds added — " + (r.details || "Add funds"), r.amount, "credit"
      );
      db.prepare("UPDATE transfer_requests SET status = 'approved' WHERE id = ?").run(r.id);
    });
    tx();
    createNotification(
      user.id,
      user.email,
      "Funds Added",
      `Your request to add $${r.amount.toFixed(2)} has been approved. New balance is available in your account.`,
      "credit"
    );
  } else {
    if (r.amount > user.available) return res.status(400).json({ error: "Insufficient customer balance" });
    const newBal = Math.round((user.balance - r.amount) * 100) / 100;
    const newAvail = Math.round((user.available - r.amount) * 100) / 100;
    const tx = db.transaction(() => {
      db.prepare("UPDATE users SET balance = ?, available = ? WHERE id = ?").run(newBal, newAvail, user.id);
      db.prepare("INSERT INTO transactions (user_id, date, description, amount, type) VALUES (?, ?, ?, ?, ?)").run(
        user.id, today, "Transfer approved — " + r.details, r.amount, "debit"
      );
      db.prepare("UPDATE transfer_requests SET status = 'approved' WHERE id = ?").run(r.id);
    });
    tx();
    createNotification(
      user.id,
      user.email,
      "Transfer Completed",
      `Your transfer of $${r.amount.toFixed(2)} has been approved and processed.`,
      "debit"
    );
  }
  res.json({ ok: true });
});

app.post("/api/admin/requests/:id/decline", authAdmin, (req, res) => {
  const r = db.prepare("SELECT * FROM transfer_requests WHERE id = ?").get(req.params.id);
  if (!r) return res.status(404).json({ error: "Request not found" });
  if (r.status !== "pending") return res.status(400).json({ error: "Already processed" });
  db.prepare("UPDATE transfer_requests SET status = 'declined' WHERE id = ?").run(r.id);
  res.json({ ok: true });
});

app.get("/api/admin/messages", authAdmin, (req, res) => {
  const rows = db.prepare("SELECT * FROM messages ORDER BY created_at DESC").all();
  res.json({
    messages: rows.map(m => ({
      id: m.id,
      email: m.email,
      userId: m.user_id,
      userName: m.user_name,
      from: m.from_role,
      subject: m.subject,
      body: m.body,
      date: m.date,
      createdAt: m.created_at,
      read: !!m.is_read
    }))
  });
});

app.post("/api/admin/messages/reply", authAdmin, (req, res) => {
  try {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const body = String((req.body || {}).body || "").trim();
    if (!email || !body) return res.status(400).json({ error: "Email and body required" });
    const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO messages (id, email, user_id, user_name, from_role, subject, body, date, created_at, is_read)
      VALUES (?, ?, ?, ?, 'admin', 'Re: Support', ?, ?, ?, 1)
    `).run(id, email, user ? user.id : null, user ? `${user.first_name} ${user.last_name}` : email, body, today, now);
    // mark customer messages as read
    db.prepare("UPDATE messages SET is_read = 1 WHERE email = ? AND from_role = 'customer'").run(email);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Reply failed" });
  }
});

// SPA-ish fallback for html pages
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api")) return next();
  const file = path.join(__dirname, "public", req.path === "/" ? "index.html" : req.path);
  res.sendFile(file, err => {
    if (err) res.sendFile(path.join(__dirname, "public", "index.html"));
  });
});

app.listen(PORT, () => {
  console.log(`Leads Bank running on http://localhost:${PORT}`);
});
