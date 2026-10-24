const express = require("express");
const cors = require("cors");
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { query, init, nextAccountId, generateRouting, generateAccountNumber } = require("./db");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "leads-bank-practice-secret-change-in-production";

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

function uid() {
  return "ID-" + Date.now() + "-" + Math.floor(Math.random() * 10000);
}

async function createNotification(userId, email, title, body, type = "info") {
  const id = uid();
  const now = new Date().toISOString();
  await query(
    `INSERT INTO notifications (id, user_id, email, title, body, type, is_read, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, 0, $7)`,
    [id, userId, email, title, body, type, now]
  );
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
app.post("/api/register", async (req, res) => {
  try {
    const b = req.body || {};
    const required = ["firstName", "lastName", "email", "phone", "address", "city", "state", "zip", "ssnLast4", "password", "accountType"];
    for (const k of required) {
      if (!b[k] || String(b[k]).trim() === "") return res.status(400).json({ error: `Missing ${k}` });
    }
    if (String(b.password).length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    const email = String(b.email).trim().toLowerCase();
    const exists = await query("SELECT id FROM users WHERE email = $1", [email]);
    if (exists.rows.length) return res.status(400).json({ error: "An account with this email already exists" });

    const id = nextAccountId();
    const hash = bcrypt.hashSync(String(b.password), 10);
    const today = new Date().toISOString().slice(0, 10);
    const routing = generateRouting();
    const acctNum = generateAccountNumber();

    await query(`
      INSERT INTO users (id, first_name, last_name, email, phone, address, city, state, zip, ssn_last4, password_hash, balance, available, account_type, status, routing_number, account_number, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,0,0,$12,'active',$13,$14,$15)
    `, [
      id, String(b.firstName).trim(), String(b.lastName).trim(), email,
      String(b.phone).trim(), String(b.address).trim(), String(b.city).trim(),
      String(b.state).trim(), String(b.zip).trim(), String(b.ssnLast4).trim(),
      hash, String(b.accountType).trim(), routing, acctNum, today
    ]);

    await query("INSERT INTO transactions (user_id, date, description, amount, type) VALUES ($1,$2,$3,$4,$5)",
      [id, today, "Account Opened", 0, "credit"]);

    await createNotification(id, email, "Account Opened Successfully",
      `Welcome to Leads Bank! Your account has been created. Account Number: ${acctNum}, Routing: ${routing}.`, "registration");

    const userRes = await query("SELECT * FROM users WHERE id = $1", [id]);
    const user = userRes.rows[0];
    const token = jwt.sign({ role: "customer", email: user.email, id: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token, user: publicUser(user) });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Registration failed" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const password = String((req.body || {}).password || "");
    const r = await query("SELECT * FROM users WHERE email = $1", [email]);
    const user = r.rows[0];
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

app.post("/api/admin/login", async (req, res) => {
  try {
    const username = String((req.body || {}).username || "").trim();
    const password = String((req.body || {}).password || "");
    const r = await query("SELECT * FROM admins WHERE username = $1", [username]);
    const admin = r.rows[0];
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
app.get("/api/me", authCustomer, async (req, res) => {
  const r = await query("SELECT * FROM users WHERE email = $1", [req.user.email]);
  const user = r.rows[0];
  if (!user) return res.status(404).json({ error: "User not found" });
  res.json({ user: publicUser(user) });
});

app.get("/api/me/transactions", authCustomer, async (req, res) => {
  const r = await query("SELECT date, description AS desc, amount, type FROM transactions WHERE user_id = $1 ORDER BY id ASC", [req.user.id]);
  res.json({ transactions: r.rows });
});

app.get("/api/me/requests", authCustomer, async (req, res) => {
  const r = await query("SELECT id, request_type AS type, details, amount, status, date FROM transfer_requests WHERE email = $1 ORDER BY created_at DESC", [req.user.email]);
  res.json({ requests: r.rows });
});

app.post("/api/me/add-funds-request", authCustomer, async (req, res) => {
  try {
    const amount = parseFloat((req.body || {}).amount);
    const memo = String((req.body || {}).memo || "Add funds request").trim();
    if (!(amount > 0)) return res.status(400).json({ error: "Invalid amount" });
    const ur = await query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const user = ur.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    await query(`
      INSERT INTO transfer_requests (id, user_id, email, user_name, request_type, details, amount, status, date, created_at)
      VALUES ($1,$2,$3,$4,'add_funds',$5,$6,'pending',$7,$8)
    `, [id, user.id, user.email, `${user.first_name} ${user.last_name}`, memo, amount, today, now]);
    res.json({ ok: true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not submit add funds request" });
  }
});

app.post("/api/me/transfer-request", authCustomer, async (req, res) => {
  try {
    const amount = parseFloat((req.body || {}).amount);
    const recipientName = String((req.body || {}).recipientName || "").trim();
    const recipientAccount = String((req.body || {}).recipientAccount || "").trim();
    const memo = String((req.body || {}).memo || "").trim();
    if (!(amount > 0)) return res.status(400).json({ error: "Invalid amount" });
    if (!recipientName || !recipientAccount) return res.status(400).json({ error: "Recipient required" });
    const ur = await query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const user = ur.rows[0];
    if (!user) return res.status(404).json({ error: "User not found" });
    if (amount > user.available) return res.status(400).json({ error: "Insufficient available balance" });
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    const details = `${recipientName} · ${recipientAccount}${memo ? " · " + memo : ""}`;
    await query(`
      INSERT INTO transfer_requests (id, user_id, email, user_name, request_type, details, amount, status, date, created_at)
      VALUES ($1,$2,$3,$4,'transfer',$5,$6,'pending',$7,$8)
    `, [id, user.id, user.email, `${user.first_name} ${user.last_name}`, details, amount, today, now]);
    res.json({ ok: true, id });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not submit transfer" });
  }
});

app.get("/api/me/messages", authCustomer, async (req, res) => {
  const r = await query("SELECT id, from_role AS from, subject, body, date, is_read AS isRead FROM messages WHERE email = $1 ORDER BY created_at ASC", [req.user.email]);
  res.json({ messages: r.rows });
});

app.post("/api/me/messages", authCustomer, async (req, res) => {
  try {
    const subject = String((req.body || {}).subject || "").trim();
    const body = String((req.body || {}).body || "").trim();
    if (!body) return res.status(400).json({ error: "Message required" });
    const ur = await query("SELECT * FROM users WHERE id = $1", [req.user.id]);
    const user = ur.rows[0];
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    await query(`
      INSERT INTO messages (id, email, user_id, user_name, from_role, subject, body, date, created_at, is_read)
      VALUES ($1,$2,$3,$4,'customer',$5,$6,$7,$8,0)
    `, [id, user.email, user.id, `${user.first_name} ${user.last_name}`, subject, body, today, now]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not send message" });
  }
});

app.get("/api/me/notifications", authCustomer, async (req, res) => {
  const r = await query("SELECT id, title, body, type, is_read AS isRead, created_at AS createdAt FROM notifications WHERE user_id = $1 ORDER BY created_at DESC", [req.user.id]);
  res.json({ notifications: r.rows });
});

app.post("/api/me/notifications/:id/read", authCustomer, async (req, res) => {
  await query("UPDATE notifications SET is_read = 1 WHERE id = $1 AND user_id = $2", [req.params.id, req.user.id]);
  res.json({ ok: true });
});

// ========== ADMIN ==========
app.get("/api/admin/stats", authAdmin, async (req, res) => {
  const customers = (await query("SELECT COUNT(*) AS c FROM users")).rows[0].c;
  const deposits = (await query("SELECT COALESCE(SUM(balance),0) AS s FROM users")).rows[0].s;
  const pending = (await query("SELECT COUNT(*) AS c FROM transfer_requests WHERE status = 'pending'")).rows[0].c;
  const openMsg = (await query("SELECT COUNT(*) AS c FROM messages WHERE from_role = 'customer' AND is_read = 0")).rows[0].c;
  res.json({ customers: Number(customers), deposits: Number(deposits), pending: Number(pending), openMessages: Number(openMsg) });
});

app.get("/api/admin/customers", authAdmin, async (req, res) => {
  const r = await query("SELECT * FROM users ORDER BY created_at DESC");
  res.json({ customers: r.rows.map(publicUser) });
});

app.get("/api/admin/customers/:email", authAdmin, async (req, res) => {
  const ur = await query("SELECT * FROM users WHERE email = $1", [String(req.params.email).toLowerCase()]);
  const user = ur.rows[0];
  if (!user) return res.status(404).json({ error: "Not found" });
  const txs = (await query("SELECT date, description AS desc, amount, type FROM transactions WHERE user_id = $1 ORDER BY id DESC LIMIT 20", [user.id])).rows;
  res.json({ user: publicUser(user), transactions: txs });
});

app.get("/api/admin/requests", authAdmin, async (req, res) => {
  const r = await query("SELECT * FROM transfer_requests ORDER BY created_at DESC");
  res.json({ requests: r.rows });
});

app.post("/api/admin/requests/:id/approve", authAdmin, async (req, res) => {
  try {
    const rr = await query("SELECT * FROM transfer_requests WHERE id = $1", [req.params.id]);
    const r = rr.rows[0];
    if (!r || r.status !== "pending") return res.status(400).json({ error: "Not pending" });
    const ur = await query("SELECT * FROM users WHERE id = $1", [r.user_id]);
    const user = ur.rows[0];
    if (!user) return res.status(404).json({ error: "User missing" });
    const today = new Date().toISOString().slice(0, 10);
    if (r.request_type === "add_funds") {
      await query("UPDATE users SET balance = balance + $1, available = available + $1 WHERE id = $2", [r.amount, user.id]);
      await query("INSERT INTO transactions (user_id, date, description, amount, type) VALUES ($1,$2,$3,$4,$5)",
        [user.id, today, "Add Funds Approved", r.amount, "credit"]);
    } else {
      if (r.amount > user.available) return res.status(400).json({ error: "Insufficient funds" });
      await query("UPDATE users SET balance = balance - $1, available = available - $1 WHERE id = $2", [r.amount, user.id]);
      await query("INSERT INTO transactions (user_id, date, description, amount, type) VALUES ($1,$2,$3,$4,$5)",
        [user.id, today, "Transfer Approved", r.amount, "debit"]);
    }
    await query("UPDATE transfer_requests SET status = 'approved' WHERE id = $1", [r.id]);
    await createNotification(user.id, user.email, "Request Approved",
      `Your ${r.request_type === "add_funds" ? "add funds" : "transfer"} request of $${r.amount} was approved.`, "credit");
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Approve failed" });
  }
});

app.post("/api/admin/requests/:id/decline", authAdmin, async (req, res) => {
  try {
    const rr = await query("SELECT * FROM transfer_requests WHERE id = $1", [req.params.id]);
    const r = rr.rows[0];
    if (!r || r.status !== "pending") return res.status(400).json({ error: "Not pending" });
    await query("UPDATE transfer_requests SET status = 'declined' WHERE id = $1", [r.id]);
    const ur = await query("SELECT * FROM users WHERE id = $1", [r.user_id]);
    const user = ur.rows[0];
    if (user) {
      await createNotification(user.id, user.email, "Request Declined",
        `Your ${r.request_type === "add_funds" ? "add funds" : "transfer"} request of $${r.amount} was declined.`, "debit");
    }
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Decline failed" });
  }
});

app.get("/api/admin/messages", authAdmin, async (req, res) => {
  const r = await query("SELECT * FROM messages ORDER BY created_at DESC");
  res.json({ messages: r.rows });
});

app.post("/api/admin/messages", authAdmin, async (req, res) => {
  try {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const body = String((req.body || {}).body || "").trim();
    const subject = String((req.body || {}).subject || "Reply from Leads Bank").trim();
    if (!email || !body) return res.status(400).json({ error: "Email and message required" });
    const id = uid();
    const today = new Date().toISOString().slice(0, 10);
    const now = new Date().toISOString();
    await query(`
      INSERT INTO messages (id, email, user_id, user_name, from_role, subject, body, date, created_at, is_read)
      VALUES ($1,$2,NULL,'Leads Bank','admin',$3,$4,$5,$6,0)
    `, [id, email, subject, body, today, now]);
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not send reply" });
  }
});

app.post("/api/admin/notifications", authAdmin, async (req, res) => {
  try {
    const email = String((req.body || {}).email || "").trim().toLowerCase();
    const title = String((req.body || {}).title || "").trim();
    const body = String((req.body || {}).body || "").trim();
    if (!email || !title || !body) return res.status(400).json({ error: "Email, title, and message required" });
    const ur = await query("SELECT * FROM users WHERE email = $1", [email]);
    const user = ur.rows[0];
    if (!user) return res.status(404).json({ error: "Customer not found" });
    await createNotification(user.id, user.email, title, body, "info");
    res.json({ ok: true });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: "Could not send notification" });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

init().then(() => {
  app.listen(PORT, () => console.log("Leads Bank running on port " + PORT));
}).catch(err => {
  console.error("Failed to init database:", err);
  process.exit(1);
});
