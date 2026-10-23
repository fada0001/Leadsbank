
const Database = require("better-sqlite3");
const path = require("path");
const bcrypt = require("bcryptjs");

const dbPath = process.env.DB_PATH || path.join(__dirname, "data", "leads.db");
const db = new Database(dbPath);
db.pragma("journal_mode = WAL");

function generateRouting() {
  // Simple 9-digit routing-style number (not real ABA)
  return Math.floor(100000000 + Math.random() * 900000000).toString();
}

function generateAccountNumber() {
  // 10-digit account number
  return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      first_name TEXT NOT NULL,
      last_name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      phone TEXT,
      address TEXT,
      city TEXT,
      state TEXT,
      zip TEXT,
      ssn_last4 TEXT,
      password_hash TEXT NOT NULL,
      balance REAL DEFAULT 0,
      available REAL DEFAULT 0,
      account_type TEXT DEFAULT 'Checking',
      status TEXT DEFAULT 'active',
      routing_number TEXT,
      account_number TEXT,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT NOT NULL,
      date TEXT NOT NULL,
      description TEXT NOT NULL,
      amount REAL NOT NULL,
      type TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS transfer_requests (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      email TEXT NOT NULL,
      user_name TEXT,
      request_type TEXT DEFAULT 'transfer',
      details TEXT,
      amount REAL NOT NULL,
      status TEXT DEFAULT 'pending',
      date TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL,
      user_id TEXT,
      user_name TEXT,
      from_role TEXT NOT NULL,
      subject TEXT,
      body TEXT NOT NULL,
      date TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_read INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      email TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      is_read INTEGER DEFAULT 0,
      created_at TEXT NOT NULL,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS admins (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);

  // Try to add columns if they don't exist (for existing DBs)
  try { db.exec("ALTER TABLE users ADD COLUMN routing_number TEXT"); } catch (e) {}
  try { db.exec("ALTER TABLE users ADD COLUMN account_number TEXT"); } catch (e) {}
  try { db.exec("ALTER TABLE transfer_requests ADD COLUMN request_type TEXT DEFAULT 'transfer'"); } catch (e) {}

  // Seed admin
  const admin = db.prepare("SELECT id FROM admins WHERE username = ?").get("admin");
  if (!admin) {
    const hash = bcrypt.hashSync("owner2026", 10);
    db.prepare("INSERT INTO admins (username, password_hash) VALUES (?, ?)").run("admin", hash);
  }

  // Seed demo customer with numbers
  const demo = db.prepare("SELECT id FROM users WHERE email = ?").get("john.kline@example.com");
  if (!demo) {
    const hash = bcrypt.hashSync("demo1234", 10);
    const id = "ACC-10001";
    const today = new Date().toISOString().slice(0, 10);
    const routing = generateRouting();
    const acctNum = generateAccountNumber();
    db.prepare(`
      INSERT INTO users (id, first_name, last_name, email, phone, address, city, state, zip, ssn_last4, password_hash, balance, available, account_type, status, routing_number, account_number, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(id, "John", "Kline", "john.kline@example.com", "(555) 123-4567", "123 Main Street", "Ashburn", "VA", "20147", "4821", hash, 40000, 40000, "Checking", "active", routing, acctNum, today);

    db.prepare("INSERT INTO transactions (user_id, date, description, amount, type) VALUES (?, ?, ?, ?, ?)").run(id, today, "Deposit - Check", 40000, "credit");
    db.prepare("INSERT INTO transactions (user_id, date, description, amount, type) VALUES (?, ?, ?, ?, ?)").run(id, "2026-10-20", "Opening Balance", 0, "credit");
  } else {
    // Ensure demo has numbers
    const d = db.prepare("SELECT routing_number FROM users WHERE email = ?").get("john.kline@example.com");
    if (!d.routing_number) {
      db.prepare("UPDATE users SET routing_number = ?, account_number = ? WHERE email = ?").run(generateRouting(), generateAccountNumber(), "john.kline@example.com");
    }
  }
}

function nextAccountId() {
  const row = db.prepare("SELECT COUNT(*) AS c FROM users").get();
  return "ACC-" + (10000 + (row.c || 0) + 1);
}

module.exports = { db, init, nextAccountId, generateRouting, generateAccountNumber };
