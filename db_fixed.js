const { Pool } = require("pg");
const bcrypt = require("bcryptjs");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL && process.env.DATABASE_URL.includes("render.com")
    ? { rejectUnauthorized: false }
    : false
});

function generateRouting() {
  return Math.floor(100000000 + Math.random() * 900000000).toString();
}

function generateAccountNumber() {
  return Math.floor(1000000000 + Math.random() * 9000000000).toString();
}

async function query(text, params) {
  const res = await pool.query(text, params);
  return res;
}

async function init() {
  await query(`
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
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS transactions (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      date TEXT NOT NULL,
      description TEXT NOT NULL,
      amount REAL NOT NULL,
      type TEXT NOT NULL
    );
  `);
  await query(`
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
      created_at TEXT NOT NULL
    );
  `);
  await query(`
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
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS notifications (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      email TEXT NOT NULL,
      title TEXT NOT NULL,
      body TEXT NOT NULL,
      type TEXT DEFAULT 'info',
      is_read INTEGER DEFAULT 0,
      created_at TEXT NOT NULL
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS admins (
      id SERIAL PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS beneficiaries (
      id SERIAL PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL,
      bank TEXT,
      account TEXT,
      created_at TEXT NOT NULL
    );
  `);
  await query(`
    CREATE TABLE IF NOT EXISTS card_controls (
      user_id TEXT PRIMARY KEY,
      spend_limit REAL DEFAULT 500,
      online_tx INTEGER DEFAULT 1,
      intl_tx INTEGER DEFAULT 0,
      locked INTEGER DEFAULT 0
    );
  `);

  const admin = await query("SELECT id FROM admins WHERE username = $1", ["admin"]);
  if (!admin.rows.length) {
    const hash = bcrypt.hashSync("owner2026", 10);
    await query("INSERT INTO admins (username, password_hash) VALUES ($1, $2)", ["admin", hash]);
  }

  const demo = await query("SELECT id FROM users WHERE email = $1", ["john.kline@example.com"]);
  if (!demo.rows.length) {
    const hash = bcrypt.hashSync("demo1234", 10);
    const id = "ACC-10001";
    const today = new Date().toISOString().slice(0, 10);
    const routing = generateRouting();
    const acctNum = generateAccountNumber();
    await query(`
      INSERT INTO users (id, first_name, last_name, email, phone, address, city, state, zip, ssn_last4, password_hash, balance, available, account_type, status, routing_number, account_number, created_at)
      VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
    `, [id, "John", "Kline", "john.kline@example.com", "(555) 123-4567", "123 Main Street", "Ashburn", "VA", "20147", "4821", hash, 40000, 40000, "Checking", "active", routing, acctNum, today]);
    await query("INSERT INTO transactions (user_id, date, description, amount, type) VALUES ($1,$2,$3,$4,$5)", [id, today, "Deposit - Check", 40000, "credit"]);
  }
}

function nextAccountId() {
  return "ACC-" + (10000 + Math.floor(Math.random() * 90000));
}

module.exports = { pool, query, init, generateRouting, generateAccountNumber, nextAccountId };
