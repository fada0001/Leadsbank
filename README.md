# Leads Bank — Full Stack Practice App

Real backend (Node.js + Express) + SQLite database + web UI.

## Local run

```bash
cd leads_bank_full
npm install
npm start
```

Open http://localhost:3000

## Logins

Customer: john.kline@example.com / demo1234  
Admin: admin / owner2026

## Deploy (free options)

### Railway
1. Push this folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Add start command: `npm start`
4. Railway gives you a public URL

### Render
1. New Web Service from GitHub
2. Build: `npm install`
3. Start: `npm start`
4. Free tier available

### Environment (optional)
- PORT (default 3000)
- JWT_SECRET (change in production)
- DB_PATH (default ./data/leads.db)

## Notes
This is a practice / demonstration system only.
It is not a licensed bank and must not be used with real money or real customer data in production.
