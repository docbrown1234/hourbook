# Hourbook

Time, expense and invoice tracking for a small hourly consulting firm.

- People log hours (or run a timer) against projects, with notes.
- Reimbursable expenses and outside-consultant bills are passed to clients with a markup.
- Monthly invoices per project: invoice PDF, time-detail PDF, and a QuickBooks Online invoice-import CSV.
- Monthly log of billable vs. cost.
- Logins: admins see everything; staff see and edit only their own time and expenses.
- Marking an invoice "invoiced" freezes its amounts and locks that project-month against edits.

## Run

Node 20+ and Postgres.

```
npm install
DATABASE_URL=postgres://user:pass@host/db npm start
```

Environment:

| Variable | Purpose |
| --- | --- |
| `DATABASE_URL` | Postgres connection string |
| `NODE_ENV` | `production` sets secure cookies and HSTS |
| `ADMIN_USERNAME` | First admin's username (default `admin`), created only when no logins exist |
| `ADMIN_SETUP_TOKEN` | One-time token for the first admin's setup link: `/setup?token=...` (valid 14 days). If unset, a link is printed to the log. |
| `DATABASE_SSL` | `true` when connecting to Postgres over a public URL that requires SSL |

Tables are created on start. Data lives in a `docs` table (one JSON document per record), plus `users` and `sessions`.

## Adding people

Setup → Logins → Add login. Each login gets a one-time setup link (7 days) where the person picks their own password. Use "Reset password" to issue a new link.
