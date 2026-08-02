# PayCST backend (item #15)

A real MySQL + Express backend, separate from the Flutter demo app. It exists
because "make it more secure" isn't something that can happen inside a
client-only Dart file that keeps everyone's data in RAM — real security needs
a server that owns the database, hashes credentials, and is the only thing
that can move money.

## What it actually does differently from the Flutter demo

- Passwords and PINs are hashed with **bcrypt** (10 rounds) and only ever
  compared with `bcrypt.compare` — never stored, logged, or compared as
  plaintext.
- Every SQL query uses `?` placeholders (`mysql2`'s parameterized queries),
  so user input can never be concatenated into SQL — this is what actually
  prevents SQL injection, not "using MySQL" by itself.
- Login is enforced server-side as two real steps: `/api/login` (password)
  returns a **short-lived, limited-purpose** token that only
  `/api/login/verify-pin` will accept — no endpoint that touches money will
  accept that token, only the full token issued after the PIN check.
- Money-moving endpoints (`/api/wallet/pay`, group contribute, admin
  approve) run inside a SQL transaction with row locks (`FOR UPDATE`), so
  two requests can't race each other into an inconsistent balance — and
  because the balance now lives in MySQL instead of a Dart Map, multiple
  devices hitting this same server *do* see the same numbers (this is also
  the real fix for item #7 — the group balance only "connects across
  devices" once there's a shared server like this one).
- The 6-member group cap is enforced with a row-locked count check inside a
  transaction, so two people can't both squeeze into the last slot at once.
- Admin has a separate login, a separate `admins` table, and its own
  endpoints to view every group's members, remove a member, and approve or
  decline a support request (item #13).

## Setup

```bash
cd backend
cp .env.example .env    # fill in your MySQL credentials + a random JWT_SECRET
npm install
mysql -u root -p < sql/schema.sql
npm run create-admin -- youradminname a-strong-password
npm start
```

The server listens on `http://localhost:3000` (or `PORT` from `.env`).

## What's NOT included yet

This covers the security-critical slice: registration, two-step login,
wallet-to-wallet payment, groups (create/join/contribute), and admin
oversight. It does not yet have endpoints for Load/Bills/withdraw-to-self —
those follow the exact same pattern (parameterized query + `FOR UPDATE` +
transaction) and can be added the same way if you want the full feature set
moved over.

## Connecting the Flutter app to this

Right now the Flutter app in `main.dart` still uses its own in-memory
`BankState` and doesn't call this server at all — wiring them together means
replacing `BankState`'s methods with `http` calls to these endpoints and
storing the JWT instead of a local `currentUser` object. That's a distinct
chunk of work (the `http` package, error handling for network calls, etc.) —
say the word and I'll do that pass next.
