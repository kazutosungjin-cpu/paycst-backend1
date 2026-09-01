// PayCST backend — MySQL + Express.
//
// What this replaces from the Flutter demo (item #15): the demo app keeps
// every username, password, PIN, and balance in a plain Dart Map that
// lives only in the app's RAM. Here, credentials are salted+hashed with
// bcrypt (never stored or compared as plaintext), every query is
// parameterized (no SQL injection surface), and login is enforced as two
// real steps — password, then a separately-verified PIN — before a usable
// session token is issued (items #1 / #11).
//
// This file intentionally covers the security-relevant slice (auth, PIN,
// wallet-to-wallet payment, groups with the 6-member cap, and admin
// oversight) rather than reimplementing every screen (bills/load/etc.) —
// those follow the exact same parameterized-query + hashed-auth pattern,
// so ask if you'd like them added too.

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const { rateLimit, ipKeyGenerator } = require('express-rate-limit');
const { mergeSort, comparators } = require('./mergeSort');
const { Stack } = require('./stack');
const { Queue } = require('./queue');

// ---------- pending-loan queue (FIFO — item: mandatory "Queue") ----------
const loanQueue = new Queue();

async function loadLoanQueueFromDatabase() {
  const [rows] = await pool.query(
    "SELECT id AS loanId, user_id AS userId FROM loans WHERE status = 'pending' ORDER BY created_at ASC"
  );
  loanQueue.items = []; // reset before rebuilding
  for (const row of rows) {
    loanQueue.enqueue(row);
  }
  console.log(`Loaded ${rows.length} pending loans into queue`);
}

const { DoublyLinkedList } = require('./dll');

// ---------- account doubly linked list (item: mandatory "Doubly Linked List") ----------
const accountList = new DoublyLinkedList();

async function loadAccountListFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users ORDER BY id ASC');
  accountList.clear();
  for (const row of rows) {
    accountList.insert(row.id, row);
  }
  console.log(`Loaded ${rows.length} accounts into doubly linked list`);
}

const { AVLTree } = require('./avl');

// ---------- wallet-ID AVL tree (item: mandatory "AVL Tree") ----------
const walletAvl = new AVLTree();

async function loadWalletAvlFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users');
  walletAvl.clear();
  for (const row of rows) {
    walletAvl.insert(row.wallet_id, row);
  }
  console.log(`Loaded ${rows.length} accounts into AVL tree (height: ${walletAvl.height()})`);
}

// ---------- per-user undo stacks (LIFO — item: mandatory "Stack") ----------
const undoStacks = new Map(); // userId -> Stack of transferRefs

function getUndoStack(userId) {
  if (!undoStacks.has(userId)) undoStacks.set(userId, new Stack());
  return undoStacks.get(userId);
}
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const pool = require('./db');
const { PROVIDERS, findCheapestRoute } = require('./graph');
process.on('unhandledRejection', (reason) => {
  console.error('Unhandled rejection (server stayed up):', reason);
});

process.on('uncaughtException', (err) => {
  console.error('Uncaught exception (server stayed up):', err);
});

const app = express();

// Railway (like most hosting platforms) puts the app behind a reverse
// proxy, so the real client IP arrives via the X-Forwarded-For header
// rather than the raw socket address. Without this, Express's req.ip
// (which express-rate-limit keys on) can't be trusted, and rate limiting
// silently fails to count attempts correctly per visitor.
app.set('trust proxy', 1);

// ---------- security middleware ----------
// helmet sets a batch of standard protective HTTP response headers
// (clickjacking protection, MIME-sniffing prevention, etc.) with sane
// defaults for an API-only server.
app.use(helmet());

// CORS is restricted to the actual deployed frontend origin — previously
// wide open (any website could call this API from a visitor's browser).
app.use(cors({
  origin: ['https://paycst11.netlify.app', 'http://localhost:12194'],
}));

app.use(express.json());

// Rate limiting on the endpoints most worth protecting against
// brute-force/credential-stuffing. A 4-digit PIN only has 10,000 possible
// values.
//
// Keyed by USERNAME rather than IP: Railway's multi-hop edge network can
// present a different X-Forwarded-For chain length per request, which
// makes req.ip unreliable even with `trust proxy` set — the same client
// can appear to come from a different "IP" on consecutive requests,
// silently defeating IP-based limiting. Username is a fixed, real value
// tied to the account under attack, so it can't be dodged by an attacker
// rotating source IPs — if anything this is the stronger defense for
// credential-stuffing specifically. Falls back to req.ip only when no
// username is present in the body (shouldn't normally happen on these
// routes, but keeps behavior sane rather than throwing).
function authKeyGenerator(req) {
  const username = req.body?.username?.toString().trim().toLowerCase();
  return username || ipKeyGenerator(req);
}

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per username per window
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authKeyGenerator,
  message: { error: 'Too many attempts. Please try again later.' },
});

// verify-pin doesn't carry a username in its body (it identifies the user
// via the pendingToken instead), so it needs its own keyGenerator that
// pulls the uid out of that token — otherwise every pending login in the
// last 5 minutes would fall back to the same req.ip bucket regardless of
// which account is actually being verified.
const pinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    const payload = req.body?.pendingToken && verify(req.body.pendingToken);
    return payload?.uid ? `pin:${payload.uid}` : ipKeyGenerator(req);
  },
  message: { error: 'Too many attempts. Please try again later.' },
});

const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: authKeyGenerator,
  message: { error: 'Too many attempts. Please try again later.' },
});

const JWT_SECRET = process.env.JWT_SECRET;
const MAX_GROUP_MEMBERS = 6;
const MAX_CENTAVOS = 100_000_000_00; // ₱100,000,000.00 — sanity ceiling, adjust as you like

// ---------- in-memory indexes (item #6 fix) ----------
// NOT the source of truth — MySQL is. These are fast lookup caches built
// from the database at startup and kept in sync after every commit that
// touches a user row. Safe to discard and rebuild at any time via
// loadIndexesFromDatabase().
const usersByUsername = new Map(); // username -> user row
const usersByWalletId = new Map(); // wallet_id -> user row 
async function loadIndexesFromDatabase() {
  const [rows] = await pool.query('SELECT * FROM users');
  usersByUsername.clear();
  usersByWalletId.clear();
  for (const row of rows) {
    usersByUsername.set(row.username, row);
    usersByWalletId.set(row.wallet_id, row);
  }
  console.log(`Loaded ${rows.length} users into hash map indexes`);
}

async function refreshUserInIndex(userId) {
  const [[row]] = await pool.query('SELECT * FROM users WHERE id = ?', [userId]);
  if (!row) {
    // User was deleted — grab the wallet_id from what we still have
    // cached (the DB row is already gone) so we can clean up the AVL
    // tree too, then remove from both structures.
    const oldNode = accountList.nodesByKey.get(userId);
    if (oldNode) {
      walletAvl.delete(oldNode.data.wallet_id);
      accountList.delete(userId);
    }
    return;
  }

  usersByUsername.set(row.username, row);
  usersByWalletId.set(row.wallet_id, row);

  if (accountList.nodesByKey.has(userId)) {
    accountList.update(userId, row);
  } else {
    accountList.insert(userId, row);
  }

  // item: mandatory "AVL Tree" — insert on first sight, update
  // thereafter (insert() handles both cases). Keyed by wallet_id, which
  // never changes once assigned, so this is safe to call every time.
  walletAvl.insert(row.wallet_id, row);
}

// ---------- money handling: integer centavos everywhere (item #1 fix) ----------
//
// Every peso amount that touches the database, an API request/response
// body, or in-process arithmetic is now a plain INTEGER count of centavos
// (₱1.00 == 100 centavos, so ₱150.50 == 15050). Previously amounts were
// JS `Number`s backed by MySQL `DECIMAL` columns — both are float-adjacent
// representations, and repeated add/subtract (payments, contributions,
// loan repayments) can silently drift a centavo here and there over time,
// or accept "amounts" like 10.005 that don't correspond to real money.
// Integers don't have that failure mode.
//
// CLIENT CONTRACT CHANGE: the Flutter app must send and expect every
// amount field as an integer number of centavos, not a decimal like
// 150.50 — send 15050 instead, and divide by 100 only when *displaying*
// a value to the user. See the migration note at the bottom of this file
// for the required DB column changes (DECIMAL -> INT).

// Validates an amount coming FROM a client request. Only accepts a
// strictly positive integer (fractional centavos aren't a real unit).
// Returns null (not a thrown error) on anything invalid so callers can
// respond with a normal 400.
function parseCentavos(value) {
  const n = typeof value === 'string' ? Number(value) : value;
  if (typeof n !== 'number' || !Number.isFinite(n)) return null;
  if (!Number.isInteger(n)) return null;
  if (n <= 0) return null;
  if (n > MAX_CENTAVOS) return null;
  return n;
}

// Normalizes a value coming FROM the database. mysql2 returns some large
// integer column types as strings rather than JS numbers, so every stored
// balance/amount is passed through this before arithmetic or comparisons.
function toCentavos(dbValue) {
  const n = typeof dbValue === 'string' ? parseInt(dbValue, 10) : dbValue;
  return Number.isSafeInteger(n) ? n : 0;
}

// Only for building human-readable error/display strings — never for
// storage or arithmetic.
function centavosToPesosLabel(centavos) {
  return (centavos / 100).toFixed(2);
}

function sign(payload, expiresIn) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

function verify(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Wraps an async Express route handler so any rejected promise (a thrown
// error, a failed query, a missing table, etc.) is forwarded to
// Express's error-handling middleware via next(err) instead of being
// silently swallowed as an "unhandled rejection" — which previously left
// the client hanging forever with no response at all.
function asyncRoute(handler) {
  return (req, res, next) => {
    Promise.resolve(handler(req, res, next)).catch(next);
  };
}

// Requires a FULL session token (password + PIN both verified).
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verify(token);
  if (!payload || payload.stage !== 'full' || payload.role !== 'user') {
    return res.status(401).json({ error: 'Not authenticated' });
  }
  req.userId = payload.uid;
  next();
}

function requireAdmin(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  const payload = token && verify(token);
  if (!payload || payload.role !== 'admin') {
    return res.status(401).json({ error: 'Not authenticated as admin' });
  }
  req.adminId = payload.uid;
  next();
}

function nextWalletId() {
  const n = Math.floor(100000 + Math.random() * 900000);
  return `PCST-${n}`;
}

// ---------- database-backed login lockout ----------
//
// Complements (doesn't replace) the in-memory express-rate-limit above.
// That limiter resets on every restart/redeploy — fine as a first line of
// defense, but not durable. This is the real enforcement: it persists in
// MySQL, so a restart can't reset an attacker's attempt count back to
// zero. Mirrors the "3 attempts then a cooldown" behavior the Flutter
// UI already implies client-side, except enforced here on the server so
// it can't be bypassed by calling the API directly (as our own curl
// testing demonstrated the client-side version could be).
const MAX_LOGIN_ATTEMPTS = 3;
const LOCKOUT_MS = 30 * 1000; // 30 seconds

// Returns null if not locked, or the number of seconds remaining if it is.
async function checkLockout(identifier) {
  const [[{ count }]] = await pool.query(
    'SELECT COUNT(*) AS count FROM login_attempts WHERE identifier = ? AND attempted_at > (NOW() - INTERVAL ? SECOND)',
    [identifier, LOCKOUT_MS / 1000]
  );
  if (count < MAX_LOGIN_ATTEMPTS) return null;

  const [[oldest]] = await pool.query(
    'SELECT attempted_at FROM login_attempts WHERE identifier = ? ORDER BY attempted_at DESC LIMIT 1 OFFSET ?',
    [identifier, MAX_LOGIN_ATTEMPTS - 1]
  );
  const unlockAt = new Date(oldest.attempted_at).getTime() + LOCKOUT_MS;
  const secondsLeft = Math.max(1, Math.ceil((unlockAt - Date.now()) / 1000));
  return secondsLeft;
}

async function recordFailedAttempt(identifier) {
  await pool.execute('INSERT INTO login_attempts (identifier) VALUES (?)', [identifier]);
}

async function clearAttempts(identifier) {
  await pool.execute('DELETE FROM login_attempts WHERE identifier = ?', [identifier]);
}

// ---------- registration / login (password, THEN pin) ----------

app.post('/api/register', authLimiter, asyncRoute(async (req, res) => {
  const { username, password, pin, phoneNumber } = req.body || {};
  if (!username || !password || !pin || !phoneNumber) {
    return res.status(400).json({ error: 'username, password, pin, and phoneNumber are required' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });
  if (!/^09\d{9}$/.test(phoneNumber)) {
    return res.status(400).json({ error: 'Phone number must be 11 digits starting with 09 (e.g. 09171234567)' });
  }

  const conn = await pool.getConnection();
  try {
    // Hash map check first (fast path) — DB check right after is still the
    // real source of truth for uniqueness, since two requests could race
    // between these two checks.
    if (usersByUsername.has(username)) {
      return res.status(409).json({ error: 'That username is already taken' });
    }
    const [existing] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (existing.length > 0) return res.status(409).json({ error: 'That username is already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);

    let walletId = nextWalletId();
    for (let i = 0; i < 5; i++) {
      const [clash] = await conn.execute('SELECT id FROM users WHERE wallet_id = ?', [walletId]);
      if (clash.length === 0) break;
      walletId = nextWalletId();
    }

    const [result] = await conn.execute(
      'INSERT INTO users (username, password_hash, pin_hash, wallet_id, balance, phone_number) VALUES (?, ?, ?, ?, ?, ?)',
      [username, passwordHash, pinHash, walletId, 0, phoneNumber]
    );

    // Row is committed to MySQL — now safe to add it to the index.
    await refreshUserInIndex(result.insertId);

    res.json({ ok: true, walletId });
  } finally {
    conn.release();
  }
}));

// Step 1: password only. Returns a short-lived "pending" token that is
// NOT enough to call any authenticated endpoint — it only unlocks the
// pin-verify step below.
app.post('/api/login', authLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

  const identifier = `login:${username.toString().trim().toLowerCase()}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, password_hash FROM users WHERE username = ?', [username]);
  const user = rows[0];
  const ok = user && (await bcrypt.compare(password, user.password_hash));
  if (!ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect username or password' });
  }
  await clearAttempts(identifier);

  const pendingToken = sign({ uid: user.id, stage: 'pending', role: 'user' }, '5m');
  res.json({ pendingToken });
}));

// Step 2: the PIN, checked separately from the password. Only after this
// succeeds does the client get a token any other endpoint will accept.
app.post('/api/login/verify-pin', pinLimiter, asyncRoute(async (req, res) => {
  const { pendingToken, pin } = req.body || {};
  const payload = pendingToken && verify(pendingToken);
  if (!payload || payload.stage !== 'pending' || payload.role !== 'user') {
    return res.status(401).json({ error: 'Login session expired, please log in again' });
  }

  const identifier = `pin:${payload.uid}`;
  const lockedForSeconds = await checkLockout(identifier);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, username, wallet_id, pin_hash, balance FROM users WHERE id = ?', [
    payload.uid,
  ]);
  const user = rows[0];
  const ok = user && (await bcrypt.compare(pin, user.pin_hash));
  if (!ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect PIN' });
  }
  await clearAttempts(identifier);

  const token = sign({ uid: user.id, stage: 'full', role: 'user' }, '12h');
  res.json({
    token,
    // balance is returned as an integer count of centavos — the client
    // divides by 100 only when displaying it.
    user: { id: user.id, username: user.username, walletId: user.wallet_id, balance: toCentavos(user.balance) },
  });
}));

app.get('/api/me', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute('SELECT id, username, wallet_id, balance FROM users WHERE id = ?', [req.userId]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  const u = rows[0];
  res.json({ id: u.id, username: u.username, wallet_id: u.wallet_id, balance: toCentavos(u.balance) });
}));

// ---------- wallet-to-wallet (QR) payment ----------

app.post('/api/wallet/pay', requireAuth, asyncRoute(async (req, res) => {
  const { walletId, amountCentavos } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  if (!walletId || amt === null) {
    return res.status(400).json({ error: 'walletId and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[sender]] = await conn.query('SELECT id, balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const [[recipient]] = await conn.query('SELECT id, username, balance FROM users WHERE wallet_id = ? FOR UPDATE', [
      walletId,
    ]);

    if (!recipient) {
      await conn.rollback();
      return res.status(404).json({ error: 'No account found for that Wallet ID' });
    }
    if (recipient.id === sender.id) {
      await conn.rollback();
      return res.status(400).json({ error: "You can't pay your own Wallet ID" });
    }

    const senderBalance = toCentavos(sender.balance);
    if (senderBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const transferRef = crypto.randomUUID();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, sender.id]);
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipient.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', sender.id, `QR Payment to ${recipient.username}`, 'QR Payment', amt, 0, transferRef]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', recipient.id, `QR Payment from user #${sender.id}`, 'QR Payment', amt, 1, transferRef]
    );

    await conn.commit();

    // Row is committed — now safe to refresh both cached users so the
    // hash-map indexes don't serve a stale balance (item #6 fix).
    await Promise.all([
      refreshUserInIndex(sender.id),
      refreshUserInIndex(recipient.id),
    ]);

    getUndoStack(sender.id).push(transferRef); // NEW — item: mandatory "Stack"

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- personal-account actions (restored) ----------

app.get('/api/notifications', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT id, label AS title, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'user' AND account_id = ?
     ORDER BY created_at DESC
     LIMIT 20`,
    [req.userId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.post('/api/send', requireAuth, asyncRoute(async (req, res) => {
  const recipient = req.body?.recipient?.toString().trim();
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!recipient || amt === null) {
    return res.status(400).json({ error: 'recipient and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[sender]] = await conn.query('SELECT id, balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const [[recipientUser]] = await conn.query('SELECT id, username, balance FROM users WHERE wallet_id = ? FOR UPDATE', [
      recipient,
    ]);

    // ---- unchanged ----
    if (!recipientUser) {
      await conn.rollback();
      return res.status(404).json({ error: 'No account found for that Wallet ID' });
    }
    if (recipientUser.id === sender.id) {
      await conn.rollback();
      return res.status(400).json({ error: "You can't send money to your own Wallet ID" });
    }

    const senderBalance = toCentavos(sender.balance);
    if (senderBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    // ---- end unchanged ----

    const transferRef = crypto.randomUUID();
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, sender.id]);
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipientUser.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', sender.id, `Sent to ${recipientUser.username}`, 'Send Money', amt, 0, transferRef]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref) VALUES (?,?,?,?,?,?,?)',
      ['user', recipientUser.id, `Received from user #${sender.id}`, 'Send Money', amt, 1, transferRef]
    );

    await conn.commit();

    // <-- NEW: only line added to this whole route
    await Promise.all([
      refreshUserInIndex(sender.id),
      refreshUserInIndex(recipientUser.id),
    ]);

    getUndoStack(sender.id).push(transferRef); // NEW — item: mandatory "Stack"

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/load', requireAuth, asyncRoute(async (req, res) => {
  const { number, network } = req.body || {};
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!number || !network || amt === null) {
    return res.status(400).json({ error: 'number, network, and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[user]] = await conn.query('SELECT id, balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const userBalance = toCentavos(user.balance);
    if (userBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

     await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Mobile Load to ${number}`, 'Load', amt, 0]
    );

    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/bills/pay', requireAuth, asyncRoute(async (req, res) => {
  const biller = req.body?.biller?.toString().trim();
  const amt = parseCentavos(req.body?.amountCentavos);
  if (!biller || amt === null) {
    return res.status(400).json({ error: 'biller and a positive amount (integer centavos) are required' });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[user]] = await conn.query('SELECT id, balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    const userBalance = toCentavos(user.balance);
    if (userBalance < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Bill Pay to ${biller}`, 'Bill Payment', amt, 0]
    );

    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/transactions', requireAuth, asyncRoute(async (req, res) => {
  const [[me]] = await pool.query('SELECT username FROM users WHERE id = ?', [req.userId]);
  const [groupRows] = await pool.execute(
    'SELECT g.id, g.name FROM group_members gm JOIN `groups` g ON g.id = gm.group_id WHERE gm.user_id = ?',
    [req.userId]
  );
  const groupNameById = Object.fromEntries(groupRows.map((g) => [g.id, g.name]));
  const groupIds = groupRows.map((g) => g.id);

  let rows;
  if (groupIds.length > 0) {
    const placeholders = groupIds.map(() => '?').join(',');
    const [result] = await pool.query(
      `SELECT id, account_type, account_id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
       FROM transactions
       WHERE (account_type = 'user' AND account_id = ?)
          OR (account_type = 'group' AND account_id IN (${placeholders}))`,
      [req.userId, ...groupIds]
    );
    rows = result;
  } else {
    const [result] = await pool.execute(
      `SELECT id, account_type, account_id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
       FROM transactions WHERE account_type = 'user' AND account_id = ?`,
      [req.userId]
    );
    rows = result;
  }

  const normalized = rows.map((row) => ({
    ...row,
    amount: toCentavos(row.amount),
    accountName: row.account_type === 'user' ? me.username : groupNameById[row.account_id] || 'Group',
  }));

  const sorted = mergeSort(normalized, comparators.dateDesc);

  res.json(sorted);
}));

app.get('/api/groups/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     JOIN group_members gm ON gm.group_id = g.id
     WHERE gm.user_id = ?`,
    [req.userId]
  );
  res.json(rows.map((g) => ({ ...g, balance: toCentavos(g.balance) })));
}));

app.get('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     ORDER BY g.name ASC`
  );
  res.json(rows.map((g) => ({ ...g, balance: toCentavos(g.balance) })));
}));

app.get('/api/groups/:id', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId)) {
    return res.status(400).json({ error: 'Invalid group ID' });
  }
  const [[group]] = await pool.query('SELECT id, name, balance FROM `groups` WHERE id = ?', [groupId]);
  if (!group) return res.status(404).json({ error: 'Group not found' });
  const [members] = await pool.execute(
    `SELECT u.id, u.username, u.wallet_id AS walletId
     FROM group_members gm JOIN users u ON u.id = gm.user_id
     WHERE gm.group_id = ?`,
    [groupId]
  );
  res.json({ id: group.id, name: group.name, balance: toCentavos(group.balance), members });
}));

app.get('/api/groups/:id/transactions', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  if (!Number.isInteger(groupId)) {
    return res.status(400).json({ error: 'Invalid group ID' });
  }
  const [rows] = await pool.execute(
    `SELECT id, label, type, amount, is_credit AS isCredit, created_at AS createdAt
     FROM transactions
     WHERE account_type = 'group' AND account_id = ?
     ORDER BY created_at DESC`,
    [groupId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.get('/api/groups/:id/requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const [rows] = await pool.execute(
    `SELECT id, requester_name AS requesterName, reason, amount, status, created_at AS createdAt
     FROM withdrawal_requests
     WHERE group_id = ?
     ORDER BY created_at DESC`,
    [groupId]
  );
  res.json(rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })));
}));

app.post('/api/groups/:id/withdraw-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  const reason = req.body?.reason?.toString().trim() || null;
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [members] = await conn.query(
      'SELECT user_id FROM group_members WHERE group_id = ?',
      [groupId]
    );
    if (!members.some((m) => m.user_id === req.userId)) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ?', [groupId]);
    if (toCentavos(group.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient group balance' });
    }

    // majority = more than half of current members
    const approvalsNeeded = Math.floor(members.length / 2) + 1;

    const [result] = await conn.execute(
      'INSERT INTO group_withdraw_requests (group_id, requester_id, amount, reason, approvals_needed) VALUES (?,?,?,?,?)',
      [groupId, req.userId, amt, reason, approvalsNeeded]
    );

    await conn.commit();
    res.json({ id: result.insertId, ok: true, approvalsNeeded });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/groups/:id/withdraw-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const [rows] = await pool.execute(
    `SELECT wr.id, wr.requester_id AS requesterId, u.username AS requesterName,
            wr.amount, wr.reason, wr.status, wr.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*) FROM group_withdraw_approvals wa WHERE wa.request_id = wr.id AND wa.decision = 'approve') AS approvalsCount,
            EXISTS(SELECT 1 FROM group_withdraw_approvals wa WHERE wa.request_id = wr.id AND wa.member_id = ?) AS decidedByMe
     FROM group_withdraw_requests wr JOIN users u ON u.id = wr.requester_id
     WHERE wr.group_id = ? AND wr.status = 'pending'
     ORDER BY wr.created_at DESC`,
    [req.userId, groupId]
  );
  res.json(rows.map((r) => ({ ...r, amount: toCentavos(r.amount) })));
}));
// ---------- groups (capped at MAX_GROUP_MEMBERS) ----------

app.post('/api/groups', requireAuth, asyncRoute(async (req, res) => {
  const { name } = req.body || {};
  if (!name) return res.status(400).json({ error: 'name is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [result] = await conn.execute('INSERT INTO `groups` (name) VALUES (?)', [name]);
    await conn.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [result.insertId, req.userId]);
    await conn.commit();
    res.json({ id: result.insertId, name });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/request-join', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);

  const [[already]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (already) return res.status(409).json({ error: 'Already a member' });

  const [[pending]] = await pool.query(
    "SELECT 1 FROM group_join_requests WHERE group_id = ? AND user_id = ? AND status = 'pending'",
    [groupId, req.userId]
  );
  if (pending) return res.status(409).json({ error: 'Request already pending' });

  await pool.execute(
    'INSERT INTO group_join_requests (group_id, user_id) VALUES (?, ?)',
    [groupId, req.userId]
  );
  res.json({ ok: true });
}));

app.get('/api/groups/:id/join-requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const [[membership]] = await pool.query(
    'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
    [groupId, req.userId]
  );
  if (!membership) return res.status(403).json({ error: 'Not a member' });

  const [rows] = await pool.execute(
    `SELECT jr.id, jr.user_id AS userId, u.username, jr.created_at AS createdAt
     FROM group_join_requests jr JOIN users u ON u.id = jr.user_id
     WHERE jr.group_id = ? AND jr.status = 'pending'`,
    [groupId]
  );
  res.json(rows);
}));

app.post('/api/groups/:groupId/join-requests/:reqId/respond', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[membership]] = await conn.query(
      'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
      [groupId, req.userId]
    );
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[request]] = await conn.query(
      "SELECT * FROM group_join_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }

    if (approve) {
      const [members] = await conn.query(
        'SELECT user_id FROM group_members WHERE group_id = ? FOR UPDATE',
        [groupId]
      );
      if (members.length >= MAX_GROUP_MEMBERS) {
        await conn.rollback();
        return res.status(409).json({ error: `Group is full (max ${MAX_GROUP_MEMBERS})` });
      }
      await conn.execute(
        'INSERT INTO group_members (group_id, user_id) VALUES (?, ?)',
        [groupId, request.user_id]
      );
    }

    await conn.execute(
      'UPDATE group_join_requests SET status = ? WHERE id = ?',
      [approve ? 'approved' : 'declined', reqId]
    );

    await conn.commit();
    res.json({ ok: true, status: approve ? 'approved' : 'declined' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:groupId/withdraw-requests/:reqId/respond', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[membership]] = await conn.query(
      'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?',
      [groupId, req.userId]
    );
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }

    const [[request]] = await conn.query(
      "SELECT * FROM group_withdraw_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }

    const [[already]] = await conn.query(
      'SELECT 1 FROM group_withdraw_approvals WHERE request_id = ? AND member_id = ?',
      [reqId, req.userId]
    );
    if (already) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already voted on this request' });
    }

    await conn.execute(
      'INSERT INTO group_withdraw_approvals (request_id, member_id, decision) VALUES (?,?,?)',
      [reqId, req.userId, approve ? 'approve' : 'decline']
    );

    if (!approve) {
      await conn.execute("UPDATE group_withdraw_requests SET status = 'declined' WHERE id = ?", [reqId]);
      await conn.commit();
      return res.json({ ok: true, status: 'declined' });
    }

    const [[{ approvals }]] = await conn.query(
      "SELECT COUNT(*) AS approvals FROM group_withdraw_approvals WHERE request_id = ? AND decision = 'approve'",
      [reqId]
    );

    if (approvals >= request.approvals_needed) {
      const amt = toCentavos(request.amount);

      const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (toCentavos(group.balance) < amt) {
        await conn.rollback();
        return res.status(400).json({ error: 'Group balance too low to complete this withdrawal now' });
      }

      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [amt, groupId]);
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, request.requester_id]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['group', groupId, `Withdrawal to user #${request.requester_id} (approved)`, 'Group Withdrawal', amt, 0]
      );
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
        ['user', request.requester_id, `Group withdrawal from #${groupId}`, 'Group Withdrawal', amt, 1]
      );
      await conn.execute("UPDATE group_withdraw_requests SET status = 'approved' WHERE id = ?", [reqId]);

      await conn.commit();
      await refreshUserInIndex(request.requester_id);
      return res.json({ ok: true, status: 'approved', executed: true });
    }

    await conn.commit();
    res.json({ ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded: request.approvals_needed });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/contribute', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[membership]] = await conn.query('SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ?', [
      groupId,
      req.userId,
    ]);
    if (!membership) {
      await conn.rollback();
      return res.status(403).json({ error: 'Not a member of this group' });
    }
    const [[user]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }
    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, req.userId]);
    await conn.execute('UPDATE `groups` SET balance = balance + ? WHERE id = ?', [amt, groupId]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['group', groupId, `Contribution from user #${req.userId}`, 'Contribution', amt, 1]
    );
    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.post('/api/groups/:id/requests', requireAuth, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const { requesterName, reason, amountCentavos } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  if (!requesterName || !reason || amt === null) {
    return res.status(400).json({ error: 'requesterName, reason, and a positive amount (integer centavos) are required' });
  }
  await pool.execute(
    'INSERT INTO withdrawal_requests (group_id, requester_name, reason, amount) VALUES (?,?,?,?)',
    [groupId, requesterName, reason, amt]
  );
  res.json({ ok: true });
}));

// ---------- admin: login + final say on groups (item #13) ----------

app.post('/api/admin/login', adminLimiter, asyncRoute(async (req, res) => {
  const { username, password } = req.body || {};
  if (!username) return res.status(400).json({ error: 'username is required' });

  console.log('DEBUG received username:', JSON.stringify(username), 'password:', JSON.stringify(password));

  const identifier = `admin:${username.toString().trim().toLowerCase()}`;
  const lockedForSeconds = await checkLockout(identifier);
  console.log('DEBUG lockedForSeconds:', lockedForSeconds);
  if (lockedForSeconds !== null) {
    return res.status(429).json({ error: `Too many failed attempts. Try again in ${lockedForSeconds} second(s).` });
  }

  const [rows] = await pool.execute('SELECT id, password_hash FROM admins WHERE username = ?', [username]);
  console.log('DEBUG rows found:', rows.length, rows[0] ? rows[0].password_hash : 'none');
  const admin = rows[0];
  const ok = admin && (await bcrypt.compare(password || '', admin.password_hash));
  console.log('DEBUG bcrypt match:', ok);
  if (!ok) {
    await recordFailedAttempt(identifier);
    return res.status(401).json({ error: 'Incorrect admin credentials' });
  }
  await clearAttempts(identifier);
  const token = sign({ uid: admin.id, role: 'admin' }, '4h');
  res.json({ token });
}));

// Full oversight view: every registered user, their balance/wallet, and
// how many groups they belong to.
app.get('/api/admin/users', requireAdmin, asyncRoute(async (req, res) => {
  const [users] = await pool.query(
    `SELECT u.id, u.username, u.wallet_id AS walletId, u.balance,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.user_id = u.id) AS groupCount
     FROM users u`
  );

  const normalized = users.map((u) => ({ ...u, balance: toCentavos(u.balance) }));

  const sortBy = req.query.sortBy === 'balance' ? 'balance' : 'username';
  const sorted =
    sortBy === 'balance'
      ? mergeSort(normalized, comparators.balanceDesc)
      : mergeSort(normalized, comparators.usernameAsc);

  res.json(sorted);
}));

// Full oversight view: every group with its members and pending requests.
app.get('/api/admin/groups', requireAdmin, asyncRoute(async (req, res) => {
  const [groups] = await pool.query('SELECT id, name, balance FROM `groups`');
  for (const g of groups) {
    g.balance = toCentavos(g.balance);
    const [members] = await pool.execute(
      `SELECT u.id, u.username, u.wallet_id AS walletId
       FROM group_members gm JOIN users u ON u.id = gm.user_id
       WHERE gm.group_id = ?`,
      [g.id]
    );
    const [requests] = await pool.execute(
      `SELECT id, requester_name AS requesterName, reason, amount, status
       FROM withdrawal_requests WHERE group_id = ? AND status = 'pending'`,
      [g.id]
    );
    g.members = members;
    g.pendingRequests = requests.map((r) => ({ ...r, amount: toCentavos(r.amount) }));
  }
  res.json(groups);
}));

// Admin removes a member from a group.
app.delete('/api/admin/groups/:id/members/:userId', requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.id);
  const userId = Number(req.params.userId);
  const [result] = await pool.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [
    groupId,
    userId,
  ]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'That user is not in this group' });
  res.json({ ok: true });
}));

// Admin is the final decider on a group's withdrawal/support request.
app.post('/api/admin/groups/:groupId/requests/:reqId/respond', requireAdmin, asyncRoute(async (req, res) => {
  const groupId = Number(req.params.groupId);
  const reqId = Number(req.params.reqId);
  const approve = !!req.body?.approve;

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const [[request]] = await conn.query(
      "SELECT * FROM withdrawal_requests WHERE id = ? AND group_id = ? AND status = 'pending' FOR UPDATE",
      [reqId, groupId]
    );
    if (!request) {
      await conn.rollback();
      return res.status(404).json({ error: 'Request not found or already decided' });
    }
    const requestAmount = toCentavos(request.amount);

    if (approve) {
      const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (toCentavos(group.balance) < requestAmount) {
        await conn.rollback();
        return res.status(400).json({ error: 'Not enough funds in the group to approve this request' });
      }
      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [requestAmount, groupId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'group',
          groupId,
          `Sent to ${request.requester_name} (Support)`,
          'Withdrawal',
          requestAmount,
          0,
          JSON.stringify({ reason: request.reason }),
        ]
      );
    }

    await conn.execute(
      'UPDATE withdrawal_requests SET status = ?, decided_by_admin_id = ?, decided_at = NOW() WHERE id = ?',
      [approve ? 'approved' : 'declined', req.adminId, reqId]
    );

    await conn.commit();
    res.json({ ok: true, status: approve ? 'approved' : 'declined' });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- admin transfer reversal ----------

// ---------- shared reversal core ----------
// Used by BOTH the admin reversal route and the user-facing /api/undo
// route, so there's one place that enforces the safety checks — no
// double-reversal, no letting a recipient's balance go negative.
async function reverseTransferByRef(conn, transferRef) {
  const [rows] = await conn.query(
    'SELECT id, account_type, account_id, label, type, amount, is_credit FROM transactions WHERE transfer_ref = ? FOR UPDATE',
    [transferRef]
  );

  if (rows.length === 0) {
    return { ok: false, status: 404, error: 'Transfer not found' };
  }

  const [[already]] = await conn.query('SELECT 1 FROM transactions WHERE reversed_transfer_ref = ?', [transferRef]);
  if (already) {
    return { ok: false, status: 409, error: 'This transfer has already been reversed' };
  }

  for (const row of rows) {
    if (row.account_type === 'user' && row.is_credit) {
      const [[recipientRow]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [row.account_id]);
      const amount = toCentavos(row.amount);
      if (toCentavos(recipientRow.balance) < amount) {
        return {
          ok: false,
          status: 409,
          error: 'Cannot reverse — the recipient no longer has sufficient balance to return the funds',
        };
      }
    }
  }

  const reversalTransferRef = crypto.randomUUID();
  const affectedUserIds = new Set();

  for (const row of rows) {
    const amount = toCentavos(row.amount);
    const reversalIsCredit = row.is_credit ? 0 : 1;
    const balanceDelta = row.is_credit ? -amount : amount;

    if (row.account_type === 'user') {
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [balanceDelta, row.account_id]);
      affectedUserIds.add(row.account_id);
    }

    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, transfer_ref, reversed_transfer_ref) VALUES (?,?,?,?,?,?,?,?)',
      [
        'user',
        row.account_id,
        `Reversal: ${row.label}`,
        row.type || 'Transfer Reversal',
        amount,
        reversalIsCredit,
        reversalTransferRef,
        transferRef,
      ]
    );
  }

  return { ok: true, reversalTransferRef, affectedUserIds };
}
app.get('/api/admin/transfers/:transferRef', requireAdmin, asyncRoute(async (req, res) => {
  const transferRef = req.params.transferRef;
  const [rows] = await pool.execute(
    `SELECT id, account_type AS accountType, account_id AS accountId, label, type, amount, is_credit AS isCredit, transfer_ref AS transferRef, created_at AS createdAt
     FROM transactions
     WHERE transfer_ref = ?
     ORDER BY created_at ASC`,
    [transferRef]
  );

  if (rows.length === 0) {
    return res.status(404).json({ error: 'Transfer not found' });
  }

  res.json({ transferRef, entries: rows.map((row) => ({ ...row, amount: toCentavos(row.amount) })) });
}));

app.post('/api/admin/transfers/:transferRef/reverse', requireAdmin, asyncRoute(async (req, res) => {
  const transferRef = req.params.transferRef;
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await reverseTransferByRef(conn, transferRef);
    if (!result.ok) {
      await conn.rollback();
      return res.status(result.status).json({ error: result.error });
    }
    await conn.commit();
    await Promise.all([...result.affectedUserIds].map(refreshUserInIndex));
    res.json({ ok: true, transferRef, reversalTransferRef: result.reversalTransferRef });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));
app.post('/api/undo', requireAuth, asyncRoute(async (req, res) => {
  const stack = getUndoStack(req.userId);
  if (stack.isEmpty()) {
    return res.status(400).json({ error: 'Nothing to undo' });
  }

  const transferRef = stack.pop(); // LIFO — most recent transfer undone first

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await reverseTransferByRef(conn, transferRef);
    if (!result.ok) {
      await conn.rollback();
      stack.push(transferRef); // undo failed — put it back so the user can see why / retry later
      return res.status(result.status).json({ error: result.error });
    }
    await conn.commit();
    await Promise.all([...result.affectedUserIds].map(refreshUserInIndex));
    res.json({ ok: true, undone: transferRef, reversalTransferRef: result.reversalTransferRef });
  } catch (err) {
    await conn.rollback();
    stack.push(transferRef);
    throw err;
  } finally {
    conn.release();
  }
}));

// ---------- loans (multi-admin verified, like a real loan) ----------
//
// Applying for a loan does NOT touch the user's balance. It creates a
// `pending` row. Each admin can cast exactly one decision on it (enforced
// by the loan_approvals UNIQUE(loan_id, admin_id) constraint, not just a
// UI check). Once the loan's approvals_needed distinct admins have
// approved, it flips to `approved` and the principal is disbursed in the
// same transaction. A single decline closes the loan immediately, no
// further voting possible.
//
// What makes this closer to a real loan instead of "ask for money":
//
// 1. LEGAL / ELIGIBILITY GATE — mirrors what an actual lender checks before
//    accepting an application at all:
//      - applicant must self-declare as 18+ (MIN_AGE)
//      - a government-issued ID number must be provided
//      - the applicant must explicitly acknowledge the loan terms
//      - the account must be at least MIN_ACCOUNT_AGE_DAYS old
//      - no other loan already pending/approved (one active loan at a time)
//      - first-time borrowers are capped at MAX_FIRST_LOAN_AMOUNT_CENTAVOS —
//        real lenders don't require you to already have money in the bank
//        to get a loan, so this is NOT tied to current balance.
//
// 2. TIERED APPROVAL — bigger asks need more sign-offs, i.e. it escalates
//    to more "higher-ups" the larger the loan, via approvalsNeededFor().
//    The number of approvals a given loan needs is decided ONCE at
//    application time and stored on the row (loans.approvals_needed), so
//    it can't drift if the tier thresholds change later.

const MIN_ACCOUNT_AGE_DAYS = 3;
const MIN_AGE = 18;
const MAX_FIRST_LOAN_AMOUNT_CENTAVOS = 1_000_000; // ₱10,000.00
const LOAN_TIER_1_CENTAVOS = 500_000; // ₱5,000.00
const LOAN_TIER_2_CENTAVOS = 2_000_000; // ₱20,000.00

function approvalsNeededFor(amountCentavos) {
  if (amountCentavos <= LOAN_TIER_1_CENTAVOS) return 1;
  if (amountCentavos <= LOAN_TIER_2_CENTAVOS) return 2;
  return 3;
}

app.post('/api/loans', requireAuth, asyncRoute(async (req, res) => {
  const { loanType, amountCentavos, purpose, termMonths, age, governmentId, legalAck } = req.body || {};
  const amt = parseCentavos(amountCentavos);
  const term = Number(termMonths);
  const applicantAge = Number(age);

  if (!loanType || !loanType.toString().trim()) return res.status(400).json({ error: 'A loan platform/type is required' });
  if (amt === null) return res.status(400).json({ error: 'A positive loan amount (integer centavos) is required' });
  if (!purpose || !purpose.toString().trim()) return res.status(400).json({ error: 'A purpose is required' });
  if (!Number.isInteger(term) || term <= 0) return res.status(400).json({ error: 'A valid term (in months) is required' });
  if (!Number.isInteger(applicantAge) || applicantAge <= 0) return res.status(400).json({ error: 'A valid age is required' });
  if (applicantAge < MIN_AGE) return res.status(400).json({ error: `You must be at least ${MIN_AGE} years old to apply for a loan` });
  if (!governmentId || !governmentId.toString().trim()) return res.status(400).json({ error: 'A government-issued ID number is required' });
  if (!legalAck) return res.status(400).json({ error: 'You must acknowledge the loan terms and conditions to proceed' });
  if (amt > MAX_FIRST_LOAN_AMOUNT_CENTAVOS) {
    return res.status(400).json({
      error: `First-time borrowers are capped at ₱${centavosToPesosLabel(MAX_FIRST_LOAN_AMOUNT_CENTAVOS)} — try a smaller amount`,
    });
  }

  const [[user]] = await pool.query('SELECT created_at FROM users WHERE id = ?', [req.userId]);

  const accountAgeDays = (Date.now() - new Date(user.created_at).getTime()) / (1000 * 60 * 60 * 24);
  if (accountAgeDays < MIN_ACCOUNT_AGE_DAYS) {
    return res.status(400).json({
      error: `Your account needs to be at least ${MIN_ACCOUNT_AGE_DAYS} day(s) old before you're eligible for a loan`,
    });
  }

  const [[{ activeCount }]] = await pool.query(
    "SELECT COUNT(*) AS activeCount FROM loans WHERE user_id = ? AND status IN ('pending','approved')",
    [req.userId]
  );
  if (activeCount > 0) {
    return res.status(400).json({ error: 'You already have a pending or active loan — repay or resolve it before applying again' });
  }

 const approvalsNeeded = approvalsNeededFor(amt);
  const [result] = await pool.execute(
    `INSERT INTO loans (user_id, loan_type, amount, purpose, term_months, applicant_age, government_id, legal_ack, approvals_needed)
     VALUES (?,?,?,?,?,?,?,?,?)`,
    [
      req.userId,
      loanType.toString().trim(),
      amt,
      purpose.toString().trim(),
      term,
      applicantAge,
      governmentId.toString().trim(),
      legalAck ? 1 : 0,
      approvalsNeeded,
    ]
  );

  loanQueue.enqueue({ loanId: result.insertId, userId: req.userId }); // NEW — item: mandatory "Queue"

  res.json({ id: result.insertId, ok: true, approvalsNeeded });
}));

app.get('/api/loans/mine', requireAuth, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l WHERE l.user_id = ? ORDER BY l.created_at DESC`,
    [req.userId]
  );
  res.json(rows.map((l) => ({ ...l, amount: toCentavos(l.amount), amountRepaid: toCentavos(l.amountRepaid) })));
}));

app.post('/api/loans/:id/repay', requireAuth, asyncRoute(async (req, res) => {
  const loanId = Number(req.params.id);
  const amt = parseCentavos(req.body?.amountCentavos);
  if (amt === null) return res.status(400).json({ error: 'A positive repayment amount (integer centavos) is required' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[loan]] = await conn.query('SELECT * FROM loans WHERE id = ? AND user_id = ? FOR UPDATE', [
      loanId,
      req.userId,
    ]);
    if (!loan) {
      await conn.rollback();
      return res.status(404).json({ error: 'Loan not found' });
    }
    if (loan.status !== 'approved') {
      await conn.rollback();
      return res.status(400).json({ error: 'This loan is not active' });
    }

    const [[user]] = await conn.query('SELECT balance FROM users WHERE id = ? FOR UPDATE', [req.userId]);
    if (toCentavos(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const loanAmount = toCentavos(loan.amount);
    const loanRepaid = toCentavos(loan.amount_repaid);
    const remaining = loanAmount - loanRepaid;
    const applied = Math.min(amt, remaining);
    const newRepaid = loanRepaid + applied;
    const nowRepaid = newRepaid >= loanAmount;

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [applied, req.userId]);
    await conn.execute('UPDATE loans SET amount_repaid = ?, status = ? WHERE id = ?', [
      newRepaid,
      nowRepaid ? 'repaid' : 'approved',
      loanId,
    ]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', req.userId, `Loan Repayment (Loan #${loanId})`, 'Loan Repayment', applied, 0]
    );

    await conn.commit();

    // Row is committed — refresh so the index doesn't serve a stale
    // balance (item #6 fix).
    await refreshUserInIndex(req.userId);

    res.json({ ok: true, remaining: loanAmount - newRepaid });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

// Admin oversight: every loan with how many approvals it has and needs, and
// whether THIS admin has already decided on it (so the UI can hide the
// buttons instead of letting them try to vote twice and get a 409).
app.get('/api/admin/loans', requireAdmin, asyncRoute(async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded, u.username,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount,
            EXISTS(SELECT 1 FROM loan_approvals la WHERE la.loan_id = l.id AND la.admin_id = ?) AS decidedByMe,
            EXISTS(SELECT 1 FROM loan_approvals la WHERE la.loan_id = l.id AND la.admin_id = ? AND la.decision = 'approve') AS approvedByMe
     FROM loans l JOIN users u ON u.id = l.user_id
     ORDER BY (l.status = 'pending') DESC, l.created_at DESC`,
    [req.adminId, req.adminId]
  );
  res.json(rows.map((l) => ({ ...l, amount: toCentavos(l.amount), amountRepaid: toCentavos(l.amountRepaid) })));
}));

app.post('/api/admin/loans/:id/respond', requireAdmin, asyncRoute(async (req, res) => {
  const loanId = Number(req.params.id);
  const approve = !!req.body?.approve;

  // NEW — enforce FIFO: admins must resolve the oldest pending loan first.
  const front = loanQueue.peek();
  if (front && front.loanId !== loanId) {
    return res.status(409).json({
      error: `Loans must be processed in submission order — resolve loan #${front.loanId} first`,
    });
  }

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    const [[loan]] = await conn.query("SELECT * FROM loans WHERE id = ? AND status = 'pending' FOR UPDATE", [
      loanId,
    ]);
    if (!loan) {
      await conn.rollback();
      return res.status(404).json({ error: 'Loan not found or already decided' });
    }

    const [[already]] = await conn.query('SELECT 1 FROM loan_approvals WHERE loan_id = ? AND admin_id = ?', [
      loanId,
      req.adminId,
    ]);
    if (already) {
      await conn.rollback();
      return res.status(409).json({ error: 'You already voted on this loan' });
    }

    await conn.execute('INSERT INTO loan_approvals (loan_id, admin_id, decision) VALUES (?,?,?)', [
      loanId,
      req.adminId,
      approve ? 'approve' : 'decline',
    ]);

    if (!approve) {
      await conn.execute("UPDATE loans SET status = 'declined', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.commit();
      loanQueue.dequeue(); // NEW — loan is finalized, remove from the front
      return res.json({ ok: true, status: 'declined' });
    }

    const [[{ approvals }]] = await conn.query(
      "SELECT COUNT(*) AS approvals FROM loan_approvals WHERE loan_id = ? AND decision = 'approve'",
      [loanId]
    );

    if (approvals >= loan.approvals_needed) {
      const loanAmount = toCentavos(loan.amount);
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [loanAmount, loan.user_id]);
      await conn.execute("UPDATE loans SET status = 'approved', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'user',
          loan.user_id,
          `Loan Disbursed (${loan.term_months}-month term)`,
          'Loan Disbursement',
          loanAmount,
          1,
          JSON.stringify({ purpose: loan.purpose }),
        ]
      );
      await conn.commit();

      await refreshUserInIndex(loan.user_id);
      loanQueue.dequeue(); // NEW — loan is finalized, remove from the front

      return res.json({ ok: true, status: 'approved' });
    }

    // Still needs more admin approvals — stays at the front of the queue,
    // since it's not finalized yet.
    await conn.commit();
    res.json({ ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded: loan.approvals_needed });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
}));

app.get('/api/admin/loans/queue/next', requireAdmin, asyncRoute(async (req, res) => {
  const front = loanQueue.peek();
  if (!front) {
    return res.json({ empty: true });
  }

  const [[loan]] = await pool.query(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.approvals_needed AS approvalsNeeded, u.username,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l JOIN users u ON u.id = l.user_id
     WHERE l.id = ?`,
    [front.loanId]
  );

  res.json({ empty: false, loan: { ...loan, amount: toCentavos(loan.amount) } });
}));

app.get('/api/admin/accounts/traverse', requireAdmin, (req, res) => {
  const direction = req.query.direction === 'backward' ? 'backward' : 'forward';
  const rows = direction === 'backward' ? accountList.traverseBackward() : accountList.traverseForward();
  res.json({
    direction,
    count: rows.length,
    accounts: rows.map((u) => ({
      id: u.id,
      username: u.username,
      walletId: u.wallet_id,
      balance: toCentavos(u.balance),
    })),
  });
});

app.get('/api/admin/accounts/avl-search/:walletId', requireAdmin, (req, res) => {
  const walletId = req.params.walletId;
  const account = walletAvl.search(walletId);

  if (!account) {
    return res.status(404).json({ error: 'No account found for that Wallet ID' });
  }

  res.json({
    foundVia: 'AVL tree search',
    treeHeight: walletAvl.height(),
    treeSize: walletAvl.size,
    account: {
      id: account.id,
      username: account.username,
      walletId: account.wallet_id,
      balance: toCentavos(account.balance),
    },
  });
});

// ---------- provider network simulation (item #4 redesign) ----------
//
// This is a SIMULATION only — no real bank/provider API is called. It
// finds the lowest-fee simulated path across a small, static provider
// graph (see graph.js). Every response is explicitly marked
// `simulated: true` so it's never mistaken for a live routing quote.

app.get('/api/routes/providers', requireAuth, (req, res) => {
  res.json(PROVIDERS);
});

app.get('/api/routes/compare', requireAuth, (req, res) => {
  const { source, destination } = req.query;
  if (!source || !destination) {
    return res.status(400).json({ error: 'source and destination provider ids are required' });
  }

  const result = findCheapestRoute(source, destination);
  if (!result) {
    return res.status(404).json({ error: 'No simulated route found between those providers' });
  }

  res.json({ simulated: true, source, destination, ...result });
});

// This must be registered AFTER every route above it — Express matches
// error-handling middleware (4-arg signature) only for errors that occur
// during/after routes already registered before it in the file.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const port = process.env.PORT || 3000;
Promise.all([
  loadIndexesFromDatabase(),
  loadLoanQueueFromDatabase(),
  loadAccountListFromDatabase(),
  loadWalletAvlFromDatabase(),
]).then(() => {
  app.listen(port, () => console.log(`PayCST backend listening on port ${port}`));
});

// ---------- DB MIGRATION REQUIRED (item #1) ----------
//
// This file now writes/reads money as INTEGER centavos, but the columns
// below were presumably created as DECIMAL(x,2) storing pesos. Run this
// migration (adjust table/column names if yours differ) BEFORE deploying
// this file, and multiply any existing data by 100 as part of it:
//
//   ALTER TABLE users
//     MODIFY balance INT NOT NULL DEFAULT 0;
//   UPDATE users SET balance = ROUND(balance * 100);
//
//   ALTER TABLE transactions
//     MODIFY amount INT NOT NULL;
//   UPDATE transactions SET amount = ROUND(amount * 100);
//
//   ALTER TABLE `groups`
//     MODIFY balance INT NOT NULL DEFAULT 0;
//   UPDATE `groups` SET balance = ROUND(balance * 100);
//
//   ALTER TABLE withdrawal_requests
//     MODIFY amount INT NOT NULL;
//   UPDATE withdrawal_requests SET amount = ROUND(amount * 100);
//
//   ALTER TABLE loans
//     MODIFY amount INT NOT NULL,
//     MODIFY amount_repaid INT NOT NULL DEFAULT 0;
//   UPDATE loans SET amount = ROUND(amount * 100), amount_repaid = ROUND(amount_repaid * 100);
//
// IMPORTANT: run the ALTER (column type change) and the UPDATE (x100) as
// one deploy step, with the app briefly stopped, so no write lands between
// the two using the "wrong" unit. INT tops out around ₱21.4 million per
// row (2^31 centavos) — swap to BIGINT above if you need headroom beyond
// that for group or admin-aggregate balances.