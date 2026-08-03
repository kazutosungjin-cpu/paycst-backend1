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
const jwt = require('jsonwebtoken');
const pool = require('./db');

const app = express();
app.use(cors());
app.use(express.json());

const JWT_SECRET = process.env.JWT_SECRET;
const MAX_GROUP_MEMBERS = 6;

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

// ---------- registration / login (password, THEN pin) ----------

app.post('/api/register', async (req, res) => {
  const { username, password, pin } = req.body || {};
  if (!username || !password || !pin) {
    return res.status(400).json({ error: 'username, password, and pin are required' });
  }
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
  if (!/^\d{4}$/.test(pin)) return res.status(400).json({ error: 'PIN must be exactly 4 digits' });

  const conn = await pool.getConnection();
  try {
    const [existing] = await conn.execute('SELECT id FROM users WHERE username = ?', [username]);
    if (existing.length > 0) return res.status(409).json({ error: 'That username is already taken' });

    const passwordHash = await bcrypt.hash(password, 10);
    const pinHash = await bcrypt.hash(pin, 10);

    // Retry on the (very unlikely) wallet-ID collision instead of trusting
    // randomness blindly.
    let walletId = nextWalletId();
    for (let i = 0; i < 5; i++) {
      const [clash] = await conn.execute('SELECT id FROM users WHERE wallet_id = ?', [walletId]);
      if (clash.length === 0) break;
      walletId = nextWalletId();
    }

    await conn.execute(
      'INSERT INTO users (username, password_hash, pin_hash, wallet_id, balance) VALUES (?, ?, ?, ?, ?)',
      [username, passwordHash, pinHash, walletId, 1000.0]
    );
    res.json({ ok: true, walletId });
  } finally {
    conn.release();
  }
});

// Step 1: password only. Returns a short-lived "pending" token that is
// NOT enough to call any authenticated endpoint — it only unlocks the
// pin-verify step below.
app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

  const [rows] = await pool.execute('SELECT id, password_hash FROM users WHERE username = ?', [username]);
  const user = rows[0];
  const ok = user && (await bcrypt.compare(password, user.password_hash));
  if (!ok) return res.status(401).json({ error: 'Incorrect username or password' });

  const pendingToken = sign({ uid: user.id, stage: 'pending', role: 'user' }, '5m');
  res.json({ pendingToken });
});

// Step 2: the PIN, checked separately from the password. Only after this
// succeeds does the client get a token any other endpoint will accept.
app.post('/api/login/verify-pin', async (req, res) => {
  const { pendingToken, pin } = req.body || {};
  const payload = pendingToken && verify(pendingToken);
  if (!payload || payload.stage !== 'pending' || payload.role !== 'user') {
    return res.status(401).json({ error: 'Login session expired, please log in again' });
  }

  const [rows] = await pool.execute('SELECT id, username, wallet_id, pin_hash, balance FROM users WHERE id = ?', [
    payload.uid,
  ]);
  const user = rows[0];
  const ok = user && (await bcrypt.compare(pin, user.pin_hash));
  if (!ok) return res.status(401).json({ error: 'Incorrect PIN' });

  const token = sign({ uid: user.id, stage: 'full', role: 'user' }, '12h');
  res.json({
    token,
    user: { id: user.id, username: user.username, walletId: user.wallet_id, balance: user.balance },
  });
});

app.get('/api/me', requireAuth, async (req, res) => {
  const [rows] = await pool.execute('SELECT id, username, wallet_id, balance FROM users WHERE id = ?', [req.userId]);
  if (!rows[0]) return res.status(404).json({ error: 'User not found' });
  res.json(rows[0]);
});

// ---------- wallet-to-wallet (QR) payment ----------

app.post('/api/wallet/pay', requireAuth, async (req, res) => {
  const { walletId, amount } = req.body || {};
  const amt = Number(amount);
  if (!walletId || !(amt > 0)) return res.status(400).json({ error: 'walletId and a positive amount are required' });

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
    if (Number(sender.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    await conn.execute('UPDATE users SET balance = balance - ? WHERE id = ?', [amt, sender.id]);
    await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [amt, recipient.id]);
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', sender.id, `QR Payment to ${recipient.username}`, 'QR Payment', amt, 0]
    );
    await conn.execute(
      'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit) VALUES (?,?,?,?,?,?)',
      ['user', recipient.id, `QR Payment from user #${sender.id}`, 'QR Payment', amt, 1]
    );

    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
});

// ---------- groups (capped at MAX_GROUP_MEMBERS) ----------

app.post('/api/groups', requireAuth, async (req, res) => {
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
});

app.post('/api/groups/:id/join', requireAuth, async (req, res) => {
  const groupId = Number(req.params.id);
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // Lock the membership rows for this group so two simultaneous joins
    // can't both slip past the cap check (the actual race condition #7's
    // "single device" note doesn't cover, but this one is fixable).
    const [members] = await conn.query('SELECT user_id FROM group_members WHERE group_id = ? FOR UPDATE', [groupId]);
    if (members.some((m) => m.user_id === req.userId)) {
      await conn.rollback();
      return res.status(409).json({ error: 'Already a member of this group' });
    }
    if (members.length >= MAX_GROUP_MEMBERS) {
      await conn.rollback();
      return res.status(409).json({ error: `This group is full (maximum ${MAX_GROUP_MEMBERS} members)` });
    }

    await conn.execute('INSERT INTO group_members (group_id, user_id) VALUES (?, ?)', [groupId, req.userId]);
    await conn.commit();
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
});

app.get('/api/groups/mine', requireAuth, async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT g.id, g.name, g.balance,
            (SELECT COUNT(*) FROM group_members gm2 WHERE gm2.group_id = g.id) AS memberCount
     FROM \`groups\` g
     JOIN group_members gm ON gm.group_id = g.id
     WHERE gm.user_id = ?`,
    [req.userId]
  );
  res.json(rows);
});

app.post('/api/groups/:id/contribute', requireAuth, async (req, res) => {
  const groupId = Number(req.params.id);
  const amt = Number(req.body?.amount);
  if (!(amt > 0)) return res.status(400).json({ error: 'A positive amount is required' });

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
    if (Number(user.balance) < amt) {
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
    res.json({ ok: true });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
});

app.post('/api/groups/:id/requests', requireAuth, async (req, res) => {
  const groupId = Number(req.params.id);
  const { requesterName, reason, amount } = req.body || {};
  const amt = Number(amount);
  if (!requesterName || !reason || !(amt > 0)) {
    return res.status(400).json({ error: 'requesterName, reason, and a positive amount are required' });
  }
  await pool.execute(
    'INSERT INTO withdrawal_requests (group_id, requester_name, reason, amount) VALUES (?,?,?,?)',
    [groupId, requesterName, reason, amt]
  );
  res.json({ ok: true });
});

// ---------- admin: login + final say on groups (item #13) ----------

app.post('/api/admin/login', async (req, res) => {
  const { username, password } = req.body || {};
  const [rows] = await pool.execute('SELECT id, password_hash FROM admins WHERE username = ?', [username]);
  const admin = rows[0];
  const ok = admin && (await bcrypt.compare(password || '', admin.password_hash));
  if (!ok) return res.status(401).json({ error: 'Incorrect admin credentials' });
  const token = sign({ uid: admin.id, role: 'admin' }, '4h');
  res.json({ token });
});

// Full oversight view: every registered user, their balance/wallet, and
// how many groups they belong to.
app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const [users] = await pool.query(
    `SELECT u.id, u.username, u.wallet_id AS walletId, u.balance,
            (SELECT COUNT(*) FROM group_members gm WHERE gm.user_id = u.id) AS groupCount
     FROM users u ORDER BY u.created_at DESC`
  );
  res.json(users);
});

// Full oversight view: every group with its members and pending requests.
app.get('/api/admin/groups', requireAdmin, async (req, res) => {
  const [groups] = await pool.query('SELECT id, name, balance FROM `groups`');
  for (const g of groups) {
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
    g.pendingRequests = requests;
  }
  res.json(groups);
});

// Admin removes a member from a group.
app.delete('/api/admin/groups/:id/members/:userId', requireAdmin, async (req, res) => {
  const groupId = Number(req.params.id);
  const userId = Number(req.params.userId);
  const [result] = await pool.execute('DELETE FROM group_members WHERE group_id = ? AND user_id = ?', [
    groupId,
    userId,
  ]);
  if (result.affectedRows === 0) return res.status(404).json({ error: 'That user is not in this group' });
  res.json({ ok: true });
});

// Admin is the final decider on a group's withdrawal/support request.
app.post('/api/admin/groups/:groupId/requests/:reqId/respond', requireAdmin, async (req, res) => {
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

    if (approve) {
      const [[group]] = await conn.query('SELECT balance FROM `groups` WHERE id = ? FOR UPDATE', [groupId]);
      if (Number(group.balance) < Number(request.amount)) {
        await conn.rollback();
        return res.status(400).json({ error: 'Not enough funds in the group to approve this request' });
      }
      await conn.execute('UPDATE `groups` SET balance = balance - ? WHERE id = ?', [request.amount, groupId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'group',
          groupId,
          `Sent to ${request.requester_name} (Support)`,
          'Withdrawal',
          request.amount,
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
});

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
//      - first-time borrowers are capped at MAX_FIRST_LOAN_AMOUNT — real
//        lenders don't require you to already have money in the bank to
//        get a loan, so this is NOT tied to current balance.
//
// 2. TIERED APPROVAL — bigger asks need more sign-offs, i.e. it escalates
//    to more "higher-ups" the larger the loan, via approvalsNeededFor().
//    The number of approvals a given loan needs is decided ONCE at
//    application time and stored on the row (loans.approvals_needed), so
//    it can't drift if the tier thresholds change later.

const MIN_ACCOUNT_AGE_DAYS = 3;
const MIN_AGE = 18;
const MAX_FIRST_LOAN_AMOUNT = 10000;

function approvalsNeededFor(amount) {
  if (amount <= 5000) return 1;
  if (amount <= 20000) return 2;
  return 3;
}

app.post('/api/loans', requireAuth, async (req, res) => {
  const { loanType, amount, purpose, termMonths, age, governmentId, legalAck } = req.body || {};
  const amt = Number(amount);
  const term = Number(termMonths);
  const applicantAge = Number(age);

  if (!loanType || !loanType.toString().trim()) return res.status(400).json({ error: 'A loan platform/type is required' });
  if (!(amt > 0)) return res.status(400).json({ error: 'A positive loan amount is required' });
  if (!purpose || !purpose.toString().trim()) return res.status(400).json({ error: 'A purpose is required' });
  if (!Number.isInteger(term) || term <= 0) return res.status(400).json({ error: 'A valid term (in months) is required' });
  if (!Number.isInteger(applicantAge) || applicantAge <= 0) return res.status(400).json({ error: 'A valid age is required' });
  if (applicantAge < MIN_AGE) return res.status(400).json({ error: `You must be at least ${MIN_AGE} years old to apply for a loan` });
  if (!governmentId || !governmentId.toString().trim()) return res.status(400).json({ error: 'A government-issued ID number is required' });
  if (!legalAck) return res.status(400).json({ error: 'You must acknowledge the loan terms and conditions to proceed' });
  if (amt > MAX_FIRST_LOAN_AMOUNT) {
    return res.status(400).json({
      error: `First-time borrowers are capped at ₱${MAX_FIRST_LOAN_AMOUNT.toFixed(2)} — try a smaller amount`,
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
  res.json({ id: result.insertId, ok: true, approvalsNeeded });
});

app.get('/api/loans/mine', requireAuth, async (req, res) => {
  const [rows] = await pool.execute(
    `SELECT l.id, l.loan_type AS loanType, l.amount, l.purpose, l.term_months AS termMonths, l.status,
            l.applicant_age AS applicantAge, l.government_id AS governmentId,
            l.amount_repaid AS amountRepaid, l.created_at, l.approvals_needed AS approvalsNeeded,
            (SELECT COUNT(*) FROM loan_approvals la WHERE la.loan_id = l.id AND la.decision = 'approve') AS approvalsCount
     FROM loans l WHERE l.user_id = ? ORDER BY l.created_at DESC`,
    [req.userId]
  );
  res.json(rows);
});

app.post('/api/loans/:id/repay', requireAuth, async (req, res) => {
  const loanId = Number(req.params.id);
  const amt = Number(req.body?.amount);
  if (!(amt > 0)) return res.status(400).json({ error: 'A positive repayment amount is required' });

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
    if (Number(user.balance) < amt) {
      await conn.rollback();
      return res.status(400).json({ error: 'Insufficient balance' });
    }

    const remaining = Number(loan.amount) - Number(loan.amount_repaid);
    const applied = Math.min(amt, remaining);
    const newRepaid = Number(loan.amount_repaid) + applied;
    const nowRepaid = newRepaid >= Number(loan.amount);

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
    res.json({ ok: true, remaining: Number(loan.amount) - newRepaid });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
});

// Admin oversight: every loan with how many approvals it has and needs, and
// whether THIS admin has already decided on it (so the UI can hide the
// buttons instead of letting them try to vote twice and get a 409).
app.get('/api/admin/loans', requireAdmin, async (req, res) => {
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
  res.json(rows);
});

app.post('/api/admin/loans/:id/respond', requireAdmin, async (req, res) => {
  const loanId = Number(req.params.id);
  const approve = !!req.body?.approve;

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

    // UNIQUE(loan_id, admin_id) below is the real enforcement — this
    // pre-check just gives a friendlier error than a raw duplicate-key one.
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
      return res.json({ ok: true, status: 'declined' });
    }

    const [[{ approvals }]] = await conn.query(
      "SELECT COUNT(*) AS approvals FROM loan_approvals WHERE loan_id = ? AND decision = 'approve'",
      [loanId]
    );

    if (approvals >= loan.approvals_needed) {
      // Fully verified — disburse now, in the same transaction as the
      // status flip, so a loan can never be marked approved without the
      // funds actually landing (or vice versa).
      await conn.execute('UPDATE users SET balance = balance + ? WHERE id = ?', [loan.amount, loan.user_id]);
      await conn.execute("UPDATE loans SET status = 'approved', decided_at = NOW() WHERE id = ?", [loanId]);
      await conn.execute(
        'INSERT INTO transactions (account_type, account_id, label, type, amount, is_credit, details) VALUES (?,?,?,?,?,?,?)',
        [
          'user',
          loan.user_id,
          `Loan Disbursed (${loan.term_months}-month term)`,
          'Loan Disbursement',
          loan.amount,
          1,
          JSON.stringify({ purpose: loan.purpose }),
        ]
      );
      await conn.commit();
      return res.json({ ok: true, status: 'approved' });
    }

    await conn.commit();
    res.json({ ok: true, status: 'pending', approvalsCount: approvals, approvalsNeeded: loan.approvals_needed });
  } catch (err) {
    await conn.rollback();
    throw err;
  } finally {
    conn.release();
  }
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error' });
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`PayCST backend listening on port ${port}`));
