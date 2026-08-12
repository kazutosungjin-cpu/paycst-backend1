-- PayCST: migrate money columns from DECIMAL pesos to INTEGER centavos
-- Run with: mysql -u root -p paycst < migrate_to_centavos.sql
--
-- IMPORTANT — do this in order:
--   1. STOP the server (server.js should not be running).
--   2. BACK UP first:
--        mysqldump -u root -p paycst > backup_before_centavos_migration.sql
--   3. Run this script.
--   4. Verify the numbers below look right (see check queries at the bottom).
--   5. Restart the server.
--
-- Each ALTER + UPDATE pair changes the column type AND multiplies existing
-- data by 100 in the same step, so no row is ever left ambiguous about
-- which unit it's in.

USE paycst;

-- users.balance: DECIMAL(14,2) pesos -> INT centavos
ALTER TABLE users MODIFY balance INT NOT NULL DEFAULT 0;
UPDATE users SET balance = ROUND(balance * 100);

-- groups.balance: DECIMAL(14,2) pesos -> BIGINT centavos
-- (BIGINT because a group's balance accumulates from multiple members)
ALTER TABLE `groups` MODIFY balance BIGINT NOT NULL DEFAULT 0;
UPDATE `groups` SET balance = ROUND(balance * 100);

-- transactions.amount: DECIMAL(14,2) pesos -> INT centavos
ALTER TABLE transactions MODIFY amount INT NOT NULL;
UPDATE transactions SET amount = ROUND(amount * 100);

-- withdrawal_requests.amount: DECIMAL(14,2) pesos -> INT centavos
ALTER TABLE withdrawal_requests MODIFY amount INT NOT NULL;
UPDATE withdrawal_requests SET amount = ROUND(amount * 100);

-- loans.amount and loans.amount_repaid: DECIMAL(14,2) pesos -> INT centavos
ALTER TABLE loans
  MODIFY amount INT NOT NULL,
  MODIFY amount_repaid INT NOT NULL DEFAULT 0;
UPDATE loans SET amount = ROUND(amount * 100), amount_repaid = ROUND(amount_repaid * 100);

-- ---------- verification ----------
-- After running, check these against what you expect (e.g. a user who had
-- a balance of 150.50 pesos should now show 15050):

SELECT id, username, balance FROM users LIMIT 10;
SELECT id, name, balance FROM `groups` LIMIT 10;
SELECT id, amount FROM transactions ORDER BY id DESC LIMIT 10;
SELECT id, amount FROM withdrawal_requests ORDER BY id DESC LIMIT 10;
SELECT id, amount, amount_repaid FROM loans ORDER BY id DESC LIMIT 10;

-- ---------- new: group join & withdraw approval tables ----------

CREATE TABLE group_join_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  user_id INT NOT NULL,
  status ENUM('pending','approved','declined') DEFAULT 'pending',
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY (group_id, user_id, status)
);

CREATE TABLE group_withdraw_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  requester_id INT NOT NULL,
  amount INT NOT NULL,
  reason VARCHAR(255),
  status ENUM('pending','approved','declined') DEFAULT 'pending',
  approvals_needed INT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE group_withdraw_approvals (
  id INT AUTO_INCREMENT PRIMARY KEY,
  request_id INT NOT NULL,
  member_id INT NOT NULL,
  decision ENUM('approve','decline') NOT NULL,
  UNIQUE KEY (request_id, member_id)
);