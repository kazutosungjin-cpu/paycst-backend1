-- PayCST: migrate money columns from DECIMAL pesos to INTEGER centavos
-- Run with: mysql -u root -p paycst < migrate_to_centavos.sql

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

-- verification queries
SELECT id, username, balance FROM users LIMIT 10;
SELECT id, name, balance FROM `groups` LIMIT 10;
SELECT id, amount FROM transactions ORDER BY id DESC LIMIT 10;
SELECT id, amount FROM withdrawal_requests ORDER BY id DESC LIMIT 10;
SELECT id, amount, amount_repaid FROM loans ORDER BY id DESC LIMIT 10;