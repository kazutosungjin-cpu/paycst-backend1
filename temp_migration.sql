ALTER TABLE `groups` MODIFY balance INT NOT NULL DEFAULT 0;
UPDATE `groups` SET balance = ROUND(balance * 100);
ALTER TABLE withdrawal_requests MODIFY amount INT NOT NULL;
UPDATE withdrawal_requests SET amount = ROUND(amount * 100);
ALTER TABLE loans MODIFY amount INT NOT NULL, MODIFY amount_repaid INT NOT NULL DEFAULT 0;
UPDATE loans SET amount = ROUND(amount * 100), amount_repaid = ROUND(amount_repaid * 100);
