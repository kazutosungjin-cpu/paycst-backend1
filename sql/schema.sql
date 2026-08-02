-- PayCST backend schema
-- Run with: mysql -u root -p < schema.sql

CREATE DATABASE IF NOT EXISTS paycst CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE paycst;

-- Regular users. Passwords and PINs are stored ONLY as bcrypt hashes —
-- never plaintext, unlike the in-memory demo app.
CREATE TABLE IF NOT EXISTS users (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash CHAR(60) NOT NULL,
  pin_hash CHAR(60) NOT NULL,
  wallet_id VARCHAR(20) NOT NULL UNIQUE,
  balance DECIMAL(14,2) NOT NULL DEFAULT 1000.00,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Separate admin table so admin auth never shares a namespace or a hash
-- scheme decision with regular user auth.
CREATE TABLE IF NOT EXISTS admins (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  password_hash CHAR(60) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS `groups` (
  id INT AUTO_INCREMENT PRIMARY KEY,
  name VARCHAR(100) NOT NULL,
  balance DECIMAL(14,2) NOT NULL DEFAULT 0.00,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Membership cap of 6 is enforced in application code (server.js), which is
-- also where the row is written -- keeps the "is this group full?" check
-- and the insert atomic within one transaction.
CREATE TABLE IF NOT EXISTS group_members (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  user_id INT NOT NULL,
  joined_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE KEY uniq_member (group_id, user_id),
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS transactions (
  id INT AUTO_INCREMENT PRIMARY KEY,
  account_type ENUM('user','group') NOT NULL,
  account_id INT NOT NULL,
  label VARCHAR(200) NOT NULL,
  type VARCHAR(50) NOT NULL,
  amount DECIMAL(14,2) NOT NULL,
  is_credit TINYINT(1) NOT NULL,
  details JSON NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS withdrawal_requests (
  id INT AUTO_INCREMENT PRIMARY KEY,
  group_id INT NOT NULL,
  requester_name VARCHAR(100) NOT NULL,
  reason VARCHAR(255) NOT NULL,
  amount DECIMAL(14,2) NOT NULL,
  status ENUM('pending','approved','declined') NOT NULL DEFAULT 'pending',
  decided_by_admin_id INT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  decided_at TIMESTAMP NULL,
  FOREIGN KEY (group_id) REFERENCES `groups`(id) ON DELETE CASCADE,
  FOREIGN KEY (decided_by_admin_id) REFERENCES admins(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- No admin is seeded here on purpose: a hand-typed bcrypt hash in a SQL
-- file is a bad habit (looks legitimate, isn't verifiable, invites
-- copy-pasted "default" credentials into production).
-- Run `node create-admin.js <username> <password>` after this schema is
-- loaded to create the first real admin with a properly generated hash.
