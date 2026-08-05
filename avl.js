// avl.js
//
// Purpose in PayCST: indexes wallet accounts by Wallet ID for fast,
// self-balancing search — guarantees O(log n) search/insert/delete even
// in the worst case, unlike a plain BST, which can degrade to O(n) if
// keys arrive in sorted order (e.g. wallet IDs assigned sequentially).
// NOT the source of truth (MySQL is) — rebuilt from the users table at
// startup, kept in sync via the same refreshUserInIndex() path already
// used for the Hash Map and Doubly Linked List.
//
// Operations performed (per the project doc): Insert, Search, Delete.

class AVLNode {
  constructor(key, data) {
    this.key = key;
    this.data = data;
    this.height = 1;
    this.left = null;
    this.right = null;
  }
}

function height(node) {
  return node ? node.height : 0;
}

function balanceFactor(node) {
  return node ? height(node.left) - height(node.right) : 0;
}

function updateHeight(node) {
  node.height = 1 + Math.max(height(node.left), height(node.right));
}

function rotateRight(y) {
  const x = y.left;
  const t2 = x.right;
  x.right = y;
  y.left = t2;
  updateHeight(y);
  updateHeight(x);
  return x;
}

function rotateLeft(x) {
  const y = x.right;
  const t2 = y.left;
  y.left = x;
  x.right = t2;
  updateHeight(x);
  updateHeight(y);
  return y;
}

function rebalance(node) {
  updateHeight(node);
  const bf = balanceFactor(node);

  if (bf > 1) {
    if (balanceFactor(node.left) < 0) {
      node.left = rotateLeft(node.left); // Left-Right case
    }
    return rotateRight(node); // Left-Left case
  }
  if (bf < -1) {
    if (balanceFactor(node.right) > 0) {
      node.right = rotateRight(node.right); // Right-Left case
    }
    return rotateLeft(node); // Right-Right case
  }
  return node;
}

class AVLTree {
  constructor() {
    this.root = null;
    this.size = 0;
  }

  insert(key, data) {
    const existed = this.search(key) !== null;
    this.root = this._insert(this.root, key, data);
    if (!existed) this.size++;
  }

  _insert(node, key, data) {
    if (!node) return new AVLNode(key, data);
    if (key < node.key) node.left = this._insert(node.left, key, data);
    else if (key > node.key) node.right = this._insert(node.right, key, data);
    else {
      node.data = data; // key already exists — update in place
      return node;
    }
    return rebalance(node);
  }

  search(key) {
    let node = this.root;
    while (node) {
      if (key === node.key) return node.data;
      node = key < node.key ? node.left : node.right;
    }
    return null;
  }

  delete(key) {
    const existed = this.search(key) !== null;
    if (existed) {
      this.root = this._delete(this.root, key);
      this.size--;
    }
    return existed;
  }

  _delete(node, key) {
    if (!node) return null;
    if (key < node.key) {
      node.left = this._delete(node.left, key);
    } else if (key > node.key) {
      node.right = this._delete(node.right, key);
    } else {
      if (!node.left) return node.right;
      if (!node.right) return node.left;
      let successor = node.right;
      while (successor.left) successor = successor.left;
      node.key = successor.key;
      node.data = successor.data;
      node.right = this._delete(node.right, successor.key);
    }
    return rebalance(node);
  }

  height() {
    return height(this.root);
  }

  clear() {
    this.root = null;
    this.size = 0;
  }
}

module.exports = { AVLTree };
