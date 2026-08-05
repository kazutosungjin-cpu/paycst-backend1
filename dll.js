// dll.js
//
// Purpose in PayCST: stores wallet accounts in registration order,
// supporting forward AND backward traversal without shifting existing
// records on insert/delete (the actual advantage over an array). NOT the
// source of truth (MySQL is) — rebuilt from the users table at startup,
// then kept in sync via insert/update/delete calls alongside the
// existing hash-map refresh logic.
//
// Design note: nodesByKey below is an internal lookup aid ONLY, so
// delete/update don't require walking the whole list to find a node —
// this is the same pairing a real-world LRU cache uses (hash map for
// O(1) node lookup + linked list for order/traversal). The list itself
// — head/tail/prev/next — is what actually stores and orders the data;
// the map just points into it.
//
// Operations performed (per the project doc): Insert, Delete, Update,
// Traverse (forward and backward).

class DLLNode {
  constructor(data) {
    this.data = data;
    this.prev = null;
    this.next = null;
  }
}

class DoublyLinkedList {
  constructor() {
    this.head = null;
    this.tail = null;
    this.nodesByKey = new Map(); // key -> node, for O(1) update/delete lookup
    this.length = 0;
  }

  insert(key, data) {
    const node = new DLLNode(data);
    if (!this.tail) {
      this.head = node;
      this.tail = node;
    } else {
      node.prev = this.tail;
      this.tail.next = node;
      this.tail = node;
    }
    this.nodesByKey.set(key, node);
    this.length++;
    return node;
  }

  update(key, data) {
    const node = this.nodesByKey.get(key);
    if (!node) return false;
    node.data = data;
    return true;
  }

  delete(key) {
    const node = this.nodesByKey.get(key);
    if (!node) return false;
    if (node.prev) node.prev.next = node.next;
    else this.head = node.next;
    if (node.next) node.next.prev = node.prev;
    else this.tail = node.prev;
    this.nodesByKey.delete(key);
    this.length--;
    return true;
  }

  traverseForward() {
    const result = [];
    let cur = this.head;
    while (cur) {
      result.push(cur.data);
      cur = cur.next;
    }
    return result;
  }

  traverseBackward() {
    const result = [];
    let cur = this.tail;
    while (cur) {
      result.push(cur.data);
      cur = cur.prev;
    }
    return result;
  }

  clear() {
    this.head = null;
    this.tail = null;
    this.nodesByKey.clear();
    this.length = 0;
  }
}

module.exports = { DoublyLinkedList };
