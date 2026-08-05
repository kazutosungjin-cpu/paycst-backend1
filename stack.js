// stack.js
//
// Purpose in PayCST: holds each user's recent reversible transfers so
// "Undo" can restore the most recent one first (LIFO — last in, first
// undone). Per-user, in-memory, rebuilt as empty on server restart (a
// restart naturally clears "recent" history, which is fine for an undo
// feature scoped to the current session).
//
// Operations performed (per the project doc): Push, Pop.

class Stack {
  constructor() {
    this.items = [];
  }

  push(item) {
    this.items.push(item);
  }

  pop() {
    return this.items.pop(); // undefined if empty — caller checks isEmpty() first
  }

  peek() {
    return this.items[this.items.length - 1];
  }

  isEmpty() {
    return this.items.length === 0;
  }

  size() {
    return this.items.length;
  }
}

module.exports = { Stack };
