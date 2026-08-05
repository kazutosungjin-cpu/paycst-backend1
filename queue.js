// queue.js
//
// Purpose in PayCST: holds pending loan applications in submission
// order, so admins review/decide on them strictly FIFO — first
// submitted, first processed. NOT the source of truth (MySQL is) —
// rebuilt from the loans table at server startup.
//
// Operations performed (per the project doc): Enqueue, Dequeue.

class Queue {
  constructor() {
    this.items = [];
  }

  enqueue(item) {
    this.items.push(item);
  }

  dequeue() {
    return this.items.shift(); // undefined if empty — caller checks isEmpty() first
  }

  peek() {
    return this.items[0];
  }

  isEmpty() {
    return this.items.length === 0;
  }

  size() {
    return this.items.length;
  }
}

module.exports = { Queue };
