// mergeSort.js — generic merge sort (item: Part B mandatory "Merge Sort")
//
// Classic divide-and-conquer merge sort. O(n log n) regardless of input
// order, which is why the proposal specifies it for transaction/account
// lists that could grow large — unlike quicksort, there's no worst-case
// O(n²) input to worry about.
//
// Takes a comparator function so it can sort by date, amount, or name
// without three separate implementations — same pattern as Array.sort,
// but this is the actual algorithm rather than delegating to it.

function mergeSort(arr, compareFn) {
  if (arr.length <= 1) return arr;

  const mid = Math.floor(arr.length / 2);
  const left = mergeSort(arr.slice(0, mid), compareFn);
  const right = mergeSort(arr.slice(mid), compareFn);

  return merge(left, right, compareFn);
}

function merge(left, right, compareFn) {
  const result = [];
  let i = 0;
  let j = 0;

  while (i < left.length && j < right.length) {
    // <= keeps the sort stable: equal elements keep their original
    // relative order instead of swapping.
    if (compareFn(left[i], right[j]) <= 0) {
      result.push(left[i]);
      i++;
    } else {
      result.push(right[j]);
      j++;
    }
  }

  while (i < left.length) {
    result.push(left[i]);
    i++;
  }
  while (j < right.length) {
    result.push(right[j]);
    j++;
  }

  return result;
}

// ---------- ready-made comparators for PayCST's actual sort needs ----------

const comparators = {
  dateDesc: (a, b) => new Date(b.createdAt) - new Date(a.createdAt),
  dateAsc: (a, b) => new Date(a.createdAt) - new Date(b.createdAt),
  amountDesc: (a, b) => b.amount - a.amount,
  amountAsc: (a, b) => a.amount - b.amount,
  balanceDesc: (a, b) => b.balance - a.balance,
  balanceAsc: (a, b) => a.balance - b.balance,
  usernameAsc: (a, b) => a.username.localeCompare(b.username),
  usernameDesc: (a, b) => b.username.localeCompare(a.username),
};

module.exports = { mergeSort, comparators };
