// graph.js — weighted graph provider-network simulation (Dijkstra)
//
// SIMULATION ONLY — PayCST has no real integration with these providers.
// Every result from findCheapestRoute() should be surfaced to the user as
// simulated, not a live quote.
//
// Weight = flat fee in centavos only (a single unit) — never mixed with
// processing time, which would be a different unit entirely.

const PROVIDERS = ['BANK_A', 'BANK_B', 'EWALLET_X', 'EWALLET_Y', 'CONVENIENCE_STORE', 'CLEARINGHOUSE', 'PCST_WALLET'];

const GRAPH = {
  BANK_A: [
    { to: 'CLEARINGHOUSE', feeCentavos: 500 },
    { to: 'EWALLET_X', feeCentavos: 1500 },
  ],
  BANK_B: [{ to: 'CLEARINGHOUSE', feeCentavos: 700 }],
  EWALLET_X: [{ to: 'PCST_WALLET', feeCentavos: 200 }],
  EWALLET_Y: [{ to: 'PCST_WALLET', feeCentavos: 300 }],
  CONVENIENCE_STORE: [
    { to: 'EWALLET_Y', feeCentavos: 1000 },
    { to: 'CLEARINGHOUSE', feeCentavos: 800 },
  ],
  CLEARINGHOUSE: [{ to: 'PCST_WALLET', feeCentavos: 400 }],
  PCST_WALLET: [],
};

function findCheapestRoute(source, destination) {
  if (!GRAPH[source] || !GRAPH[destination]) return null;

  const distances = {};
  const previous = {};
  const visited = new Set();
  const remaining = new Set(Object.keys(GRAPH));

  for (const vertex of remaining) distances[vertex] = Infinity;
  distances[source] = 0;

  while (remaining.size > 0) {
    let current = null;
    let currentDist = Infinity;
    for (const vertex of remaining) {
      if (distances[vertex] < currentDist) {
        current = vertex;
        currentDist = distances[vertex];
      }
    }
    if (current === null) break;
    remaining.delete(current);
    visited.add(current);

    if (current === destination) break;

    for (const edge of GRAPH[current] || []) {
      if (visited.has(edge.to)) continue;
      const candidate = distances[current] + edge.feeCentavos;
      if (candidate < distances[edge.to]) {
        distances[edge.to] = candidate;
        previous[edge.to] = current;
      }
    }
  }

  if (distances[destination] === Infinity) return null;

  const path = [destination];
  let step = destination;
  while (previous[step] !== undefined) {
    step = previous[step];
    path.unshift(step);
  }

  const hops = [];
  for (let i = 0; i < path.length - 1; i++) {
    const edge = GRAPH[path[i]].find((e) => e.to === path[i + 1]);
    hops.push({ from: path[i], to: path[i + 1], feeCentavos: edge.feeCentavos });
  }

  return { path, totalFeeCentavos: distances[destination], hops };
}

module.exports = { PROVIDERS, findCheapestRoute };
