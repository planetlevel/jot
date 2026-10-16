"use strict";
// Places the nodes of the path graph in columns, left to right. Routes are the first column, then the application
// methods by how far they are from a route, then the effects that sensors saw, then the routes a forward or redirect
// leads to. Within a column the order is chosen so edges cross as little as possible.
(function (root) {
  const NODE_W = 200, NODE_H = 26, GAP_Y = 10, COL_GAP = 80, PAD = 16, HEADER = 28;

  function layout(nodes, edges) {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const out = new Map(nodes.map((n) => [n.id, []]));
    const inn = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) {
      if (!byId.has(e.from) || !byId.has(e.to)) continue;
      out.get(e.from).push(e.to);
      inn.get(e.to).push(e.from);
    }

    // how far each method is from a route, along the longest path. A call cycle is cut where it closes.
    const depth = new Map();
    const visiting = new Set();
    function depthOf(id) {
      if (depth.has(id)) return depth.get(id);
      if (visiting.has(id)) return 0;
      visiting.add(id);
      let d = 1;
      for (const p of inn.get(id)) {
        if (byId.get(p).kind === "code") d = Math.max(d, depthOf(p) + 1);
      }
      visiting.delete(id);
      depth.set(id, d);
      return d;
    }
    let maxCode = 0;
    for (const n of nodes) if (n.kind === "code") maxCode = Math.max(maxCode, depthOf(n.id));

    const hasExit = nodes.some((n) => n.kind === "exit");
    const column = (n) => n.kind === "route" ? 0 : n.kind === "code" ? depth.get(n.id) : n.kind === "effect" ? maxCode + 1 : maxCode + 2;
    const columns = [];
    for (const n of nodes) {
      const c = column(n);
      (columns[c] = columns[c] || []).push(n);
    }
    for (let c = 0; c < columns.length; c++) columns[c] = columns[c] || [];
    const titles = ["Routes in"];
    for (let c = 1; c <= maxCode; c++) titles.push(c === 1 ? "Application code" : "");
    titles.push("What was seen");
    if (hasExit) titles.push("Routes out");

    // start with the busiest on top, then pull each node toward the middle of the nodes it is connected to
    const y = new Map();
    for (const col of columns) {
      col.sort((a, b) => b.events - a.events || a.label.localeCompare(b.label));
      col.forEach((n, i) => y.set(n.id, i));
    }
    const mean = (ids) => ids.reduce((s, id) => s + y.get(id), 0) / ids.length;
    for (let pass = 0; pass < 4; pass++) {
      const order = pass % 2 === 0 ? columns.map((_, i) => i) : columns.map((_, i) => columns.length - 1 - i);
      for (const c of order) {
        const col = columns[c];
        const key = new Map(col.map((n) => {
          const near = (pass % 2 === 0 ? inn : out).get(n.id);
          return [n.id, near.length ? mean(near) : y.get(n.id)];
        }));
        col.sort((a, b) => key.get(a.id) - key.get(b.id) || b.events - a.events || a.label.localeCompare(b.label));
        col.forEach((n, i) => y.set(n.id, i));
      }
    }

    const pos = new Map();
    columns.forEach((col, c) => col.forEach((n, i) => {
      pos.set(n.id, { x: PAD + c * (NODE_W + COL_GAP), y: PAD + HEADER + i * (NODE_H + GAP_Y), column: c });
    }));
    const tallest = Math.max(1, ...columns.map((col) => col.length));
    return {
      pos, titles, columns: columns.length, colX: columns.map((_, c) => PAD + c * (NODE_W + COL_GAP)),
      width: PAD * 2 + Math.max(1, columns.length) * NODE_W + Math.max(0, columns.length - 1) * COL_GAP,
      height: PAD * 2 + HEADER + tallest * (NODE_H + GAP_Y),
      nodeW: NODE_W, nodeH: NODE_H,
    };
  }

  // every node on a path through this one, in both directions
  function through(id, edges) {
    const seen = new Set([id]);
    for (const [from, to] of [["from", "to"], ["to", "from"]]) {
      const stack = [id];
      while (stack.length) {
        const here = stack.pop();
        for (const e of edges) {
          if (e[from] === here && !seen.has(e[to])) { seen.add(e[to]); stack.push(e[to]); }
        }
      }
    }
    return seen;
  }

  function curve(a, b, w) {
    const x1 = a.x + w, y1 = a.y, x2 = b.x, y2 = b.y;
    const dx = Math.max(40, Math.abs(x2 - x1) / 2);
    return "M" + x1 + "," + y1 + " C" + (x1 + dx) + "," + y1 + " " + (x2 - dx) + "," + y2 + " " + x2 + "," + y2;
  }

  const api = { layout, through, curve };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotGraph = api;
})(typeof window !== "undefined" ? window : globalThis);
