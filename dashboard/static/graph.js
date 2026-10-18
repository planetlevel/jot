"use strict";
// Places the nodes of the path graph in columns, left to right. Routes are the first column, then everything a
// request's own path reaches, in the order it reaches it: application methods by how far they are from a route, then
// the effects those methods led to, each at its own distance rather than all lumped into one column. An effect
// reached by a short path and also by a longer one sits at the longer distance, so both edges draw into the one
// shared node, the way two subway lines share a station. Finally the routes a forward or redirect leads to. Within a
// column the order is chosen so edges cross as little as possible.
(function (root) {
  const NODE_W = 200, NODE_H = 26, GAP_Y = 10, COL_GAP = 80, PAD = 16, HEADER = 0;

  function layout(nodes, edges) {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const all = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) if (byId.has(e.from) && byId.has(e.to)) all.get(e.from).push(e);
    // Requests that did the same things in a different order make loops. An edge that closes a loop is left out of the
    // layout, found by walking from the routes with the busiest edges first, so the order most requests used is the one
    // drawn and nothing runs backwards across the page. It is still counted as a path, only not drawn.
    const closing = new Set(), state = new Map();
    const walk = (id) => {
      state.set(id, 1);
      for (const e of all.get(id).slice().sort((a, b) => b.events - a.events)) {
        const s = state.get(e.to);
        if (s === 1) closing.add(e);
        else if (!s) walk(e.to);
      }
      state.set(id, 2);
    };
    for (const n of nodes) if (n.kind === "route" && !state.get(n.id)) walk(n.id);
    for (const n of nodes) if (!state.get(n.id)) walk(n.id);
    const out = new Map(nodes.map((n) => [n.id, []]));
    const inn = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) {
      if (!byId.has(e.from) || !byId.has(e.to) || closing.has(e)) continue;
      out.get(e.from).push(e.to);
      inn.get(e.to).push(e.from);
    }

    // how far each node on a request's path is from a route, along the longest path to it. Code and effect nodes
    // both count, so a chain of application methods ending in an effect, and an effect that follows another effect,
    // are placed one after the other rather than effects all being dropped into a single final column. A call cycle
    // is cut where it closes.
    const depth = new Map();
    const visiting = new Set();
    function depthOf(id) {
      if (depth.has(id)) return depth.get(id);
      if (visiting.has(id)) return 0;
      visiting.add(id);
      let d = 1;
      for (const p of inn.get(id)) {
        const kind = byId.get(p).kind;
        if (kind === "code" || kind === "effect") d = Math.max(d, depthOf(p) + 1);
      }
      visiting.delete(id);
      depth.set(id, d);
      return d;
    }
    let maxDepth = 0;
    for (const n of nodes) if (n.kind === "code" || n.kind === "effect") maxDepth = Math.max(maxDepth, depthOf(n.id));
    // the first column that holds an effect, so columns before it are titled for application code and the rest for
    // what was seen. A column can hold both kinds, when one path reaches an effect sooner than another path reaches
    // its own deeper application code, so this is where the effects begin, not a hard boundary between the kinds.
    let firstEffect = maxDepth + 1;
    for (const n of nodes) if (n.kind === "effect") firstEffect = Math.min(firstEffect, depth.get(n.id));

    const hasExit = nodes.some((n) => n.kind === "exit");
    const column = (n) => n.kind === "route" ? 0 : (n.kind === "code" || n.kind === "effect") ? depth.get(n.id) : maxDepth + 1;
    const columns = [];
    for (const n of nodes) {
      const c = column(n);
      (columns[c] = columns[c] || []).push(n);
    }
    for (let c = 0; c < columns.length; c++) columns[c] = columns[c] || [];
    const titles = ["Routes in"];
    let labeledCode = false, labeledEffect = false;
    for (let c = 1; c <= maxDepth; c++) {
      if (c < firstEffect) { titles.push(labeledCode ? "" : "Application code"); labeledCode = true; }
      else { titles.push(labeledEffect ? "" : "What was seen"); labeledEffect = true; }
    }
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

    // every column is as tall as the tallest. A shorter one is spread over that height, each node in the middle of its
    // own share of it, so a lone node sits at the middle and the edges between columns stay level
    const tallest = Math.max(1, ...columns.map((col) => col.length));
    const slot = NODE_H + GAP_Y, span = tallest * slot;
    const pos = new Map();
    columns.forEach((col, c) => col.forEach((n, i) => {
      const share = span / col.length;
      pos.set(n.id, { x: PAD + c * (NODE_W + COL_GAP), y: PAD + HEADER + (i + 0.5) * share - NODE_H / 2, column: c });
    }));
    return {
      pos, closing, titles, columns: columns.length, colX: columns.map((_, c) => PAD + c * (NODE_W + COL_GAP)),
      width: PAD * 2 + Math.max(1, columns.length) * NODE_W + Math.max(0, columns.length - 1) * COL_GAP,
      height: PAD * 2 + HEADER + tallest * (NODE_H + GAP_Y),
      nodeW: NODE_W, nodeH: NODE_H,
    };
  }

  // What goes through a node. A line is one kind of request, from its route through its stops, and the server says which
  // lines use each node and edge. What lights up with a node is what those lines use, a path through it. Following edges
  // out from the node instead would join requests that never met, because one that did A and then B and another that did
  // B and then A make a loop between the two, and everything on the loop is then reachable from everything else.
  function through(id, nodes, edges) {
    const node = nodes.find((x) => x.id === id);
    const mine = new Set(node && node.lines ? node.lines : []);
    const uses = (x) => (x.lines || []).some((l) => mine.has(l));
    return { nodes: new Set([id, ...nodes.filter(uses).map((x) => x.id)]), edges: new Set(edges.filter(uses)) };
  }

  const union = (a, b) => [...new Set([...(a || []), ...(b || [])])].sort((x, y) => x - y);

  function curve(a, b, w) {
    const x1 = a.x + w, y1 = a.y, x2 = b.x, y2 = b.y;
    const dx = Math.max(40, Math.abs(x2 - x1) / 2);
    return "M" + x1 + "," + y1 + " C" + (x1 + dx) + "," + y1 + " " + (x2 - dx) + "," + y2 + " " + x2 + "," + y2;
  }

  // the class a method belongs to, from its full name
  const classOf = (full) => { const i = full.lastIndexOf("."); return i < 0 ? full : full.slice(0, i); };

  // Folds a straight run of methods of one class into a single node, like a static initializer that makes the instance
  // whose constructor calls init. A step joins the run only when it is the one thing its caller calls, its caller is the
  // one thing that calls it, and the same events pass through both, so nothing that branches is ever hidden. The merged
  // node keeps the first member's id, lists every member in members, and edges are rewired to its ends.
  function collapseRuns(nodes, edges) {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const out = new Map(nodes.map((n) => [n.id, []]));
    const inn = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) {
      if (!byId.has(e.from) || !byId.has(e.to)) continue;
      out.get(e.from).push(e);
      inn.get(e.to).push(e);
    }
    const next = new Map();   // a step to the step after it in its run
    for (const a of nodes) {
      if (a.kind !== "code" || out.get(a.id).length !== 1) continue;
      const b = byId.get(out.get(a.id)[0].to);
      if (b.id !== a.id && b.kind === "code" && inn.get(b.id).length === 1 && a.events === b.events && classOf(a.full) === classOf(b.full)) next.set(a.id, b.id);
    }
    const follows = new Set(next.values());
    const head = new Map();   // every member of a run to the id of the node that stands for it
    const merged = new Map();
    for (const a of nodes) {
      if (follows.has(a.id)) continue;
      const run = [a];
      while (next.has(run[run.length - 1].id)) run.push(byId.get(next.get(run[run.length - 1].id)));
      if (run.length < 2) continue;
      for (const m of run) head.set(m.id, a.id);
      const cls = classOf(a.full), method = (m) => m.label.slice(m.label.lastIndexOf(".") + 1);
      merged.set(a.id, Object.assign({}, a, {
        label: cls.slice(cls.lastIndexOf(".") + 1) + " (" + run.map(method).join(", ") + ")",
        full: run.map((m) => m.full).join("\n"),
        members: run.map((m) => m.id),
        lines: run.reduce((all, m) => union(all, m.lines), []),
        firstUse: run.reduce((sum, m) => sum + (m.firstUse || 0), 0) || undefined,
      }));
    }
    return {
      nodes: nodes.filter((n) => !head.has(n.id) || merged.has(n.id)).map((n) => merged.get(n.id) || n),
      edges: edges.filter((e) => next.get(e.from) !== e.to)
        .map((e) => head.has(e.from) || head.has(e.to) ? Object.assign({}, e, { from: head.get(e.from) || e.from, to: head.get(e.to) || e.to }) : e),
      head,
    };
  }

  // A static initializer runs once, when its class is first used, so it is setup rather than a step of the request, and
  // its constructor has plenty of other callers. When all it leads to is a method of its own class, it isn't drawn.
  // Whatever called it calls that method instead, and the method says how many events were that first use.
  function foldInitializers(nodes, edges) {
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const out = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) if (byId.has(e.from) && byId.has(e.to)) out.get(e.from).push(e);
    const head = new Map();   // a dropped initializer to the node that stands for it
    const firstUse = new Map();
    for (const a of nodes) {
      if (a.kind !== "code" || !a.full.endsWith(".<clinit>") || out.get(a.id).length !== 1) continue;
      const b = byId.get(out.get(a.id)[0].to);
      if (b.kind !== "code" || b.id === a.id || classOf(b.full) !== classOf(a.full) || head.has(b.id)) continue;
      head.set(a.id, b.id);
      firstUse.set(b.id, (firstUse.get(b.id) || 0) + a.events);
    }
    const merged = new Map();
    for (const e of edges) {
      if (head.has(e.from)) continue;   // the initializer's own edge
      const from = e.from, to = head.get(e.to) || e.to;
      if (from === to) continue;
      const key = from + "\n" + to;
      if (merged.has(key)) {
        const into = merged.get(key);
        into.events += e.events;
        into.lines = union(into.lines, e.lines);
      } else merged.set(key, to === e.to ? e : Object.assign({}, e, { to }));
    }
    return {
      nodes: nodes.filter((n) => !head.has(n.id)).map((n) => firstUse.has(n.id) ? Object.assign({}, n, { firstUse: (n.firstUse || 0) + firstUse.get(n.id) }) : n),
      edges: [...merged.values()].map((e) => Object.assign({}, e)),
      head,
    };
  }

  // the two folds one after the other, and where each node that was folded away went
  function collapse(nodes, edges) {
    const first = foldInitializers(nodes, edges);
    const second = collapseRuns(first.nodes, first.edges);
    const head = new Map(second.head);
    for (const [id, to] of first.head) head.set(id, second.head.get(to) || to);
    return { nodes: second.nodes, edges: second.edges, head };
  }

  const api = { layout, through, curve, collapse };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotGraph = api;
})(typeof window !== "undefined" ? window : globalThis);
