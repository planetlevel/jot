"use strict";
// Places the nodes of the path graph as a main line with branches, left to right. See layout for how. Which box a line leaves
// and where it joins again is what the edges say, and within a column the boxes are in an order that keeps the lines apart.
(function (root) {
  const NODE_W = 200, NODE_H = 26, GAP_Y = 10, COL_GAP = 80, PAD = 16, HEADER = 0;
  // going down, boxes in a row are this far apart, and rows this far, which leaves room for the lines between them to bend
  const GAP_X = 28, ROW_GAP = 40;

  // The picture is a main line with branches. The main line is the path through the busiest nodes, from the route to the last thing
  // that happened, one box after another along a row. Anything else sits next to where it leaves that line, one column on from
  // the box it follows, on a row above or below, and carries on along its own row. A box is only ever as far along as the path
  // that led to it, so nothing is pushed out to the right to line up with something else. Where a branch joins the main line
  // again, its line just reaches across.
  //
  // With down, the same picture runs top to bottom, the main line a column and the branches beside it.
  function layout(nodes, edges, options) {
    const down = !!(options && options.down);
    const byId = new Map(nodes.map((n) => [n.id, n]));
    const all = new Map(nodes.map((n) => [n.id, []]));
    for (const e of edges) if (byId.has(e.from) && byId.has(e.to)) all.get(e.from).push(e);
    // Requests that did the same things in a different order make loops. An edge that closes a loop is left out of the layout,
    // found by walking from the routes with the busiest edges first, so the order most requests used is the one drawn and
    // nothing runs backwards across the page. It is still counted as a path, only not drawn.
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

    // the order to place them in, every box after the ones that lead to it
    const order = [], seen = new Set();
    const visit = (id) => {
      if (seen.has(id)) return;
      seen.add(id);
      for (const to of out.get(id)) visit(to);
      order.push(id);
    };
    for (const n of nodes) visit(n.id);
    order.reverse();

    // the main line is what most requests did, the kind of request that came most often, a line in the server's words, taken in the
    // order the boxes happen. Without a count of requests for each kind it is the path from a route through the most events, the
    // busiest route if there are several
    const counts = options && options.lineCounts;
    let spine = [];
    if (counts) {
      let top = null;
      for (const key of Object.keys(counts)) {
        const mine = nodes.filter((n) => (n.lines || []).includes(Number(key))).length;
        if (top === null || counts[key] > counts[top.key] || (counts[key] === counts[top.key] && mine > top.mine)) top = { key, mine };
      }
      if (top) spine = order.filter((id) => (byId.get(id).lines || []).includes(Number(top.key)));
    }
    const best = new Map(), next = new Map();
    for (const id of order.slice().reverse()) {
      let top = 0, pick = null;
      for (const to of out.get(id)) {
        if (best.get(to) > top || (best.get(to) === top && pick !== null && byId.get(to).events > byId.get(pick).events)) { top = best.get(to); pick = to; }
      }
      best.set(id, byId.get(id).events + top);
      if (pick !== null) next.set(id, pick);
    }
    const starts = nodes.filter((n) => !inn.get(n.id).length);
    const routes = starts.filter((n) => n.kind === "route");
    const first = (routes.length ? routes : starts).slice().sort((a, b) => best.get(b.id) - best.get(a.id) || a.label.localeCompare(b.label))[0];
    if (!spine.length) for (let id = first && first.id; id !== undefined; id = next.get(id)) spine.push(id);
    const onSpine = new Set(spine);

    // columns. The main line is one column to a box. Anything else is one on from the last box before it, and the exit that
    // a forward leads to is one on from the forward, so it sits next to it
    const col = new Map(spine.map((id, i) => [id, i]));
    for (const id of order) {
      if (col.has(id)) continue;
      const from = inn.get(id).filter((p) => col.has(p));
      col.set(id, from.length ? Math.max(...from.map((p) => col.get(p))) + 1 : 0);
    }

    // rows. The main line is row 0. A branch stays on the row of the box it follows when that is free, and otherwise takes the
    // nearest free one, going below first and then above, so the branches are spread on both sides of the line
    const rowOf = new Map(spine.map((id) => [id, 0]));
    const taken = new Map();       // column -> the rows in use
    const use = (c, r) => { if (!taken.has(c)) taken.set(c, new Set()); taken.get(c).add(r); };
    const free = (c, r) => !(taken.get(c) && taken.get(c).has(r));
    for (const id of spine) use(col.get(id), 0);
    const placement = order.filter((id) => !onSpine.has(id)).sort((a, b) => col.get(a) - col.get(b) || byId.get(b).events - byId.get(a).events || byId.get(a).label.localeCompare(byId.get(b).label));
    for (const id of placement) {
      const from = inn.get(id).filter((p) => rowOf.has(p));
      const anchor = from.length ? Math.round(from.reduce((t, p) => t + rowOf.get(p), 0) / from.length) : 0;
      const c = col.get(id);
      let r = anchor;
      for (let step = 0; !free(c, r); step++) r = anchor + (step % 2 === 0 ? step / 2 + 1 : -((step + 1) / 2));
      rowOf.set(id, r);
      use(c, r);
    }
    const rows = nodes.map((n) => rowOf.get(n.id));
    const low = nodes.length ? Math.min(...rows) : 0, high = nodes.length ? Math.max(...rows) : 0;
    const columns = nodes.length ? Math.max(...nodes.map((n) => col.get(n.id))) + 1 : 0;
    const across = high - low + 1;

    const pos = new Map();
    if (down) {
      for (const n of nodes) pos.set(n.id, { x: PAD + (rowOf.get(n.id) - low) * (NODE_W + GAP_X), y: PAD + col.get(n.id) * (NODE_H + ROW_GAP), column: col.get(n.id), row: rowOf.get(n.id) });
      return {
        pos, closing, spine, columns, down: true, nodeW: NODE_W, nodeH: NODE_H,
        width: PAD * 2 + Math.max(1, across) * NODE_W + Math.max(0, across - 1) * GAP_X,
        height: PAD * 2 + Math.max(1, columns) * NODE_H + Math.max(0, columns - 1) * ROW_GAP,
      };
    }
    for (const n of nodes) pos.set(n.id, { x: PAD + col.get(n.id) * (NODE_W + COL_GAP), y: PAD + HEADER + (rowOf.get(n.id) - low) * (NODE_H + GAP_Y), column: col.get(n.id), row: rowOf.get(n.id) });
    return {
      pos, closing, spine, columns, down: false, nodeW: NODE_W, nodeH: NODE_H,
      width: PAD * 2 + Math.max(1, columns) * NODE_W + Math.max(0, columns - 1) * COL_GAP,
      height: PAD * 2 + HEADER + Math.max(1, across) * NODE_H + Math.max(0, across - 1) * GAP_Y,
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

  // a line from the bottom middle of a box to the top middle of the next, for a layout that runs down. a and b are those two points
  function curveDown(a, b) {
    const dy = Math.max(20, Math.abs(b.y - a.y) / 2);
    return "M" + a.x + "," + a.y + " C" + a.x + "," + (a.y + dy) + " " + b.x + "," + (b.y - dy) + " " + b.x + "," + b.y;
  }

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

  // Leaves out the paths few requests took, so what most did can be read. The paths are the lines between boxes, and each says
  // which kinds of request used it, so how many requests did is the sum of the counts of those kinds. Up to ten requests nothing
  // is left out, then a path is left out if fewer than two requests took it, and from twenty if fewer than a tenth did. A route and
  // the line it starts are always kept, and a box that is left with no line goes with them.
  // A rare path is not an unimportant one, the one request in a hundred that read /etc/passwd is the one to see. So what a sensor saw is
  // never left out. If every path to it is rare, the most common of them is kept, and if a rule blocked or reported something it, all of
  // its paths are kept, since those are the requests that mattered.
  function prune(nodes, edges, lineCounts) {
    const counts = lineCounts || {};
    const total = Object.keys(counts).reduce((t, k) => t + counts[k], 0);
    const need = total >= 20 ? Math.ceil(total * 0.1) : total >= 10 ? 2 : 1;
    if (need <= 1) return { nodes, edges, hiddenEdges: 0, hiddenNodes: 0 };
    const requests = (edge) => (edge.lines || []).reduce((t, l) => t + (counts[l] || 0), 0);
    const kept = new Set(edges.filter((edge) => requests(edge) >= need || !(edge.lines || []).length));
    const pathOf = (line) => edges.filter((edge) => (edge.lines || []).includes(line));
    const reached = () => {
      const used = new Set();
      for (const edge of kept) { used.add(edge.from); used.add(edge.to); }
      return used;
    };
    const effects = nodes.filter((n) => n.kind === "effect" && (n.lines || []).length);
    for (const n of effects) {
      if ((n.blocked || 0) > 0 || (n.monitored || 0) > 0) for (const line of n.lines) for (const edge of pathOf(line)) kept.add(edge);
    }
    for (const n of effects) {
      if (reached().has(n.id)) continue;
      const commonest = n.lines.reduce((best, line) => ((counts[line] || 0) > (counts[best] || 0) ? line : best), n.lines[0]);
      for (const edge of pathOf(commonest)) kept.add(edge);
    }
    const keptEdges = edges.filter((edge) => kept.has(edge));
    const used = reached();
    const left = nodes.filter((n) => used.has(n.id) || n.kind === "route");
    return { nodes: left, edges: keptEdges, hiddenEdges: edges.length - keptEdges.length, hiddenNodes: nodes.length - left.length };
  }

  // A starting JOT for an application method, from its full name like com.acme.Database.getConnection, or null when a method of
  // that name can't be watched, like a static initializer. Its name is the class and method as words, made unique among those taken.
  function sensorFor(full, taken) {
    if (!full || !/^([\p{L}_$][\p{L}\p{N}_$]*\.)+(<init>|[\p{L}_$][\p{L}\p{N}_$]*)$/u.test(full)) return null;
    const parts = full.split(".");
    const method = parts.pop(), cls = parts.pop().replace(/^.*\$/, "");
    const words = (text) => text.replace(/([a-z0-9])([A-Z])/g, "$1-$2").replace(/([A-Z]+)([A-Z][a-z])/g, "$1-$2").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    let base = words(cls) + "-" + (method === "<init>" ? "new" : words(method));
    if (!/^[a-z]/.test(base)) base = "jot-" + base;
    const used = new Set(taken || []);
    let name = base;
    for (let i = 2; used.has(name); i++) name = base + "-" + i;
    return [
      "name: " + name,
      "description: Identifies calls to " + cls + "." + (method === "<init>" ? "<init>" : method),
      "methods:",
      "- " + full,
      "captures:",
      '  args: "#ARGS"',
      '  result: "#RET"',
      "",
    ].join("\n");
  }

  // The method of a stack frame, java.base/javax.crypto.Cipher.getInstance(Cipher.java:531) is javax.crypto.Cipher.getInstance
  function frameMethod(frame) {
    const head = String(frame || "").split("(")[0];
    return head.includes("/") ? head.slice(head.lastIndexOf("/") + 1) : head;
  }

  // The node nearest to one in a direction, for the arrow keys, or null when there is none that way. Boxes are all the same size, so the difference of
  // their corners is the difference of their centers. A node counts when it is on that side of this one, and the nearest has the least distance
  // along the direction plus a heavier distance across it, so a key follows the row or the column the eye is on and doesn't jump to a far box
  // that happens to be a little closer in a straight line. Ties go to the one that was drawn first.
  function neighbor(pos, from, dir) {
    const at = pos.get(from);
    if (!at) return null;
    const vertical = dir === "up" || dir === "down";
    const sign = dir === "right" || dir === "down" ? 1 : -1;
    let best = null, bestScore = Infinity;
    for (const [id, p] of pos) {
      if (id === from) continue;
      const along = (vertical ? p.y - at.y : p.x - at.x) * sign;
      if (along <= 0) continue;
      const score = along + 2.5 * Math.abs(vertical ? p.x - at.x : p.y - at.y);
      if (score < bestScore) { best = id; bestScore = score; }
    }
    return best;
  }

  const api = { layout, through, curve, curveDown, collapse, prune, sensorFor, frameMethod, neighbor };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotGraph = api;
})(typeof window !== "undefined" ? window : globalThis);
