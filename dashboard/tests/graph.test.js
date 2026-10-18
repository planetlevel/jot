"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { layout, through, pathEdges, curve, collapse } = require("../static/graph.js");

const n = (id, kind, events = 1) => ({ id, kind, label: id, events });
const e = (from, to, events = 1) => ({ from, to, events });

const nodes = [n("r1", "route", 9), n("r2", "route", 3), n("a", "code", 9), n("b", "code", 5), n("s", "effect", 9), n("x", "exit", 1)];
const edges = [e("r1", "a"), e("a", "b"), e("b", "s"), e("r2", "s"), e("s", "x")];

test("routes are in the first column, code by distance from a route, then effects, then exits", () => {
  const L = layout(nodes, edges);
  const col = (id) => L.pos.get(id).column;
  assert.deepStrictEqual(["r1", "r2", "a", "b", "s", "x"].map(col), [0, 0, 1, 2, 3, 4]);
  assert.strictEqual(L.columns, 5);
  assert.deepStrictEqual(L.titles, ["Routes in", "Application code", "", "What was seen", "Routes out"]);
});

test("an effect reached by a short path sits ahead of one reached by a longer path, not lumped into one column", () => {
  // r -> s1 directly, r -> a -> s2, so s1's own request span is one hop and s2's is two
  const ns = [n("r", "route"), n("a", "code"), n("s1", "effect"), n("s2", "effect")];
  const L = layout(ns, [e("r", "a"), e("r", "s1"), e("a", "s2")]);
  const col = (id) => L.pos.get(id).column;
  assert.strictEqual(col("s1"), 1, "s1 is one hop from its route, same distance as a");
  assert.strictEqual(col("s2"), 2, "s2 is a hop further, after a");
  assert.ok(col("s1") < col("s2"));
});

test("two paths of different lengths to the same effect both draw in, and the shared node sits at the longer distance", () => {
  // r -> s directly (short), and r -> a -> b -> s (long), both ending at the same shared effect
  const ns = [n("r", "route"), n("a", "code"), n("b", "code"), n("s", "effect")];
  const L = layout(ns, [e("r", "a"), e("a", "b"), e("r", "s"), e("b", "s")]);
  const col = (id) => L.pos.get(id).column;
  assert.strictEqual(col("a"), 1);
  assert.strictEqual(col("b"), 2);
  assert.strictEqual(col("s"), 3, "the shared node sits at the far end of its longest incoming path");
});

test("no two nodes overlap and everything is inside the drawing", () => {
  const L = layout(nodes, edges);
  const boxes = [...L.pos.values()];
  for (let i = 0; i < boxes.length; i++) {
    assert.ok(boxes[i].x >= 0 && boxes[i].y >= 0);
    assert.ok(boxes[i].x + L.nodeW <= L.width && boxes[i].y + L.nodeH <= L.height);
    for (let j = i + 1; j < boxes.length; j++) {
      const apart = boxes[i].x + L.nodeW <= boxes[j].x || boxes[j].x + L.nodeW <= boxes[i].x ||
                    boxes[i].y + L.nodeH <= boxes[j].y || boxes[j].y + L.nodeH <= boxes[i].y;
      assert.ok(apart, "nodes " + i + " and " + j + " overlap");
    }
  }
});

test("a column with no exits is not drawn, and with no code the effects follow the routes", () => {
  const L = layout([n("r", "route"), n("s", "effect")], [e("r", "s")]);
  assert.strictEqual(L.columns, 2);
  assert.deepStrictEqual(L.titles, ["Routes in", "What was seen"]);
});

test("a call cycle does not hang and still gives every method a column", () => {
  const L = layout([n("r", "route"), n("a", "code"), n("b", "code"), n("s", "effect")],
    [e("r", "a"), e("a", "b"), e("b", "a"), e("b", "s")]);
  assert.ok(L.pos.get("a").column >= 1 && L.pos.get("b").column >= 1);
  assert.ok(L.pos.get("s").column > L.pos.get("b").column);
});

test("a node is placed near the ones it is connected to so edges cross less", () => {
  const ns = [n("r1", "route", 5), n("r2", "route", 4), n("s1", "effect", 5), n("s2", "effect", 4)];
  const L = layout(ns, [e("r1", "s2", 5), e("r2", "s1", 4)]);
  const order = (a, b) => L.pos.get(a).y < L.pos.get(b).y;
  assert.strictEqual(order("r1", "r2"), order("s2", "s1"), "r1 -> s2 and r2 -> s1 should not cross");
});

test("edges to nodes that are not there are ignored", () => {
  assert.doesNotThrow(() => layout([n("r", "route")], [e("r", "missing")]));
});

test("through follows paths in both directions and nothing else", () => {
  const seen = through("b", edges);
  assert.deepStrictEqual([...seen].sort(), ["a", "b", "r1", "s", "x"]);
  assert.ok(!seen.has("r2"), "r2 only reaches s, not b");
});

test("an empty graph has a size", () => {
  const L = layout([], []);
  assert.ok(L.width > 0 && L.height > 0);
});

test("a curve starts at the right edge of one node and ends at the left edge of the next", () => {
  assert.strictEqual(curve({ x: 0, y: 10 }, { x: 340, y: 50 }, 220).startsWith("M220,10 C"), true);
  assert.ok(curve({ x: 0, y: 10 }, { x: 340, y: 50 }, 220).endsWith("340,50"));
});

test("only the edges on a path through a node light up, not a call that skips it", () => {
  // init calls both create and update, and create calls update, so init -> update skips create
  const ns = [n("route", "route"), n("init", "code"), n("create", "code"), n("update", "code"), n("effect", "effect")];
  const es = [e("route", "init"), e("init", "create"), e("create", "update"), e("init", "update"), e("update", "effect")];
  const on = [...pathEdges("create", es)].map((x) => x.from + ">" + x.to).sort();
  assert.deepStrictEqual(on, ["create>update", "init>create", "route>init", "update>effect"]);
  assert.ok(through("create", es).has("init"), "init is still on a path through create");
});

test("every inbound edge of a node lights up, however many there are", () => {
  const es = [e("r1", "a"), e("r2", "b"), e("a", "m"), e("b", "m"), e("c", "m"), e("m", "s")];
  const on = [...pathEdges("m", es)].filter((x) => x.to === "m").map((x) => x.from).sort();
  assert.deepStrictEqual(on, ["a", "b", "c"]);
});

const m = (id, full, events) => ({ id, kind: "code", label: full.split(".").slice(-2).join("."), full, events });

test("a straight run of one class's methods folds into one node that keeps the ends' edges", () => {
  const ns = [n("r", "route", 50), m("i", "app.Database.<init>", 50), m("j", "app.Database.load", 50), m("d", "app.Database.init", 50), n("s", "effect", 50)];
  const es = [e("r", "i", 50), e("i", "j", 50), e("j", "d", 50), e("d", "s", 50)];
  const out = collapse(ns, es);
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r", "i", "s"]);
  assert.deepStrictEqual(out.nodes[1].members, ["i", "j", "d"]);
  assert.strictEqual(out.nodes[1].label, "Database (<init>, load, init)");
  assert.deepStrictEqual(out.edges.map((x) => x.from + ">" + x.to), ["r>i", "i>s"]);
  assert.strictEqual(out.head.get("d"), "i");
});

test("a run that branches, changes class, or loses events is left open", () => {
  const branch = collapse([n("r", "route"), m("a", "app.A.x", 5), m("b", "app.A.y", 5), n("s", "effect")],
    [e("r", "a"), e("a", "b"), e("a", "s")]);
  assert.strictEqual(branch.nodes.length, 4);
  const other = collapse([n("r", "route"), m("a", "app.A.x", 5), m("b", "app.B.y", 5)], [e("r", "a"), e("a", "b")]);
  assert.strictEqual(other.nodes.length, 3);
  const fewer = collapse([n("r", "route"), m("a", "app.A.x", 5), m("b", "app.A.y", 2)], [e("r", "a"), e("a", "b", 2)]);
  assert.strictEqual(fewer.nodes.length, 3);
  const merge = collapse([n("r", "route"), n("r2", "route"), m("a", "app.A.x", 5), m("b", "app.A.y", 5)], [e("r", "a"), e("a", "b"), e("r2", "b")]);
  assert.strictEqual(merge.nodes.length, 4, "b has two callers, so it is a meeting point");
});

test("a call cycle of one class does not hang collapse", () => {
  assert.doesNotThrow(() => collapse([m("a", "app.A.x", 5), m("b", "app.A.y", 5)], [e("a", "b"), e("b", "a")]));
});

test("a static initializer that only leads to a method of its own class is dropped and counted on that method", () => {
  // Ticket.<clinit> is 11 of the 62 events through Ticket.<init>, which other methods call too
  const ns = [n("r", "route", 62), m("o", "app.Other.go", 51), m("c", "app.Ticket.<clinit>", 11), m("i", "app.Ticket.<init>", 62)];
  const es = [e("r", "o", 51), e("r", "c", 11), e("o", "i", 51), e("c", "i", 11)];
  const out = collapse(ns, es);
  assert.deepStrictEqual(out.nodes.map((x) => x.id).sort(), ["i", "o", "r"]);
  assert.strictEqual(out.nodes.find((x) => x.id === "i").firstUse, 11);
  assert.deepStrictEqual(out.edges.map((x) => x.from + ">" + x.to + ":" + x.events).sort(), ["o>i:51", "r>i:11", "r>o:51"]);
  assert.strictEqual(out.head.get("c"), "i");
});

test("an initializer that leads on to anything else stays, and so does one into another class", () => {
  const branch = collapse([n("r", "route"), m("c", "app.A.<clinit>", 5), m("i", "app.A.<init>", 5), n("s", "effect")],
    [e("r", "c"), e("c", "i"), e("c", "s")]);
  assert.ok(branch.nodes.some((x) => x.id === "c"));
  const other = collapse([n("r", "route"), m("c", "app.A.<clinit>", 5), m("i", "app.B.<init>", 5)], [e("r", "c"), e("c", "i")]);
  assert.ok(other.nodes.some((x) => x.id === "c"));
});

test("an initializer that folds away still lets the rest of the chain fold, and the count carries to the merged node", () => {
  const ns = [n("r", "route", 50), m("c", "app.Database.<clinit>", 50), m("i", "app.Database.<init>", 50), m("d", "app.Database.init", 50)];
  const out = collapse(ns, [e("r", "c", 50), e("c", "i", 50), e("i", "d", 50)]);
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r", "i"]);
  assert.deepStrictEqual(out.nodes[1].members, ["i", "d"]);
  assert.strictEqual(out.nodes[1].firstUse, 50);
  assert.strictEqual(out.head.get("c"), "i");
  assert.strictEqual(out.head.get("d"), "i");
});

test("a shorter column is spread over the height of the tallest, and a lone node sits at its middle", () => {
  const ns = [n("r", "route", 9), n("a", "effect", 5), n("b", "effect", 4), n("c", "effect", 3), n("x", "exit", 1)];
  const L = layout(ns, [e("r", "a"), e("r", "b"), e("r", "c"), e("a", "x")]);
  const mid = (id) => L.pos.get(id).y + L.nodeH / 2;
  const top = Math.min(...["a", "b", "c"].map((id) => L.pos.get(id).y));
  const bottom = Math.max(...["a", "b", "c"].map((id) => L.pos.get(id).y)) + L.nodeH;
  assert.ok(Math.abs(mid("r") - (top + bottom) / 2) < L.nodeH, "the lone route is level with the middle of the tall column");
  assert.ok(Math.abs(mid("x") - (top + bottom) / 2) < L.nodeH);
});

test("the nodes of a spread column keep their order and are evenly apart", () => {
  const ns = [n("r1", "route", 9), n("r2", "route", 8), n("s1", "effect", 5), n("s2", "effect", 4), n("s3", "effect", 3), n("s4", "effect", 2)];
  const L = layout(ns, [e("r1", "s1"), e("r1", "s2"), e("r2", "s3"), e("r2", "s4")]);
  const ys = ["r1", "r2"].map((id) => L.pos.get(id).y);
  const col = ["s1", "s2", "s3", "s4"].map((id) => L.pos.get(id).y).sort((p, q) => p - q);
  assert.ok(ys[1] - ys[0] > col[1] - col[0], "two routes are further apart than four effects");
  assert.ok(Math.abs((col[2] - col[1]) - (col[1] - col[0])) < 0.001);
});
