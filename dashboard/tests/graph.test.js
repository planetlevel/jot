"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { layout, through, pathEdges, curve } = require("../static/graph.js");

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
