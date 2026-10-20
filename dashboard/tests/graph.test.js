"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { layout, through, curve, collapse, sensorFor, frameMethod, curveDown } = require("../static/graph.js");

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

test("an empty graph has a size", () => {
  const L = layout([], []);
  assert.ok(L.width > 0 && L.height > 0);
});

test("a curve starts at the right edge of one node and ends at the left edge of the next", () => {
  assert.strictEqual(curve({ x: 0, y: 10 }, { x: 340, y: 50 }, 220).startsWith("M220,10 C"), true);
  assert.ok(curve({ x: 0, y: 10 }, { x: 340, y: 50 }, 220).endsWith("340,50"));
});

// a node or an edge that says which lines, kinds of request, use it
const L = (id, kind, lines) => ({ id, kind, label: id, events: 1, lines });
const E = (from, to, lines) => ({ from, to, events: 1, lines });
const ids = (set) => [...set].sort();
const pairs = (set) => [...set].map((x) => x.from + ">" + x.to).sort();

test("what lights up with a node is what the lines through it use, not everything that can be reached", () => {
  // line 1 is r1 a b, line 2 is r2 b c. b is reachable from a, and c from b, but no request did a and then c
  const ns = [L("r1", "route", [1]), L("a", "code", [1]), L("b", "code", [1, 2]), L("r2", "route", [2]), L("c", "effect", [2])];
  const es = [E("r1", "a", [1]), E("a", "b", [1]), E("r2", "b", [2]), E("b", "c", [2])];
  const lit = through("a", ns, es);
  assert.deepStrictEqual(ids(lit.nodes), ["a", "b", "r1"]);
  assert.deepStrictEqual(pairs(lit.edges), ["a>b", "r1>a"]);
});

test("requests that did the same two things in opposite orders do not light up the whole graph", () => {
  // r1 does A then B, r2 does B then A, so A and B loop. r3 does C and has nothing to do with them
  const ns = [L("r1", "route", [1]), L("r2", "route", [2]), L("r3", "route", [3]), L("A", "effect", [1, 2]), L("B", "effect", [1, 2]), L("C", "effect", [3])];
  const es = [E("r1", "A", [1]), E("A", "B", [1]), E("r2", "B", [2]), E("B", "A", [2]), E("r3", "C", [3])];
  assert.deepStrictEqual(ids(through("C", ns, es).nodes), ["C", "r3"]);
  const lit = through("A", ns, es);
  assert.deepStrictEqual(ids(lit.nodes), ["A", "B", "r1", "r2"], "both requests went through A");
  assert.ok(!lit.nodes.has("C") && !lit.nodes.has("r3"));
  assert.deepStrictEqual(pairs(lit.edges), ["A>B", "B>A", "r1>A", "r2>B"]);
});

test("every inbound edge of a node lights up, however many there are", () => {
  const ns = [L("r1", "route", [1]), L("r2", "route", [2]), L("r3", "route", [3]), L("a", "code", [1]), L("b", "code", [2]), L("c", "code", [3]),
    L("m", "code", [1, 2, 3]), L("s", "effect", [1, 2, 3])];
  const es = [E("r1", "a", [1]), E("r2", "b", [2]), E("r3", "c", [3]), E("a", "m", [1]), E("b", "m", [2]), E("c", "m", [3]), E("m", "s", [1, 2, 3])];
  const on = pairs(through("m", ns, es).edges).filter((x) => x.endsWith(">m"));
  assert.deepStrictEqual(on, ["a>m", "b>m", "c>m"]);
});

test("a node that no line is known for lights up alone", () => {
  const lit = through("x", [n("x", "code")], [e("x", "y")]);
  assert.deepStrictEqual(ids(lit.nodes), ["x"]);
  assert.strictEqual(lit.edges.size, 0);
  assert.strictEqual(through("missing", [], []).nodes.size, 1);
});

test("folding keeps which lines use a node and an edge, and a merged edge uses the lines of both", () => {
  const k = (id, full, lines) => ({ id, kind: "code", label: full, full, events: 5, lines });
  // the initializer is only on line 1, its method is on both, and the route reaches it directly on line 2
  const ns = [L("r", "route", [1, 2]), k("i", "app.Db.<clinit>", [1]), k("g", "app.Db.get", [1, 2]), L("s", "effect", [1, 2])];
  const es = [E("r", "i", [1]), E("i", "g", [1]), E("r", "g", [2]), E("g", "s", [1, 2])];
  const folded = collapse(ns, es);
  const direct = folded.edges.find((x) => x.from === "r" && x.to === "g");
  assert.deepStrictEqual(direct.lines, [1, 2]);
  assert.deepStrictEqual(folded.nodes.find((x) => x.id === "g").lines, [1, 2]);
  assert.deepStrictEqual(ids(through("g", folded.nodes, folded.edges).nodes), ["g", "r", "s"]);
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

test("an edge that closes a loop is left out of the layout, so nothing runs backwards", () => {
  // most requests did A then B, one did B then A, which makes a loop between them
  const ns = [n("r", "route"), n("A", "effect"), n("B", "effect")];
  const es = [e("r", "A", 9), e("A", "B", 9), e("B", "A", 1)];
  const L = layout(ns, es);
  assert.deepStrictEqual([...L.closing], [es[2]], "the order most requests used stays");
  for (const x of es) if (!L.closing.has(x)) assert.ok(L.pos.get(x.from).column < L.pos.get(x.to).column);
});

test("a method becomes a starting JOT named for the class and method", () => {
  const text = sensorFor("com.acme.ticketbook.Database.getConnection", []);
  assert.strictEqual(text, [
    "name: database-get-connection",
    "description: Identifies calls to Database.getConnection",
    "methods:",
    "- com.acme.ticketbook.Database.getConnection",
    "captures:",
    '  args: "#ARGS"',
    '  result: "#RET"',
    "",
  ].join("\n"));
});

test("the name is made unique, handles acronyms and constructors, and what can't be watched gives nothing", () => {
  assert.match(sensorFor("a.b.Database.getConnection", ["database-get-connection"]), /^name: database-get-connection-2\n/);
  assert.match(sensorFor("a.b.UrlHelper.getURLPath", []), /^name: url-helper-get-url-path\n/);
  assert.match(sensorFor("a.b.Ticket.<init>", []), /^name: ticket-new\n/);
  assert.match(sensorFor("a.b.Outer$Inner.run", []), /^name: inner-run\n/);
  assert.strictEqual(sensorFor("a.b.Ticket.<clinit>", []), null);
  assert.strictEqual(sensorFor("a.b.C.m\na.b.C.n", []), null, "a folded run is more than one method");
  assert.strictEqual(sensorFor("", []), null);
});

test("the method of a stack frame has no module, line or file", () => {
  assert.strictEqual(frameMethod("java.base/javax.crypto.Cipher.getInstance(Cipher.java:531)"), "javax.crypto.Cipher.getInstance");
  assert.strictEqual(frameMethod("org.hsqldb.jdbc.JDBCStatement.executeUpdate(Unknown Source)"), "org.hsqldb.jdbc.JDBCStatement.executeUpdate");
  assert.strictEqual(frameMethod("com.acme.Ticket.<init>(Ticket.java:12)"), "com.acme.Ticket.<init>");
  assert.strictEqual(frameMethod(""), "");
});

test("a route a forward leads to sits right after the forward, in the column of what else came at that distance", () => {
  // r -> f (forward) -> page code -> later effect, and f -> x, the route it forwards to
  const ns = [n("r", "route", 9), n("f", "effect", 6), n("page", "code", 4), n("later", "effect", 4), n("x", "exit", 6)];
  const L = layout(ns, [e("r", "f"), e("f", "page"), e("page", "later"), e("f", "x")]);
  const col = (id) => L.pos.get(id).column;
  assert.strictEqual(col("x"), col("f") + 1, "side by side with the forward, not at the far end");
  assert.strictEqual(col("x"), col("page"));
  assert.strictEqual(L.columns, 4, "no column of its own at the end");
  assert.ok(!L.titles.includes("Routes out"));
  assert.notStrictEqual(L.pos.get("x").y, L.pos.get("page").y, "the column grows taller instead of overlapping");
});

test("a route out that comes after everything else still has its own column", () => {
  const ns = [n("r", "route"), n("f", "effect"), n("x", "exit")];
  const L = layout(ns, [e("r", "f"), e("f", "x")]);
  assert.strictEqual(L.pos.get("x").column, 2);
  assert.deepStrictEqual(L.titles, ["Routes in", "What was seen", "Routes out"]);
});

test("laid out down, each step is a row, and a straight path is a straight vertical line", () => {
  const ns = [n("r", "route"), n("a", "code"), n("b", "code"), n("s", "effect")];
  const L = layout(ns, [e("r", "a"), e("a", "b"), e("b", "s")], { down: true });
  assert.ok(L.down);
  const p = (id) => L.pos.get(id);
  assert.ok(p("r").y < p("a").y && p("a").y < p("b").y && p("b").y < p("s").y, "rows go down");
  assert.strictEqual(new Set(ns.map((x) => p(x.id).x)).size, 1, "one box to a row, so they line up");
  assert.ok(L.width < 300, "a long path doesn't make it wide");
  assert.ok(L.height > L.width, "it grows tall instead");
});

test("laid out down, boxes that share a step sit side by side and don't overlap", () => {
  const ns = [n("r", "route"), n("a", "code"), n("b", "code"), n("c", "code")];
  const L = layout(ns, [e("r", "a"), e("r", "b"), e("r", "c")], { down: true });
  const xs = ["a", "b", "c"].map((id) => L.pos.get(id).x).sort((u, v) => u - v);
  assert.ok(xs[1] - xs[0] >= L.nodeW && xs[2] - xs[1] >= L.nodeW, "each box has its own room");
  assert.strictEqual(new Set(["a", "b", "c"].map((id) => L.pos.get(id).y)).size, 1, "on one row");
  assert.ok(L.width >= xs[2] + L.nodeW, "and the picture is wide enough to hold them");
});

test("the layout still runs sideways by default", () => {
  const ns = [n("r", "route"), n("a", "code")];
  const L = layout(ns, [e("r", "a")]);
  assert.ok(!L.down);
  assert.ok(L.pos.get("a").x > L.pos.get("r").x);
});

test("a line down leaves the bottom of one box and arrives at the top of the next", () => {
  assert.strictEqual(curveDown({ x: 100, y: 40 }, { x: 160, y: 120 }), "M100,40 C100,80 160,80 160,120");
});
