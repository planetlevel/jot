"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { layout, through, curve, collapse, sensorFor, frameMethod, curveDown, prune, neighbor, heightOf, innerAt } = require("../static/graph.js");

const n = (id, kind, events = 1) => ({ id, kind, label: id, events });
const e = (from, to, events = 1) => ({ from, to, events });

const nodes = [n("r1", "route", 9), n("r2", "route", 3), n("a", "code", 9), n("b", "code", 5), n("s", "effect", 9), n("x", "exit", 1)];
const edges = [e("r1", "a"), e("a", "b"), e("b", "s"), e("r2", "s"), e("s", "x")];

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

test("the main line is the path through the busiest boxes, one box to a column, and the rest branch off it", () => {
  const L = layout(nodes, edges);
  const col = (id) => L.pos.get(id).column;
  assert.deepStrictEqual(L.spine, ["r1", "a", "b", "s", "x"]);
  assert.deepStrictEqual(["r1", "a", "b", "s", "x"].map(col), [0, 1, 2, 3, 4]);
  assert.strictEqual(new Set(L.spine.map((id) => L.pos.get(id).row)).size, 1, "all on one row");
  assert.notStrictEqual(L.pos.get("r2").row, L.pos.get("r1").row, "the other route is on another row");
  assert.strictEqual(L.columns, 5);
});

test("a branch sits one column on from where it leaves the main line, not out at the end", () => {
  const ns = [n("r", "route", 9), n("a", "code", 9), n("b", "code", 9), n("c", "code", 9), n("d", "code", 9), n("x", "effect", 2)];
  const L = layout(ns, [e("r", "a"), e("a", "b"), e("b", "c"), e("c", "d"), e("a", "x")]);
  assert.strictEqual(L.pos.get("x").column, 2, "right after a");
  assert.strictEqual(L.columns, 5, "the picture is as long as the main line");
});

test("a branch that joins the main line again doesn't push the main line along", () => {
  const ns = [n("r", "route", 9), n("a", "code", 9), n("b", "code", 9), n("c", "code", 9), n("d", "code", 9), n("x", "code", 2), n("y", "code", 2), n("z", "code", 2)];
  const L = layout(ns, [e("r", "a"), e("a", "b"), e("b", "c"), e("c", "d"), e("a", "x"), e("x", "y"), e("y", "z"), e("z", "d")]);
  assert.deepStrictEqual(["r", "a", "b", "c", "d"].map((id) => L.pos.get(id).column), [0, 1, 2, 3, 4], "d stays where the line puts it");
});

test("branches are spread on both sides of the main line, each on its own row in a column", () => {
  const ns = [n("r", "route", 9), n("m", "code", 9), n("z", "code", 9), n("p", "effect", 3), n("q", "effect", 2), n("w", "effect", 1)];
  const L = layout(ns, [e("r", "m"), e("m", "z"), e("m", "p"), e("m", "q"), e("m", "w")]);
  const rows = ["p", "q", "w"].map((id) => L.pos.get(id).row);
  assert.strictEqual(new Set(rows).size, 3, "no two share a row, so none overlap");
  assert.ok(rows.some((r) => r > 0) && rows.some((r) => r < 0), "some above and some below");
  assert.ok(!rows.includes(0), "none on the main line");
  assert.strictEqual(L.pos.get("p").column, L.pos.get("z").column);
});

test("a route a forward leads to sits right after the forward, beside what else came then", () => {
  const ns = [n("r", "route", 9), n("f", "effect", 6), n("page", "code", 4), n("later", "effect", 4), n("x", "exit", 6)];
  const L = layout(ns, [e("r", "f"), e("f", "page"), e("page", "later"), e("f", "x")]);
  const col = (id) => L.pos.get(id).column;
  assert.strictEqual(col("x"), col("f") + 1, "next to the forward, not at the far end");
  assert.strictEqual(col("x"), col("page"));
  assert.notStrictEqual(L.pos.get("x").row, L.pos.get("page").row, "on its own row");
  assert.strictEqual(L.columns, 4);
});

test("the main line is what most requests did when the server says how many did each", () => {
  // one request went r, a, b and five went r, c, d, e. a, b are busier boxes in the sum but the five are the main line
  const ns = [
    { id: "r", kind: "route", label: "r", events: 6, lines: [0, 1] },
    { id: "a", kind: "code", label: "a", events: 40, lines: [0] }, { id: "b", kind: "code", label: "b", events: 40, lines: [0] },
    { id: "c", kind: "code", label: "c", events: 5, lines: [1] }, { id: "d", kind: "code", label: "d", events: 5, lines: [1] },
    { id: "e", kind: "code", label: "e", events: 5, lines: [1] },
  ];
  const es = [{ from: "r", to: "a", events: 1, lines: [0] }, { from: "a", to: "b", events: 1, lines: [0] }, { from: "r", to: "c", events: 5, lines: [1] },
    { from: "c", to: "d", events: 5, lines: [1] }, { from: "d", to: "e", events: 5, lines: [1] }];
  assert.deepStrictEqual(layout(ns, es, { lineCounts: { 0: 1, 1: 5 } }).spine, ["r", "c", "d", "e"]);
  assert.deepStrictEqual(layout(ns, es).spine, ["r", "a", "b"], "without counts it is the path through the most events");
});

test("laid out down it is the same picture with the main line a column", () => {
  const A = layout(nodes, edges), D = layout(nodes, edges, { down: true });
  assert.deepStrictEqual(D.spine, A.spine);
  assert.strictEqual(D.pos.get("x").y > D.pos.get("r1").y, true);
  assert.strictEqual(D.pos.get("x").x, D.pos.get("r1").x, "the main line shares an x");
});

const pn = (id, kind = "code") => ({ id, kind, label: id, events: 1, lines: [] });
const pe = (from, to, lines) => ({ from, to, events: 1, lines });

test("with ten requests or fewer nothing is left out", () => {
  const ns = [pn("r", "route"), pn("a"), pn("b")];
  const es = [pe("r", "a", [0]), pe("r", "b", [1])];
  const out = prune(ns, es, { 0: 8, 1: 1 });
  assert.strictEqual(out.edges.length, 2);
  assert.strictEqual(out.hiddenEdges, 0);
});

test("a path that fewer than two of ten or more requests took is left out, with the box only it led to", () => {
  const ns = [pn("r", "route"), pn("a"), pn("b"), pn("rare")];
  const es = [pe("r", "a", [0, 1]), pe("a", "b", [0]), pe("a", "rare", [1])];
  const out = prune(ns, es, { 0: 10, 1: 1 });
  assert.deepStrictEqual(out.edges.map((x) => x.to), ["a", "b"]);
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r", "a", "b"]);
  assert.strictEqual(out.hiddenEdges, 1);
  assert.strictEqual(out.hiddenNodes, 1);
});

test("from twenty requests a path needs a tenth of them, counted over every kind of request that used it", () => {
  const ns = [pn("r", "route"), pn("a"), pn("b")];
  // twenty-five requests of five kinds, five each. The path to b is taken by two kinds, ten requests, so it stays
  const es = [pe("r", "a", [0, 1, 2, 3, 4]), pe("a", "b", [0, 1])];
  assert.strictEqual(prune(ns, es, { 0: 5, 1: 5, 2: 5, 3: 5, 4: 5 }).edges.length, 2);
  // thirty requests, and a path only one kind of three took is two of thirty
  const only = prune([pn("r", "route"), pn("a"), pn("c")], [pe("r", "a", [0, 1]), pe("a", "c", [2])], { 0: 14, 1: 14, 2: 2 });
  assert.deepStrictEqual(only.edges.map((x) => x.to), ["a"]);
});

test("the route is always kept, even when every path from it is rare", () => {
  const out = prune([pn("r", "route"), pn("a")], [pe("r", "a", [3])], { 0: 30, 3: 1 });
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r"]);
});

// a box that holds the sensors that fired directly in it, as inner boxes. What it says of itself is made of them
const hold = (id, ...inner) => {
  const held = inner.map((i) => Object.assign({ sensor: id, events: 1, blocked: 0, monitored: 0, lines: [] }, i));
  return Object.assign(pn(id), { inner: held, lines: [...new Set(held.flatMap((i) => i.lines))], blocked: held.reduce((t, i) => t + i.blocked, 0), monitored: held.reduce((t, i) => t + i.monitored, 0) });
};
const fx = (id, extra = {}) => hold(id, extra);

test("what a sensor saw is never left out, even when only one request in a hundred did it", () => {
  // the xxe page, 99 ordinary requests and one that read a file
  const ns = [pn("r", "route"), fx("cache", { lines: [0] }), fx("file", { lines: [1] })];
  const es = [pe("r", "cache", [0]), pe("r", "file", [1])];
  const out = prune(ns, es, { 0: 99, 1: 1 });
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r", "cache", "file"], "the file read is drawn");
  assert.strictEqual(out.edges.length, 2);
  assert.strictEqual(out.hiddenEdges, 0);
});

test("when every path to a sensor's box is rare the commonest one is kept, and not all of them", () => {
  const ns = [pn("r", "route"), pn("a"), pn("b"), fx("file", { lines: [1, 2] })];
  const es = [pe("r", "a", [0, 1, 2]), pe("a", "file", [1, 2]), pe("r", "b", [1]), pe("b", "file", [1])];
  // 100 requests, 97 did something else, 2 took the path through a, and 1 the path through b
  const out = prune(ns, es, { 0: 97, 1: 1, 2: 2 });
  assert.deepStrictEqual(out.edges.map((x) => x.to).sort(), ["a", "file"], "the edge through a is common enough, the one through b is not brought back");
  assert.strictEqual(out.hiddenEdges, 2);
});

test("a box with a rare path and a common one keeps only the common one", () => {
  const ns = [pn("r", "route"), pn("a"), pn("rare"), fx("file", { lines: [0, 1] })];
  const es = [pe("r", "a", [0, 1]), pe("a", "file", [0]), pe("r", "rare", [1]), pe("rare", "file", [1])];
  const out = prune(ns, es, { 0: 99, 1: 1 });
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r", "a", "file"], "the sensor is drawn, so there is nothing to bring back");
});

test("everything a rule blocked or reported keeps every path to it, however rare", () => {
  const ns = [pn("r", "route"), pn("a"), pn("rare"), fx("exec", { lines: [0, 1], blocked: 1 })];
  const es = [pe("r", "a", [0]), pe("a", "exec", [0]), pe("r", "rare", [1]), pe("rare", "exec", [1])];
  const out = prune(ns, es, { 0: 99, 1: 1 });
  assert.strictEqual(out.edges.length, 4, "the one request that was blocked is drawn along with the others");
  assert.strictEqual(out.hiddenEdges, 0);
  const reported = prune([pn("r", "route"), pn("a"), pn("rare"), fx("exec", { lines: [0, 1], monitored: 3 })], es, { 0: 99, 1: 1 });
  assert.strictEqual(reported.edges.length, 4, "and the same for what was only reported");
});

test("a path that leads to no sensor is still left out when it is rare", () => {
  const ns = [pn("r", "route"), pn("a"), pn("dead"), fx("cache", { lines: [0] })];
  const es = [pe("r", "a", [0, 1]), pe("a", "cache", [0]), pe("a", "dead", [1])];
  const out = prune(ns, es, { 0: 99, 1: 1 });
  assert.deepStrictEqual(out.nodes.map((x) => x.id), ["r", "a", "cache"]);
  assert.strictEqual(out.hiddenEdges, 1);
});

test("a sensor with no line of its own is left to the rule for every other box", () => {
  const out = prune([pn("r", "route"), fx("odd")], [pe("r", "odd", [])], { 0: 99, 1: 1 });
  assert.strictEqual(out.edges.length, 1, "an edge with no lines is always kept, and nothing here is brought back");
});

// boxes at (x, y), the top left corner of each, laid out like columns of a left to right graph
const grid = new Map([["r", { x: 0, y: 100 }], ["a", { x: 200, y: 0 }], ["b", { x: 200, y: 100 }], ["c", { x: 200, y: 200 }], ["s", { x: 400, y: 100 }], ["t", { x: 400, y: 260 }]]);

test("an arrow key goes to the nearest box on that side", () => {
  assert.strictEqual(neighbor(grid, "r", "right"), "b", "straight along the row, not the box above or below");
  assert.strictEqual(neighbor(grid, "b", "right"), "s");
  assert.strictEqual(neighbor(grid, "s", "left"), "b");
  assert.strictEqual(neighbor(grid, "b", "left"), "r");
  assert.strictEqual(neighbor(grid, "b", "up"), "a");
  assert.strictEqual(neighbor(grid, "b", "down"), "c");
});

test("a key follows the row or column it is on and doesn't jump to a box that is only a little closer in a straight line", () => {
  // from c, s is 200 right and 100 up, t is 200 right and 60 down, and t is the closer to the same row
  assert.strictEqual(neighbor(grid, "c", "right"), "t");
  // from a, the box straight below is chosen over one that is nearer the diagonal
  assert.strictEqual(neighbor(grid, "a", "down"), "b");
});

test("there is nothing to go to past the edge, and a box that is not drawn goes nowhere", () => {
  assert.strictEqual(neighbor(grid, "r", "left"), null);
  assert.strictEqual(neighbor(grid, "a", "up"), null);
  assert.strictEqual(neighbor(grid, "s", "right"), null);
  assert.strictEqual(neighbor(grid, "nope", "right"), null);
});

test("boxes in the same column are not to the left or the right of each other", () => {
  assert.strictEqual(neighbor(new Map([["p", { x: 0, y: 0 }], ["q", { x: 0, y: 80 }]]), "p", "right"), null);
  assert.strictEqual(neighbor(new Map([["p", { x: 0, y: 0 }], ["q", { x: 0, y: 80 }]]), "p", "down"), "q");
});

// ---- a box is a method with a stack of the sensors that fired in it
const holding = (id, sensors, extra = {}) => Object.assign({ id, kind: "code", label: id, full: id, events: 5, lines: [1],
  inner: sensors.map((x) => ({ sensor: x, events: 1, blocked: 0, monitored: 0, lines: [1] })) }, extra);

test("a box is as tall as its header and a row for each sensor inside it", () => {
  assert.strictEqual(heightOf({ inner: [] }), heightOf({}), "no sensors, a plain box");
  const one = heightOf({ inner: [{}] }), two = heightOf({ inner: [{}, {}] }), three = heightOf({ inner: [{}, {}, {}] });
  assert.ok(one > heightOf({}));
  assert.strictEqual(three - two, two - one, "each sensor adds the same");
  assert.ok(innerAt(1).y > innerAt(0).y + innerAt(0).h - 1, "the inner boxes are stacked, not overlapping");
  assert.ok(innerAt(2).y + innerAt(2).h <= three, "and they all fit in the box");
});

test("boxes in a column are stacked by their height so a tall one doesn't cover the one below it", () => {
  const ns = [n("r", "route", 9), holding("a", ["s1", "s2", "s3"], { lines: [1, 2] }), holding("b", ["t"], { lines: [2] }), holding("c", ["u", "v"], { lines: [3] })];
  ns[0].lines = [1, 2, 3];
  const es = [E("r", "a", [1, 2]), E("r", "b", [2]), E("r", "c", [3])];
  const placed = layout(ns, es, { lineCounts: { 1: 5, 2: 2, 3: 1 } });
  const boxes = ["a", "b", "c"].map((id) => ({ id, p: placed.pos.get(id) })).sort((x, y) => x.p.y - y.p.y);
  for (let i = 1; i < boxes.length; i++) assert.ok(boxes[i].p.y >= boxes[i - 1].p.y + boxes[i - 1].p.h, boxes[i].id + " is below " + boxes[i - 1].id);
  assert.strictEqual(placed.pos.get("a").h, heightOf(ns[1]), "a position says how tall its box is");
  assert.ok(placed.height >= Math.max(...boxes.map((x) => x.p.y + x.p.h)), "the picture is as tall as its lowest box");
});

test("the main line is a path, so methods called from the same place are beside each other and not one after another", () => {
  // a calls b and c. Every request went to both, and the line must not run through b and then c as if b called c
  const ns = [L("r", "route", [1]), L("a", "code", [1]), L("b", "code", [1]), L("c", "code", [1])];
  ns[1].events = 9; ns[2].events = 6; ns[3].events = 3;
  const es = [E("r", "a", [1]), E("a", "b", [1]), E("a", "c", [1])];
  const placed = layout(ns, es, { lineCounts: { 1: 4 } });
  assert.deepStrictEqual(placed.spine, ["r", "a", "b"], "the busier of the two carries on");
  assert.strictEqual(placed.pos.get("c").column, placed.pos.get("b").column, "c is next to b");
  assert.notStrictEqual(placed.pos.get("c").y, placed.pos.get("b").y, "and not behind it");
});

test("picking a sensor lights every method it fired in and the paths of the requests that did", () => {
  const ns = [L("r1", "route", [1]), L("r2", "route", [2]), L("r3", "route", [3]),
    holding("a", ["cipher"], { lines: [1] }), holding("b", ["cipher", "hash"], { lines: [2] }), holding("c", ["hash"], { lines: [3] })];
  ns[3].inner[0].lines = [1]; ns[4].inner[0].lines = [2]; ns[4].inner[1].lines = [2]; ns[5].inner[0].lines = [3];
  const es = [E("r1", "a", [1]), E("r2", "b", [2]), E("r3", "c", [3])];
  const lit = through("effect:cipher", ns, es);
  assert.deepStrictEqual(ids(lit.nodes), ["a", "b", "effect:cipher", "r1", "r2"], "the two methods that have it, and the routes into them");
  assert.deepStrictEqual(pairs(lit.edges), ["r1>a", "r2>b"]);
  assert.deepStrictEqual(ids(through("effect:nothing", ns, es).nodes), ["effect:nothing"]);
});

test("folding doesn't drop an initializer that fired a sensor, and a merged run holds what its members did", () => {
  const k = (id, full, inner) => ({ id, kind: "code", label: full, full, events: 5, lines: [1], inner });
  const sensors = (...names) => names.map((x) => ({ sensor: x, events: 1, blocked: 0, monitored: 0, lines: [1] }));
  const kept = collapse([L("r", "route", [1]), k("i", "app.Db.<clinit>", sensors("sql-connection")), k("g", "app.Db.get", [])],
    [E("r", "i", [1]), E("i", "g", [1])]);
  assert.ok(kept.nodes.some((x) => x.id === "i"), "its sensor would be lost with it");
  const merged = collapse([L("r", "route", [1]), k("p", "app.Db.load", []), k("q", "app.Db.init", sensors("sql-statement"))], [E("r", "p", [1]), E("p", "q", [1])]);
  assert.deepStrictEqual(merged.nodes.find((x) => x.id === "p").inner.map((x) => x.sensor), ["sql-statement"]);
});

test("a key goes by where the middle of a tall box is, not its top", () => {
  const tall = new Map([["a", { x: 0, y: 0, h: 120 }], ["b", { x: 200, y: 0, h: 26 }], ["c", { x: 200, y: 50, h: 26 }]]);
  assert.strictEqual(neighbor(tall, "a", "right"), "c", "the middle of a is nearer the middle of c than of b");
  assert.strictEqual(neighbor(tall, "b", "down"), "c");
});
