"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { pivot } = require("../static/grid.js");

test("routes by roles with an X where detected, columns come from the data", () => {
  const g = pivot(["route", "role"], [
    ["/buy", "RoleB"], ["/buy", "RoleA"], ["/home", "RoleA"], ["/buy", "RoleA"],
  ]);
  assert.deepStrictEqual(g.columns, ["RoleA", "RoleB"]);
  assert.deepStrictEqual(g.rows, [
    { label: "/buy", cells: [["X"], ["X"]] },
    { label: "/home", cells: [["X"], []] },
  ]);
  assert.strictEqual(g.corner, "route");
});

test("a third column supplies the cell values, several are listed together", () => {
  const g = pivot(["route", "sensor", "value"], [
    ["/a", "crypto-cipher", "DES"], ["/a", "crypto-cipher", "AES"], ["/a", "crypto-hash", "MD5"], ["/a", "crypto-cipher", "DES"],
  ]);
  assert.deepStrictEqual(g.columns, ["crypto-cipher", "crypto-hash"]);
  assert.deepStrictEqual(g.rows[0].cells, [["AES", "DES"], ["MD5"]]);
});

test("an empty or missing value falls back to X", () => {
  const g = pivot(["r", "c", "v"], [["a", "b", ""], ["a", "d", null]]);
  assert.deepStrictEqual(g.rows[0].cells, [["X"], ["X"]]);
});

test("null labels are shown as a dash and numbers sort naturally", () => {
  const g = pivot(["r", "c"], [[null, "col10"], ["row2", "col2"], ["row10", "col1"]]);
  assert.deepStrictEqual(g.columns, ["col1", "col2", "col10"]);
  assert.deepStrictEqual(g.rows.map((r) => r.label), ["row2", "row10", "—"].sort((a, b) => a.localeCompare(b, undefined, { numeric: true })));
});

test("too many columns are cut and counted", () => {
  const rows = [];
  for (let i = 0; i < 10; i++) rows.push(["r", "c" + String(i).padStart(2, "0")]);
  const g = pivot(["r", "c"], rows, { maxCols: 4 });
  assert.strictEqual(g.columns.length, 4);
  assert.strictEqual(g.hiddenColumns, 6);
  assert.strictEqual(g.rows[0].cells.length, 4);
});

test("html in values stays text, the grid only returns strings", () => {
  const g = pivot(["r", "c"], [["<img src=x onerror=alert(1)>", "<b>"]]);
  assert.strictEqual(typeof g.rows[0].label, "string");
  assert.strictEqual(g.rows[0].label, "<img src=x onerror=alert(1)>");
});

test("an empty result gives an empty grid", () => {
  const g = pivot(["r", "c"], []);
  assert.deepStrictEqual(g.rows, []);
  assert.deepStrictEqual(g.columns, []);
});

test("a captured list loses its brackets so each item reads on its own", () => {
  const g = pivot(["r", "c", "v"], [["a", "q", "[SELECT 1]"], ["a", "q", "[SELECT 2]"], ["a", "w", "[x], [y]"]]);
  assert.deepStrictEqual(g.rows[0].cells, [["SELECT 1", "SELECT 2"], ["[x], [y]"]]);
});

test("a fourth column says who had each value, kept by cell and value", () => {
  const g = pivot(["route", "role", "allowed", "user"], [
    ["/a", "RoleA", "true", "UserB"], ["/a", "RoleA", "false", "UserA"], ["/a", "RoleA", "false", "UserC"], ["/a", "RoleA", "false", "UserA"],
  ]);
  assert.deepStrictEqual(g.rows[0].cells[0], ["false", "true"]);
  assert.deepStrictEqual(g.rows[0].notes[0], { true: ["UserB"], false: ["UserA", "UserC"] });
});

test("without a fourth column the cells have no notes", () => {
  const g = pivot(["route", "role", "allowed"], [["/a", "RoleA", "true"]]);
  assert.strictEqual(g.rows[0].notes, undefined);
});
