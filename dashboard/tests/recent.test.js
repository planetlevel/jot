"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { remember, MAX } = require("../static/recent.js");

const q = (question, sql = "SELECT 1") => ({ question, sql });

test("a question that returned rows is remembered, newest last", () => {
  let list = remember([], q("a"), 3);
  list = remember(list, q("b"), 1);
  assert.deepStrictEqual(list.map((h) => h.question), ["a", "b"]);
});

test("a question that returned no rows is not remembered", () => {
  const before = [q("a")];
  assert.deepStrictEqual(remember(before, q("nothing"), 0), before);
});

test("a result with no row count, or an error, is not remembered", () => {
  assert.deepStrictEqual(remember([], q("x"), undefined), []);
  assert.deepStrictEqual(remember([], q("x"), null), []);
  assert.deepStrictEqual(remember([], q("x"), -1), []);
});

test("an answer with no SQL, such as 'can't be answered', is not remembered", () => {
  assert.deepStrictEqual(remember([], q("weather?", ""), 5), []);
  assert.deepStrictEqual(remember([], { question: "weather?" }, 5), []);
});

test("asking the same question again moves it to the end instead of repeating it", () => {
  let list = remember([], q("a"), 1);
  list = remember(list, q("b"), 1);
  list = remember(list, q("a", "SELECT 2"), 4);
  assert.deepStrictEqual(list.map((h) => h.question), ["b", "a"]);
  assert.strictEqual(list[1].sql, "SELECT 2");
});

test("a repeat that now returns nothing leaves the earlier entry alone", () => {
  const list = remember([], q("a"), 2);
  assert.deepStrictEqual(remember(list, q("a"), 0), list);
});

test("only the most recent ones are kept", () => {
  let list = [];
  for (let i = 0; i < MAX + 4; i++) list = remember(list, q("q" + i), 1);
  assert.strictEqual(list.length, MAX);
  assert.strictEqual(list[0].question, "q4");
  assert.strictEqual(list[MAX - 1].question, "q" + (MAX + 3));
});

test("the list that was passed in is not modified", () => {
  const before = [q("a")];
  remember(before, q("b"), 1);
  assert.strictEqual(before.length, 1);
});
