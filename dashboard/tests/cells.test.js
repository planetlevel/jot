"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { shortTime, shortCallSite, shorten } = require("../static/cells.js");

test("a time is shown as hh:mm:ss", () => {
  assert.strictEqual(shortTime("2026-10-17 15:05:16"), "15:05:16");
  assert.strictEqual(shortTime("2026-10-17T15:05:16Z"), "15:05:16");
  assert.strictEqual(shortTime("not a time"), "not a time");
});

test("a call site is shown as Class.method, with or without its file and line", () => {
  assert.strictEqual(shortCallSite("com.acme.ticketbook.Ticket.encrypt"), "Ticket.encrypt");
  assert.strictEqual(shortCallSite("com.acme.Ticket.encrypt(Ticket.java:125)"), "Ticket.encrypt");
  assert.strictEqual(shortCallSite("Main"), "Main");
});

test("the full value is the title only when something was cut", () => {
  assert.deepStrictEqual(shorten("time", "2026-10-17 15:05:16"), { text: "15:05:16", title: "2026-10-17 15:05:16" });
  assert.deepStrictEqual(shorten("call_site", "a.B.c"), { text: "B.c", title: "a.B.c" });
  assert.deepStrictEqual(shorten("call_site", "B.c"), { text: "B.c", title: null });
  assert.deepStrictEqual(shorten("capture", "AES"), { text: "AES", title: null });
});

test("a value that isn't text is left alone", () => {
  assert.deepStrictEqual(shorten("time", 5), { text: 5, title: null });
});
