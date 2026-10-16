"use strict";
const test = require("node:test");
const assert = require("node:assert");
const { makeEl } = require("../static/dom.js");

// just enough of a document to see what el() does to an element
function fakeDocument() {
  return {
    createElement(tag) {
      const node = { tag, attrs: {}, listeners: {}, kids: [], className: "", textContent: "" };
      node.setAttribute = (k, v) => { node.attrs[k] = String(v); };
      node.addEventListener = (type, fn) => { node.listeners[type] = fn; };
      node.append = (kid) => { node.kids.push(kid); };
      return node;
    },
  };
}
const el = makeEl(fakeDocument());

test("a null or undefined or false property is left off, so disabled: null does not disable", () => {
  const b = el("button", { disabled: null, hidden: undefined, "aria-checked": false, title: "t" });
  assert.deepStrictEqual(b.attrs, { title: "t" });
});

test("an empty string sets the attribute, which is how a control is disabled", () => {
  const b = el("button", { disabled: "" });
  assert.ok("disabled" in b.attrs);
});

test("the condition form used by the rule switches works both ways", () => {
  const cond = (writable) => el("button", { disabled: !writable ? "" : null });
  assert.ok("disabled" in cond(false).attrs);
  assert.ok(!("disabled" in cond(true).attrs));
});

test("class, text and handlers are set the right way", () => {
  let clicked = false;
  const b = el("button", { class: "chip", text: "hi", onclick: () => { clicked = true; } });
  assert.strictEqual(b.className, "chip");
  assert.strictEqual(b.textContent, "hi");
  b.listeners.click();
  assert.ok(clicked);
});

test("children are appended and null children are skipped", () => {
  const d = el("div", {}, "text", null, el("span"), undefined);
  assert.strictEqual(d.kids.length, 2);
});

test("true sets a bare attribute", () => {
  assert.strictEqual(el("input", { required: true }).attrs.required, "");
});
