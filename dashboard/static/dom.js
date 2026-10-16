"use strict";
// Builds elements. Text is only ever added as text, because captured values can be hostile.
// A property that is null, undefined or false is left off, so `disabled: cond ? "" : null` means
// disabled only when cond is true. (Setting the attribute to the string "null" would still disable it.)
(function (root) {
  function makeEl(doc) {
    return function el(tag, props, ...kids) {
      const e = doc.createElement(tag);
      for (const [k, v] of Object.entries(props || {})) {
        if (v === null || v === undefined || v === false) continue;
        if (k === "class") e.className = v;
        else if (k === "text") e.textContent = v;
        else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
        else e.setAttribute(k, v === true ? "" : v);
      }
      for (const kid of kids) if (kid != null) e.append(kid);
      return e;
    };
  }

  const api = { makeEl };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotDom = api;
})(typeof window !== "undefined" ? window : globalThis);
