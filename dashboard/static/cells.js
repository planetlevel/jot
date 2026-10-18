"use strict";
// Shortens the values of columns that are long to read in a table of events. The full value stays available as the
// title, so hovering shows it.
(function (root) {
  // 2026-10-17 15:05:16 is shown as 15:05:16
  function shortTime(v) {
    const m = /^\d{4}-\d\d-\d\d[ T](\d\d:\d\d:\d\d)/.exec(v);
    return m ? m[1] : v;
  }

  // com.acme.ticketbook.Ticket.encrypt, or the same with its file and line, is shown as Ticket.encrypt
  function shortCallSite(v) {
    const name = v.split("(")[0];
    return name.split(".").slice(-2).join(".") || v;
  }

  // what to show for a value in this column, and the title that gives all of it. A column that isn't shortened has no title.
  function shorten(col, v) {
    if (typeof v !== "string") return { text: v, title: null };
    const text = col === "time" ? shortTime(v) : col === "call_site" ? shortCallSite(v) : v;
    return { text, title: text === v ? null : v };
  }

  const api = { shortTime, shortCallSite, shorten };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotCells = api;
})(typeof window !== "undefined" ? window : globalThis);
