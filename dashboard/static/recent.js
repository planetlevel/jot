"use strict";
// The list of recent questions. A question is only remembered if it returned something, so the list
// holds questions that worked, and it is also what the model is shown as earlier context.
(function (root) {
  const MAX = 8;

  /**
   * Returns the list with this question added at the end, newest last. The same question moves to the
   * end instead of appearing twice. Nothing is added when the result had no rows, or there was no SQL.
   * The list passed in is not changed.
   */
  function remember(list, item, rowCount, max) {
    if (!item || !item.question || !item.sql || !(rowCount > 0)) return list;
    return list.filter((h) => h.question !== item.question).concat(item).slice(-(max || MAX));
  }

  const api = { remember, MAX };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotRecent = api;
})(typeof window !== "undefined" ? window : globalThis);
