"use strict";
// Turns rows of (row label, column label, optional value) into a grid. The columns are whatever
// values appear, so the query doesn't need to know them. A cell shows its value, or X when the
// result has no value column. Several values in one cell are listed together.
(function (root) {
  function text(v) { return v === null || v === undefined ? "—" : String(v); }
  const byName = (a, b) => a.localeCompare(b, undefined, { numeric: true });

  function pivot(columns, rows, options) {
    const maxCols = (options && options.maxCols) || 80;
    const hasValue = columns.length > 2;
    const cells = new Map();   // row label -> Map(column label -> Set of values)
    const seenCols = new Set();
    for (const x of rows) {
      const row = text(x[0]);
      const col = text(x[1]);
      const value = hasValue && x[2] !== null && x[2] !== undefined && String(x[2]) !== "" ? String(x[2]) : "X";
      seenCols.add(col);
      if (!cells.has(row)) cells.set(row, new Map());
      const byCol = cells.get(row);
      if (!byCol.has(col)) byCol.set(col, new Set());
      byCol.get(col).add(value);
    }
    const allCols = [...seenCols].sort(byName);
    const cols = allCols.slice(0, maxCols);
    const body = [...cells.keys()].sort(byName).map((label) => ({
      label,
      cells: cols.map((c) => {
        const set = cells.get(label).get(c);
        return set ? [...set].sort(byName).join(", ") : "";
      }),
    }));
    return { corner: columns[0] || "", columns: cols, hiddenColumns: allCols.length - cols.length, rows: body };
  }

  const api = { pivot };
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.JotGrid = api;
})(typeof window !== "undefined" ? window : globalThis);
