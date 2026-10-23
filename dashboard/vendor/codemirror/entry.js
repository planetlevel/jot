// The YAML editor of the JOTs page. Bundled into ../../static/codemirror.js, see package.json.
import { EditorState, Compartment } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting, indentOnInput } from "@codemirror/language";
import { setDiagnostics, lintGutter } from "@codemirror/lint";
import { autocompletion, completionKeymap } from "@codemirror/autocomplete";
import { tags as t } from "@lezer/highlight";

// colors come from the page's own variables, so the editor follows the light and dark themes
const theme = EditorView.theme({
  "&": { color: "var(--text)", backgroundColor: "var(--code)", border: "1px solid var(--line)", borderRadius: "8px",
         fontSize: "12.5px" },
  "&.cm-focused": { outline: "2px solid var(--accent)", outlineOffset: "-1px" },
  ".cm-scroller": { fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace", lineHeight: "1.5" },
  ".cm-gutters": { backgroundColor: "transparent", color: "var(--muted)", border: "none" },
  ".cm-activeLine, .cm-activeLineGutter": { backgroundColor: "color-mix(in srgb, var(--accent) 8%, transparent)" },
  ".cm-cursor": { borderLeftColor: "var(--text)" },
  "&.cm-focused .cm-selectionBackground, .cm-selectionBackground": { backgroundColor: "color-mix(in srgb, var(--accent) 28%, transparent)" },
  ".cm-diagnostic-error": { borderLeft: "3px solid var(--blocked)" },
  ".cm-tooltip": { backgroundColor: "var(--panel)", color: "var(--text)", border: "1px solid var(--line)" },
  ".cm-tooltip-autocomplete ul li[aria-selected]": { backgroundColor: "color-mix(in srgb, var(--accent) 24%, transparent)", color: "var(--text)" },
  ".cm-completionDetail": { color: "var(--muted)", fontStyle: "normal", marginLeft: "1em" },
});

const highlight = HighlightStyle.define([
  { tag: [t.propertyName, t.definition(t.propertyName)], color: "var(--accent)" },
  { tag: [t.string, t.special(t.string)], color: "var(--observed)" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "var(--monitored)" },
  { tag: [t.comment, t.lineComment], color: "var(--muted)", fontStyle: "italic" },
  { tag: [t.meta, t.separator, t.punctuation], color: "var(--muted)" },
]);


// What a report can say, and the code completion for it. sensors() gives [{ name, description, fields }], the JOTs that are defined,
// so what is offered for rows, cols, value and by is only what a report can read, written sensor.field.
const REPORT_KEYS = [["name", "what the report is called"], ["type", "list, compare or table"], ["rows", "compare and table, what the rows are"],
  ["cols", "what the columns are"], ["value", "compare, what fills the cells"], ["by", "compare, who had each value"]];
const REPORT_TYPES = [["list", "where each thing is used"], ["compare", "a grid of rows against columns"], ["table", "several facts about each row"]];

function reportCompletions(sensors) {
  return (context) => {
    const line = context.state.doc.lineAt(context.pos);
    const before = line.text.slice(0, context.pos - line.from);
    const word = context.matchBefore(/[\w.-]*/);
    const from = word ? word.from : context.pos;
    if (!context.explicit && !word) return null;
    const known = sensors() || [];
    const text = context.state.doc.toString();
    const value = (key) => { const m = new RegExp("^" + key + ":[ \\t]*[\"']?([^\"'\\n]*)", "m").exec(text); return m ? m[1].trim() : ""; };
    const key = /^([ \t]*)([a-z-]*)$/.exec(before);
    if (key) {
      const used = new Set([...text.matchAll(/^([a-z-]+):/gm)].map((m) => m[1]));
      return { from, validFor: /^[a-z-]*$/, options: REPORT_KEYS.filter(([k]) => !used.has(k))
        .map(([k, d]) => ({ label: k, detail: d, type: "property", apply: k + ": " })) };
    }
    const at = /^[ \t]*(type|rows|cols|value|by):[ \t]*["']?(?:[^"']*[,\s])?[\w.-]*$/.exec(before);
    if (!at) return null;
    if (at[1] === "type") return { from, validFor: /^[a-z]*$/, options: REPORT_TYPES.map(([k, d]) => ({ label: k, detail: d, type: "keyword" })) };
    // value and by are fields of the sensor that cols reads, so only that sensor is offered once cols says which it is
    const colsSensor = value("cols").split(",")[0].trim().split(".")[0];
    const only = (at[1] === "value" || at[1] === "by") && known.some((s) => s.name === colsSensor) ? colsSensor : null;
    const options = [];
    for (const s of known) {
      if (only && s.name !== only) continue;
      for (const f of s.fields || []) options.push({ label: s.name + "." + f, detail: s.description || s.name, type: "variable", boost: 1 });
      options.push({ label: s.name, detail: "everything it captured, as one line", type: "class", boost: -1 });
    }
    return { from, validFor: /^[\w.-]*$/, options };
  };
}

/** An editor in parent. options are doc, readOnly, onChange(text), onSave() and sensors(), which turns on code completion for a report.
 *  Returns what the page needs of it. */
function create(parent, options) {
  const opts = options || {};
  const editable = new Compartment();
  const view = new EditorView({
    parent,
    state: EditorState.create({
      doc: opts.doc || "",
      extensions: [
        lineNumbers(), highlightActiveLine(), highlightActiveLineGutter(), drawSelection(), history(), indentOnInput(),
        lintGutter(), yaml(), syntaxHighlighting(highlight), theme,
        ...(opts.sensors ? [autocompletion({ override: [reportCompletions(opts.sensors)], icons: false }), keymap.of(completionKeymap)] : []),
        keymap.of([{ key: "Mod-s", preventDefault: true, run: () => { if (opts.onSave) opts.onSave(); return true; } },
                   ...defaultKeymap, ...historyKeymap, indentWithTab]),
        editable.of([EditorState.readOnly.of(!!opts.readOnly), EditorView.editable.of(!opts.readOnly)]),
        EditorView.updateListener.of((u) => { if (u.docChanged && opts.onChange) opts.onChange(u.state.doc.toString()); }),
      ],
    }),
  });
  return {
    get: () => view.state.doc.toString(),
    set: (text) => view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: text || "" } }),
    readOnly: (on) => view.dispatch({ effects: editable.reconfigure([EditorState.readOnly.of(!!on), EditorView.editable.of(!on)]) }),
    // problems is a list of { line, message }, line counting from 1. An empty list clears them
    problems: (list) => view.dispatch(setDiagnostics(view.state, (list || []).map((p) => {
      const line = view.state.doc.line(Math.min(Math.max(1, p.line || 1), view.state.doc.lines));
      return { from: line.from, to: line.to, severity: "error", message: p.message };
    }))),
    focus: () => view.focus(),
    destroy: () => view.destroy(),
  };
}

export { create };
