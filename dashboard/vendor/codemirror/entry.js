// The YAML editor of the JOTs page. Bundled into ../../static/codemirror.js, see package.json.
import { EditorState, Compartment } from "@codemirror/state";
import { EditorView, keymap, lineNumbers, highlightActiveLine, highlightActiveLineGutter, drawSelection } from "@codemirror/view";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { yaml } from "@codemirror/lang-yaml";
import { HighlightStyle, syntaxHighlighting, indentOnInput } from "@codemirror/language";
import { setDiagnostics, lintGutter } from "@codemirror/lint";
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
});

const highlight = HighlightStyle.define([
  { tag: [t.propertyName, t.definition(t.propertyName)], color: "var(--accent)" },
  { tag: [t.string, t.special(t.string)], color: "var(--observed)" },
  { tag: [t.number, t.bool, t.null, t.atom], color: "var(--monitored)" },
  { tag: [t.comment, t.lineComment], color: "var(--muted)", fontStyle: "italic" },
  { tag: [t.meta, t.separator, t.punctuation], color: "var(--muted)" },
]);

/** An editor in parent. options are doc, readOnly and onChange(text). Returns what the page needs of it. */
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
        keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
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
