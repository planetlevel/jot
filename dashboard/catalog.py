"""The catalog of generic sensors, rules and reports in the repository's catalog folder, which the assistant copies from.

A project's configuration is one file, so nothing is loaded from the catalog. The assistant looks through it for what fits the application it
has looked at, and proposes copies to put in the project's own jot.yaml, where they can be changed. The catalog files are the same format as
any .jot file, so they are checked like one, see CatalogTests.
"""

import glob
import os
import re

import yaml

import store


def _mapping(item):
    """A list item as a mapping, which is how a draft is written. The comments before it stay, the dash goes, and what was indented under it
    moves left to match."""
    out, started = [], False
    for line in item.rstrip("\n").split("\n"):
        if not started and line.startswith("- "):
            started = True
            out.append(line[2:])
        elif started and line.startswith("  "):
            out.append(line[2:])
        else:
            out.append(line)
    return "\n".join(out) + "\n"


class Catalog:
    def __init__(self, path):
        self.path = path
        self._seen = None
        self._items = []

    def available(self):
        return bool(self.path) and os.path.isdir(self.path)

    def items(self):
        """Every sensor, rule and report as dicts with name, kind (sensor, rule or report), area (the file it is in), description, needs (the
        sensors a report reads, or the fields of a sensor) and text, which is the definition as written. Read again when a file changes."""
        if not self.available():
            return []
        files = sorted(glob.glob(os.path.join(self.path, "*.jot")))
        signature = [(f, os.path.getmtime(f)) for f in files]
        if signature == self._seen:
            return self._items
        out, names = [], {}
        for f in files:
            area = os.path.splitext(os.path.basename(f))[0]
            with open(f, encoding="utf-8") as fh:
                text = fh.read()
            try:
                doc = yaml.safe_load(text) or {}
            except yaml.YAMLError:
                continue
            for key, kind in (("sensors", "sensor"), ("reports", "report")):
                for (name, body), definition in zip(store._list_items(text, key), doc.get(key) or []):
                    if not name or name in names:
                        continue
                    row = {"name": name, "kind": "report" if kind == "report" else "rule" if "block-when" in definition else "sensor", "area": area,
                           "description": definition.get("description") or definition.get("title") or "", "text": _mapping(body), "definition": definition}
                    names[name] = row
                    out.append(row)
        sensors = [n for n, r in names.items() if r["kind"] != "report"]
        for row in out:
            if row["kind"] == "report":
                used = " ".join(str(v) for v in row["definition"].values() if isinstance(v, (str, list)))
                row["needs"] = [n for n in sensors if re.search(r"(?<![\w-])%s(?:\.\w|\s*\))" % re.escape(n), used)]
            else:
                row["needs"] = []
                row["fields"] = list((row["definition"].get("captures") or {}).keys())
        self._seen, self._items = signature, out
        return out

    def get(self, name):
        return next((r for r in self.items() if r["name"] == name), None)

    def listing(self):
        """What the model is shown first, short, so it can choose."""
        out = []
        for r in self.items():
            row = {"name": r["name"], "kind": r["kind"], "area": r["area"], "description": r["description"]}
            if r["kind"] == "report":
                row["needs_sensors"] = r["needs"]
            else:
                row["methods"] = (r["definition"].get("methods") or [])[:3]
                row["fields"] = r.get("fields", [])
            out.append(row)
        return out
