#!/usr/bin/env python3
"""JOT dashboard. Follows JOT's JSON event logs into SQLite and answers questions about them,
in plain English or SQL, as tables and charts that can update live.

    python3 server.py --jots ../demo/ticketbook/.jot/jot.yaml
    ANTHROPIC_API_KEY=... python3 server.py --log '/var/log/app/*.jsonl'
"""

import argparse
import getpass
import json
import os
import sqlite3
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import yaml

import control as control_module
import assistant
import catalog
import launcher
import scanner
import llm
import store

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 64 * 1024
MAX_REPAIRS = 2
MAX_GRID_ROWS = 5000
SCRIPTS = {"/dom.js": "dom.js", "/grid.js": "grid.js", "/recent.js": "recent.js", "/graph.js": "graph.js", "/cells.js": "cells.js",
           "/codemirror.js": "codemirror.js"}   # the only files served besides the page


def load_env(path):
    """Set environment variables from a KEY=VALUE file, such as the one that holds ANTHROPIC_API_KEY.
    Variables already set in the environment win. Returns the names that were set."""
    try:
        with open(path) as f:
            lines = f.read().splitlines()
        mode = os.stat(path).st_mode
    except OSError:
        return []
    if mode & 0o077:
        print("[dashboard] %s can be read by other users, run: chmod 600 %s" % (path, path), file=sys.stderr)
    names = []
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key[len("export "):].strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if key and key not in os.environ:
            os.environ[key] = value
            names.append(key)
    return names


KEY_SKIPPED = "# JOT asked for ANTHROPIC_API_KEY and it was skipped. Delete this line to be asked again."


def ask_for_key(path, ask=getpass.getpass, interactive=None, out=print):
    """On a first run in a terminal, offers to keep an ANTHROPIC_API_KEY in the .env file at path, with only the owner able to read it.
    Does nothing when a key is set already, when the answer was skip last time, or when nobody is at a terminal to answer. Returns True
    when a key was saved."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        return False
    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        return False
    try:
        with open(path) as f:
            lines = f.read().splitlines()
    except OSError:
        lines = []
    if KEY_SKIPPED in lines:
        return False
    out("JOT can answer questions in plain English and set itself up for you, with a model from Anthropic. That needs an "
        "ANTHROPIC_API_KEY.")
    out("It is kept in %s, readable only by you, and git ignores it. Press Enter to skip, the rest of JOT works without it." % path)
    try:
        key = ask("ANTHROPIC_API_KEY: ").strip()
    except (EOFError, KeyboardInterrupt):
        out("")
        return False
    if key and any(c.isspace() for c in key):
        out("That doesn't look like a key, so nothing was saved.")
        return False
    lines = [l for l in lines if l != KEY_SKIPPED]
    lines.append("ANTHROPIC_API_KEY=" + key if key else KEY_SKIPPED)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(path, 0o600)
    if not key:
        out("Skipped. Add ANTHROPIC_API_KEY=... to %s whenever you want it." % path)
        return False
    os.environ["ANTHROPIC_API_KEY"] = key
    out("Saved to %s." % path)
    return True


class App:
    """Everything the dashboard does, apart from HTTP. The generate function is a parameter so tests
    can run without a model."""

    def __init__(self, db_path, ingestor, generate=llm.generate, control=None, jot_paths=(), editable=False, draft=llm.draft_jot,
                 draft_report=llm.draft_report, jots_file=None, assistant_post=None, local=True, catalog_path=None):
        self.draft = draft          # writes a JOT for a request, a parameter so tests can run without a model
        self.draft_report_with = draft_report   # and the same for a report
        self.db_path = db_path
        self.jot_paths = list(jot_paths)   # where the .jot files are, which is where an edited sensor is saved
        self.jots_file = jots_file         # the jots file that lists them, where the entry points are
        self.editable = editable
        self.catalog = catalog.Catalog(catalog_path if catalog_path is not None else os.environ.get("JOT_CATALOG") or os.path.join(HERE, "..", "catalog"))
        self.scanner = scanner.Scanner(self, local=local)   # looks in the project folder, if one is set and this dashboard is not reachable from elsewhere
        self.assistant = assistant.Assistant(self, post=assistant_post, project=self.scanner)
        self._jot_lock = threading.Lock()
        self._jot_seen = self._jot_signature()
        self.ingestor = ingestor
        self.launcher = None        # starts the application from the console, set by build_project for a console only this machine can reach
        self.generate = generate
        self.control = control      # a ControlStore, or None when the jots file has no control

    def report_events(self, name, row=None, col=None):
        """The query for the events behind a cell of a report, or a row or a column of it, and a title for them."""
        db = sqlite3.connect(self.db_path)
        try:
            found = db.execute("SELECT type, rows, cols FROM reports WHERE name = ?", (name,)).fetchone()
        finally:
            db.close()
        if not found:
            raise LookupError("no report called %s" % name)
        sql = store.report_events_sql(found[0], found[1], found[2], row, col)
        parts = [x for x in (row, col) if x is not None]
        return {"sql": sql, "title": "Events behind %s%s" % (name, ", " + ", ".join(parts) if parts else "")}

    def sensors(self):
        db = sqlite3.connect(self.db_path)
        try:
            out = []
            for name, description, methods, scopes, blocks, captures in db.execute(
                    "SELECT name, description, methods, scopes, blocks, captures FROM sensors ORDER BY name"):
                out.append({"name": name, "description": description, "methods": json.loads(methods or "[]"),
                            "scopes": json.loads(scopes or "[]"), "blocks": blocks,
                            "fields": list(json.loads(captures or "{}"))})
            return out
        finally:
            db.close()

    def _jot_signature(self):
        """Which .jot files there are and when each last changed, so a change to any of them can be noticed."""
        out = []
        for f in store.jot_files(self.jot_paths):
            try:
                st = os.stat(f)
                out.append((f, st.st_mtime_ns, st.st_size))
            except OSError:
                pass
        return tuple(out)

    def close(self):
        """Stops following the events, any conversation that is working and the application the console started, when another project replaces
        this one or the console ends."""
        for chat in list(self.assistant.running):
            self.assistant.stop(chat)
        if self.launcher:
            self.launcher.close()
        self.ingestor.stop()
        with self.ingestor.lock:
            self.ingestor.db.close()

    def reload_jots(self, force=False):
        """Read the .jot files again when one has changed since they were last read, whoever changed it, so the page
        shows what the files say without the dashboard being restarted."""
        with self._jot_lock:
            now = self._jot_signature()
            if not force and now == self._jot_seen:
                return False
            self._restart_cache = None          # the files changed, so whether the application needs a restart is worked out again
            db = store.connect(self.db_path)
            try:
                store.load_sensors(db, self.jot_paths)
                store.load_reports(db, self.jot_paths)
            finally:
                db.close()
            self._jot_seen = now
            return True

    def draft_jot(self, request, history=()):
        """Writes a JOT for what the person asked, with the model, and checks it the way the editor does and a little more. A draft
        with problems goes back to the model with them, as a question's SQL does. Returns {"yaml", "explanation", "problems",
        "rule", "hooks"}. Nothing is saved. The model is sent the names and descriptions of the JOTs, the instrumented methods the
        application was seen calling, and the request, never what was captured."""
        request = (request or "").strip()
        if not request:
            raise store.QueryError("say what the JOT should do")
        if len(request) > 2000:
            raise store.QueryError("that is too long, a few sentences are enough")
        sensors = self.sensors()
        taken = {x["name"] for x in sensors}
        seen = store.run_query(self.db_path, """
            SELECT method_name, COUNT(*) AS n FROM events_raw WHERE method_name IS NOT NULL AND sensor NOT LIKE 'jot-%'
            GROUP BY method_name ORDER BY n DESC LIMIT 80""")["rows"]
        past = [{"request": str(h.get("request", ""))[:2000], "yaml": str(h.get("yaml", ""))[:6000]}
                for h in (history or [])[-3:] if isinstance(h, dict)]
        problems, out, text = None, {"explanation": ""}, ""
        for attempt in range(MAX_REPAIRS + 1):
            out = self.draft(request, sensors, [m for m, _ in seen], past, problems)
            text = (out.get("yaml") or "").strip("\n")
            if not text:
                return {"yaml": "", "explanation": out.get("explanation") or "", "problems": [], "rule": False, "hooks": []}
            text = store.stage_rule(text)
            problems = store.check_draft(text, taken)
            if not problems:
                break
        doc = {}
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            pass
        doc = doc if isinstance(doc, dict) else {}
        counts = dict(seen)
        wanted = [str(m).replace("static ", "").lstrip("!").strip() for m in doc.get("methods") or []]
        exact = {}
        if wanted:
            rows = store.run_query(self.db_path, "SELECT method_name, COUNT(*) FROM events_raw WHERE method_name IN (%s) GROUP BY method_name"
                                   % ", ".join(store._lit(m) for m in wanted))["rows"]
            exact = dict(rows)
        hooks = [{"method": m, "seen": exact.get(m, counts.get(m, 0))} for m in wanted]
        return {"yaml": text, "explanation": out.get("explanation") or "", "problems": problems or [],
                "rule": "block-when" in doc, "hooks": hooks}

    def sensor_fields(self):
        """{name: [fields]} of the JOTs that are defined, which is everything a report can read."""
        return {s["name"]: s["fields"] for s in self.sensors()}

    def report_names(self):
        db = sqlite3.connect(self.db_path)
        try:
            return [n for (n,) in db.execute("SELECT name FROM reports ORDER BY rowid")]
        finally:
            db.close()

    def check_report(self, text, editing=None):
        """What is wrong with a report as written, for the editor, including a name another report has. editing is the name of the
        report being changed, which is not another report."""
        return store.check_report_text(text, self.sensor_fields(), [n for n in self.report_names() if n != editing])

    def save_report(self, name, original, text):
        """Write an edited report back into its .jot file, then read the files again so the page shows it."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        path = store.save_report(self.jot_paths, name, original, text, self.sensor_fields(), self.report_names())
        self.reload_jots(force=True)
        return {"saved": os.path.basename(path), "name": (yaml.safe_load(text) or {}).get("name") or name, "reports": [], "notes": []}

    def draft_report(self, request, history=()):
        """Writes a report for what the person asked, with the model, from the JOTs that are defined and the fields they capture, and
        checks it the way the editor does. A draft with problems goes back to the model with them. Returns {"yaml", "explanation",
        "problems", "quiet"}, quiet being the JOTs it reads that have recorded nothing yet, so the report would be empty. Nothing is
        saved. The model is sent definitions only, never what was captured."""
        request = (request or "").strip()
        if not request:
            raise store.QueryError("say what the report should show")
        if len(request) > 2000:
            raise store.QueryError("that is too long, a few sentences are enough")
        sensors = [s for s in self.sensors() if not s["name"].startswith("jot-")]
        fields = {s["name"]: s["fields"] for s in sensors}
        taken = self.report_names()
        past = [{"request": str(h.get("request", ""))[:2000], "yaml": str(h.get("yaml", ""))[:3000]}
                for h in (history or [])[-3:] if isinstance(h, dict)]
        problems, out, text = None, {"explanation": ""}, ""
        for attempt in range(MAX_REPAIRS + 1):
            out = self.draft_report_with(request, sensors, taken, past, problems)
            text = (out.get("yaml") or "").strip("\n")
            if not text:
                return {"yaml": "", "explanation": out.get("explanation") or "", "problems": [], "quiet": []}
            problems = store.check_report_draft(text, fields, taken)
            if not problems:
                break
        doc = {}
        try:
            doc = yaml.safe_load(text) or {}
        except yaml.YAMLError:
            pass
        doc = doc if isinstance(doc, dict) else {}
        used = {str(doc[k]).partition(".")[0] for k in ("rows", "value", "by") if doc.get(k)}
        used |= {c.strip().partition(".")[0] for c in str(doc.get("cols") or "").split(",") if c.strip()}
        used &= set(fields)
        seen = {n for (n,) in store.run_query(self.db_path, "SELECT DISTINCT sensor FROM events_raw")["rows"]}
        return {"yaml": text, "explanation": out.get("explanation") or "", "problems": problems or [],
                "quiet": sorted(used - seen)}

    def add_report(self, file, text):
        """Adds a new report to a file and reads the files again. Like adding a JOT, it needs the dashboard to be allowed to write."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        path = store.add_report(self.jot_paths, file, text, self.sensor_fields())
        self.reload_jots(force=True)
        return {"added": (yaml.safe_load(text) or {}).get("name"), "file": os.path.basename(path)}

    def add_jot(self, file, text):
        """Adds a new JOT to a file and reads the files again. Like a save, it needs the dashboard to be allowed to write."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        path = store.add_sensor(self.jot_paths, file, text)
        self.reload_jots(force=True)
        return {"added": (yaml.safe_load(text) or {}).get("name"), "file": os.path.basename(path)}

    def save_jot(self, name, original, text):
        """Write an edited sensor back into its .jot file, then read the files again so the page shows it."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        path, reports = store.save_sensor(self.jot_paths, name, original, text)
        new_name = (yaml.safe_load(text) or {}).get("name") or name
        notes = []
        if new_name != name and self.control is not None:
            file = self.control.read()
            if name in file["rules"] or name in file["enabled"]:
                notes.append("the control file still has a setting for %s" % name)
        self.reload_jots(force=True)
        return {"saved": os.path.basename(path), "name": new_name, "reports": reports, "notes": notes}

    def delete_jot(self, name, original):
        """Remove a sensor or rule from its .jot file. Reports that read it are left as they are and say so afterward, since the
        page shows them as having a sensor that isn't defined."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        used = store.reports_using(self.jot_paths, name)
        path = store.delete_entry(self.jot_paths, "sensors", name, original)
        notes = []
        if self.control is not None:
            file = self.control.read()
            if name in file["rules"] or name in file["enabled"]:
                notes.append("the control file still has a setting for %s" % name)
        self.reload_jots(force=True)
        return {"deleted": os.path.basename(path), "name": name, "reports": used, "notes": notes}

    def delete_report(self, name, original):
        """Remove a report from its .jot file."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        path = store.delete_entry(self.jot_paths, "reports", name, original)
        self.reload_jots(force=True)
        return {"deleted": os.path.basename(path), "name": name, "reports": [], "notes": []}

    def reports(self):
        """The reports from the .jot files, each with the query that builds it and how to show it."""
        db = sqlite3.connect(self.db_path)
        try:
            out = []
            for name, rtype, rows, cols, value, by in db.execute("SELECT name, type, rows, cols, value, by FROM reports ORDER BY rowid"):
                try:
                    out.append({"name": name, "type": rtype, "title": name, "chart": "grid",
                                "sql": store.report_sql(rtype, rows, cols, value, by)})
                except ValueError:
                    continue
            return out
        finally:
            db.close()

    def jots(self):
        """Everything the JOTs view shows. Read only. How each sensor, rule and report is defined, which file it
        is in, whether it has fired, and what looks wrong."""
        if self.jot_paths:
            self.reload_jots()
        db = sqlite3.connect(self.db_path)
        try:
            rows = db.execute("""SELECT name, description, methods, scopes, captures, blocks, protect, source,
                                        matchers, excludes, definition, enabled FROM sensors ORDER BY rowid""").fetchall()
            issues = [{"level": l, "text": t, "file": f} for l, t, f in db.execute(
                "SELECT level, text, source FROM jot_issues ORDER BY rowid")]
            report_rows = db.execute("SELECT name, type, rows, cols, value, by, source FROM reports ORDER BY rowid").fetchall()
        finally:
            db.close()

        stats = {}
        for sensor, total, last, hour, blocked, monitored in store.run_query(self.db_path, """
                SELECT %s AS jot, COUNT(*), MAX(ts), SUM(ts > (strftime('%%s','now') - 3600) * 1000),
                       SUM(action = 'blocked'), SUM(action = 'monitored')
                FROM events GROUP BY jot""" % store.JOT_NAME_SQL)["rows"]:
            stats[sensor] = {"events": total, "last_ts": last, "last_hour": hour or 0,
                             "blocked": blocked or 0, "monitored": monitored or 0}
        # the reports that read each sensor, which is what deleting it would break
        readers = {}
        for rname, _t, rrows, rcols, rvalue, rby, _f in report_rows:
            refs = [rrows, rvalue, rby]
            for col in str(rcols or "").split(","):
                try:
                    refs += store.column_refs(col.strip()) if col.strip() else []
                except ValueError:
                    pass
            for sensor in sorted({x.partition(".")[0] for x in refs if x}):
                readers.setdefault(sensor, []).append(rname)
        modes = {}
        control = self.control_state() if self.control is not None else None
        if control and control["enabled"]:
            modes = {r["name"]: r["mode"] for r in control["rules"]}

        sensors = []
        for (name, description, methods, scopes, captures, blocks, protect, source,
             matchers, excludes, definition, jot_enabled) in rows:
            rule = blocks is not None
            mode = modes.get(name, "monitor" if protect == "false" else "block") if rule else "observe"
            sensors.append({
                "name": name, "kind": "rule" if rule else "sensor", "mode": mode, "description": description,
                "methods": json.loads(methods or "[]"), "scopes": json.loads(scopes or "[]"),
                "captures": json.loads(captures or "{}"), "matchers": json.loads(matchers or "{}"),
                "excludes": json.loads(excludes or "[]"), "block_when": blocks, "file": source,
                "definition": definition, "jot_enabled": jot_enabled != "false", "used_by": readers.get(name, []),
                "report_sql": store.sensor_report_sql(name, list(json.loads(captures or "{}")), rule),
                **stats.get(name, {"events": 0, "last_ts": None, "last_hour": 0, "blocked": 0, "monitored": 0})})

        # a sensor or rule the agent left out because its file said something wrong
        for text in self.agent_state().get("problems", []):
            issues.append({"level": "warning", "file": None, "text": "the agent left something out, " + text})

        sql_by_name = {r["name"]: r["sql"] for r in self.reports()}
        written = store.report_definitions(self.jot_paths) if self.jot_paths else {}
        reports = [{"name": n, "type": t, "rows": r, "cols": c, "value": v, "by": b, "file": f, "sql": sql_by_name.get(n),
                    "definition": written.get((f, n)) or yaml.safe_dump(
                        {k: x for k, x in (("name", n), ("type", t), ("rows", r), ("cols", c), ("value", v), ("by", b)) if x},
                        sort_keys=False, allow_unicode=True).rstrip()}
                   for n, t, r, c, v, b, f in report_rows]
        files = {}
        main = os.path.basename(self.jots_file) if self.jots_file else None
        if main:
            files[main] = {"sensors": 0, "rules": 0, "reports": 0}      # it can hold sensors and reports of its own, so it is always a place to add them
        for x in sensors:
            files.setdefault(x["file"], {"sensors": 0, "rules": 0, "reports": 0})["rules" if x["kind"] == "rule" else "sensors"] += 1
        for r in reports:
            files.setdefault(r["file"], {"sensors": 0, "rules": 0, "reports": 0})["reports"] += 1
        return {"files": [{"name": k, "main": k == main, **v} for k, v in files.items()], "sensors": sensors, "reports": reports,
                "issues": issues, "editable": self.editable}

    def set_since(self, value):
        """Show only events from this time on. "now" starts from this moment, None shows everything again. Nothing is
        deleted. The events stay in the log and in the database."""
        if value == "now":
            value = int(time.time() * 1000)
        elif value is not None:
            value = int(value)
        with self.ingestor.lock:
            store.set_since(self.ingestor.db, value)
        return self.status()

    def event(self, pk):
        """One event with everything recorded about it, the stack with each frame marked as application, library or
        platform, and the other events from the same request. Found even when the filters hide it from the views."""
        pk = int(pk)
        r = store.run_query(self.db_path, "SELECT * FROM events_raw WHERE pk = %d" % pk)
        if not r["rows"]:
            raise LookupError("no event %d" % pk)
        e = dict(zip(r["columns"], r["rows"][0]))
        stack = json.loads(e["stack"]) if e.get("stack") else []
        prefixes = self.ingestor.app_prefixes
        e["stack"] = [{"frame": f, "kind": store.frame_kind(f, prefixes)} for f in stack]
        e["data"] = json.loads(e["data"]) if e.get("data") else None
        e["related"] = []
        if e.get("trace") is not None:
            e["related"] = store.run_query(self.db_path, """
                SELECT pk, ts, action, sensor, capture FROM events_raw
                WHERE run = '%s' AND trace = %d ORDER BY ts, pk""" % (str(e["run"]).replace("'", "''"), int(e["trace"])),
                limit=200)["rows"]
        return e

    def search(self, query):
        """The SQL that finds the events matching a search, newest first, and how many more matches the filters leave out. The dashboard runs the SQL like any other view, so it also refreshes and shows its SQL."""
        where = store.search_where(query)
        sql = ("SELECT pk, datetime(ts/1000, 'unixepoch', 'localtime') AS time, action, sensor,\n"
               "       entry, call_site_name AS call_site, capture\nFROM events\nWHERE %s\nORDER BY ts DESC LIMIT 500" % where)
        since = store.get_since(self.db_path) or 0
        shown = store.run_query(self.db_path, "SELECT COUNT(*) FROM events WHERE %s" % where)["rows"][0][0]
        every = store.run_query(self.db_path, "SELECT COUNT(*) FROM events_raw WHERE ts >= %d AND %s" % (since, where))["rows"][0][0]
        return {"sql": sql, "matches": shown, "left_out": every - shown}

    @staticmethod
    def _route_per_request(table, more):
        """SQL for the route of each request or run of an entry point, which is the path the http-route sensor saw, or else the entry point
        it ran under."""
        return ("SELECT COALESCE(MAX(CASE WHEN sensor IN %s THEN %s END), MAX(entry)) AS route FROM %s WHERE (sensor IN %s OR entry IS NOT NULL)%s "
                "GROUP BY run, trace" % (store.ROUTE_SENSORS_SQL, store.route_of(), table, store.ROUTE_SENSORS_SQL, more))

    def graph(self, route=None, details=False, split=False, method=None):
        """The paths through the application, from each route through the methods that ran to what the sensors saw. A method limits
        it to the requests that used that HTTP method, and the methods seen are always all of them so they can be colored."""
        rows = store.graph_rows(self.db_path, route or None, method or None)
        routes = [r[0] for r in store.run_query(self.db_path, """
            SELECT route, COUNT(*) FROM (%s) WHERE route IS NOT NULL GROUP BY route ORDER BY route"""
            % self._route_per_request("events_raw", " AND ts >= %d" % (store.get_since(self.db_path) or 0)), limit=2000)["rows"]]
        build = store.build_graphs if split else store.build_graph
        # entry points that are not requests, which is when what happened outside them is drawn from its caller only
        entries = bool(store.run_query(self.db_path, """SELECT 1 FROM events_raw e WHERE entry IS NOT NULL AND NOT EXISTS (
            SELECT 1 FROM events_raw r WHERE r.run = e.run AND r.trace = e.trace AND r.sensor IN %s) LIMIT 1""" % store.ROUTE_SENSORS_SQL)["rows"])
        if not split:
            return build(rows["rows"], routes, self.ingestor.app_prefixes, bool(details), rows["truncated"], store.graph_methods(self.db_path), entries)
        # how many requests each route had, since a busy one is drawn from its newest and the graph should say so
        requests = dict(store.run_query(self.db_path, "SELECT route, COUNT(*) FROM (%s) WHERE route IS NOT NULL GROUP BY route"
                                        % self._route_per_request("events", ""), limit=5000)["rows"])
        built = build(rows["rows"], routes, self.ingestor.app_prefixes, bool(details), rows["truncated"], store.graph_methods(self.db_path), requests, entries)
        # every entry is on the graph, with or without sensor events in it. One picked is the only one, and a method means the requests that used it,
        # which aren't counted for an entry that had no events
        if not method:
            drawn = {g["route"] for g in built["graphs"]}
            built["graphs"] += [store.empty_graph(r, requests.get(r, 0)) for r in routes if r not in drawn and (not route or r == route)]
            built["graphs"].sort(key=lambda g: (g["route"] == store.NO_REQUEST, g["route"].lower()))
        return built

    def reset_filters(self):
        """Take every filter off, the start time included, so every event shows again."""
        with self.ingestor.lock:
            store.reset_filters(self.ingestor.db)
        return self.status()

    def entry(self):
        """The application's entry points as the jots file has them, with the default list the agent uses when it has none, and whether
        they can be changed here. entry is None when the file doesn't say, which is the default list, and [] is no application scope."""
        if not self.jots_file:
            return {"entry": None, "default": list(store.DEFAULT_ENTRY), "file": None, "editable": False, "problems": []}
        found = store.read_entry(self.jots_file)
        return {"entry": found["entry"], "default": list(store.DEFAULT_ENTRY), "file": os.path.basename(self.jots_file),
                "editable": bool(self.editable), "problems": found["problems"]}

    def restart_application(self):
        """Stops the application, whether the console started it or not, and starts it again with the command the person last started it with
        at the console. The command is never one that came from anywhere else."""
        run = self.launcher
        if not run:
            raise store.SaveError("the application can't be started or stopped from here, the console is open to other machines or has no project", 404)
        command = run.command
        if not command:
            raise store.QueryError("the console doesn't know how this application starts, start it once from the Run page and then it can restart it")
        if run.running():
            run.stop()
        else:
            for found in launcher.running_elsewhere(self.db_path):
                if not launcher.stop_elsewhere(self.db_path, found["pid"]):
                    raise store.SaveError("the application (process %d) is still running after being asked to end, stop it yourself and try again" % found["pid"], 409)
        run.start(command)
        self._restart_cache = None
        return {"command": command}

    RESTART_MARGIN = 2          # seconds, a change this soon after the application started is read by it

    def restart_state(self):
        """Whether the application that is running was started before the configuration last changed, which the agent reads only when the
        application starts. Every process that is running counts, the one the console started and one that was started some other way.
        None when the console can't start applications. The protection settings are not part of it, the agents read those while they run.
        It is worked out at most every few seconds, since it looks at the processes."""
        run = self.launcher
        if not run:
            return None
        cached = getattr(self, "_restart_cache", None)
        if cached and time.time() - cached[0] < 3:
            return cached[1]
        files = [f for f in [self.jots_file] + store.jot_files(self.jot_paths) if f and os.path.isfile(f)]
        changed = max((os.path.getmtime(f) for f in files), default=0)
        if run.running():
            starts = [(run.started or 0) / 1000]
        else:
            starts = [f["started"] for f in launcher.running_elsewhere(self.db_path)]
        state = {"needed": any(changed > started + self.RESTART_MARGIN for started in starts), "command": run.command, "running": bool(starts),
                 "changed": int(changed * 1000)}
        self._restart_cache = (time.time(), state)
        return state

    def reset_preview(self):
        """What a reset would remove, for the page to show before anything is deleted."""
        where = store.jot_dir(self.jots_file, getattr(self, "project_dir", None))
        names = sorted(os.listdir(where)) if os.path.isdir(where) else []
        jots = self.jots()
        found = store.read_entry(self.jots_file) if self.jots_file else {"entry": None}
        mine = os.path.abspath(where) + os.sep
        return {"folder": getattr(self, "project_dir", None), "dir": where, "files": names,
                "events": store.run_query(self.db_path, "SELECT COUNT(*) FROM events_raw")["rows"][0][0],
                "sensors": len(jots["sensors"]), "reports": len(jots["reports"]),
                "entry": len(found["entry"]) if found["entry"] else 0,
                "kept": [p for p in self.jot_paths if not os.path.abspath(p).startswith(mine) and os.path.abspath(p) != os.path.abspath(self.jots_file or "")],
                "running": bool(self.launcher and self.launcher.running()),
                "elsewhere": [] if self.launcher and self.launcher.running() else launcher.running_elsewhere(self.db_path)}

    SETTINGS = {"entry": (lambda: list(store.DEFAULT_ENTRY), store.entry_problems), "ignore": (lambda: list(store.DEFAULT_IGNORE), store.ignore_problems),
                "packages": (lambda: [], store.package_problems)}

    def setting(self, name):
        """One of the list settings of the jots file for the page to edit, entry, ignore or packages. values is the list as written, [] for an
        empty one and None when the file doesn't say, which is the default, and default is what the agent uses then."""
        if name not in self.SETTINGS:
            raise store.QueryError("%r is not a setting, the settings are entry, ignore and packages" % name)
        default, check = self.SETTINGS[name]
        if not self.jots_file:
            return {"name": name, "values": None, "default": default(), "file": None, "editable": False, "problems": []}
        if name == "entry":
            found = store.read_entry(self.jots_file)
            values, problems = found["entry"], found["problems"]
        else:
            values = store.read_settings(self.jots_file)[name]
            problems = check(values) if values is not None else []
        return {"name": name, "values": values, "default": default(), "file": os.path.basename(self.jots_file),
                "editable": bool(self.editable), "problems": problems}

    def check_setting(self, name, values):
        if name not in self.SETTINGS:
            raise store.QueryError("%r is not a setting, the settings are entry, ignore and packages" % name)
        return self.SETTINGS[name][1](values)

    def change_setting(self, name, values, original):
        """Saves one of those settings, and for the two that decide how events are told apart, ignore and packages, applies it here at once.
        The events already recorded are sorted again, so the graph and the reports follow, and the agent reads the file when the
        application starts."""
        if name not in self.SETTINGS:
            raise store.QueryError("%r is not a setting, the settings are entry, ignore and packages" % name)
        done = self.save_setting(name, values, original)
        if name in ("ignore", "packages"):
            self.reclassify()
        return dict(self.setting(name), saved=done["saved"])

    def reclassify(self):
        packages = store.read_settings(self.jots_file)["packages"] or []
        store.set_ignore(store.read_ignore(self.jots_file))
        with self.ingestor.lock:
            self.ingestor.app_prefixes = tuple(dict.fromkeys(packages + list(getattr(self, "cli_apps", []))))
            store.retag(self.ingestor.db, self.ingestor.app_prefixes)

    def check_entry(self, entries):
        """What is wrong with entry points as they are being typed, before anything is saved."""
        return store.entry_problems(entries)

    def save_setting(self, setting, values, original):
        """Writes one of the list settings of the jots file, entry, ignore or packages, or takes it out with None, which is the default.
        Like saving a JOT it needs the dashboard to be allowed to write, and it refuses if the file has changed since it was read."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        if not self.jots_file:
            raise store.SaveError("not saved, the dashboard was not started with --jots, so there is no jots file to write", 400)
        write = {"entry": store.write_entry, "ignore": store.write_ignore, "packages": store.write_packages}.get(setting)
        if write is None:
            raise store.SaveError("not saved, %r is not a setting that can be changed, the settings are entry, ignore and packages" % setting, 400)
        write(self.jots_file, values, original)
        self.reload_jots(force=True)
        return {"saved": os.path.basename(self.jots_file), "setting": setting, "values": store.read_settings(self.jots_file)[setting]}

    def save_entry(self, entries, original):
        """Writes the entry points into the jots file, or the default list when entries is None. Like saving a JOT, it needs the dashboard to
        be allowed to write, and it refuses if the file has changed since the editor was opened. The agent reads the file when the
        application starts, so a running one keeps what it had."""
        if not self.editable:
            raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
        if not self.jots_file:
            raise store.SaveError("not saved, the dashboard was not started with --jots, so there is no jots file to write", 400)
        store.write_entry(self.jots_file, entries, original)
        state = self.entry()
        state["saved"] = os.path.basename(self.jots_file)
        return state

    def set_filters(self, actions=None, origins=None):
        """Show these actions and these origins. Each is the list of what is shown, and one that is left out is left as it is. Nothing is
        deleted, and an event shows when every filter lets it through."""
        with self.ingestor.lock:
            if actions is not None:
                store.set_shown_actions(self.ingestor.db, actions)
            if origins is not None:
                store.set_shown_origins(self.ingestor.db, origins)
        return self.status()

    def set_hidden_jots(self, names):
        """Leave out every event of these JOTs from every view except the reports, which each name the sensors they need."""
        if not isinstance(names, list):
            raise ValueError("names must be a list")
        with self.ingestor.lock:
            store.set_hidden_jots(self.ingestor.db, names)
        return self.status()

    def filter_jots(self):
        """Every JOT there is to hide, from the files and from the events, with how many events each has recorded. The agent's own events
        are a JOT here too, jot-control for a rule being switched and jot-config for what it started with."""
        counts = dict(store.run_query(self.db_path, "SELECT %s AS jot, COUNT(*) FROM events_raw GROUP BY jot" % store.JOT_NAME_SQL,
                                      limit=5000)["rows"])
        names = {s["name"] for s in self.sensors()} | set(counts) | set(store.get_hidden_jots(self.db_path))
        return [{"name": n, "events": counts.get(n, 0)} for n in sorted(names)]

    def filter_counts(self):
        """How many events there are of each action and from each origin since the start time, whatever else is hidden, so the choices say
        how much they would add or take away."""
        since = store.get_since(self.db_path) or 0
        actions = dict(store.run_query(self.db_path, "SELECT COALESCE(action, 'observed'), COUNT(*) FROM events_raw WHERE ts >= %d GROUP BY 1" % since)["rows"])
        origins = dict(store.run_query(self.db_path, "SELECT COALESCE(origin, 'none'), COUNT(*) FROM events_raw WHERE ts >= %d GROUP BY 1" % since)["rows"])
        return {"actions": {a: actions.get(a, 0) for a in store.ACTIONS}, "origins": {o: origins.get(o, 0) for o in store.ORIGINS}}

    def sensors_enabled(self):
        """Every sensor and rule the loaded .jot files define, and whether the .jot file leaves it on."""
        db = sqlite3.connect(self.db_path)
        try:
            return {n: e != "false" for n, e in db.execute("SELECT name, enabled FROM sensors ORDER BY name")}
        finally:
            db.close()

    def sensor_names(self):
        """Every sensor and rule the loaded .jot files define. Any of them can be switched off."""
        return list(self.sensors_enabled())

    def rule_names(self):
        """The sensors that are rules, meaning they have an exception. Only these can be switched."""
        return [r["name"] for r in self.rules_declared()]

    def rules_declared(self):
        db = sqlite3.connect(self.db_path)
        try:
            return [{"name": n, "description": d, "message": m, "staged": e == "false"}
                    for n, d, m, e in db.execute(
                        "SELECT name, description, blocks, protect FROM sensors WHERE blocks IS NOT NULL ORDER BY name")]
        finally:
            db.close()

    def agent_state(self):
        """What the most recent agent said it started with, from its jot-config events. Nothing is guessed from
        files. {"known": False} when no agent has reported yet, which is the case for an agent older than this."""
        latest = store.run_query(self.db_path, """
            SELECT run, host, app, MAX(ts) FROM events WHERE sensor = 'jot-config'
            GROUP BY run ORDER BY MAX(ts) DESC LIMIT 1""")["rows"]
        if not latest:
            return {"known": False, "locked": False, "loaded": []}
        run, host, app, ts = latest[0]
        db = sqlite3.connect(self.db_path)
        try:
            said = [c for (c,) in db.execute(
                "SELECT capture FROM events WHERE sensor = 'jot-config' AND run = ? ORDER BY pk", (run,))]
        finally:
            db.close()
        def values(key):
            return [c[len(key) + 1:] for c in said if c.startswith(key + "=")]
        return {"known": True, "run": run, "host": host, "app": app, "started": ts,
                "locked": "monitor" in values("lock"), "jots": (values("jots") or [None])[0],
                "control": (values("control") or [None])[0], "loaded": values("loaded"), "problems": values("problem")}

    def control_state(self):
        """What the Protection panel shows. Each rule's setting is what the control file says, or else what its
        .jot file says. An agent started with -Djot.protect=false ignores the file, and it says so in its
        jot-config events, so a locked agent shows as monitor here whatever the file says."""
        if self.control is None:
            return {"enabled": False}
        file = self.control.read()
        counts = {}
        recent = store.run_query(self.db_path, """
            SELECT %s AS jot, SUM(action = 'blocked'), SUM(action = 'monitored') FROM events
            WHERE action IN ('blocked', 'monitored') AND ts > (strftime('%%s','now') - 3600) * 1000
            GROUP BY jot""" % store.JOT_NAME_SQL)["rows"]
        for name, blocked, monitored in recent:
            counts[name] = {"blocked": blocked or 0, "monitored": monitored or 0}
        agent = self.agent_state()
        loaded = set(agent["loaded"])
        # whether each sensor and rule runs, the control file's setting or else what its .jot file says
        on = {name: file["enabled"].get(name, jot_on) for name, jot_on in self.sensors_enabled().items()}
        rules = []
        for r in self.rules_declared():
            setting = file["rules"].get(r["name"])
            blocks = (setting if setting is not None else not r["staged"]) and file["protect"] and not agent["locked"]
            rules.append({**r, "setting": setting, "enabled": on.get(r["name"], True), "mode": "block" if blocks else "monitor",
                          "loaded": (r["name"] in loaded) if agent["known"] else None,
                          "last_hour": counts.get(r["name"], {"blocked": 0, "monitored": 0})})
        applied = store.run_query(self.db_path, """
            SELECT ts, host, app, capture FROM events_raw WHERE sensor = 'jot-control' ORDER BY pk DESC LIMIT 10""")["rows"]
        return {"enabled": True, "master": file["protect"] and not agent["locked"],
                "file_master": file["protect"], "agent": agent, "rules": rules, "enabled": on,
                "updated": file["updated"], "by": file["by"], "file_exists": file["exists"],
                "applied": [{"ts": t, "host": h, "app": a, "change": c} for t, h, a, c in applied]}

    def change_control(self, master, rules, enabled=None):
        if self.control is None:
            raise control_module.ControlError("this dashboard was started without a jots file that names a control file")
        self.control.write(master=master, rules=rules, enabled=enabled, known_rules=self.rule_names(),
                           known_sensors=self.sensor_names())
        return self.control_state()

    def report_summaries(self):
        """Report definitions for the model. Names and sensor names only, no data."""
        db = sqlite3.connect(self.db_path)
        try:
            return [{"name": n, "type": t, "rows_sensor": r, "cols": c, "value": v, "by": b}
                    for n, t, r, c, v, b in db.execute("SELECT name, type, rows, cols, value, by FROM reports ORDER BY rowid")]
        finally:
            db.close()

    def status(self):
        r = store.run_query(self.db_path, """
            SELECT COUNT(*) AS events,
                   COALESCE(SUM(action = 'blocked'), 0) AS blocked,
                   COALESCE(SUM(action = 'monitored'), 0) AS monitored,
                   COUNT(DISTINCT sensor) AS sensors,
                   MAX(ts) AS last_ts,
                   MAX(pk) AS last_pk FROM events""")
        keys = r["columns"]
        status = dict(zip(keys, r["rows"][0]))
        status["since"] = store.get_since(self.db_path)
        since = status["since"] or 0
        counts = store.run_query(self.db_path, """
            SELECT COALESCE(SUM(ts < %d), 0), COALESCE(SUM(ts >= %d), 0) FROM events_raw""" % (since, since))["rows"][0]
        status["hidden"] = counts[0]                       # before the start time
        status["shown_actions"] = store.get_shown_actions(self.db_path)
        status["shown_origins"] = store.get_shown_origins(self.db_path)
        status["hidden_jots"] = store.get_hidden_jots(self.db_path)
        status["filtered"] = counts[1] - status["events"]  # left out by the filters, which is everything since the start time that isn't shown
        status["llm"] = llm.configured()
        status["model"] = llm.model() if llm.configured() else None
        status["known_sensors"] = len(self.sensors())
        status["restart"] = self.restart_state()
        return status

    def recent(self, after=None, limit=30):
        if after is None:
            sql = ("SELECT pk, ts, action, sensor, capture, call_site_name, message FROM events "
                   "ORDER BY pk DESC LIMIT %d" % limit)
        else:
            sql = ("SELECT pk, ts, action, sensor, capture, call_site_name, message FROM events "
                   "WHERE pk > %d ORDER BY pk DESC LIMIT %d" % (int(after), limit))
        return store.run_query(self.db_path, sql, limit=limit)

    def sql(self, sql, limit=None):
        """Run a query. A grid may be wide in rows because it is made of one row per cell, so it can ask for more."""
        limit = min(int(limit), MAX_GRID_ROWS) if limit else 1000
        result = store.run_query(self.db_path, sql, limit=limit)
        if not result["rows"]:
            result["hint"] = self.empty_hint()
        return result

    def empty_hint(self):
        """Said when a question matched nothing, so it is clear whether the data is missing or the question is."""
        seen = store.run_query(self.db_path, "SELECT sensor, COUNT(*) FROM events GROUP BY sensor ORDER BY 2 DESC",
                               limit=20)["rows"]
        if not seen:
            since = store.get_since(self.db_path)
            raw = store.run_query(self.db_path, "SELECT COUNT(*) FROM events_raw")["rows"][0][0]
            if since and raw:
                return ("Nothing has been recorded since the dashboard was cleared at %s. Show all brings back the earlier %d events."
                        % (time.strftime("%H:%M:%S", time.localtime(since / 1000)), raw))
            return "No events have been loaded yet. Check that the application is running with JOT and that --log points at its event log."
        return ("No events matched. Sensors that have recorded events so far are %s. "
                "A sensor only records events when the code it watches runs." %
                ", ".join("%s (%d)" % (name, n) for name, n in seen))

    def ask(self, question, history=()):
        """Returns {"title", "sql", "chart", "explanation"} plus the query result, or no result when the
        question can't be answered from the events."""
        question = (question or "").strip()
        if not question:
            raise store.QueryError("ask a question")
        schema = store.schema_for_model()
        sensors = self.sensors()
        error = None
        for attempt in range(MAX_REPAIRS + 1):
            answer = self.generate(question, schema, sensors, history, error, reports=self.report_summaries())
            if not answer["sql"]:
                answer.update(columns=[], rows=[], truncated=False, ms=0)
                return answer
            try:
                answer.update(self.sql(answer["sql"], limit=MAX_GRID_ROWS if answer["chart"] == "grid" else None))
                return answer
            except store.QueryError as e:
                error = "%s\nSQL: %s" % (e, answer["sql"])
                last = e
        raise store.QueryError("the generated SQL did not run: %s" % last)


class Handler(BaseHTTPRequestHandler):
    app = None
    host = None       # opens another project, set by make_server
    port = 0
    enforce_host = True
    server_version = "jot-dashboard"

    def log_message(self, fmt, *args):
        pass

    def _send(self, status, body, content_type="application/json"):
        if not isinstance(body, bytes):
            body = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(body)

    def _launcher(self):
        if not self.app.launcher:
            raise store.SaveError("the application can't be started from here, the console is open to other machines or has no project", 404)
        return self.app.launcher

    def _host_ok(self):
        if not self.enforce_host:
            return True
        # only this machine, whatever address the server ended up listening on
        if self.client_address[0] not in ("127.0.0.1", "::1", "::ffff:127.0.0.1"):
            return False
        host = (self.headers.get("Host") or "").lower()
        return host in ("localhost:%d" % self.port, "127.0.0.1:%d" % self.port, "[::1]:%d" % self.port)

    def do_GET(self):
        if not self._host_ok():
            return self._send(403, {"error": "unexpected Host header"})
        url = urlparse(self.path)
        try:
            if url.path in ("/", "/index.html"):
                with open(os.path.join(HERE, "static", "index.html"), "rb") as f:
                    return self._send(200, f.read(), "text/html; charset=utf-8")
            if url.path in SCRIPTS:
                with open(os.path.join(HERE, "static", SCRIPTS[url.path]), "rb") as f:
                    return self._send(200, f.read(), "text/javascript; charset=utf-8")
            if url.path == "/api/status":
                return self._send(200, self.app.status())
            if url.path == "/api/reports":
                return self._send(200, self.app.reports())
            if url.path == "/api/jots":
                return self._send(200, self.app.jots())
            if url.path == "/api/control":
                return self._send(200, self.app.control_state())
            if url.path == "/api/sensors":
                return self._send(200, self.app.sensors())
            if url.path == "/api/report-events":
                q = parse_qs(url.query)
                try:
                    return self._send(200, self.app.report_events(q.get("name", [""])[0], q["row"][0] if "row" in q else None,
                                                                  q["col"][0] if "col" in q else None))
                except LookupError as e:
                    return self._send(404, {"error": str(e)})
            if url.path == "/api/filter-jots":
                return self._send(200, self.app.filter_jots())
            if url.path == "/api/filter-counts":
                return self._send(200, self.app.filter_counts())
            if url.path == "/api/entry":
                return self._send(200, self.app.entry())
            if url.path == "/api/setting":
                return self._send(200, self.app.setting(parse_qs(url.query).get("name", [""])[0]))
            if url.path == "/api/folders":
                if not self.host:
                    return self._send(404, {"error": "no folders to list"})
                return self._send(200, self.host.folders(parse_qs(url.query).get("path", [""])[0]))
            if url.path == "/api/reset":
                if not self.host or self.host.remote:
                    raise store.SaveError("the project can't be reset, the dashboard is open to other machines", 403)
                return self._send(200, self.app.reset_preview())
            if url.path == "/api/run":
                run = self._launcher()
                state = run.state(int(parse_qs(url.query).get("after", ["0"])[0]))
                state["elsewhere"] = [] if state["running"] else launcher.running_elsewhere(self.app.db_path)
                return self._send(200, state)
            if url.path == "/api/project":
                return self._send(200, self.host.info() if self.host else {"path": None, "can_switch": False, "recent": []})
            if url.path == "/api/assistant":
                return self._send(200, {"chats": self.app.assistant.chats(), "configured": llm.configured(), "editable": self.app.assistant._editable(),
                                         "folder": self.app.scanner.root, "can_scan": self.app.scanner.local})
            if url.path == "/api/assistant/chat":
                q = parse_qs(url.query)
                try:
                    return self._send(200, self.app.assistant.view(int(q.get("id", ["0"])[0]), q.get("after", ["0"])[0]))
                except LookupError as e:
                    return self._send(404, {"error": str(e)})
            if url.path == "/api/graph":
                q = parse_qs(url.query)
                return self._send(200, self.app.graph(q.get("route", [""])[0], q.get("details", [""])[0] == "1",
                                                        q.get("split", [""])[0] == "1", q.get("method", [""])[0]))
            if url.path == "/api/search":
                return self._send(200, self.app.search(parse_qs(url.query).get("q", [""])[0]))
            if url.path == "/api/event":
                try:
                    return self._send(200, self.app.event(parse_qs(url.query).get("pk", [""])[0]))
                except LookupError as e:
                    return self._send(404, {"error": str(e)})
            if url.path == "/api/recent":
                after = parse_qs(url.query).get("after", [None])[0]
                return self._send(200, self.app.recent(after))
        except (store.QueryError, ValueError) as e:
            return self._send(400, {"error": str(e)})
        except store.SaveError as e:
            return self._send(e.status, {"error": str(e)})
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if not self._host_ok():
            return self._send(403, {"error": "unexpected Host header"})
        # a cross-site page can't set this header without a CORS preflight, which is never granted
        if self.headers.get("X-JOT-Dashboard") != "1" or "application/json" not in (self.headers.get("Content-Type") or ""):
            return self._send(403, {"error": "missing X-JOT-Dashboard header"})
        try:
            length = int(self.headers.get("Content-Length") or 0)
            if length > MAX_BODY:
                return self._send(413, {"error": "request too large"})
            body = json.loads(self.rfile.read(length) or b"{}")
            url = urlparse(self.path)
            if url.path == "/api/ask":
                return self._send(200, self.app.ask(body.get("question"), body.get("history") or []))
            if url.path == "/api/sql":
                return self._send(200, self.app.sql(body.get("sql"), body.get("limit")))
            if url.path == "/api/jots/draft":
                return self._send(200, self.app.draft_jot(body.get("request"), body.get("history") or []))
            if url.path == "/api/jots/add":
                return self._send(200, self.app.add_jot(body.get("file"), body.get("text")))
            if url.path == "/api/jots/save":
                return self._send(200, self.app.save_jot(body.get("name"), body.get("original"), body.get("text")))
            if url.path == "/api/jots/delete":
                return self._send(200, self.app.delete_jot(body.get("name"), body.get("original")))
            if url.path == "/api/reports/delete":
                return self._send(200, self.app.delete_report(body.get("name"), body.get("original")))
            if url.path == "/api/jots/check":
                return self._send(200, {"problems": store.check_jot_text(body.get("text"))})
            if url.path == "/api/reports/draft":
                return self._send(200, self.app.draft_report(body.get("request"), body.get("history") or []))
            if url.path == "/api/reports/add":
                return self._send(200, self.app.add_report(body.get("file"), body.get("text")))
            if url.path == "/api/reports/check":
                return self._send(200, {"problems": self.app.check_report(body.get("text"), body.get("name"))})
            if url.path == "/api/reports/save":
                return self._send(200, self.app.save_report(body.get("name"), body.get("original"), body.get("text")))
            if url.path == "/api/filters/reset":
                return self._send(200, self.app.reset_filters())
            if url.path == "/api/since":
                return self._send(200, self.app.set_since(body.get("since")))
            if url.path == "/api/hidden-jots":
                return self._send(200, self.app.set_hidden_jots(body.get("names")))
            if url.path == "/api/filters":
                return self._send(200, self.app.set_filters(body.get("actions"), body.get("origins")))
            if url.path == "/api/reset":
                if not self.host:
                    return self._send(404, {"error": "no project to reset"})
                if body.get("confirm") is not True:
                    raise store.QueryError("a reset has to be confirmed")
                return self._send(200, self.host.reset())
            if url.path == "/api/run/start":
                self.app._restart_cache = None
                return self._send(200, self._launcher().start(body.get("command")))
            if url.path == "/api/run/restart":
                self._launcher()
                return self._send(200, self.app.restart_application())
            if url.path == "/api/run/stop":
                run = self._launcher()
                self.app._restart_cache = None
                if body.get("pid") is not None:
                    ended = launcher.stop_elsewhere(self.app.db_path, int(body["pid"]))
                    return self._send(200, dict(run.state(), ended=ended, elsewhere=launcher.running_elsewhere(self.app.db_path)))
                return self._send(200, run.stop())
            if url.path == "/api/project/open":
                if not self.host:
                    return self._send(404, {"error": "no projects to open"})
                return self._send(200, self.host.open(body.get("path"), bool(body.get("create"))))
            if url.path == "/api/assistant/new":
                chat = self.app.assistant.new_chat()
                return self._send(200, self.app.assistant.view(chat, 0))
            if url.path == "/api/assistant/folder":
                try:
                    return self._send(200, {"folder": self.app.scanner.set_root(body.get("folder"))})
                except scanner.ScanError as e:
                    return self._send(400, {"error": str(e)})
            if url.path == "/api/assistant/send":
                return self._send(200, self.app.assistant.send(int(body.get("chat")), body.get("text")))
            if url.path == "/api/assistant/stop":
                return self._send(200, self.app.assistant.stop(int(body.get("chat"))))
            if url.path == "/api/assistant/proposal":
                return self._send(200, self.app.assistant.resolve(body.get("id"), body.get("action"), body.get("file")))
            if url.path == "/api/setting/check":
                return self._send(200, {"problems": self.app.check_setting(body.get("name"), body.get("values"))})
            if url.path == "/api/setting/save":
                return self._send(200, self.app.change_setting(body.get("name"), body.get("values"), body.get("original")))
            if url.path == "/api/entry/check":
                return self._send(200, {"problems": self.app.check_entry(body.get("entry"))})
            if url.path == "/api/entry/save":
                return self._send(200, self.app.save_entry(body.get("entry"), body.get("original")))
            if url.path == "/api/control":
                return self._send(200, self.app.change_control(body.get("master"), body.get("rules"), body.get("enabled")))
        except store.QueryError as e:
            return self._send(400, {"error": str(e)})
        except LookupError as e:
            return self._send(404, {"error": str(e)})
        except store.SaveError as e:
            return self._send(e.status, {"error": str(e)})
        except control_module.ControlError as e:
            return self._send(400, {"error": str(e)})
        except llm.LLMError as e:
            return self._send(502, {"error": str(e)})
        except (ValueError, AttributeError, TypeError):
            return self._send(400, {"error": "bad request"})
        except Exception as e:
            print("[dashboard] error:", repr(e), file=sys.stderr)
            return self._send(500, {"error": "internal error"})
        self._send(404, {"error": "not found"})


def parse_since(text):
    """A start time given on the command line, now, epoch milliseconds, or a date and time like 2026-10-16T09:30."""
    text = text.strip()
    if text.lower() == "now":
        return "now"
    if text.isdigit():
        return int(text)
    return int(datetime.fromisoformat(text).timestamp() * 1000)


LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1")


class NeedsSetup(Exception):
    """The folder has no jot.yaml, and making one there has to be agreed to first."""


def project_root(jots, folder):
    """The folder of a project, which is the one the .jot folder is in."""
    here = os.path.dirname(os.path.abspath(jots)) if jots else os.path.abspath(folder)
    return os.path.dirname(here) if os.path.basename(here) == store.JOT_DIR else here


def build_project(folder, jots=None, db=None, logs=None, apps=(), remote=False, create=False, say=print):
    """Opens a project, the folder with its .jot folder, and returns the App for it, with its events being followed. The jots file is
    .jot/jot.yaml or jot.yaml in the folder. With neither, create makes .jot/jot.yaml for the assistant to fill and without create it raises
    NeedsSetup, so nothing is written into a folder until the person says so. The database, the events and the control file are in .jot."""
    if not jots:
        jots = store.find_config(folder)
        if jots:
            say("  using %s" % os.path.relpath(jots))
        elif not remote:
            if not create:
                raise NeedsSetup(folder)
            jots = os.path.join(store.make_jot_dir(store.jot_dir(None, folder)), "jot.yaml")
            with open(jots, "w") as f:
                f.write(store.FRESH_CONFIG)
            say("  no jot.yaml yet, made %s for the assistant to fill" % os.path.relpath(jots))
    root = project_root(jots, folder)
    where = store.make_jot_dir(store.jot_dir(jots, folder))
    db = db or os.path.join(where, "dashboard.db")
    logs = logs or [os.path.join(where, "events.jsonl")]
    jot_paths = store.config_paths(jots) if jots else []
    _, control_path, jots_app = store.read_jots_file(jots) if jots else ([], None, [])
    for problem in (store.jots_file_problems(jots) if jots else []):
        print("  jots file, %s" % problem, file=sys.stderr)
    store.set_ignore(store.read_ignore(jots) if jots else None)   # before the events are tagged, the agent reads the same list
    ingestor = store.Ingestor(db, logs, app_prefixes=list(dict.fromkeys((jots_app or []) + list(apps or []))))
    loaded = store.load_sensors(ingestor.db, jot_paths)
    reports = store.load_reports(ingestor.db, jot_paths)
    first = ingestor.poll()
    ingestor.start()
    control = control_module.ControlStore(control_path) if control_path else None
    # the toggles and hidden JOTs of an earlier session start off again. Clear is kept, it is a choice to start fresh that the stats line
    # shows and Show all undoes, and a restart is not a reason to bring back what was cleared
    with ingestor.lock:
        store.reset_filters(ingestor.db, keep=("since",))
    app = App(db, ingestor, control=control, jot_paths=jot_paths, jots_file=jots,
              editable=bool(jots) and not remote, local=not remote)
    app.project_dir, app.first, app.loaded, app.reports_loaded = root, first, loaded, reports
    app.cli_apps = list(apps or [])      # packages given on the command line, which are kept when the configuration's change
    if not remote and app.scanner.root is None and os.path.isdir(root):
        app.scanner.set_root(root)          # the assistant looks at the project it is for
    if not remote and jots and os.path.isdir(root):
        app.launcher = launcher.Launcher(root, os.path.abspath(jots))
    return app


def recent_file(home=None):
    return os.path.join(home or os.environ.get("JOT_HOME") or os.path.join(os.path.expanduser("~"), ".jot"), "recent.json")


class Host:
    """Holds the project that is open and opens another, so the console can move between projects without being restarted."""

    def __init__(self, handler, remote=False, apps=(), home=None):
        self.handler, self.remote, self.apps, self.home = handler, remote, list(apps or []), home
        self.lock = threading.Lock()

    def recent(self):
        try:
            with open(recent_file(self.home)) as f:
                found = json.load(f)
        except (OSError, ValueError):
            return []
        return [p for p in found if isinstance(p, str) and os.path.isdir(p)][:12]

    def _remember(self, folder):
        paths = [folder] + [p for p in self.recent() if p != folder]
        try:
            os.makedirs(os.path.dirname(recent_file(self.home)), exist_ok=True)
            with open(recent_file(self.home), "w") as f:
                json.dump(paths[:12], f)
        except OSError:
            pass            # the list is a convenience

    def info(self):
        app = self.handler.app
        root = getattr(app, "project_dir", None)
        return {"path": root, "name": os.path.basename(root) if root else None, "jots": app.jots_file, "can_switch": not self.remote,
                "recent": self.recent()}

    def folders(self, path=None):
        """The folders inside a folder, for the console's folder picker. A browser can't tell the server the path of a folder the person chose,
        so the console lists the machine's folders itself, which is only done for a console that other machines can't reach. Folders whose
        names start with a dot are left out, and a folder with a .jot in it is marked as a project."""
        if self.remote:
            raise store.SaveError("folders can't be listed, the dashboard is open to other machines", 403)
        home = os.path.expanduser("~")
        start = (path or "").strip() or getattr(self.handler.app, "project_dir", None) or home
        folder = os.path.realpath(os.path.expanduser(start))
        if not os.path.isdir(folder):
            raise store.QueryError("%s isn't a folder" % start)
        names, more = [], False
        try:
            entries = sorted(os.scandir(folder), key=lambda e: e.name.lower())
        except OSError as e:
            raise store.QueryError("can't read %s, %s" % (folder, e.strerror or e))
        for entry in entries:
            if entry.name.startswith("."):
                continue
            try:
                if not entry.is_dir():
                    continue
            except OSError:
                continue
            if len(names) >= 500:
                more = True
                break
            names.append({"name": entry.name, "project": os.path.isfile(os.path.join(entry.path, store.JOT_DIR, "jot.yaml")) or os.path.isfile(os.path.join(entry.path, "jot.yaml"))})
        parent = os.path.dirname(folder)
        return {"path": folder, "parent": parent if parent != folder else None, "home": home, "folders": names, "more": more,
                "project": os.path.isfile(os.path.join(folder, store.JOT_DIR, "jot.yaml")) or os.path.isfile(os.path.join(folder, "jot.yaml"))}

    def reset(self):
        """Puts the open project back to how it was before JOT, and opens it again. The application is stopped first, the one the console started
        and one that was started some other way and is still writing events, since it would only write them again. If one doesn't end, nothing
        is deleted."""
        if self.remote:
            raise store.SaveError("the project can't be reset, the dashboard is open to other machines", 403)
        with self.lock:
            current = self.handler.app
            root, jots = getattr(current, "project_dir", None), current.jots_file
            if not root or not jots:
                raise store.QueryError("there is no project open to reset")
            if not (current.launcher and current.launcher.running()):
                for found in launcher.running_elsewhere(current.db_path):
                    if not launcher.stop_elsewhere(current.db_path, found["pid"]):
                        raise store.SaveError("the application (process %d) is still running after being asked to end, nothing was deleted. "
                                              "Stop it yourself and try again" % found["pid"], 409)
            default_db = os.path.join(store.jot_dir(jots, root), "dashboard.db")
            extra = [] if current.db_path == default_db else [current.db_path, current.db_path + "-wal", current.db_path + "-shm"]
            current.close()
            try:
                store.reset_project(jots, root, extra)
            finally:
                self.handler.app = build_project(root, apps=self.apps, create=True, say=lambda *_: None)
        return dict(self.info(), reset=True)

    def open(self, path, create=False):
        if self.remote:
            raise store.SaveError("the project can't be changed, the dashboard is open to other machines", 403)
        text = (path or "").strip()
        if not text:
            raise store.QueryError("give the folder of a project")
        folder = os.path.realpath(os.path.expanduser(text))
        if not os.path.isdir(folder):
            raise store.QueryError("%s isn't a folder" % text)
        if os.path.basename(folder) == store.JOT_DIR:
            folder = os.path.dirname(folder)
        with self.lock:
            current = self.handler.app
            if getattr(current, "project_dir", None) == folder:
                return dict(self.info(), opened=False)
            try:
                new = build_project(folder, apps=self.apps, create=create, say=lambda *_: None)
            except NeedsSetup:
                return {"needs_setup": True, "folder": folder}
            except OSError as e:
                raise store.QueryError("can't open %s, %s" % (folder, e))
            self.handler.app = new
            current.close()
            self._remember(folder)
        return dict(self.info(), opened=True)


def make_server(app, host, port, remote=False, apps=()):
    handler = type("BoundHandler", (Handler,), {
        "app": app, "port": port, "enforce_host": host in LOCAL_HOSTS})
    server = ThreadingHTTPServer((host, port), handler)
    handler.host = Host(handler, remote=remote or host not in LOCAL_HOSTS, apps=apps)
    return server


def main(argv=None):
    p = argparse.ArgumentParser(description="JOT dashboard")
    p.add_argument("--log", action="append", help="JOT event log to follow, may be a glob. Repeatable. "
                   "Default .jot/events.jsonl")
    p.add_argument("--jots", help="the jots file, by default .jot/jot.yaml or jot.yaml here, that lists the JOTs and the control file. Start each agent with "
                   "-javaagent:jot.jar=<this path> so the agent and the dashboard use the same definitions. ")
    p.add_argument("--db", help="SQLite file to keep events in. Default .jot/dashboard.db")
    p.add_argument("--host", default="127.0.0.1", help="address to listen on. Only this machine can reach the "
                   "dashboard unless --allow-remote is also given")
    p.add_argument("--allow-remote", action="store_true", help="let other machines reach the dashboard. There is no "
                   "login, so anyone who can reach the port can read every event and switch rules, only use this on "
                   "a network you trust")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--app", action="append", help="a package of the application, like com.acme, may be repeated. "
                   "Events whose stack has no frame from these packages are left out by App events only. "
                   "Without it, anything that is not the JDK or the server counts as the application.")
    p.add_argument("--since", help="show only events from this time on, now, or a date and time like 2026-10-16T09:30. "
                   "Nothing is deleted, the Clear and Show all buttons on the Events page change it later")
    p.add_argument("--env", help="file of KEY=VALUE settings, such as ANTHROPIC_API_KEY. Default .jot/.env in the project. "
                   "The first time JOT runs in a terminal it offers to keep the key in this file")
    args = p.parse_args(argv)
    if args.host not in LOCAL_HOSTS and not args.allow_remote:
        p.error("--host %s would let other machines in, and the dashboard has no login. Add --allow-remote if you "
                "really want that" % args.host)
    env_file = args.env or os.path.join(store.jot_dir(args.jots or store.find_config()), ".env")
    loaded_env = load_env(env_file)
    if loaded_env:
        print("  read %s from %s" % (", ".join(loaded_env), env_file))

    try:
        app = build_project(os.getcwd(), jots=args.jots, db=args.db, logs=args.log, apps=args.app, remote=args.allow_remote, create=True)
    except (OSError, store.QueryError) as e:
        p.error(str(e))
    ask_for_key(env_file)
    ingestor = app.ingestor
    if args.since:
        app.set_since(parse_since(args.since))
    first, loaded, reports, control = app.first, app.loaded, app.reports_loaded, app.control

    server = make_server(app, args.host, args.port, remote=args.allow_remote, apps=args.app)
    if app.project_dir:
        server.RequestHandlerClass.host._remember(app.project_dir)
    print("JOT dashboard on http://%s:%d" % (args.host, args.port))
    print("  following %s, %d events so far, %d sensor definitions, %d reports"
          % (", ".join(ingestor.patterns), first, loaded, reports))
    if control:
        print("  protection can be changed, agents read %s. Every change is logged in %s" % (control.path, control.audit_path))
    if llm.configured():
        print("  questions go to %s. Only the table definitions, sensor descriptions and your questions are sent. "
              "A request for a new JOT also sends the JOT names and descriptions, and the names of the methods JOTs watch that "
              "the application was seen calling." % llm.model())
    else:
        print("  ANTHROPIC_API_KEY is not set. Natural language is off, SQL still works.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.RequestHandlerClass.app.close()


if __name__ == "__main__":
    main()
