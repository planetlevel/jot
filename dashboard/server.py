#!/usr/bin/env python3
"""JOT dashboard. Follows JOT's JSON event logs into SQLite and answers questions about them,
in plain English or SQL, as tables and charts that can update live.

    python3 server.py --log jot-events.jsonl --jots ../demo/ticketbook/jots.yaml
    ANTHROPIC_API_KEY=... python3 server.py --log '/var/log/app/*.jsonl'
"""

import argparse
import json
import os
import sqlite3
import sys
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import control as control_module
import llm
import store

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 64 * 1024
MAX_REPAIRS = 2
MAX_GRID_ROWS = 5000
SCRIPTS = {"/dom.js": "dom.js", "/grid.js": "grid.js", "/recent.js": "recent.js", "/graph.js": "graph.js", "/cells.js": "cells.js"}   # the only files served besides the page


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


class App:
    """Everything the dashboard does, apart from HTTP. The generate function is a parameter so tests
    can run without a model."""

    def __init__(self, db_path, ingestor, generate=llm.generate, control=None):
        self.db_path = db_path
        self.ingestor = ingestor
        self.generate = generate
        self.control = control      # a ControlStore, or None when the jots file has no control

    def sensors(self):
        db = sqlite3.connect(self.db_path)
        try:
            out = []
            for name, description, methods, scopes, blocks in db.execute(
                    "SELECT name, description, methods, scopes, blocks FROM sensors ORDER BY name"):
                out.append({"name": name, "description": description, "methods": json.loads(methods or "[]"),
                            "scopes": json.loads(scopes or "[]"), "blocks": blocks})
            return out
        finally:
            db.close()

    def reports(self):
        """The reports from the .jot files, each with the query that builds it and how to show it."""
        db = sqlite3.connect(self.db_path)
        try:
            out = []
            for name, rtype, rows, cols in db.execute("SELECT name, type, rows, cols FROM reports ORDER BY rowid"):
                try:
                    out.append({"name": name, "type": rtype, "title": name, "chart": "grid",
                                "sql": store.report_sql(rtype, rows, cols)})
                except ValueError:
                    continue
            return out
        finally:
            db.close()

    def jots(self):
        """Everything the JOTs view shows. Read only. How each sensor, rule and report is defined, which file it
        is in, whether it has fired, and what looks wrong."""
        db = sqlite3.connect(self.db_path)
        try:
            rows = db.execute("""SELECT name, description, methods, scopes, captures, blocks, protect, source,
                                        matchers, excludes, definition, enabled FROM sensors ORDER BY rowid""").fetchall()
            issues = [{"level": l, "text": t, "file": f} for l, t, f in db.execute(
                "SELECT level, text, source FROM jot_issues ORDER BY rowid")]
            report_rows = db.execute("SELECT name, type, rows, cols, source FROM reports ORDER BY rowid").fetchall()
        finally:
            db.close()

        stats = {}
        for sensor, total, last, hour, blocked, monitored in store.run_query(self.db_path, """
                SELECT sensor, COUNT(*), MAX(ts), SUM(ts > (strftime('%s','now') - 3600) * 1000),
                       SUM(action = 'blocked'), SUM(action = 'monitored')
                FROM events GROUP BY sensor""")["rows"]:
            stats[sensor] = {"events": total, "last_ts": last, "last_hour": hour or 0,
                             "blocked": blocked or 0, "monitored": monitored or 0}
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
                "captures": json.loads(captures or "[]"), "matchers": json.loads(matchers or "[]"),
                "excludes": json.loads(excludes or "[]"), "exception": blocks, "file": source,
                "definition": definition, "jot_enabled": jot_enabled != "false",
                **stats.get(name, {"events": 0, "last_ts": None, "last_hour": 0, "blocked": 0, "monitored": 0})})

        known = {x["name"] for x in sensors}
        for sensor in sorted(set(stats) - known - {"jot-control", "jot-config"}):
            issues.append({"level": "info", "file": None,
                           "text": "the log has %d events from %s, which isn't in the loaded .jot files"
                                   % (stats[sensor]["events"], sensor)})

        sql_by_name = {r["name"]: r["sql"] for r in self.reports()}
        reports = [{"name": n, "type": t, "rows": r, "cols": c, "file": f, "sql": sql_by_name.get(n)}
                   for n, t, r, c, f in report_rows]
        files = {}
        for x in sensors:
            files.setdefault(x["file"], {"sensors": 0, "rules": 0, "reports": 0})["rules" if x["kind"] == "rule" else "sensors"] += 1
        for r in reports:
            files.setdefault(r["file"], {"sensors": 0, "rules": 0, "reports": 0})["reports"] += 1
        return {"files": [{"name": k, **v} for k, v in files.items()], "sensors": sensors, "reports": reports,
                "issues": issues}

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
        e["related"] = []
        if e.get("trace") is not None:
            e["related"] = store.run_query(self.db_path, """
                SELECT pk, ts, action, sensor, capture FROM events_raw
                WHERE run = '%s' AND trace = %d ORDER BY ts, pk""" % (str(e["run"]).replace("'", "''"), int(e["trace"])),
                limit=200)["rows"]
        return e

    def search(self, query):
        """The SQL that finds the events matching a search, newest first, and how many more matches the App events only
        filter leaves out. The dashboard runs the SQL like any other view, so it also refreshes and shows its SQL."""
        where = store.search_where(query)
        sql = ("SELECT pk, datetime(ts/1000, 'unixepoch', 'localtime') AS time, action, sensor,\n"
               "       call_site_name AS call_site, capture\nFROM events\nWHERE %s\nORDER BY ts DESC LIMIT 500" % where)
        since = store.get_since(self.db_path) or 0
        shown = store.run_query(self.db_path, "SELECT COUNT(*) FROM events WHERE %s" % where)["rows"][0][0]
        every = store.run_query(self.db_path, "SELECT COUNT(*) FROM events_raw WHERE ts >= %d AND %s" % (since, where))["rows"][0][0]
        return {"sql": sql, "matches": shown, "left_out": every - shown}

    def graph(self, route=None, details=False):
        """The paths through the application, from each route through the methods that ran to what the sensors saw."""
        rows = store.graph_rows(self.db_path, route or None)
        routes = [r[0] for r in store.run_query(self.db_path, """
            SELECT capture, COUNT(*) FROM events_raw WHERE sensor = 'get-routes' AND ts >= %d
            GROUP BY capture ORDER BY capture""" % (store.get_since(self.db_path) or 0), limit=2000)["rows"]]
        return store.build_graph(rows["rows"], routes, self.ingestor.app_prefixes, bool(details), rows["truncated"])

    def set_app_only(self, on):
        """Leave out observed events that have no frame from the application, which is everything the JDK and the
        application server do on their own. Blocked and reported events always show."""
        with self.ingestor.lock:
            store.set_app_only(self.ingestor.db, bool(on))
        return self.status()

    def set_action_filter(self, blocked, monitored):
        """Limit what is shown to blocked events, monitored ones, or both. Neither means everything."""
        with self.ingestor.lock:
            store.set_action_filter(self.ingestor.db, None if blocked is None else bool(blocked),
                                    None if monitored is None else bool(monitored))
        return self.status()

    def set_show_jot_control(self, on):
        """Show or leave out the agent's own jot-control events, which record a rule being switched."""
        with self.ingestor.lock:
            store.set_show_jot_control(self.ingestor.db, bool(on))
        return self.status()

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
                "control": (values("control") or [None])[0], "loaded": values("loaded")}

    def control_state(self):
        """What the Protection panel shows. Each rule's setting is what the control file says, or else what its
        .jot file says. An agent started with -Djot.protect=false ignores the file, and it says so in its
        jot-config events, so a locked agent shows as monitor here whatever the file says."""
        if self.control is None:
            return {"enabled": False}
        file = self.control.read()
        counts = {}
        recent = store.run_query(self.db_path, """
            SELECT sensor, SUM(action = 'blocked'), SUM(action = 'monitored') FROM events
            WHERE action IN ('blocked', 'monitored') AND ts > (strftime('%s','now') - 3600) * 1000
            GROUP BY sensor""")["rows"]
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
            return [{"name": n, "type": t, "rows_sensor": r, "cols": c}
                    for n, t, r, c in db.execute("SELECT name, type, rows, cols FROM reports ORDER BY rowid")]
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
        status["app_only"] = store.get_app_only(self.db_path)
        status["filter"] = store.get_action_filter(self.db_path)
        status["show_jot_control"] = store.get_show_jot_control(self.db_path)
        status["filtered"] = counts[1] - status["events"]  # JDK and server events left out
        status["llm"] = llm.configured()
        status["model"] = llm.model() if llm.configured() else None
        status["known_sensors"] = len(self.sensors())
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

    def _host_ok(self):
        if not self.enforce_host:
            return True
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
            if url.path == "/api/graph":
                q = parse_qs(url.query)
                return self._send(200, self.app.graph(q.get("route", [""])[0], q.get("details", [""])[0] == "1"))
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
            if url.path == "/api/since":
                return self._send(200, self.app.set_since(body.get("since")))
            if url.path == "/api/jot-control-events":
                return self._send(200, self.app.set_show_jot_control(body.get("on")))
            if url.path == "/api/action-filter":
                return self._send(200, self.app.set_action_filter(body.get("blocked"), body.get("monitored")))
            if url.path == "/api/app-only":
                return self._send(200, self.app.set_app_only(body.get("on")))
            if url.path == "/api/control":
                return self._send(200, self.app.change_control(body.get("master"), body.get("rules"), body.get("enabled")))
        except store.QueryError as e:
            return self._send(400, {"error": str(e)})
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


def make_server(app, host, port):
    handler = type("BoundHandler", (Handler,), {
        "app": app, "port": port, "enforce_host": host in ("127.0.0.1", "localhost", "::1")})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    p = argparse.ArgumentParser(description="JOT dashboard")
    p.add_argument("--log", action="append", help="JOT event log to follow, may be a glob. Repeatable. "
                   "Default jot-events.jsonl")
    p.add_argument("--jots", help="the jots file that lists the JOTs and the control file. Start each agent with "
                   "-javaagent:jot.jar=<this path> so the agent and the dashboard use the same definitions. ")
    p.add_argument("--db", default="jot-dashboard.db", help="SQLite file to keep events in")
    p.add_argument("--host", default="127.0.0.1", help="address to listen on. There is no login, "
                   "so only change this on a network you trust")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--app", action="append", help="a package of the application, like com.acme, may be repeated. "
                   "Events whose stack has no frame from these packages are left out by App events only. "
                   "Without it, anything that is not the JDK or the server counts as the application.")
    p.add_argument("--since", help="show only events from this time on, now, or a date and time like 2026-10-16T09:30. "
                   "Nothing is deleted, the Clear and Show all buttons on the Events page change it later")
    p.add_argument("--env", default=os.path.join(HERE, ".env"),
                   help="file of KEY=VALUE settings, such as ANTHROPIC_API_KEY. Default dashboard/.env")
    args = p.parse_args(argv)
    loaded_env = load_env(args.env)
    if loaded_env:
        print("  read %s from %s" % (", ".join(loaded_env), args.env))

    jot_paths, control_path, jots_app = store.read_jots_file(args.jots) if args.jots else ([], None, [])

    ingestor = store.Ingestor(args.db, args.log or ["jot-events.jsonl"], app_prefixes=list(dict.fromkeys((jots_app or []) + (args.app or []))))
    loaded = store.load_sensors(ingestor.db, jot_paths)
    reports = store.load_reports(ingestor.db, jot_paths)
    first = ingestor.poll()
    ingestor.start()
    control = None
    if control_path:
        control = control_module.ControlStore(control_path)
    app = App(args.db, ingestor, control=control)
    if args.since:
        app.set_since(parse_since(args.since))

    server = make_server(app, args.host, args.port)
    print("JOT dashboard on http://%s:%d" % (args.host, args.port))
    print("  following %s, %d events so far, %d sensor definitions, %d reports"
          % (", ".join(ingestor.patterns), first, loaded, reports))
    if control:
        print("  protection can be changed, agents read %s. Every change is logged in %s" % (control.path, control.audit_path))
    if llm.configured():
        print("  questions go to %s. Only the table definitions, sensor descriptions and your questions are sent."
              % llm.model())
    else:
        print("  ANTHROPIC_API_KEY is not set. Natural language is off, SQL still works.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        ingestor.stop()


if __name__ == "__main__":
    main()
