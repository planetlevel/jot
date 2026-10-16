#!/usr/bin/env python3
"""JOT dashboard. Follows JOT's JSON event logs into SQLite and answers questions about them,
in plain English or SQL, as tables and charts that can update live.

    python3 server.py --log jot-events.jsonl --jot ../src/main/resources
    ANTHROPIC_API_KEY=... python3 server.py --log '/var/log/app/*.jsonl'
"""

import argparse
import json
import os
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import llm
import store

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_BODY = 64 * 1024
MAX_REPAIRS = 2


class App:
    """Everything the dashboard does, apart from HTTP. The generate function is a parameter so tests
    can run without a model."""

    def __init__(self, db_path, ingestor, generate=llm.generate):
        self.db_path = db_path
        self.ingestor = ingestor
        self.generate = generate

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

    def sql(self, sql):
        return store.run_query(self.db_path, sql)

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
            answer = self.generate(question, schema, sensors, history, error)
            if not answer["sql"]:
                answer.update(columns=[], rows=[], truncated=False, ms=0)
                return answer
            try:
                answer.update(self.sql(answer["sql"]))
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
            if url.path == "/api/status":
                return self._send(200, self.app.status())
            if url.path == "/api/sensors":
                return self._send(200, self.app.sensors())
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
                return self._send(200, self.app.sql(body.get("sql")))
        except store.QueryError as e:
            return self._send(400, {"error": str(e)})
        except llm.LLMError as e:
            return self._send(502, {"error": str(e)})
        except (ValueError, AttributeError, TypeError):
            return self._send(400, {"error": "bad request"})
        except Exception as e:
            print("[dashboard] error:", repr(e), file=sys.stderr)
            return self._send(500, {"error": "internal error"})
        self._send(404, {"error": "not found"})


def make_server(app, host, port):
    handler = type("BoundHandler", (Handler,), {
        "app": app, "port": port, "enforce_host": host in ("127.0.0.1", "localhost", "::1")})
    return ThreadingHTTPServer((host, port), handler)


def main(argv=None):
    p = argparse.ArgumentParser(description="JOT dashboard")
    p.add_argument("--log", action="append", help="JOT event log to follow, may be a glob. Repeatable. "
                   "Default jot-events.jsonl")
    p.add_argument("--jot", action="append", default=[], help=".jot file or directory, for sensor descriptions. Repeatable")
    p.add_argument("--db", default="jot-dashboard.db", help="SQLite file to keep events in")
    p.add_argument("--host", default="127.0.0.1", help="address to listen on. There is no login, "
                   "so only change this on a network you trust")
    p.add_argument("--port", type=int, default=8765)
    args = p.parse_args(argv)

    ingestor = store.Ingestor(args.db, args.log or ["jot-events.jsonl"])
    loaded = store.load_sensors(ingestor.db, args.jot)
    first = ingestor.poll()
    ingestor.start()
    app = App(args.db, ingestor)

    server = make_server(app, args.host, args.port)
    print("JOT dashboard on http://%s:%d" % (args.host, args.port))
    print("  following %s, %d events so far, %d sensor definitions" % (", ".join(ingestor.patterns), first, loaded))
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
