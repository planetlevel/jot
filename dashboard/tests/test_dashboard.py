import contextlib
import glob
import http.server
import io
import json
import yaml
import os
import re
import sqlite3
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import threading
import unittest
import unittest.mock
import zipfile
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import assistant
import catalog
import scanner
import control
import llm
import launcher
import libraries
import server
import store


def event(i, sensor="crypto-cipher", capture="AES", action="observed", trace=1, run="r1", **extra):
    e = {"v": 1, "time": "2026-10-16T00:00:00Z", "ts": 1792111134000 + i, "run": run, "host": "h", "pid": 1,
         "app": "App", "id": i, "trace": trace, "thread": "main", "thread_id": 1, "sensor": sensor,
         "action": action, "capture": capture,
         "method": "java.base/javax.crypto.Cipher.getInstance(Cipher.java:531)",
         "call_site": "com.acme.Ticket.encrypt(Ticket.java:125)", "stack": ["a", "b"]}
    if sensor == "http-route" and "data" not in extra:
        e["data"] = {"path": capture}      # the route sensor captures its path by name, which is where the dashboard reads it
    e.update(extra)
    return e


class Env:
    def __init__(self, create_log=True):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "events.jsonl")
        self.db = os.path.join(self.dir, "test.db")
        if create_log:
            open(self.log, "w").close()
        self.ingestor = store.Ingestor(self.db, [self.log])

    def write(self, *events, raw=None):
        with open(self.log, "a") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")
            if raw:
                f.write(raw)


class IngestTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()

    def count(self):
        return store.run_query(self.env.db, "SELECT COUNT(*) FROM events")["rows"][0][0]

    def test_stores_events_and_derives_names(self):
        self.env.write(event(1))
        self.assertEqual(1, self.env.ingestor.poll())
        r = store.run_query(self.env.db, "SELECT method_name, call_site_name, stack FROM events")
        self.assertEqual(["javax.crypto.Cipher.getInstance", "com.acme.Ticket.encrypt", '["a", "b"]'], r["rows"][0])

    def test_the_named_values_are_kept_and_can_be_read_with_json_extract(self):
        self.env.write(event(1, data={"algorithm": "AES", "bits": 128, "modes": ["CBC", "GCM"]}), event(2))
        self.env.ingestor.poll()
        rows = store.run_query(self.env.db, "SELECT json_extract(data, '$.algorithm'), json_extract(data, '$.bits'), "
                               "json_extract(data, '$.modes[1]') FROM events WHERE data IS NOT NULL")["rows"]
        self.assertEqual([["AES", 128, "GCM"]], rows)
        self.assertEqual(1, store.run_query(self.env.db, "SELECT COUNT(*) FROM events WHERE data IS NULL")["rows"][0][0])

    def test_reads_only_what_is_new(self):
        self.env.write(event(1))
        self.env.ingestor.poll()
        self.env.write(event(2), event(3))
        self.assertEqual(2, self.env.ingestor.poll())
        self.assertEqual(0, self.env.ingestor.poll())
        self.assertEqual(3, self.count())

    def test_waits_for_the_end_of_a_partial_line(self):
        line = json.dumps(event(1))
        self.env.write(raw=line[:30])
        self.assertEqual(0, self.env.ingestor.poll())
        self.env.write(raw=line[30:] + "\n")
        self.assertEqual(1, self.env.ingestor.poll())

    def test_bad_lines_are_counted_not_fatal(self):
        self.env.write(event(1), raw="not json\n[1,2]\n")
        self.env.ingestor.poll()
        self.assertEqual(1, self.count())
        bad = store.run_query(self.env.db, "SELECT bad_lines FROM sources")["rows"][0][0]
        self.assertEqual(2, bad)

    def test_restart_does_not_duplicate(self):
        self.env.write(event(1), event(2))
        self.env.ingestor.poll()
        again = store.Ingestor(self.env.db, [self.env.log])
        self.assertEqual(0, again.poll())
        self.assertEqual(2, self.count())

    def test_truncated_log_is_read_again_without_duplicates(self):
        self.env.write(event(1), event(2))
        self.env.ingestor.poll()
        # the same file name, same size, but a new JVM run wrote it
        with open(self.env.log, "w") as f:
            f.write(json.dumps(event(1, run="r2")) + "\n")
            f.write(json.dumps(event(2, run="r2")) + "\n")
        self.assertEqual(2, self.env.ingestor.poll())
        self.assertEqual(4, self.count())

    def test_follows_a_log_that_appears_later(self):
        env = Env(create_log=False)
        self.assertEqual(0, env.ingestor.poll())
        env.write(event(1))
        self.assertEqual(1, env.ingestor.poll())

    def test_loads_sensor_descriptions(self):
        jot = os.path.join(self.env.dir, "a.jot")
        with open(jot, "w") as f:
            f.write("sensors:\n- name: 'crypto-cipher'\n  description: 'Identifies ciphers'\n  methods:\n"
                    "  - 'javax.crypto.Cipher.getInstance'\n- name: 'block-it'\n  block-when: true\n")
        self.assertEqual(2, store.load_sensors(self.env.ingestor.db, [self.env.dir]))
        app = server.App(self.env.db, self.env.ingestor)
        by_name = {s["name"]: s for s in app.sensors()}
        self.assertEqual("Identifies ciphers", by_name["crypto-cipher"]["description"])
        self.assertEqual("true", by_name["block-it"]["blocks"], "block-when: true is a rule that blocks every call")


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.env.write(*[event(i) for i in range(5)])
        self.env.ingestor.poll()

    def q(self, sql, **kw):
        return store.run_query(self.env.db, sql, **kw)

    def test_select_works_and_limits(self):
        r = self.q("SELECT id FROM events ORDER BY id", limit=3)
        self.assertEqual([[0], [1], [2]], r["rows"])
        self.assertTrue(r["truncated"])
        self.assertFalse(self.q("SELECT id FROM events")["truncated"])

    def test_trailing_semicolon_and_comment_are_fine(self):
        self.assertEqual(5, len(self.q("SELECT id FROM events; ")["rows"]))
        self.assertEqual(5, len(self.q("SELECT id FROM events -- all of them")["rows"]))

    def test_with_clause_and_json_functions(self):
        r = self.q("WITH s AS (SELECT stack FROM events LIMIT 1) SELECT value FROM s, json_each(s.stack)")
        self.assertEqual([["a"], ["b"]], r["rows"])

    def test_writes_and_admin_statements_are_refused(self):
        for sql in ["DELETE FROM events", "DROP TABLE events", "UPDATE events SET sensor='x'",
                    "INSERT INTO sensors (name) VALUES ('x')", "ATTACH DATABASE '/tmp/x.db' AS x",
                    "PRAGMA journal_mode=DELETE", "SELECT load_extension('x')",
                    "SELECT 1; DROP TABLE events", "CREATE TABLE t (a)"]:
            with self.subTest(sql=sql):
                with self.assertRaises(store.QueryError):
                    self.q(sql)
        self.assertEqual(5, self.q("SELECT COUNT(*) FROM events")["rows"][0][0])

    def test_a_write_hidden_in_a_subquery_is_refused(self):
        with self.assertRaises(store.QueryError):
            self.q("SELECT * FROM (DELETE FROM events RETURNING *)")

    def test_runaway_query_is_stopped(self):
        with self.assertRaises(store.QueryError) as c:
            self.q("WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM n) SELECT COUNT(*) FROM n",
                   timeout=0.3)
        self.assertIn("longer than", str(c.exception))

    def test_empty_and_broken_sql(self):
        for sql in ["", "   ", "SELEC 1", "SELECT nope FROM events"]:
            with self.assertRaises(store.QueryError):
                self.q(sql)

    def test_schema_for_model_lists_the_queryable_tables_only(self):
        schema = store.schema_for_model()
        self.assertIn("CREATE TABLE events", schema)
        self.assertIn("CREATE TABLE sensors", schema)
        self.assertNotIn("sources", schema)


REPORTS_JOT = """
sensors:
- name: 'http-route'
reports:
- name: 'Access Control Matrix'
  type: 'compare'
  rows: 'http-route.path'
  cols: 'auth-role-check.role'
- name: 'Test Coverage Matrix'
  type: 'compare'
  rows: 'http-route.path'
  cols: 'auth-user.user'
  value: 'auth-user.roles'
- name: 'Encryption Usage'
  type: 'list'
  cols: 'crypto-cipher.algorithm'
- name: 'Cipher Table'
  type: 'table'
  rows: 'http-route.path'
  cols: 'crypto-cipher.algorithm, crypto-hash.algorithm'
- name: 'Old Timeseries'
  type: 'series'
  rows: 'x'
  cols: 'y'
- name: 'Broken'
  type: 'table'
  cols: 'crypto-cipher'
"""


class ReportTests(unittest.TestCase):
    """The original JOT reports, rebuilt from events."""

    def setUp(self):
        self.env = Env()
        jot = os.path.join(self.env.dir, "r.jot")
        with open(jot, "w") as f:
            f.write(REPORTS_JOT)
        store.load_reports(self.env.ingestor.db, [jot])
        self.app = server.App(self.env.db, self.env.ingestor)
        # two requests. /buy has two roles and a cipher, /home has one role and none
        self.env.write(
            event(1, sensor="http-route", capture="/buy", trace=7, data={"path": "/buy"}),
            event(2, sensor="auth-role-check", capture="RoleA", trace=7, data={"role": "RoleA"}),
            event(3, sensor="auth-role-check", capture="RoleB", trace=7, data={"role": "RoleB"}),
            event(4, sensor="auth-role-check", capture="RoleB", trace=7, data={"role": "RoleB"}),
            event(5, sensor="crypto-cipher", capture="DES", trace=7, data={"algorithm": "DES"}),
            event(6, sensor="http-route", capture="/home", trace=8, data={"path": "/home"}),
            event(7, sensor="auth-role-check", capture="RoleA", trace=8, data={"role": "RoleA"}),
            event(8, sensor="auth-user", capture="alice", trace=8, data={"user": "alice", "roles": ["Role1", "Role2"]}),
            event(9, sensor="http-route", capture="/other", trace=9, run="r2", data={"path": "/other"}),
            event(10, sensor="auth-role-check", capture="RoleC", trace=9, run="r1", data={"role": "RoleC"}))  # a different run, must not join
        self.env.ingestor.poll()

    def report(self, name):
        return next(r for r in self.app.reports() if r["name"] == name)

    def rows(self, name):
        r = self.app.sql(self.report(name)["sql"], limit=5000)
        return sorted(tuple(x) for x in r["rows"])

    def test_only_reports_that_can_be_built_are_listed(self):
        names = [r["name"] for r in self.app.reports()]
        self.assertEqual(["Access Control Matrix", "Test Coverage Matrix", "Encryption Usage", "Cipher Table"], names)
        self.assertTrue(all(r["chart"] == "grid" for r in self.app.reports()))

    def test_compare_is_routes_by_roles_with_x_where_detected(self):
        self.assertEqual([("/buy", "RoleA", "x"), ("/buy", "RoleB", "x"), ("/home", "RoleA", "x")],
                         self.rows("Access Control Matrix"))

    def test_compare_fills_the_cells_from_the_value_field_and_a_list_gives_a_row_per_item(self):
        self.assertEqual([("/home", "alice", "Role1"), ("/home", "alice", "Role2")], self.rows("Test Coverage Matrix"))

    def test_a_boolean_is_true_or_false_in_a_report(self):
        self.env.write(event(30, sensor="auth-role-check", capture="RoleD", trace=7, data={"role": "RoleD", "allowed": True}),
                       event(31, sensor="auth-role-check", capture="RoleE", trace=7, data={"role": "RoleE", "allowed": False}))
        self.env.ingestor.poll()
        sql = store.report_sql("compare", "http-route.path", "auth-role-check.role", "auth-role-check.allowed")
        self.assertIn(("/buy", "RoleD", "true"), [tuple(r) for r in self.app.sql(sql)["rows"]])
        self.assertIn(("/buy", "RoleE", "false"), [tuple(r) for r in self.app.sql(sql)["rows"]])

    def test_the_heading_of_the_row_column_is_what_the_rows_are(self):
        for name, heading in (("Access Control Matrix", "http-route.path"), ("Cipher Table", "http-route.path"), ("Test Coverage Matrix", "http-route.path")):
            out = self.app.sql(self.report(name)["sql"], limit=5000)
            self.assertEqual(heading, out["columns"][0], name)
        out = self.app.sql(store.report_sql("compare", 'weird"name.path', "auth-user.user"))
        self.assertEqual('weird"name.path', out["columns"][0], "a quote in a name can't break the heading")

    def test_a_field_that_isnt_a_name_cannot_break_the_query(self):
        with self.assertRaises(ValueError):
            store.report_sql("table", "http-route.path", "a.b'); DROP TABLE events; --")

    def test_list_is_call_sites_with_what_they_captured(self):
        self.assertEqual([("com.acme.Ticket.encrypt(Ticket.java:125)", "crypto-cipher.algorithm", "DES")], self.rows("Encryption Usage"))

    def test_table_has_a_column_per_sensor(self):
        self.assertEqual([("/buy", "crypto-cipher.algorithm", "DES")], self.rows("Cipher Table"))

    def events_behind(self, name, row=None, col=None):
        q = self.app.report_events(name, row, col)
        out = self.app.sql(q["sql"], limit=5000)
        self.assertEqual(["pk", "time", "action", "sensor", "call_site", "capture"], out["columns"], "pk first, so a row opens its event")
        return q, out["rows"]

    def test_a_cell_has_the_events_that_put_its_values_there(self):
        q, rows = self.events_behind("Access Control Matrix", "/buy", "RoleA")
        self.assertEqual([["auth-role-check", "RoleA"]], [[r[3], r[5]] for r in rows], "the role check of RoleA in the /buy request")
        self.assertEqual("Events behind Access Control Matrix, /buy, RoleA", q["title"])

    def test_a_row_has_all_of_its_events_and_a_column_all_of_its_events(self):
        _, rows = self.events_behind("Access Control Matrix", "/buy", None)
        self.assertEqual(["RoleA", "RoleB", "RoleB"], sorted(r[5] for r in rows), "every role check of that route, two of RoleB")
        _, rows = self.events_behind("Access Control Matrix", None, "RoleB")
        self.assertEqual(["RoleB", "RoleB"], [r[5] for r in rows])
        _, rows = self.events_behind("Access Control Matrix")
        self.assertEqual(4, len(rows), "no row and no column is every event the report uses, that join the route in their request")

    def test_a_table_and_a_list_have_theirs_too(self):
        _, rows = self.events_behind("Cipher Table", "/buy", "crypto-cipher.algorithm")
        self.assertEqual([["crypto-cipher", "DES"]], [[r[3], r[5]] for r in rows])
        _, rows = self.events_behind("Encryption Usage", "com.acme.Ticket.encrypt(Ticket.java:125)", "crypto-cipher.algorithm")
        self.assertEqual(["DES"], [r[5] for r in rows])

    def test_a_row_with_a_quote_in_it_cannot_break_the_query_and_an_unknown_report_is_refused(self):
        _, rows = self.events_behind("Access Control Matrix", "a'b); DROP TABLE events; --", "RoleA")
        self.assertEqual([], rows)
        self.assertEqual(10, self.app.sql("SELECT COUNT(*) FROM events")["rows"][0][0])
        with self.assertRaises(LookupError):
            self.app.report_events("Nothing", None, None)

    def test_sensor_names_with_quotes_cannot_break_the_query(self):
        sql = store.report_sql("compare", "a'b", "c'); DROP TABLE events; --")
        self.assertEqual([], self.app.sql(sql)["rows"])
        self.assertEqual(10, self.app.sql("SELECT COUNT(*) FROM events")["rows"][0][0])

    def test_a_grid_can_return_more_rows_than_an_ordinary_query(self):
        many = [event(100 + i, sensor="get-roles-many", capture="R%d" % i, trace=50) for i in range(1200)]
        self.env.write(*many)
        self.env.ingestor.poll()
        self.assertEqual(1000, len(self.app.sql("SELECT capture FROM events WHERE sensor='get-roles-many'")["rows"]))
        self.assertEqual(1200, len(self.app.sql("SELECT capture FROM events WHERE sensor='get-roles-many'", limit=5000)["rows"]))
        self.assertEqual(5000, len(self.app.sql("SELECT 1 FROM events e, events f", limit=10**6)["rows"]))

    def test_the_model_is_told_about_grids_and_the_reports(self):
        self.assertIn("'localtime'", llm.SYSTEM)
        self.assertIn("grid", llm.SYSTEM)
        self.assertIn("Never ask the user for values", llm.SYSTEM)
        self.assertIn("grid", llm.TOOL["input_schema"]["properties"]["chart"]["enum"])
        prompt = llm.build_prompt("recreate it", "s", [], reports=self.app.report_summaries())
        self.assertIn("Access Control Matrix (compare, rows http-route.path, cols auth-role-check.role)", prompt)
        self.assertIn("Encryption Usage (list, rows none, cols crypto-cipher.algorithm)", prompt)

    def test_report_definitions_sent_to_the_model_contain_no_event_data(self):
        sent = json.dumps(self.app.report_summaries())
        for value in ("/buy", "RoleA", "DES", "alice"):
            self.assertNotIn(value, sent)

    def test_reports_endpoint(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        req = urllib.request.Request("http://127.0.0.1:%d/api/reports" % port, headers={"Host": "127.0.0.1:%d" % port})
        with urllib.request.urlopen(req) as r:
            listed = json.load(r)
        self.assertEqual("Access Control Matrix", listed[0]["name"])
        self.assertIn("SELECT DISTINCT", listed[0]["sql"])


class AskTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.env.write(event(1, sensor="http-route", capture="/buy", trace=7),
                       event(2, sensor="crypto-cipher", capture="DES", trace=7),
                       event(3, sensor="crypto-cipher", capture="AES", trace=8))
        self.env.ingestor.poll()
        self.calls = []

    def app(self, *answers):
        queue = list(answers)

        def generate(question, schema, sensors, history, error, reports=()):
            self.calls.append({"question": question, "schema": schema, "history": history, "error": error,
                               "reports": reports})
            return queue.pop(0)
        return server.App(self.env.db, self.env.ingestor, generate)

    def answer(self, sql, chart="table"):
        return {"title": "T", "sql": sql, "chart": chart, "explanation": "E"}

    def test_runs_the_generated_sql(self):
        app = self.app(self.answer(
            "SELECT r.capture AS route, c.capture AS cipher FROM events r JOIN events c "
            "ON r.run = c.run AND r.trace = c.trace WHERE r.sensor='http-route' AND c.sensor='crypto-cipher'"))
        r = app.ask("which routes use which ciphers?")
        self.assertEqual([["/buy", "DES"]], r["rows"])
        self.assertEqual("T", r["title"])

    def test_repairs_sql_that_fails_by_telling_the_model_the_error(self):
        app = self.app(self.answer("SELECT nope FROM events"), self.answer("SELECT COUNT(*) AS n FROM events"))
        r = app.ask("how many?")
        self.assertEqual([[3]], r["rows"])
        self.assertIn("no such column", self.calls[1]["error"])

    def test_gives_up_after_the_repair_limit(self):
        app = self.app(*[self.answer("SELECT nope FROM events")] * 3)
        with self.assertRaises(store.QueryError):
            app.ask("x")
        self.assertEqual(3, len(self.calls))

    def test_an_empty_result_says_which_sensors_do_have_events(self):
        r = self.app(self.answer("SELECT capture FROM events WHERE sensor = 'get-routes-nothing'")).ask("routes?")
        self.assertEqual([], r["rows"])
        self.assertIn("crypto-cipher (2)", r["hint"])
        self.assertIn("http-route (1)", r["hint"])

    def test_an_empty_result_with_no_events_at_all_points_at_the_log(self):
        env = Env()
        app = server.App(env.db, env.ingestor, lambda *a, **k: self.answer("SELECT 1 WHERE 0"))
        self.assertIn("No events have been loaded", app.ask("anything")["hint"])

    def test_no_sql_means_the_question_could_not_be_answered(self):
        r = self.app({"title": "No", "sql": "", "chart": "table", "explanation": "no such data"}).ask("weather?")
        self.assertEqual([], r["rows"])
        self.assertEqual("no such data", r["explanation"])

    def test_the_model_is_never_sent_event_data(self):
        app = self.app(self.answer("SELECT 1"))
        app.ask("anything?")
        sent = json.dumps(self.calls)
        for secret in ("/buy", "DES", "AES"):
            self.assertNotIn('"%s"' % secret, sent)

    def test_prompt_contains_sensors_history_and_error(self):
        prompt = llm.build_prompt(
            "q?", "CREATE TABLE events (a);",
            [{"name": "crypto-cipher", "description": "Identifies ciphers",
              "methods": ["javax.crypto.Cipher.getInstance"], "scopes": [], "blocks": None},
             {"name": "blocker", "description": None, "methods": [], "scopes": ["a.B.c"], "blocks": "denied"}],
            [{"question": "before", "sql": "SELECT 1"}], error="boom")
        for text in ("crypto-cipher: Identifies ciphers", "watches javax.crypto.Cipher.getInstance",
                     "only inside a.B.c", "a rule, blocks when: denied", "Q: before", "SQL: SELECT 1",
                     "Question: q?", "boom"):
            self.assertIn(text, prompt)

    def test_asking_without_a_key_explains_itself(self):
        saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        try:
            with self.assertRaises(llm.LLMError) as c:
                llm.generate("q", "schema", [])
            self.assertIn("ANTHROPIC_API_KEY", str(c.exception))
        finally:
            if saved:
                os.environ["ANTHROPIC_API_KEY"] = saved


class FakeModel(threading.Thread):
    """Stands in for the model API, so the real request and response handling can be tested."""

    def __init__(self, status=200, reply=None):
        super().__init__(daemon=True)
        self.requests = []
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                outer.requests.append(({k.lower(): v for k, v in self.headers.items()}, json.loads(body)))
                data = json.dumps(reply if reply is not None else {}).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self.httpd = http.server.HTTPServer(("127.0.0.1", 0), H)
        self.url = "http://127.0.0.1:%d/v1/messages" % self.httpd.server_address[1]

    def run(self):
        self.httpd.serve_forever()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


class ModelApiTests(unittest.TestCase):
    def setUp(self):
        self.saved = {k: os.environ.get(k) for k in ("ANTHROPIC_API_KEY", "JOT_DASHBOARD_API_URL", "JOT_DASHBOARD_MODEL")}
        os.environ["ANTHROPIC_API_KEY"] = "test-key"
        os.environ.pop("JOT_DASHBOARD_MODEL", None)

    def tearDown(self):
        for k, v in self.saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def fake(self, **kw):
        fake = FakeModel(**kw)
        fake.start()
        self.addCleanup(fake.stop)
        os.environ["JOT_DASHBOARD_API_URL"] = fake.url
        return fake

    def tool_reply(self, **fields):
        return {"content": [{"type": "tool_use", "name": "report", "input": fields}]}

    def test_sends_the_documented_request_and_reads_the_tool_result(self):
        fake = self.fake(reply=self.tool_reply(title="Ciphers", sql="SELECT 1", chart="bar", explanation="why"))
        out = llm.generate("which ciphers?", "CREATE TABLE events (a);", [{"name": "s", "description": "d"}],
                           [{"question": "earlier", "sql": "SELECT 2"}])
        self.assertEqual({"title": "Ciphers", "sql": "SELECT 1", "chart": "bar", "explanation": "why"}, out)
        headers, body = fake.requests[0]
        self.assertEqual("test-key", headers["x-api-key"])
        self.assertEqual("2023-06-01", headers["anthropic-version"])
        self.assertEqual(llm.DEFAULT_MODEL, body["model"])
        self.assertNotIn("tool_choice", body)  # forcing a tool is rejected by some models
        self.assertEqual("report", body["tools"][0]["name"])
        prompt = body["messages"][0]["content"]
        for text in ("which ciphers?", "CREATE TABLE events", "- s: d", "SQL: SELECT 2"):
            self.assertIn(text, prompt)

    def test_a_jot_is_drafted_with_the_documented_request_and_reads_the_draft_tool_result(self):
        fake = self.fake(reply={"content": [{"type": "tool_use", "name": "draft", "input": {"yaml": GOOD_DRAFT, "explanation": "Watches keys."}}]})
        out = llm.draft_jot("block weak keys", [{"name": "crypto-cipher", "description": "Records ciphers", "methods": ["a.B.c"]}],
                            ["javax.crypto.Cipher.getInstance"], [{"request": "before", "yaml": "name: x"}], ["name is used"])
        self.assertEqual({"yaml": GOOD_DRAFT.strip("\n"), "explanation": "Watches keys."}, out)
        headers, body = fake.requests[0]
        self.assertEqual("test-key", headers["x-api-key"])
        self.assertEqual("draft", body["tools"][0]["name"])
        self.assertIn("block-when", body["system"], "the model is told the whole format")
        self.assertIn("Never capture secrets", body["system"])
        prompt = body["messages"][0]["content"]
        for text in ("crypto-cipher: Records ciphers", "javax.crypto.Cipher.getInstance", "Request: before", "Request: block weak keys", "name is used"):
            self.assertIn(text, prompt)
        self.assertNotIn("AES", prompt, "no captured values are ever sent")

    def test_a_reply_with_no_draft_is_an_error_and_a_missing_key_is_said_plainly(self):
        self.fake(reply={"content": [{"type": "text", "text": "hello"}]})
        with self.assertRaises(llm.LLMError):
            llm.draft_jot("x", [], [])
        os.environ.pop("ANTHROPIC_API_KEY")
        with self.assertRaises(llm.LLMError) as e:
            llm.draft_jot("x", [], [])
        self.assertIn("ANTHROPIC_API_KEY is not set", str(e.exception))

    def test_a_report_is_drafted_with_the_draft_tool_and_a_missing_reply_is_an_error(self):
        fake = self.fake(reply={"content": [{"type": "tool_use", "name": "draft", "input": {"yaml": "name: x\ntype: list", "explanation": "e"}}]})
        self.assertEqual({"yaml": "name: x\ntype: list", "explanation": "e"}, llm.draft_report("q", [], []))
        self.assertEqual("draft", fake.requests[0][1]["tools"][0]["name"])
        self.assertIn("Never invent a sensor or a field", fake.requests[0][1]["system"])
        self.fake(reply={"content": [{"type": "text", "text": "hello"}]})
        with self.assertRaises(llm.LLMError):
            llm.draft_report("q", [], [])

    def test_there_is_room_to_think_and_still_write_the_answer(self):
        fake = self.fake(reply={"content": [{"type": "tool_use", "name": "draft", "input": {"yaml": "name: x", "explanation": "e"}}]})
        llm.draft_jot("q", [], [])
        llm.draft_report("q", [], [])
        asked = self.fake(reply=self.tool_reply(title="t", sql="SELECT 1", chart="table", explanation=""))
        llm.generate("q", "s", [])
        for headers, body in fake.requests + asked.requests:
            self.assertGreaterEqual(body["max_tokens"], 16000, "thinking counts against it, and a request that thought a lot ran out before it answered")
        self.assertEqual(3, len(fake.requests + asked.requests))

    def test_a_reply_that_ran_out_of_room_or_was_declined_says_so_and_is_not_an_empty_answer(self):
        cut = {"stop_reason": "max_tokens", "content": [{"type": "thinking", "thinking": ""},
                                                        {"type": "tool_use", "name": "draft", "input": {"yaml": "name: x\nmeth"}}]}
        refused = {"stop_reason": "refusal", "content": []}
        for call in (lambda: llm.draft_jot("q", [], []), lambda: llm.draft_report("q", [], []), lambda: llm.generate("q", "s", [])):
            self.fake(reply=cut)
            with self.assertRaises(llm.LLMError) as e:
                call()
            self.assertIn("ran out of room", str(e.exception))
            self.fake(reply=refused)
            with self.assertRaises(llm.LLMError) as e:
                call()
            self.assertIn("declined", str(e.exception))

    def test_a_draft_with_nothing_in_it_is_an_error_rather_than_a_blank_message(self):
        self.fake(reply={"content": [{"type": "tool_use", "name": "draft", "input": {}}]})
        for call in (lambda: llm.draft_jot("q", [], []), lambda: llm.draft_report("q", [], [])):
            with self.assertRaises(llm.LLMError) as e:
                call()
            self.assertIn("empty", str(e.exception))
        self.fake(reply={"content": [{"type": "tool_use", "name": "draft", "input": {"yaml": "", "explanation": "That can't be a JOT."}}]})
        self.assertEqual({"yaml": "", "explanation": "That can't be a JOT."}, llm.draft_jot("q", [], []), "no JOT with a reason is a fine answer")

    def test_a_bad_chart_type_falls_back_to_table(self):
        self.fake(reply=self.tool_reply(title="t", sql="SELECT 1", chart="pie", explanation=""))
        self.assertEqual("table", llm.generate("q", "s", [])["chart"])

    def test_api_errors_become_readable_messages_without_the_key(self):
        self.fake(status=401, reply={"error": {"type": "authentication_error", "message": "invalid x-api-key"}})
        with self.assertRaises(llm.LLMError) as c:
            llm.generate("q", "s", [])
        self.assertIn("401", str(c.exception))
        self.assertIn("invalid x-api-key", str(c.exception))
        self.assertNotIn("test-key", str(c.exception))

    def test_a_reply_without_the_tool_is_an_error(self):
        self.fake(reply={"content": [{"type": "text", "text": "sorry"}]})
        with self.assertRaises(llm.LLMError):
            llm.generate("q", "s", [])

    def test_tls_is_verified_but_not_strict(self):
        ctx = llm.tls_context()
        self.assertEqual(ssl.CERT_REQUIRED, ctx.verify_mode)
        self.assertTrue(ctx.check_hostname)
        self.assertFalse(ctx.verify_flags & ssl.VERIFY_X509_STRICT)

    def test_the_model_can_be_chosen(self):
        fake = self.fake(reply=self.tool_reply(title="t", sql="", chart="table", explanation="e"))
        os.environ["JOT_DASHBOARD_MODEL"] = "claude-opus-5-5"
        llm.generate("q", "s", [])
        self.assertEqual("claude-opus-5-5", fake.requests[0][1]["model"])


class EnvFileTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".env")
        self.names = ["JOT_T_PLAIN", "JOT_T_QUOTED", "JOT_T_SINGLE", "JOT_T_EXPORTED", "JOT_T_EXISTING", "JOT_T_EQ"]
        for n in self.names:
            os.environ.pop(n, None)
        self.addCleanup(lambda: [os.environ.pop(n, None) for n in self.names])

    def write(self, text, mode=0o600):
        with open(self.path, "w") as f:
            f.write(text)
        os.chmod(self.path, mode)

    def test_reads_values_comments_quotes_and_export(self):
        self.write("# a comment\n\nJOT_T_PLAIN=abc\nJOT_T_QUOTED=\"with space\"\nJOT_T_SINGLE='x'\n"
                   "export JOT_T_EXPORTED=yes\nJOT_T_EQ=a=b=c\nnot a setting\n")
        names = server.load_env(self.path)
        self.assertEqual(["JOT_T_PLAIN", "JOT_T_QUOTED", "JOT_T_SINGLE", "JOT_T_EXPORTED", "JOT_T_EQ"], names)
        self.assertEqual("abc", os.environ["JOT_T_PLAIN"])
        self.assertEqual("with space", os.environ["JOT_T_QUOTED"])
        self.assertEqual("x", os.environ["JOT_T_SINGLE"])
        self.assertEqual("yes", os.environ["JOT_T_EXPORTED"])
        self.assertEqual("a=b=c", os.environ["JOT_T_EQ"])

    def test_the_environment_wins_over_the_file(self):
        os.environ["JOT_T_EXISTING"] = "from-shell"
        self.write("JOT_T_EXISTING=from-file\n")
        self.assertEqual([], server.load_env(self.path))
        self.assertEqual("from-shell", os.environ["JOT_T_EXISTING"])

    def test_a_missing_file_is_fine(self):
        self.assertEqual([], server.load_env(os.path.join(self.dir, "nope")))

    def test_warns_when_others_can_read_the_file(self):
        self.write("JOT_T_PLAIN=abc\n", mode=0o644)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            server.load_env(self.path)
        self.assertIn("chmod 600", err.getvalue())
        self.assertNotIn("abc", err.getvalue())


class AskForKeyTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, ".jot", ".env")
        self.saved = os.environ.pop("ANTHROPIC_API_KEY", None)
        self.out = []

        def restore():
            os.environ.pop("ANTHROPIC_API_KEY", None)
            if self.saved is not None:
                os.environ["ANTHROPIC_API_KEY"] = self.saved
        self.addCleanup(restore)

    def run_it(self, answer, interactive=True):
        asked = []

        def ask(prompt):
            asked.append(prompt)
            if isinstance(answer, BaseException):
                raise answer
            return answer
        saved = server.ask_for_key(self.path, ask=ask, interactive=interactive, out=self.out.append)
        return saved, asked

    def test_a_key_is_kept_in_a_file_only_the_owner_can_read_and_is_used_at_once(self):
        saved, asked = self.run_it("  sk-ant-abc123 \n".strip())
        self.assertTrue(saved)
        self.assertEqual(1, len(asked))
        self.assertEqual("ANTHROPIC_API_KEY=sk-ant-abc123\n", open(self.path).read())
        self.assertEqual(0o600, os.stat(self.path).st_mode & 0o777)
        self.assertEqual("sk-ant-abc123", os.environ["ANTHROPIC_API_KEY"])
        self.assertNotIn("sk-ant-abc123", "\n".join(self.out))

    def test_a_key_is_added_to_the_other_settings_in_the_file(self):
        os.makedirs(os.path.dirname(self.path))
        with open(self.path, "w") as f:
            f.write("JOT_DASHBOARD_MODEL=x\n")
        self.run_it("sk-ant-abc123")
        self.assertEqual("JOT_DASHBOARD_MODEL=x\nANTHROPIC_API_KEY=sk-ant-abc123\n", open(self.path).read())

    def test_skipping_is_remembered_so_it_is_not_asked_again(self):
        saved, asked = self.run_it("")
        self.assertFalse(saved)
        self.assertNotIn("ANTHROPIC_API_KEY", os.environ)
        self.assertEqual(1, len(asked))
        self.assertEqual([], server.load_env(self.path))
        saved, asked = self.run_it("sk-ant-abc123")
        self.assertEqual([], asked)
        self.assertFalse(saved)

    def test_a_key_added_later_replaces_the_skip_note(self):
        self.run_it("")
        os.environ.pop("ANTHROPIC_API_KEY", None)
        with open(self.path, "w") as f:
            f.write("")
        saved, asked = self.run_it("sk-ant-abc123")
        self.assertTrue(saved)
        self.assertEqual("ANTHROPIC_API_KEY=sk-ant-abc123\n", open(self.path).read())

    def test_nothing_is_asked_when_a_key_is_set_or_nobody_is_at_a_terminal(self):
        os.environ["ANTHROPIC_API_KEY"] = "already"
        self.assertEqual((False, []), self.run_it("sk-ant-abc123"))
        os.environ.pop("ANTHROPIC_API_KEY")
        self.assertEqual((False, []), self.run_it("sk-ant-abc123", interactive=False))
        self.assertFalse(os.path.exists(self.path))

    def test_a_pasted_sentence_is_not_saved_and_ctrl_c_leaves_no_file(self):
        saved, asked = self.run_it("my key is abc")
        self.assertFalse(saved)
        self.assertFalse(os.path.exists(self.path))
        saved, asked = self.run_it(KeyboardInterrupt())
        self.assertFalse(saved)
        self.assertFalse(os.path.exists(self.path))


RULES_JOT = """
sensors:
- name: 'rule-a'
  description: 'blocks a'
  block-when: true
- name: 'rule-b'
  block-when: true
  protect: false
- name: 'just-watching'
"""


JOTS_A = """
sensors:
- name: 'http-route'
  description: 'Identifies the route'
  methods: ['javax.servlet.Servlet.service']
  captures: {path: '#P0.getRequestURI()'}
  matchers: {path: ['!null']}
- name: 'never-fires'
  description: 'No events will ever come'
  methods: ['a.b.C.method']
- name: 'no-methods'
- name: 'bad-method'
  methods: ['not a method']
- name: 'block-exec'
  description: 'No processes'
  methods: ['java.lang.ProcessBuilder.<init>']
  scopes: ['javax.servlet.Servlet.service']
  block-when: true
- name: 'example'
  methods: ['a.b.c.Class.method']
reports:
- name: 'Routes by users'
  type: 'compare'
  rows: 'http-route'
  cols: 'auth-user'
- name: 'Old series'
  type: 'series'
  rows: 'http-route'
  cols: 'http-route'
"""

JOTS_B = """
sensors:
- name: 'http-route'
  methods: ['x.Y.z']
- name: 'block-staged'
  methods: ['java.net.Socket.<init>']
  block-when: true
  protect: false
"""


class JotsViewTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        for name, text in (("a.jot", JOTS_A), ("b.jot", JOTS_B)):
            with open(os.path.join(self.env.dir, name), "w") as f:
                f.write(text)
        store.load_sensors(self.env.ingestor.db, [self.env.dir])
        store.load_reports(self.env.ingestor.db, [self.env.dir])
        now = int(time.time() * 1000)
        self.env.write(event(1, sensor="http-route", capture="/a", ts=now),
                       event(2, sensor="http-route", capture="/b", ts=now - 7200 * 1000),
                       event(3, sensor="block-exec", action="blocked", ts=now),
                       event(4, sensor="block-exec", action="monitored", ts=now),
                       event(5, sensor="mystery", ts=now),
                       event(6, sensor="jot-control", capture="x=block", ts=now))
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)
        self.view = self.app.jots()
        self.by_name = {s["name"]: s for s in self.view["sensors"]}

    def test_lists_sensors_rules_and_reports_with_their_definitions(self):
        self.assertEqual({"http-route", "never-fires", "no-methods", "bad-method", "block-exec", "block-staged"},
                         set(self.by_name))
        routes = self.by_name["http-route"]
        self.assertEqual(("sensor", "observe"), (routes["kind"], routes["mode"]))
        self.assertEqual(["javax.servlet.Servlet.service"], routes["methods"])
        self.assertEqual({"path": "#P0.getRequestURI()"}, routes["captures"])
        self.assertEqual({"path": ["!null"]}, routes["matchers"])
        self.assertIn("name: 'http-route'", routes["definition"], "the sensor as written in its file")
        self.assertEqual(["Routes by users"], [r["name"] for r in self.view["reports"]])

    def test_the_first_definition_wins_like_the_agent_and_the_duplicate_is_reported(self):
        self.assertEqual("a.jot", self.by_name["http-route"]["file"])
        self.assertEqual(["javax.servlet.Servlet.service"], self.by_name["http-route"]["methods"])
        self.assertTrue(any("http-route is defined again in b.jot" in i["text"] and "a.jot" in i["text"]
                            for i in self.view["issues"]))

    def test_rules_show_their_mode_and_a_staged_rule_is_monitor(self):
        self.assertEqual(("rule", "block"), (self.by_name["block-exec"]["kind"], self.by_name["block-exec"]["mode"]))
        self.assertEqual("monitor", self.by_name["block-staged"]["mode"])
        self.assertEqual("true", self.by_name["block-exec"]["block_when"])

    def test_activity_counts(self):
        routes = self.by_name["http-route"]
        self.assertEqual((2, 1), (routes["events"], routes["last_hour"]))
        self.assertIsNotNone(routes["last_ts"])
        rule = self.by_name["block-exec"]
        self.assertEqual((1, 1, 2), (rule["blocked"], rule["monitored"], rule["events"]))
        self.assertEqual(0, self.by_name["never-fires"]["events"])
        self.assertIsNone(self.by_name["never-fires"]["last_ts"])

    def test_notices_what_looks_wrong(self):
        texts = " | ".join(i["text"] for i in self.view["issues"])
        self.assertIn("no-methods has no methods", texts)
        self.assertIn("'not a method'", texts)
        self.assertIn("report Routes by users uses auth-user, which no loaded sensor defines", texts)
        self.assertIn("Old series is type series", texts)
        self.assertFalse([t for t in texts if "mystery" in t or "isn't in the loaded" in t], "events from a name that isn't loaded are history, not a problem")
        self.assertNotIn("jot-control", texts)          # the agent's own events aren't a sensor
        self.assertNotIn("example", " ".join(self.by_name))   # the placeholder is skipped

    def test_files_are_summarised(self):
        files = {f["name"]: f for f in self.view["files"]}
        self.assertEqual({"sensors": 4, "rules": 1, "reports": 1}, {k: files["a.jot"][k] for k in ("sensors", "rules", "reports")})
        self.assertEqual({"sensors": 0, "rules": 1, "reports": 0}, {k: files["b.jot"][k] for k in ("sensors", "rules", "reports")})

    def test_a_reports_query_is_included_so_it_can_be_opened(self):
        self.assertIn("SELECT DISTINCT", self.view["reports"][0]["sql"])

    def test_the_view_is_served_over_http_and_changes_nothing(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        req = urllib.request.Request("http://127.0.0.1:%d/api/jots" % port, headers={"Host": "127.0.0.1:%d" % port})
        with urllib.request.urlopen(req) as r:
            served = json.load(r)
        self.assertEqual(len(self.view["sensors"]), len(served["sensors"]))

    CHROME = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                               shutil.which("google-chrome") or "", shutil.which("chromium") or "") if c and os.path.exists(c)), None)

    def render(self, address):
        """The page after its scripts have run, from a real headless browser with a throwaway profile."""
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        profile = tempfile.mkdtemp()
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + profile,
                               "--virtual-time-budget=8000", "--dump-dom", "http://127.0.0.1:%d/%s" % (port, address)],
                              capture_output=True, text=True, timeout=90)
        return done.stdout

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_list_is_sorted_by_name_and_the_headers_say_so(self):
        page = self.render("#jots")
        table = re.search(r'<table class="list">(.*?)</table>', page, re.S).group(1)
        names = re.findall(r'<td>([a-z-]+)</td><td class="watch"', table)
        self.assertEqual(6, len(names))
        self.assertEqual(sorted(names, key=str.lower), names, "A to Z by name")
        self.assertRegex(table, r'aria-sort="ascending"[^>]*>Name ▲')
        self.assertRegex(table, r'<th[^>]*>Protect</th>', "the last column is Protect, a toggle")
        self.assertNotIn(">Mode<", table)
        self.assertNotIn("modeswitch", table, "no Monitor and Protect words around the toggle")
        self.assertEqual(3, table.count('class="sortable"') + table.count(' sortable"'), "Name, Location and File can be sorted")
        self.assertNotIn('id="jotKind"', page, "there is no Sensors and rules filter, they are the same thing")
        for gone in (">Kind<", ">Last hour<", ">Total<", ">Last fired<"):
            self.assertNotIn(gone, table)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_selected_sensor_is_shown_without_stray_null_text_and_nothing_shows_before_a_selection(self):
        page = self.render("#jots/never-fires/edit")
        detail = re.search(r'<aside id="jotDetail"([^>]*)>(.*?)</aside>', page, re.S)
        self.assertIsNotNone(detail, "the detail panel is not on the page")
        self.assertNotIn("hidden", detail.group(1), "the detail panel should be showing")
        text = re.sub(r"<[^>]+>", " ", detail.group(2))
        self.assertIn("never-fires", text)
        self.assertIn("No events in the log yet", text)
        self.assertNotIn("null", text.lower(), "an empty section was passed to the DOM as null, which prints the word null")
        self.assertIn("YAML", text)
        self.assertIn('aria-label="Copy YAML"', detail.group(2), "the definition has a copy button")
        self.assertIn("cm-editor", detail.group(2), "the definition is in the editor")
        self.assertIn("a.b.C.method", detail.group(2), "and the YAML is in it")
        self.assertIn("cm-line", detail.group(2))
        self.assertIn("cm-gutters", detail.group(2), "with line numbers")
        self.assertNotIn("Select a sensor", page, "the empty placeholder panel is gone")
        backdrop = re.search(r'<div id="jotBackdrop"([^>]*)>', page)
        self.assertNotIn("hidden", backdrop.group(1), "the page behind the panel is dimmed")

        page = self.render("#jots")
        detail = re.search(r'<aside id="jotDetail"([^>]*)>', page)
        self.assertIn("hidden", detail.group(1), "with nothing selected there is no detail panel")
        backdrop = re.search(r'<div id="jotBackdrop"([^>]*)>', page)
        self.assertIn("hidden", backdrop.group(1), "and nothing is dimmed")

    def console(self, address):
        """What the page wrote to the browser console, which is where a script error shows up."""
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--enable-logging=stderr",
                               "--log-level=0", "--user-data-dir=" + tempfile.mkdtemp(), "--virtual-time-budget=8000",
                               "--dump-dom", "http://127.0.0.1:%d/%s" % (port, address)], capture_output=True, text=True, timeout=90)
        return [l for l in done.stderr.splitlines() if "CONSOLE" in l]

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_no_page_has_a_script_error(self):
        for address in ("", "#jots", "#graph", "#event/1"):
            errors = [l for l in self.console(address) if "Uncaught" in l or "TypeError" in l or "ReferenceError" in l]
            self.assertEqual([], errors, "script error on " + (address or "the events page"))

    def page_section(self, page, name):
        return re.search(r'<main id="%s"[^>]*>(.*?)</main>' % name, page, re.S).group(1)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_reports_are_on_their_own_tab_apart_from_the_list_of_jots(self):
        page = self.render("#reports")
        self.assertRegex(page, r'<a href="#reports" id="navReports" class="active">Reports</a>')
        self.assertNotIn("hidden", re.search(r'<main id="reportsPage"([^>]*)>', page).group(1), "the Reports tab is showing")
        self.assertIn("hidden", re.search(r'<main id="jotsPage"([^>]*)>', page).group(1))
        reports = self.page_section(page, "reportsPage")
        jots = self.page_section(page, "jotsPage")
        report_names = [r["name"] for r in self.view["reports"]]
        self.assertTrue(report_names)
        for name in report_names:
            self.assertIn(name, reports, "the report is listed on the Reports tab")
            self.assertNotIn(">%s<" % name, jots, "and not among the JOTs")
        self.assertNotIn("Open</button>", reports, "a report runs where it is, it isn't sent to the Events page")
        self.assertNotIn('value="report"', page, "there is no longer a report choice in the kind list")
        self.assertRegex(re.sub(r"<[^>]+>", "", reports), r"\d+ reports")
        self.assertRegex(re.sub(r"<[^>]+>", "", jots), r"\d+ sensors and \d+ rules")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_report_selected_on_the_reports_tab_runs_there_under_the_list(self):
        page = self.render("#reports/Routes%20by%20users")
        result = re.search(r'<div class="card wide result" id="reportResult"([^>]*)>(.*?)</div>\s*</div>\s*</main>', page, re.S)
        self.assertIsNotNone(result, "the result sits on the Reports tab")
        self.assertNotIn("hidden", result.group(1), "and it is showing")
        text = re.sub(r"<[^>]+>", " ", result.group(2))
        self.assertIn("Routes by users", text)
        self.assertRegex(text, r"\d+ rows in \d+ ms", "it ran and says how long it took")
        self.assertNotIn('aria-label="Next"', result.group(2), "with one report there is nothing to step to")
        self.assertIn("hidden", re.search(r'<aside id="jotDetail"([^>]*)>', page).group(1), "no panel opens for a report")
        self.assertIn('<tr class="selected"', self.page_section(page, "reportsPage"), "the report's row is marked")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_views_picker_on_the_events_page_no_longer_lists_reports(self):
        page = self.render("")
        picker = re.search(r'<select id="reportSelect".*?</select>', page, re.S).group(0)
        self.assertNotIn("Reports from your .jot files", picker)
        self.assertNotIn("Routes by users", picker)
        self.assertIn("Latest events", picker)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_event_panel_links_its_sensor_to_the_jot_definition(self):
        pk = store.run_query(self.env.db, "SELECT pk FROM events WHERE sensor = 'http-route' LIMIT 1")["rows"][0][0]
        page = self.render("#event/%d" % pk)
        drawer = re.search(r'<aside id="eventDrawer"[^>]*>(.*?)</aside>', page, re.S).group(1)
        self.assertGreaterEqual(drawer.count('href="#jots/http-route/edit"'), 2, "linked in the heading and in the details")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_panel_has_previous_and_next_buttons_with_the_position_in_the_list(self):
        page = self.render("#jots/http-route/edit")
        detail = re.search(r'<aside id="jotDetail"([^>]*)>(.*?)</aside>', page, re.S).group(2)
        self.assertIn('aria-label="Previous"', detail)
        self.assertIn('aria-label="Next"', detail)
        position = re.search(r'<span class="pos">(\d+) of (\d+)</span>', detail)
        self.assertIsNotNone(position, "the panel says where this is in the list")
        self.assertEqual(len(self.view["sensors"]), int(position.group(2)), "the list is every sensor and rule")
        first = re.search(r'<button[^>]*aria-label="Previous"[^>]*>', detail).group(0)
        self.assertEqual(position.group(1) == "1", "disabled" in first, "there is nothing before the first one")

    def switches_app(self, **settings):
        """The page with a control file, so each rule has its switches. settings are written before it loads."""
        path = os.path.join(self.env.dir, "control-switches.yaml")
        store_ = control.ControlStore(path)
        if settings:
            store_.write(known_rules=["block-exec", "block-staged"], **settings)
        self.app = server.App(self.env.db, self.env.ingestor, control=store_)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_every_jot_is_one_line_with_an_enabled_switch_and_only_rules_have_a_mode_switch(self):
        self.switches_app()
        page = self.render("#jots")
        jots = self.page_section(page, "jotsPage")
        table = re.search(r'<table class="list">(.*?)</table>', jots, re.S).group(1)
        rows = re.findall(r"<tr[^>]*>(.*?)</tr>", table.split("<tbody>")[1], re.S)
        self.assertEqual(len(self.view["sensors"]), len(rows), "one row for each sensor and rule, and nothing else is listed")
        for name in ("block-exec", "block-staged"):
            self.assertIn('aria-label="%s enabled"' % name, jots, "a rule has an enabled switch on its left")
            self.assertIn('aria-label="%s protects"' % name, jots, "and a monitor or protect switch on its right")
        for sensor in ("http-route", "never-fires"):
            row = next(r for r in rows if ">%s<" % sensor in r)
            self.assertIn('aria-label="%s enabled"' % sensor, row, "a sensor that only observes can be switched off too")
            self.assertNotIn("protects", row, "but it has no monitor or protect switch")
        for row in rows:
            self.assertEqual(1, row.count("enabled\""), "every JOT has exactly one enabled switch")
        first = next(r for r in rows if ">block-exec<" in r)
        self.assertLess(first.index("block-exec enabled"), first.index(">block-exec<"))
        self.assertGreater(first.index("block-exec protects"), first.index(">block-exec<"))

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_protection_panel_no_longer_lists_the_rules_a_second_time(self):
        self.switches_app()
        page = self.render("#jots")
        panel = re.search(r'<div class="card wide" id="protectionCard"[^>]*>(.*?)</div>\s*<(?:details|div) class="card wide" id="(?:entryCard|sensorsCard)"', page, re.S).group(1)
        self.assertNotIn("block-exec", panel)
        self.assertNotIn("role=\"switch\"", panel)
        self.assertIn("Monitor", panel)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_sensor_that_is_not_enabled_shows_off_too(self):
        path = os.path.join(self.env.dir, "control-sensor.yaml")
        store_ = control.ControlStore(path)
        store_.write(enabled={"http-route": False}, known_rules=["block-exec"], known_sensors=["http-route"])
        self.app = server.App(self.env.db, self.env.ingestor, control=store_)
        jots = self.page_section(self.render("#jots"), "jotsPage")
        rows = re.findall(r'<tr[^>]*>.*?</tr>', jots, re.S)
        self.assertRegex(next(r for r in rows if ">http-route<" in r), r'<tr class="off"')
        self.assertNotIn('class="off"', next(r for r in rows if ">never-fires<" in r))

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_rule_that_is_not_enabled_shows_off_and_cannot_be_switched_between_monitor_and_protect(self):
        self.switches_app(enabled={"block-exec": False})
        page = self.render("#jots")
        jots = self.page_section(page, "jotsPage")
        row = next(r for r in re.findall(r'<tr[^>]*>.*?</tr>', jots, re.S) if ">block-exec<" in r)
        self.assertRegex(row, r'<tr class="off"')
        self.assertRegex(row, r'aria-checked="false"[^>]*aria-label="block-exec enabled"|aria-label="block-exec enabled"[^>]*aria-checked="false"')
        protects = re.search(r"<button[^>]*aria-label=\"block-exec protects\"[^>]*>", row).group(0)
        self.assertIn("disabled", protects)
        other = next(r for r in re.findall(r'<tr[^>]*>.*?</tr>', jots, re.S) if ">block-staged<" in r)
        self.assertNotIn('class="off"', other)

    def test_rule_modes_follow_the_control_file_when_there_is_one(self):
        path = os.path.join(self.env.dir, "control.yaml")
        control_store = control.ControlStore(path)
        control_store.write(rules={"block-exec": False}, known_rules=["block-exec", "block-staged"])
        app = server.App(self.env.db, self.env.ingestor, control=control_store)
        modes = {s["name"]: s["mode"] for s in app.jots()["sensors"]}
        self.assertEqual("monitor", modes["block-exec"])


class StartTimeTests(unittest.TestCase):
    """Clearing the dashboard sets a start time. Nothing is deleted."""

    def setUp(self):
        self.env = Env()
        self.app = server.App(self.env.db, self.env.ingestor)
        self.env.write(*[event(i, ts=1000 + i) for i in range(5)])       # ids 0 to 4 at ts 1000 to 1004
        self.env.ingestor.poll()

    def visible(self):
        return store.run_query(self.env.db, "SELECT COUNT(*) FROM events")["rows"][0][0]

    def test_everything_is_visible_until_a_start_time_is_set(self):
        status = self.app.status()
        self.assertEqual((5, None, 0), (status["events"], status["since"], status["hidden"]))

    def test_a_start_time_hides_older_events_and_counts_them(self):
        status = self.app.set_since(1003)
        self.assertEqual((2, 1003, 3), (status["events"], status["since"], status["hidden"]))
        self.assertEqual(2, self.visible())

    def test_events_that_arrive_after_the_start_time_show_up(self):
        self.app.set_since(1003)
        self.env.write(event(10, ts=5000), event(11, ts=5001))
        self.env.ingestor.poll()
        self.assertEqual(4, self.visible())

    def test_events_with_an_older_time_that_arrive_late_stay_hidden(self):
        self.app.set_since(1003)
        self.env.write(event(12, ts=900))
        self.env.ingestor.poll()
        self.assertEqual(2, self.visible())

    def test_show_all_brings_everything_back(self):
        self.app.set_since(1003)
        status = self.app.set_since(None)
        self.assertEqual((5, None, 0), (status["events"], status["since"], status["hidden"]))

    def test_now_hides_everything_recorded_so_far(self):
        before = int(time.time() * 1000)
        status = self.app.set_since("now")
        self.assertGreaterEqual(status["since"], before)
        self.assertEqual((0, 5), (status["events"], status["hidden"]))

    def test_the_start_time_survives_a_restart(self):
        self.app.set_since(1003)
        again = server.App(self.env.db, store.Ingestor(self.env.db, [self.env.log]))
        self.assertEqual(1003, again.status()["since"])
        self.assertEqual(2, again.status()["events"])

    def test_every_query_and_view_honours_it_including_the_ones_the_model_writes(self):
        self.app.set_since(1003)
        for sql in ("SELECT COUNT(*) FROM events", "SELECT COUNT(*) FROM events WHERE sensor = 'crypto-cipher'",
                    "SELECT COUNT(DISTINCT trace) FROM events"):
            self.assertLessEqual(self.app.sql(sql)["rows"][0][0], 2, sql)

    def test_the_model_is_told_about_events_not_the_raw_table(self):
        schema = store.schema_for_model()
        self.assertIn("CREATE TABLE events (", schema)
        self.assertNotIn("events_raw", schema)

    def test_a_database_from_before_start_times_is_migrated_and_keeps_its_events(self):
        import sqlite3
        path = os.path.join(tempfile.mkdtemp(), "old.db")
        old = sqlite3.connect(path)
        old.execute("CREATE TABLE events (pk INTEGER PRIMARY KEY, time TEXT, ts INTEGER, run TEXT, host TEXT, pid INTEGER, "
                    "app TEXT, id INTEGER, trace INTEGER, thread TEXT, thread_id INTEGER, sensor TEXT, action TEXT, "
                    "capture TEXT, message TEXT, method TEXT, method_name TEXT, call_site TEXT, call_site_name TEXT, "
                    "stack TEXT, UNIQUE (run, id))")
        old.execute("INSERT INTO events (ts, run, id, sensor, action, capture) VALUES (7, 'r', 1, 's', 'observed', 'x')")
        old.commit(); old.close()
        migrated = store.Ingestor(path, [os.path.join(tempfile.mkdtemp(), "none.jsonl")])
        self.assertEqual(1, store.run_query(path, "SELECT COUNT(*) FROM events")["rows"][0][0])
        self.assertEqual(1, store.run_query(path, "SELECT COUNT(*) FROM events_raw")["rows"][0][0])
        store.set_since(migrated.db, 100)
        self.assertEqual(0, store.run_query(path, "SELECT COUNT(*) FROM events")["rows"][0][0])

    def test_an_empty_view_after_clearing_says_so_instead_of_saying_nothing_was_loaded(self):
        self.app.set_since("now")
        hint = self.app.sql("SELECT * FROM events")["hint"]
        self.assertIn("since the dashboard was cleared", hint)
        self.assertIn("5 events", hint)
        self.assertNotIn("No events have been loaded", hint)

    def test_parse_since(self):
        self.assertEqual("now", server.parse_since(" NOW "))
        self.assertEqual(1792111134000, server.parse_since("1792111134000"))
        self.assertIsInstance(server.parse_since("2026-10-16T09:30"), int)
        with self.assertRaises(ValueError):
            server.parse_since("yesterday")

    def test_the_start_time_can_be_set_over_http(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)

        def post(body, headers=None):
            h = {"Host": "127.0.0.1:%d" % port, "Content-Type": "application/json", "X-JOT-Dashboard": "1"}
            h.update(headers or {})
            req = urllib.request.Request("http://127.0.0.1:%d/api/since" % port, data=json.dumps(body).encode(), method="POST", headers=h)
            with urllib.request.urlopen(req) as r:
                return json.load(r)
        self.assertEqual(2, post({"since": 1003})["events"])
        self.assertEqual(5, post({"since": None})["events"])
        self.assertEqual(0, post({"since": "now"})["events"])
        with self.assertRaises(urllib.error.HTTPError) as c:
            urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/api/since" % port, data=b'{"since":null}', method="POST",
                                   headers={"Host": "127.0.0.1:%d" % port, "Content-Type": "text/plain"}))
        self.assertEqual(403, c.exception.code)


class ControlStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "control.yaml")
        self.control = control.ControlStore(self.path)
        self.known = ["rule-a", "rule-b"]

    def files(self):
        return sorted(os.listdir(self.dir))

    def test_a_missing_file_means_the_defaults(self):
        state = self.control.read()
        self.assertEqual((True, {}, False), (state["protect"], state["rules"], state["exists"]))

    def test_writes_merge_and_null_goes_back_to_the_jot_setting(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known)
        self.control.write(master=False, rules={"rule-b": True}, known_rules=self.known)
        state = self.control.read()
        self.assertEqual((False, {"rule-a": False, "rule-b": True}), (state["protect"], state["rules"]))
        self.control.write(rules={"rule-a": None}, known_rules=self.known)
        self.assertEqual({"rule-b": True}, self.control.read()["rules"])

    def test_the_file_has_the_format_the_agent_reads(self):
        self.control.write(master=True, rules={"rule-a": False}, known_rules=self.known, who="jeff")
        with open(self.path) as f:
            doc = yaml.safe_load(f)
        self.assertEqual(1, doc["v"])
        self.assertEqual({"rule-a": {"protect": False}}, doc["sensors"])
        self.assertNotIn("rules", doc, "settings are written under each sensor's name")
        self.assertEqual("jeff", doc["by"])
        self.assertEqual(0o644, os.stat(self.path).st_mode & 0o777)

    def test_writing_leaves_no_temporary_files_behind(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known)
        self.assertEqual(["control.yaml", "control.yaml.audit"], self.files())

    def test_every_change_is_logged_with_before_and_after(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known, who="jeff")
        self.control.write(master=False, known_rules=self.known, who="jeff")
        with open(self.control.audit_path) as f:
            entries = [json.loads(line) for line in f]
        self.assertEqual(2, len(entries))
        self.assertEqual({"protect": True, "rules": {}, "enabled": {}}, entries[0]["before"])
        self.assertEqual({"protect": True, "rules": {"rule-a": False}, "enabled": {}}, entries[0]["after"])
        self.assertEqual(False, entries[1]["after"]["protect"])

    def test_bad_changes_are_refused_and_change_nothing(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known)
        for kwargs in [{"rules": {"nobody": False}}, {"rules": {"rule-a": "no"}}, {"rules": []}, {"master": "off"}]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(control.ControlError):
                    self.control.write(known_rules=self.known, **kwargs)
        self.assertEqual({"rule-a": False}, self.control.read()["rules"])

    def test_enabled_is_a_setting_of_the_sensor_and_null_goes_back_to_the_jot_file(self):
        self.control.write(enabled={"rule-a": False}, known_rules=self.known)
        self.control.write(enabled={"rule-b": True}, known_rules=self.known)
        self.assertEqual({"rule-a": False, "rule-b": True}, self.control.read()["enabled"])
        with open(self.path) as f:
            self.assertEqual({"rule-a": {"enabled": False}, "rule-b": {"enabled": True}}, yaml.safe_load(f)["sensors"])
        self.control.write(enabled={"rule-a": None}, known_rules=self.known)
        self.assertEqual({"rule-b": True}, self.control.read()["enabled"])
        self.control.write(enabled={"rule-b": None}, known_rules=self.known)
        self.assertEqual({}, self.control.read()["enabled"])

    def test_one_sensor_keeps_protect_and_enabled_together_and_other_changes_keep_them(self):
        self.control.write(rules={"rule-a": True}, enabled={"rule-a": False}, known_rules=self.known)
        self.control.write(master=False, known_rules=self.known)
        state = self.control.read()
        self.assertEqual(({"rule-a": True}, {"rule-a": False}, False), (state["rules"], state["enabled"], state["protect"]))
        with open(self.path) as f:
            self.assertEqual({"rule-a": {"protect": True, "enabled": False}}, yaml.safe_load(f)["sensors"])

    def test_a_rules_map_is_no_longer_read_and_is_dropped_when_the_file_is_written(self):
        with open(self.path, "w") as f:
            f.write("v: 1\nprotect: true\nrules:\n  rule-a: false\n")
        self.assertEqual({}, self.control.read()["rules"], "the agent refuses a file like this, so it isn't taken as a setting")
        self.control.write(enabled={"rule-b": False}, known_rules=self.known)
        with open(self.path) as f:
            doc = yaml.safe_load(f)
        self.assertEqual({"rule-b": {"enabled": False}}, doc["sensors"])
        self.assertNotIn("rules", doc)

    def test_bad_enabled_values_are_refused_and_change_nothing(self):
        self.control.write(enabled={"rule-a": False}, known_rules=self.known)
        for bad in [{"nobody": True}, {"rule-a": "yes"}, ["rule-a"]]:
            with self.subTest(bad=bad):
                with self.assertRaises(control.ControlError):
                    self.control.write(enabled=bad, known_rules=self.known)
        self.assertEqual({"rule-a": False}, self.control.read()["enabled"])

    def test_a_corrupt_file_reads_as_the_defaults(self):
        with open(self.path, "w") as f:
            f.write("not json")
        self.assertEqual((True, False), (self.control.read()["protect"], self.control.read()["exists"]))



class ControlApiTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        jot = os.path.join(self.env.dir, "rules.jot")
        with open(jot, "w") as f:
            f.write(RULES_JOT)
        store.load_sensors(self.env.ingestor.db, [jot])
        self.control_path = os.path.join(self.env.dir, "control.yaml")
        self.control = control.ControlStore(self.control_path)
        self.app = server.App(self.env.db, self.env.ingestor, control=self.control)
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        self.port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = self.port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)

    def call(self, body=None):
        headers = {"Host": "127.0.0.1:%d" % self.port}
        if body is not None:
            headers.update({"Content-Type": "application/json", "X-JOT-Dashboard": "1"})
        req = urllib.request.Request("http://127.0.0.1:%d/api/control" % self.port, headers=headers,
                                     method="POST" if body is not None else "GET",
                                     data=json.dumps(body).encode() if body is not None else None)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def modes(self, state):
        return {r["name"]: r["mode"] for r in state["rules"]}

    def test_only_rules_are_listed_and_a_staged_rule_starts_in_monitor(self):
        code, state = self.call()
        self.assertEqual(200, code)
        self.assertEqual({"rule-a": "block", "rule-b": "monitor"}, self.modes(state))

    def test_switching_a_rule_changes_the_file_and_the_mode(self):
        code, state = self.call({"rules": {"rule-a": False, "rule-b": True}})
        self.assertEqual(200, code)
        self.assertEqual({"rule-a": "monitor", "rule-b": "block"}, self.modes(state))
        self.assertEqual({"rule-a": False, "rule-b": True}, self.control.read()["rules"])

    def test_a_rule_that_is_not_enabled_keeps_its_mode_and_enabling_it_again_removes_the_setting(self):
        _, state = self.call({"enabled": {"rule-a": False}})
        self.assertEqual({"rule-a": "block", "rule-b": "monitor"}, self.modes(state), "being off doesn't change what it would do")
        self.assertEqual({"rule-a": False, "rule-b": True}, {r["name"]: r["enabled"] for r in state["rules"]})
        self.assertEqual({"rule-a": False, "rule-b": True, "just-watching": True}, state["enabled"])
        self.assertEqual({"rule-a": False}, self.control.read()["enabled"])
        _, state = self.call({"enabled": {"rule-a": None}})
        self.assertTrue(state["enabled"]["rule-a"])
        self.assertEqual({}, self.control.read()["enabled"])

    def test_a_sensor_that_only_observes_can_be_switched_off_but_an_unknown_name_is_refused(self):
        code, state = self.call({"enabled": {"nobody": False}})
        self.assertEqual(400, code)
        self.assertFalse(self.control.read()["exists"])
        code, state = self.call({"enabled": {"just-watching": False}})
        self.assertEqual(200, code)
        self.assertFalse(state["enabled"]["just-watching"])
        self.assertEqual({"rule-a": "block", "rule-b": "monitor"}, self.modes(state), "it is not a rule, so no rule changes")

    def test_the_master_switch_makes_everything_monitor(self):
        _, state = self.call({"master": False, "rules": {"rule-b": True}})
        self.assertEqual({"rule-a": "monitor", "rule-b": "monitor"}, self.modes(state))
        self.assertFalse(state["master"])



    def test_unknown_rules_and_sensors_that_are_not_rules_are_refused(self):
        for rule in ["nobody", "just-watching"]:
            code, body = self.call({"rules": {rule: False}})
            self.assertEqual(400, code, rule)
        self.assertFalse(self.control.read()["exists"])

    def test_without_a_control_file_the_panel_is_off(self):
        app = server.App(self.env.db, self.env.ingestor)
        self.assertEqual({"enabled": False}, app.control_state())

    def test_the_panel_shows_recent_violations_and_what_agents_applied(self):
        now = int(time.time() * 1000)
        self.env.write(event(1, sensor="rule-a", action="blocked", ts=now),
                       event(2, sensor="rule-a", action="monitored", ts=now),
                       event(3, sensor="rule-a", action="monitored", ts=now),
                       event(4, sensor="jot-control", capture="rule-a=monitor", ts=now))
        self.env.ingestor.poll()
        state = self.app.control_state()
        rule_a = next(r for r in state["rules"] if r["name"] == "rule-a")
        self.assertEqual({"blocked": 1, "monitored": 2}, rule_a["last_hour"])
        self.assertEqual("rule-a=monitor", state["applied"][0]["change"])

    def test_an_agent_that_says_it_is_locked_to_monitor_shows_as_monitor_whatever_the_file_says(self):
        now = int(time.time() * 1000)
        self.env.write(event(1, sensor="jot-config", capture="lock=monitor", ts=now, run="r9"),
                       event(2, sensor="jot-config", capture="jots=/x/jot.yaml", ts=now, run="r9"),
                       event(3, sensor="jot-config", capture="loaded=rule-a", ts=now, run="r9"))
        self.env.ingestor.poll()
        state = self.app.control_state()
        self.assertTrue(state["agent"]["locked"])
        self.assertEqual("/x/jot.yaml", state["agent"]["jots"])
        self.assertFalse(state["master"])
        self.assertTrue(all(r["mode"] == "monitor" for r in state["rules"]))
        rule_a = next(r for r in state["rules"] if r["name"] == "rule-a")
        self.assertTrue(rule_a["loaded"])

    def test_the_panel_says_which_rules_the_running_agent_did_not_load(self):
        now = int(time.time() * 1000)
        self.env.write(event(1, sensor="jot-config", capture="lock=none", ts=now, run="r9"),
                       event(2, sensor="jot-config", capture="loaded=rule-a", ts=now, run="r9"))
        self.env.ingestor.poll()
        state = self.app.control_state()
        self.assertFalse(state["agent"]["locked"])
        loaded = {r["name"]: r["loaded"] for r in state["rules"]}
        self.assertTrue(loaded["rule-a"])
        self.assertTrue(any(v is False for v in loaded.values()), loaded)

    def test_without_a_startup_report_nothing_is_claimed_about_loaded_rules(self):
        state = self.app.control_state()
        self.assertFalse(state["agent"]["known"])
        self.assertTrue(all(r["loaded"] is None for r in state["rules"]))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class GridScriptTests(unittest.TestCase):
    def test_grid_pivot_logic(self):
        here = os.path.dirname(__file__)
        result = subprocess.run(["node", "--test", os.path.join(here, "grid.test.js"), os.path.join(here, "recent.test.js"),
                                 os.path.join(here, "dom.test.js")],
                                capture_output=True, text=True)
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.env.write(event(1, action="blocked", message="denied"), event(2))
        cls.env.ingestor.poll()
        app = server.App(cls.env.db, cls.env.ingestor, lambda *a, **k: {
            "title": "Count", "sql": "SELECT COUNT(*) AS n FROM events", "chart": "bar", "explanation": "x"})
        cls.httpd = server.make_server(app, "127.0.0.1", 0)
        cls.port = cls.httpd.server_address[1]
        cls.httpd.RequestHandlerClass.port = cls.port
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()

    def call(self, path, body=None, headers=None, host=None):
        h = {"Host": host or "127.0.0.1:%d" % self.port}
        if body is not None:
            h.update({"Content-Type": "application/json", "X-JOT-Dashboard": "1"})
        h.update(headers or {})
        req = urllib.request.Request(
            "http://127.0.0.1:%d%s" % (self.port, path), method="POST" if body is not None else "GET",
            data=json.dumps(body).encode() if body is not None else None, headers=h)
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.load(r) if "json" in r.headers["Content-Type"] else r.read()
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.load(e)

    def test_status(self):
        code, s = self.call("/api/status")
        self.assertEqual(200, code)
        self.assertEqual((2, 1), (s["events"], s["blocked"]))

    def test_serves_the_page_and_the_grid_script_it_uses(self):
        code, page = self.call("/")
        self.assertEqual(200, code)
        self.assertIn(b"JOT Dashboard", page)
        self.assertIn(b'src="/grid.js"', page)
        # hidden pages must stay hidden, an earlier layout showed two pages at once because a display rule won
        self.assertIn(b"[hidden] { display: none !important; }", page)
        self.assertIn(b'id="eventsPage"', page)
        self.assertIn(b'id="jotsPage" hidden', page)
        self.assertNotIn(b'id="feed"', page)       # the Latest events panel became a view
        # times are shown in local time, a UTC column next to local clock times looked like a bug
        self.assertNotIn(b"'unixepoch')", page)
        self.assertIn(b"white-space: nowrap; display: inline-block;", page)     # badges must not wrap
        self.assertNotIn(b"adminToken", page)       # no token to type, changes just work
        # tables must not scroll inside the page, an earlier height limit hid the last rows
        self.assertNotIn(b"max-height: 560px", page)
        # the Events page can be cleared, which sets a start time
        self.assertIn(b'id="clearBtn"', page)
        self.assertIn(b'id="showAllBtn"', page)
        # recent questions live in the top menu, not on the page
        self.assertIn(b'id="recentMenu"', page)
        self.assertNotIn(b'id="history"', page)
        self.assertIn(b'src="/recent.js"', page)
        self.assertIn(b'src="/dom.js"', page)
        # the page must build elements with the shared helper, a copy that sets disabled="null" disables controls
        self.assertIn(b"JotDom.makeEl(document)", page)
        self.assertNotIn(b"function el(tag, props", page)
        code, script = self.call("/grid.js")
        self.assertEqual(200, code)
        self.assertIn(b"pivot", script)
        code, script = self.call("/recent.js")
        self.assertEqual(200, code)
        self.assertIn(b"remember", script)

    def test_ask_and_sql(self):
        code, r = self.call("/api/ask", {"question": "how many?"})
        self.assertEqual((200, [[2]]), (code, r["rows"]))
        _, r = self.call("/api/sql", {"sql": "SELECT sensor FROM events WHERE action='blocked'"})
        self.assertEqual([["crypto-cipher"]], r["rows"])

    def test_bad_sql_is_a_400_with_a_message(self):
        code, r = self.call("/api/sql", {"sql": "DROP TABLE events"})
        self.assertEqual(400, code)
        self.assertIn("error", r)

    def test_recent_events(self):
        code, r = self.call("/api/recent")
        self.assertEqual(2, len(r["rows"]))
        newest = r["rows"][0][0]
        _, r = self.call("/api/recent?after=%d" % newest)
        self.assertEqual([], r["rows"])

    def test_posts_without_the_header_are_refused(self):
        req = urllib.request.Request("http://127.0.0.1:%d/api/sql" % self.port, method="POST",
                                     data=b'{"sql":"SELECT 1"}', headers={"Content-Type": "text/plain"})
        with self.assertRaises(urllib.error.HTTPError) as c:
            urllib.request.urlopen(req)
        self.assertEqual(403, c.exception.code)

    def test_other_host_names_are_refused(self):
        code, _ = self.call("/api/status", host="evil.example:%d" % self.port)
        self.assertEqual(403, code)

    def test_oversized_bodies_are_refused(self):
        code, _ = self.call("/api/sql", {"sql": "SELECT 1", "pad": "x" * (server.MAX_BODY + 10)})
        self.assertEqual(413, code)


JDK_ONLY = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:182)",
            "java.base/java.util.jar.JarFile.getInputStream(JarFile.java:845)",
            "org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:164)",
            "java.base/java.lang.Thread.run(Thread.java:833)"]
VIA_LIBRARY = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:182)",
               "org.hsqldb.rights.GranteeManager.getDigester(Unknown Source)",
               "com.acme.ticketbook.Ticket.save(Ticket.java:40)",
               "org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:164)"]
LIBRARY_ONLY = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:182)",
                "org.hsqldb.rights.GranteeManager.getDigester(Unknown Source)",
                "java.base/java.lang.Thread.run(Thread.java:833)"]
# a hash made by the JVM checking a jar's signature while it loads a class for a page Jasper is compiling, in the middle of a request
CLASSLOAD = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:297)",
             "java.base/java.util.jar.JarVerifier.beginEntry(JarVerifier.java:190)",
             "java.base/java.net.URLClassLoader.defineClass(URLClassLoader.java:511)",
             "java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:587)",
             "org.eclipse.jdt.internal.compiler.parser.Parser.parse(Parser.java:11936)",
             "org.apache.jasper.compiler.Compiler.compile(Compiler.java:409)",
             "org.apache.jasper.servlet.JspServlet.service(JspServlet.java:290)",
             "jakarta.servlet.http.HttpServlet.service(HttpServlet.java:710)",
             "com.acme.ticketbook.ProfileController.doPost(ProfileController.java:28)"]
# a hash made inside the JDK's TLS key derivation, because a page asked to fetch an https address
TLS = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:182)",
       "java.base/com.sun.crypto.provider.HmacCore.<init>(HmacCore.java:68)",
       "java.base/javax.crypto.Mac.getMacLength(Mac.java:413)",
       "java.base/sun.security.ssl.HKDF.<init>(HKDF.java:65)",
       "java.base/sun.security.ssl.SSLSecretDerivation.deriveKey(SSLSecretDerivation.java:104)",
       "java.base/sun.net.www.protocol.https.HttpsURLConnectionImpl.connect(HttpsURLConnectionImpl.java:142)",
       "org.apache.jsp.ssrf_jsp._jspService(ssrf_jsp.java:156)"]
# the application asking for a hash itself, and a page opening a jar from a url, which is what an exploit does
DIRECT_HASH = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:182)",
               "org.apache.jsp.hash_jsp._jspService(hash_jsp.java:80)"]
JAR_FROM_URL = ["java.base/java.io.File.<init>(File.java:288)",
                "java.base/sun.net.www.protocol.jar.URLJarFile.<init>(URLJarFile.java:68)",
                "java.base/java.util.jar.JarFile.<init>(JarFile.java:339)",
                "org.yaml.snakeyaml.constructor.Constructor$ConstructMapping.construct(Constructor.java:100)",
                "org.apache.jsp.snakeyaml_jsp._jspService(snakeyaml_jsp.java:60)"]
# the same TLS work, but started by the JDK loading a class from a url, which nothing in the application asked for
TLS_FOR_CLASSLOADING = TLS[:5] + ["java.base/sun.net.www.protocol.https.HttpsURLConnectionImpl.connect(HttpsURLConnectionImpl.java:142)",
                                  "java.base/java.net.URLClassLoader.findClass(URLClassLoader.java:420)",
                                  "java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:587)",
                                  "org.apache.jsp.ssrf_jsp._jspService(ssrf_jsp.java:156)"]
# the same loader, but the application's or a library's own code ran first, like a class initializer
CLASSLOAD_AFTER_LIBRARY = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:297)",
                           "org.hsqldb.rights.GranteeManager.getDigester(Unknown Source)",
                           "java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:587)",
                           "com.acme.ticketbook.Ticket.save(Ticket.java:40)"]
CLASSLOAD_AFTER_APP = ["java.base/java.security.MessageDigest.getInstance(MessageDigest.java:297)",
                       "com.acme.ticketbook.Ticket.<clinit>(Ticket.java:12)",
                       "java.base/java.lang.ClassLoader.loadClass(ClassLoader.java:587)",
                       "com.acme.ticketbook.ProfileController.doPost(ProfileController.java:28)"]
JSP = ["java.base/javax.crypto.Cipher.getInstance(Cipher.java:534)",
       "org.apache.jsp.accessE_jsp._jspService(accessE_jsp.java:249)",
       "org.apache.jasper.runtime.HttpJspBase.service(HttpJspBase.java:67)"]


BUNDLE = """---
# a bundle, with a note
sensors:

# first
- name: "one"   # trailing comment
  description: "First"
  methods:
  - "a.b.C.m"
  captures:
    value: "#P0"

# second
- name: two
  methods:
  - a.b.C.n
  captures:
    value: "#P0"
  matchers:
    value:
    - '!x'   # keep
"""


class SaveJotTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.path = os.path.join(self.env.dir, "bundle.jot")
        with open(self.path, "w") as f:
            f.write(BUNDLE)
        self.paths = [self.env.dir]
        store.load_sensors(self.env.ingestor.db, self.paths)
        self.app = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, editable=True)

    def shown(self, name):
        return next(s for s in self.app.jots()["sensors"] if s["name"] == name)["definition"]

    def read(self):
        with open(self.path) as f:
            return f.read()

    def test_a_saved_sensor_changes_only_itself_and_the_page_shows_it(self):
        one = self.shown("one")
        self.assertIn("# trailing comment", one, "the sensor is shown as it is written, comments too")
        self.assertEqual({"saved": "bundle.jot", "name": "one", "reports": [], "notes": []}, self.app.save_jot("one", one, one.replace("First", "Changed") + "\nenabled: false"))
        saved = self.read()
        self.assertEqual(BUNDLE.replace('"First"', '"Changed"').replace('    value: "#P0"\n', '    value: "#P0"\n  enabled: false\n', 1), saved)
        self.assertIn("# keep", saved)
        self.assertIn("Changed", self.shown("one"))
        self.assertEqual("false", next(s for s in store.run_query(self.env.db, "SELECT name, enabled FROM sensors")["rows"] if s[0] == "one")[1])

    def test_a_file_changed_from_outside_shows_up_without_a_restart(self):
        self.assertNotIn("Edited elsewhere", self.shown("one"))
        time.sleep(0.01)
        with open(self.path, "w") as f:
            f.write(BUNDLE.replace('"First"', '"Edited elsewhere"'))
        self.assertIn("Edited elsewhere", self.shown("one"), "the next look at the JOTs page reads the files again")
        with open(os.path.join(self.env.dir, "new.jot"), "w") as f:
            f.write("sensors:\n- name: added\n  methods:\n  - a.b.C.m\n")
        self.assertIn("added", {s["name"] for s in self.app.jots()["sensors"]}, "and a new file is found")

    def test_a_file_that_changed_since_the_editor_opened_is_not_overwritten(self):
        original = self.shown("two")
        with open(self.path, "w") as f:       # someone else edits the file by hand
            f.write(BUNDLE.replace("a.b.C.n", "x.y.Z.o"))
        with self.assertRaises(store.SaveError) as e:
            self.app.save_jot("two", original, original.replace("a.b.C.n", "a.b.C.q"))
        self.assertEqual(409, e.exception.status)
        self.assertIn("x.y.Z.o", self.read())

    def test_bad_saves_are_refused_and_change_nothing(self):
        two = self.shown("two")
        for text, status in (("name: one\nmethods:\n- a.b.C.n", 400), ("name: Two\nmethods:\n- a.b.C.n", 400),
                             ("name: two\nmethods:\n- nope", 400), ("", 400)):
            with self.assertRaises(store.SaveError) as e:
                self.app.save_jot("two", two, text)
            self.assertEqual(status, e.exception.status, text)
        with self.assertRaises(store.SaveError) as e:
            self.app.save_jot("nobody", "x", "name: nobody\nmethods:\n- a.b.C.n")
        self.assertEqual(404, e.exception.status)
        self.assertEqual(BUNDLE, self.read())

    def test_a_renamed_sensor_is_renamed_in_the_reports_that_use_it(self):
        reports = "# reports\nreports:\n- name: Uses Two\n  type: list\n  rows: other\n  cols: \"one, two\"   # both\n- name: Not Two\n  type: list\n  rows: twofold\n  cols: two-ish\n"
        other = os.path.join(self.env.dir, "r.jot")
        with open(other, "w") as f:
            f.write(reports)
        store.load_sensors(self.env.ingestor.db, self.paths)
        two = self.shown("two")
        done = self.app.save_jot("two", two, two.replace("name: two", "name: three"))
        self.assertEqual("three", done["name"])
        self.assertEqual(["Uses Two"], done["reports"])
        self.assertEqual(BUNDLE.replace("- name: two", "- name: three"), self.read(), "only the name changed, the rest of the bundle is as it was")
        with open(other) as f:
            self.assertEqual(reports.replace('"one, two"', '"one, three"'), f.read(), "the whole name only, in this report only, comment kept")
        self.assertEqual({"one", "three"}, {s["name"] for s in self.app.jots()["sensors"]})

    def test_a_report_in_the_same_file_as_the_renamed_sensor_is_changed_with_it(self):
        bundle = BUNDLE + "\nreports:\n- name: Two Report\n  type: list\n  cols: two\n"
        with open(self.path, "w") as f:
            f.write(bundle)
        store.load_sensors(self.env.ingestor.db, self.paths)
        two = self.shown("two")
        done = self.app.save_jot("two", two, two.replace("name: two", "name: three"))
        self.assertEqual(["Two Report"], done["reports"])
        self.assertEqual(bundle.replace("- name: two", "- name: three").replace("cols: two", "cols: three"), self.read())

    def test_other_edits_leave_the_reports_alone(self):
        one = self.shown("one")
        done = self.app.save_jot("one", one, one.replace("First", "Second"))
        self.assertEqual([], done["reports"])

    def test_saving_is_off_when_the_dashboard_is_open_to_other_machines(self):
        app = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, editable=False)
        with self.assertRaises(store.SaveError) as e:
            app.save_jot("two", self.shown("two"), self.shown("two"))
        self.assertEqual(403, e.exception.status)
        self.assertFalse(app.jots()["editable"])
        self.assertTrue(self.app.jots()["editable"])
        self.assertEqual(BUNDLE, self.read())

    def test_over_http_and_a_stray_temp_file_is_not_left(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        def post(body, headers=None):
            req = urllib.request.Request("http://127.0.0.1:%d/api/jots/save" % port, data=json.dumps(body).encode(), method="POST",
                                         headers={"Host": "127.0.0.1:%d" % port, "Content-Type": "application/json", **({"X-JOT-Dashboard": "1"} if headers is None else headers)})
            return urllib.request.urlopen(req)
        two = self.shown("two")
        with self.assertRaises(urllib.error.HTTPError) as e:
            post({"name": "two", "original": two, "text": two}, {})
        self.assertEqual(403, e.exception.code, "a page on another site can't save")
        with post({"name": "two", "original": two, "text": two.replace("a.b.C.n", "a.b.C.z")}) as r:
            self.assertEqual("bundle.jot", json.load(r)["saved"])
        with self.assertRaises(urllib.error.HTTPError) as e:
            post({"name": "two", "original": two, "text": two})
        self.assertEqual(409, e.exception.code)
        self.assertEqual(["bundle.jot"], [f for f in os.listdir(self.env.dir) if f.endswith(".jot") or f.endswith(".saving")])


class CveStatusViewTests(unittest.TestCase):
    def test_a_cve_is_active_when_its_active_sensor_has_events_and_the_rule_counts_requests(self):
        page = open(os.path.join(os.path.dirname(__file__), "..", "static", "index.html")).read()
        sql = json.loads('"' + re.search(r'label: "CVE status".*?sql: "(.*?)" \},', page, re.S).group(1) + '"')
        env = Env()
        env.write(event(1, sensor="cve-1-active", capture="reached", trace=1), event(2, sensor="cve-1-active", capture="reached", trace=2),
                  event(3, sensor="cve-1-blocked", action="blocked", capture="[ls]", trace=2),
                  event(4, sensor="cve-1-blocked", action="blocked", capture="[id]", trace=2),
                  event(5, sensor="cve-2-monitored", action="monitored", capture="[ls]", trace=3))
        env.ingestor.poll()
        rows = {r[0]: r[1:] for r in server.App(env.db, env.ingestor).sql(sql)["rows"]}
        self.assertEqual(["active", 2, 1, 0], rows["cve-1"], "active, run twice, blocked in one request")
        self.assertEqual(["not seen", 0, 0, 1], rows["cve-2"], "a rule fired but the vulnerable code was never seen running")


GOOD_DRAFT = """name: crypto-weak-key
description: Identifies a key shorter than 2048 bits being generated
methods:
- java.security.KeyPairGenerator.initialize
captures:
  value: '#P0'
block-when: '#P0 < 2048'
"""


# the draft a model really produced for "identify log library use", which could not work
LOG_DRAFT_AS_WRITTEN = """name: file-log-write
description: Code opened a log file for writing
methods:
  - java.io.FileOutputStream.<init>
  - java.io.FileWriter.<init>
  - static java.nio.file.Files.newBufferedWriter
  - static java.nio.file.Files.newOutputStream
  - static java.nio.file.Files.write
captures:
  path: '#P0'
matchers:
  path:
  - '(?i)\\.log(\\.\\d+)?$'
"""


class JotPromptTests(unittest.TestCase):
    def examples(self):
        text = llm.JOT_SYSTEM[llm.JOT_SYSTEM.index("Examples that were run"):llm.JOT_SYSTEM.index("Always answer by calling")]
        return [e.strip("\n") for e in re.split(r"\n\n(?=name: )", text[text.index("name: "):]) if e.strip()]

    def test_the_draft_that_could_not_work_is_refused_and_says_why(self):
        problems = store.check_draft(LOG_DRAFT_AS_WRITTEN)
        said = " ".join(problems)
        self.assertIn("static java.nio.file.Files.newBufferedWriter", said)
        self.assertIn("with no static or other modifiers", said)
        self.assertEqual(3, sum("isn't a method name" in p for p in problems), "each of the three static methods")

    def test_a_draft_must_say_what_it_identifies(self):
        for description, fine in (("Identifies starting a native process", True), ("Records each process started", False),
                                  ("A web request started a process", False), ("", False)):
            text = "name: x-y\ndescription: %s\nmethods:\n- a.b.C.m\ncaptures:\n  value: '#P0'\n" % description
            said = " ".join(store.check_draft(text))
            self.assertEqual(fine, "starts with" not in said, description)
        self.assertNotIn("Records", llm.JOT_SYSTEM.split("Examples that were run")[1], "no example teaches it")
        self.assertIn("Never start with Records or Detects", llm.JOT_SYSTEM)

    def test_the_prompt_never_teaches_static_and_says_not_to_use_it(self):
        text = llm.JOT_SYSTEM
        self.assertNotRegex(text, r"(?m)^\s*-\s+static ", "no example has it")
        self.assertIn("Never write\n                static", text)

    def test_every_example_in_the_prompt_passes_the_checks_a_draft_must_pass(self):
        found = self.examples()
        self.assertEqual(["file-log-write", "http-cookie-set", "native-process", "sql-database", "sql-result"], [yaml.safe_load(e)["name"] for e in found])
        for example in found:
            self.assertEqual([], store.check_draft(example), example)
        self.assertIs(False, yaml.safe_load(found[2])["protect"], "the example rule is staged, like every drafted rule")

    def test_the_log_example_matches_what_the_agent_records_for_every_way_of_writing_a_file(self):
        matcher = yaml.safe_load(self.examples()[0])["matchers"]["path"][0]
        for captured in ("/var/log/app.log", "/var/log/app.LOG", "logs/app.log.1", "C:\\logs\\app.log.12"):
            self.assertTrue(re.search(matcher, captured, flags=0) or re.search(matcher.replace("(?i)", ""), captured, re.I), captured)
        for captured in ("/var/log/app.txt", "/var/data/blog.html", "/var/log/app.log.bak", "{class java.io.File:/var/log/app.log}"):
            self.assertFalse(re.search(matcher.replace("(?i)", ""), captured, re.I), captured)

    def test_the_prompt_says_how_a_capture_looks_to_a_matcher_and_which_method_to_watch(self):
        for text in ("recorded as its plain text", "{class the.Name:its text}", "Watch the lowest-level method", "Files.newOutputStream"):
            self.assertIn(text, llm.JOT_SYSTEM)


class DraftJotTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        with open(os.path.join(self.env.dir, "a.jot"), "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Records ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n  captures:\n    value: '#P0'\n")
        store.load_sensors(self.env.ingestor.db, [self.env.dir])
        self.env.write(event(1, method_name="javax.crypto.Cipher.getInstance"), event(2, method_name="javax.crypto.Cipher.getInstance"))
        self.env.ingestor.poll()
        self.calls = []

    def app(self, *replies, editable=True):
        replies = list(replies)
        def fake(request, sensors, methods, history, problems):
            self.calls.append({"request": request, "sensors": [x["name"] for x in sensors], "methods": methods, "history": history, "problems": problems})
            return replies.pop(0) if len(replies) > 1 else replies[0]
        return server.App(self.env.db, self.env.ingestor, jot_paths=[self.env.dir], editable=editable, draft=fake)

    def test_a_good_draft_comes_back_with_what_the_model_was_told_and_which_hooks_the_log_has_seen(self):
        app = self.app({"yaml": GOOD_DRAFT, "explanation": "Watches key generation."})
        out = app.draft_jot("block weak RSA keys")
        self.assertEqual([], out["problems"])
        self.assertTrue(out["rule"])
        self.assertIn("protect: false", out["yaml"], "a new rule only reports until it is turned on")
        self.assertEqual("Watches key generation.", out["explanation"])
        self.assertEqual([{"method": "java.security.KeyPairGenerator.initialize", "seen": 0}], out["hooks"], "never seen in the log")
        call = self.calls[0]
        self.assertEqual(["crypto-cipher"], call["sensors"], "the existing JOTs, so it doesn't repeat a name")
        self.assertEqual(["javax.crypto.Cipher.getInstance"], call["methods"], "only the names of instrumented methods, never captured values")
        self.assertIsNone(call["problems"])

    def test_the_hooks_that_the_log_has_seen_are_counted(self):
        draft = "name: crypto-cipher-use\ndescription: Cipher use\nmethods:\n- javax.crypto.Cipher.getInstance\n- javax.crypto.Cipher.other\ncaptures:\n  value: '#P0'\n"
        out = self.app({"yaml": draft, "explanation": "x"}).draft_jot("ciphers")
        self.assertEqual([("javax.crypto.Cipher.getInstance", 2), ("javax.crypto.Cipher.other", 0)], [(h["method"], h["seen"]) for h in out["hooks"]])
        self.assertFalse(out["rule"])

    def test_a_draft_with_problems_goes_back_to_the_model_with_them_and_the_repair_is_used(self):
        bad = "name: crypto-cipher\nmethods:\n- a.b.C.m\ncaptures:\n  value: '#P0 + T(java.lang.Runtime).getRuntime()'\n"
        app = self.app({"yaml": bad, "explanation": "first"}, {"yaml": GOOD_DRAFT, "explanation": "second"})
        out = app.draft_jot("something")
        self.assertEqual([], out["problems"])
        self.assertEqual("second", out["explanation"])
        self.assertEqual(2, len(self.calls))
        said = " ".join(self.calls[1]["problems"])
        self.assertIn("already used", said)
        self.assertIn("T( or new", said)

    def test_a_draft_that_stays_wrong_is_returned_with_its_problems_for_the_person_to_fix(self):
        bad = "name: crypto-cipher\nmethods:\n- a.b.C.m\n"
        out = self.app({"yaml": bad, "explanation": "tried"}).draft_jot("x")
        self.assertEqual(server.MAX_REPAIRS + 1, len(self.calls), "it was asked again, up to the limit")
        self.assertTrue(out["problems"])
        self.assertEqual(bad.strip("\n"), out["yaml"])

    def test_a_request_the_model_says_cannot_be_a_jot_comes_back_empty_with_the_reason(self):
        out = self.app({"yaml": "", "explanation": "That needs the application's source."}).draft_jot("fix my bug")
        self.assertEqual(("", "That needs the application's source.", []), (out["yaml"], out["explanation"], out["problems"]))

    def test_the_conversation_is_sent_back_so_a_follow_up_changes_the_draft(self):
        app = self.app({"yaml": GOOD_DRAFT, "explanation": "x"})
        app.draft_jot("make it report only", [{"request": "block weak keys", "yaml": GOOD_DRAFT}] * 5)
        history = self.calls[0]["history"]
        self.assertEqual(3, len(history), "the last few turns")
        self.assertEqual("block weak keys", history[0]["request"])

    def test_an_empty_or_huge_request_is_refused(self):
        app = self.app({"yaml": GOOD_DRAFT, "explanation": "x"})
        for request in ("", "   ", "x" * 2001):
            with self.assertRaises(store.QueryError):
                app.draft_jot(request)
        self.assertEqual([], self.calls)

    def test_a_drafted_jot_is_added_after_the_last_one_in_the_file_and_the_page_has_it(self):
        app = self.app({"yaml": GOOD_DRAFT, "explanation": "x"})
        out = app.draft_jot("weak keys")
        self.assertEqual({"added": "crypto-weak-key", "file": "a.jot"}, app.add_jot("a.jot", out["yaml"]))
        with open(os.path.join(self.env.dir, "a.jot")) as f:
            saved = yaml.safe_load(f)
        self.assertEqual(["crypto-cipher", "crypto-weak-key"], [x["name"] for x in saved["sensors"]])
        self.assertFalse(saved["sensors"][1]["protect"])
        self.assertEqual("rule", next(x for x in app.jots()["sensors"] if x["name"] == "crypto-weak-key")["kind"])

    def test_a_new_file_is_made_when_the_name_is_not_loaded_and_nothing_else_is_touched(self):
        app = self.app({"yaml": GOOD_DRAFT, "explanation": "x"})
        before = open(os.path.join(self.env.dir, "a.jot")).read()
        self.assertEqual("weak-keys.jot", app.add_jot("weak-keys.jot", GOOD_DRAFT)["file"])
        self.assertEqual(before, open(os.path.join(self.env.dir, "a.jot")).read())
        self.assertIn("crypto-weak-key", {x["name"] for x in app.jots()["sensors"]})
        for bad in ("../x.jot", "x.txt", ".hidden.jot", ""):
            with self.assertRaises(store.SaveError):
                app.add_jot(bad, GOOD_DRAFT.replace("crypto-weak-key", "other-name"))

    def test_adding_refuses_a_taken_name_a_bad_draft_and_a_dashboard_that_may_not_write(self):
        app = self.app({"yaml": GOOD_DRAFT, "explanation": "x"})
        with self.assertRaises(store.SaveError) as e:
            app.add_jot("a.jot", GOOD_DRAFT.replace("crypto-weak-key", "crypto-cipher"))
        self.assertIn("already used", str(e.exception))
        with self.assertRaises(store.SaveError):
            app.add_jot("a.jot", "name: x\nmethods:\n- nope\n")
        with self.assertRaises(store.SaveError) as e:
            self.app({"yaml": GOOD_DRAFT, "explanation": "x"}, editable=False).add_jot("a.jot", GOOD_DRAFT)
        self.assertEqual(403, e.exception.status)

    def test_over_http_the_model_failing_is_a_502_and_a_bad_request_is_a_400(self):
        def broken(*a):
            raise llm.LLMError("ANTHROPIC_API_KEY is not set")
        app = server.App(self.env.db, self.env.ingestor, jot_paths=[self.env.dir], editable=True, draft=broken)
        httpd = server.make_server(app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        def post(path, body):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=json.dumps(body).encode(), method="POST",
                                         headers={"Host": "127.0.0.1:%d" % port, "Content-Type": "application/json", "X-JOT-Dashboard": "1"})
            return urllib.request.urlopen(req)
        with self.assertRaises(urllib.error.HTTPError) as e:
            post("/api/jots/draft", {"request": "weak keys"})
        self.assertEqual(502, e.exception.code)
        with self.assertRaises(urllib.error.HTTPError) as e:
            post("/api/jots/draft", {"request": ""})
        self.assertEqual(400, e.exception.code)
        with self.assertRaises(urllib.error.HTTPError) as e:
            post("/api/jots/add", {"file": "a.jot", "text": "name: x\nmethods:\n- nope\n"})
        self.assertEqual(400, e.exception.code)


class DraftUiTests(unittest.TestCase):
    CHROME = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/usr/bin/google-chrome", "/usr/bin/chromium",
                               "/usr/bin/chromium-browser") if os.path.exists(c)), None)

    # runs in the page. It uses the New JOT chat the way a person does, then writes what it saw into the page
    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const button = (text) => [...document.querySelectorAll("#jotDetail button")].find((b) => b.textContent === text);
      const out = {};
      try {
        location.hash = "#jots";
        await until(() => document.querySelector("#jotList table"));
        document.getElementById("newJot").click();
        const box = await until(() => document.getElementById("draftRequest"));
        out.opened = !!box && !document.getElementById("jotDetail").hidden;
        box.value = "block weak keys";
        button("Draft").click();
        await until(() => document.querySelector("#jotDetail .bot") && document.querySelector("#jotDetail .cm-content"));
        await until(() => /No problems found/.test((document.querySelector("#jotDetail .editstatus.ok") || {}).textContent || ""));
        out.bot = document.querySelector("#jotDetail .bot").innerText;
        out.draft = document.querySelector("#jotDetail .cm-content").innerText;
        out.files = [...document.querySelectorAll("#jotDetail select option")].map((o) => o.value);
        out.addEnabled = !button("Add to file").disabled;
        button("Add to file").click();
        await until(() => (document.querySelector("#jotDetail h2") || {}).textContent === "crypto-weak-key");
        await until(() => /Added to a.jot/.test(document.getElementById("jotDetail").innerText));
        out.drawer = document.getElementById("jotDetail").innerText;
        out.listed = document.getElementById("jotList").innerText.indexOf("crypto-weak-key") >= 0;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_person_describes_a_jot_reads_the_draft_and_adds_it_to_a_file(self):
        env = Env()
        path = os.path.join(env.dir, "a.jot")
        with open(path, "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Records ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n  captures:\n    value: '#P0'\n")
        store.load_sensors(env.ingestor.db, [env.dir])
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir], editable=True,
                         draft=lambda *a: {"yaml": GOOD_DRAFT, "explanation": "Watches key generation."})
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        profile = tempfile.mkdtemp()
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + profile,
                               "--virtual-time-budget=20000", "--dump-dom", "http://127.0.0.1:%d/" % port],
                              capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        self.assertTrue(out["opened"])
        self.assertIn("Watches key generation.", out["bot"])
        self.assertIn("It is a rule", out["bot"], "the person is told it only reports until switched on")
        self.assertIn("Not seen in your log yet", out["bot"])
        self.assertIn("name: crypto-weak-key", out["draft"])
        self.assertIn("protect: false", out["draft"])
        self.assertEqual(["a.jot", ""], out["files"])
        self.assertTrue(out["addEnabled"])
        self.assertIn("crypto-weak-key", out["drawer"])
        self.assertIn("Added to a.jot", out["drawer"])
        self.assertTrue(out["listed"])
        with open(path) as f:
            saved = yaml.safe_load(f)
        self.assertEqual(["crypto-cipher", "crypto-weak-key"], [x["name"] for x in saved["sensors"]])


class DraftReportUiTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME
    GOOD = "name: Ciphers\ntype: list\ncols: crypto-cipher.algorithm\n"

    # runs in the page. It uses New report the way a person does, then writes what it saw into the page
    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const button = (text) => [...document.querySelectorAll("#jotDetail button")].find((b) => b.textContent === text);
      // puts the cursor at the end of the editor and asks for suggestions, as Ctrl Space does
      const suggest = async (text) => {
        draft.editor.set(text);
        const content = document.querySelector("#jotDetail .cm-content");
        content.focus();
        const sel = window.getSelection(), range = document.createRange();
        range.selectNodeContents(content.lastChild);
        range.collapse(false);
        sel.removeAllRanges(); sel.addRange(range);
        await wait(100);
        content.dispatchEvent(new KeyboardEvent("keydown", { key: " ", code: "Space", ctrlKey: true, bubbles: true, cancelable: true }));
        const tip = await until(() => document.querySelector(".cm-tooltip-autocomplete"));
        const hints = tip ? tip.innerText : "";
        content.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", code: "Escape", bubbles: true, cancelable: true }));
        await until(() => !document.querySelector(".cm-tooltip-autocomplete"));
        return hints;
      };
      const out = {};
      try {
        location.hash = "#reports";
        await until(() => document.querySelector("#reportList table"));
        document.getElementById("newReport").click();
        const box = await until(() => document.getElementById("draftRequest"));
        out.title = document.querySelector("#jotDetail h2").textContent;
        box.value = "which ciphers does the app use";
        button("Draft").click();
        await until(() => document.querySelector("#jotDetail .bot") && document.querySelector("#jotDetail .cm-content"));
        await until(() => /No problems found/.test((document.querySelector("#jotDetail .editstatus.ok") || {}).textContent || ""));
        out.bot = document.querySelector("#jotDetail .bot").innerText;
        out.draft = document.querySelector("#jotDetail .cm-content").innerText;
        out.files = [...document.querySelectorAll("#jotDetail select option")].map((o) => o.textContent);
        out.fieldHints = await suggest("name: Mine\\ntype: list\\ncols: ");
        out.typeHints = await suggest("name: Mine\\ntype: ");
        out.keyHints = await suggest("name: Mine\\n");
        out.sameSensorHints = await suggest("name: Mine\\ntype: compare\\nrows: http-route.path\\ncols: crypto-cipher.algorithm\\nvalue: ");
        draft.editor.set(GOOD);
        await until(() => /No problems found/.test((document.querySelector("#jotDetail .editstatus.ok") || {}).textContent || ""));
        out.addEnabled = !button("Add to file").disabled;
        button("Add to file").click();
        await until(() => document.getElementById("jotDetail").hidden && (document.querySelector("#reportResult h2") || {}).textContent === "Ciphers");
        out.shown = (document.querySelector("#reportResult h2") || {}).textContent;
        out.listed = document.getElementById("reportList").innerText.indexOf("Ciphers") >= 0;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """.replace("GOOD", json.dumps(GOOD))

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_person_describes_a_report_gets_field_suggestions_and_adds_it_to_a_file(self):
        env = Env()
        path = os.path.join(env.dir, "a.jot")
        with open(path, "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Identifies ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n"
                    "  captures:\n    algorithm: '#P0'\n    key_size: '#P1'\n"
                    "- name: http-route\n  description: Identifies a route\n  methods:\n  - a.B.c\n  captures:\n    path: '#P0'\n"
                    "reports:\n- name: Routes\n  type: list\n  cols: http-route.path\n")
        store.load_sensors(env.ingestor.db, [env.dir])
        store.load_reports(env.ingestor.db, [env.dir])
        good = self.GOOD
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir], editable=True,
                         draft_report=lambda *a: {"yaml": good, "explanation": "Ciphers by call site."})
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        httpd.RequestHandlerClass.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--window-size=1400,1000", "--virtual-time-budget=40000", "--dump-dom",
                               "http://127.0.0.1:%d/" % httpd.server_address[1]], capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        self.assertEqual("New report", out["title"])
        self.assertIn("Ciphers by call site.", out["bot"])
        self.assertIn("Nothing has been recorded by crypto-cipher", out["bot"], "nothing in the log yet, so the report would be empty")
        self.assertIn("name: Ciphers", out["draft"])
        self.assertEqual(["a.jot (1 reports)", "A new file"], out["files"])
        for ref in ("crypto-cipher.algorithm", "crypto-cipher.key_size", "http-route.path"):
            self.assertIn(ref, out["fieldHints"], "every field of every JOT is offered for cols")
        for word in ("list", "compare", "table"):
            self.assertIn(word, out["typeHints"])
        self.assertIn("rows", out["keyHints"])
        self.assertNotIn("name", out["keyHints"].replace("name:", "").split(), "a key already written is not offered again")
        self.assertIn("crypto-cipher.key_size", out["sameSensorHints"], "value is a field of the JOT that cols reads")
        self.assertNotIn("http-route.path", out["sameSensorHints"])
        self.assertTrue(out["addEnabled"])
        self.assertEqual("Ciphers", out["shown"], "the new report is run and shown")
        self.assertTrue(out["listed"])
        with open(path) as f:
            saved = yaml.safe_load(f)
        self.assertEqual(["Routes", "Ciphers"], [r["name"] for r in saved["reports"]])


class DraftEditorTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME
    DRAFT = "name: crypto-weak-key\ndescription: Identifies a key under 2048 bits\nmethods:\n- java.security.KeyPairGenerator.initialize\ncaptures:\n  size: \"#P0\"\n"

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const out = {};
      try {
        if (location.search.indexOf("broken") >= 0) {
          const st = document.createElement("style"); st.textContent = ".cm-editor { display: none !important }"; document.head.append(st);
        }
        await wait(1200); location.hash = "#jots"; await wait(800);
        document.getElementById("newJot").click(); await wait(400);
        document.getElementById("draftRequest").value = "watch key sizes";
        [...document.querySelectorAll("#jotDetail button")].find((b) => /^Draft/.test(b.textContent)).click();
        await wait(2500);
        const cm = document.querySelector("#jotDetail .cm-editor"), plain = document.querySelector("#jotDetail textarea.plainedit");
        out.cmHeight = cm ? cm.offsetHeight : 0;
        out.plain = plain ? plain.offsetHeight : 0;
        out.text = draft.editor.get();
        // what is typed in whichever editor is showing is what gets added
        draft.editor.set(draft.editor.get() + "# edited\\n");
        out.edited = draft.editor.get().indexOf("# edited") >= 0;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    def run_page(self, query):
        env = Env()
        draft = self.DRAFT
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir], editable=True, draft=lambda *a: {"yaml": draft, "explanation": "Watches key sizes."})
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        httpd.RequestHandlerClass.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--window-size=1400,1000", "--virtual-time-budget=30000", "--dump-dom",
                               "http://127.0.0.1:%d/%s" % (httpd.server_address[1], query)], capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        return json.loads(htmllib.unescape(found.group(1)))

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_draft_is_shown_in_an_editor_that_can_be_changed(self):
        out = self.run_page("")
        self.assertNotIn("error", out, out)
        self.assertGreater(out["cmHeight"], 20, "the draft is on screen")
        self.assertEqual(self.DRAFT.strip(), out["text"].replace("# edited\n", "").strip())
        self.assertTrue(out["edited"])

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_when_the_code_editor_cant_show_a_plain_text_box_takes_its_place_with_the_draft(self):
        out = self.run_page("?broken")
        self.assertNotIn("error", out, out)
        self.assertGreater(out["plain"], 100, "the draft is still on screen, in a text box")
        self.assertEqual(self.DRAFT.strip(), out["text"].replace("# edited\n", "").strip())
        self.assertTrue(out["edited"])


class ReportCellTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 6000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const out = {};
      try {
        location.hash = "#reports";
        await until(() => jots && jots.reports && jots.reports.length);
        selectReport("Access Control Matrix");
        await until(() => document.querySelector("#reportResult table.grid td.go"));
        out.cells = document.querySelectorAll("#reportResult table.grid td.go:not(.rowlabel)").length;
        out.rowLabels = document.querySelectorAll("#reportResult table.grid td.rowlabel.go").length;
        out.headers = document.querySelectorAll("#reportResult table.grid th.go").length;
        const cell = [...document.querySelectorAll("#reportResult table.grid tbody tr")].find((tr) => tr.firstChild.textContent === "/buy").children[1];
        cell.click();
        await until(() => location.hash === "#events" && (document.querySelector("#results h2") || {}).textContent === "Events behind Access Control Matrix, /buy, RoleA");
        out.hash = location.hash;
        out.title = (document.querySelector("#results h2") || {}).textContent;
        out.rows = document.querySelectorAll("#results tr.clickable").length;
        out.columns = [...document.querySelectorAll("#results th")].map((th) => th.textContent);
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_clicking_a_cell_of_a_report_lists_the_events_behind_it(self):
        env = Env()
        with open(os.path.join(env.dir, "r.jot"), "w") as f:
            f.write("sensors:\n- name: http-route\n  methods:\n  - a.b.C.m\n  captures:\n    path: '#P0'\n"
                    "- name: auth-role-check\n  methods:\n  - a.b.C.n\n  captures:\n    role: '#P0'\n"
                    "reports:\n- name: Access Control Matrix\n  type: compare\n  rows: http-route.path\n  cols: auth-role-check.role\n")
        env.write(event(1, sensor="http-route", capture="/buy", trace=7, data={"path": "/buy"}),
                  event(2, sensor="auth-role-check", capture="RoleA", trace=7, data={"role": "RoleA"}),
                  event(3, sensor="auth-role-check", capture="RoleB", trace=7, data={"role": "RoleB"}))
        env.ingestor.poll()
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir])
        app.reload_jots(force=True)
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        httpd.RequestHandlerClass.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--window-size=1400,1000", "--virtual-time-budget=30000", "--dump-dom",
                               "http://127.0.0.1:%d/" % httpd.server_address[1]], capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        self.assertEqual(2, out["cells"], "each filled cell can be clicked")
        self.assertEqual(2, out["headers"], "and each column")
        self.assertEqual(1, out["rowLabels"], "and each row")
        self.assertEqual("#events", out["hash"])
        self.assertEqual("Events behind Access Control Matrix, /buy, RoleA", out["title"])
        self.assertEqual(1, out["rows"], "only the events of that cell, each of which opens")
        self.assertEqual(["time", "action", "sensor", "call_site", "capture"], out["columns"])


class GraphLinesTests(unittest.TestCase):
    def test_each_route_says_how_many_requests_did_each_kind_of_thing_so_the_main_line_can_be_the_commonest(self):
        rows = []
        # five requests of /a that did x then y, one that did only x
        for trace in range(5):
            rows += [("/a", "r1", trace, "s-x", "observed", "1", json.dumps(["a.b.C.x(C.java:1)"])),
                     ("/a", "r1", trace, "s-y", "observed", "2", json.dumps(["a.b.C.y(C.java:2)"]))]
        rows += [("/a", "r1", 99, "s-x", "observed", "1", json.dumps(["a.b.C.x(C.java:1)"]))]
        out = store.build_graphs(rows, ["/a"], ())["graphs"]
        self.assertEqual(1, len(out))
        counts = out[0]["line_counts"]
        self.assertEqual([5, 1], sorted(counts.values(), reverse=True))
        busiest = max(counts, key=counts.get)
        other = min(counts, key=counts.get)
        uses = lambda line: {n["id"] for n in out[0]["nodes"] if line in n["lines"]}
        self.assertTrue(uses(other) < uses(busiest), "what the commonest request used is a longer path that contains the other's")


class GraphMethodTests(unittest.TestCase):
    """A request's HTTP method is what the http-route sensor captured beside the path, and a route is the path alone."""
    STACK = ["com.acme.Ticket.encrypt(Ticket.java:125)"]

    def setUp(self):
        self.env = Env()
        route = lambda i, trace, path, method: event(i, sensor="http-route", trace=trace, capture="path=%s, method=%s" % (path, method),
                                                     data={"path": path, "method": method}, stack=self.STACK)
        effect = lambda i, trace, sensor: event(i, sensor=sensor, trace=trace, stack=self.STACK)
        self.env.write(
            route(1, 1, "/buy", "GET"), effect(2, 1, "crypto-cipher"),
            route(3, 2, "/buy", "POST"), effect(4, 2, "crypto-cipher"), effect(5, 2, "sql-statement"),
            route(6, 3, "/buy", "post"), effect(7, 3, "crypto-cipher"), effect(8, 3, "sql-statement"),
            # a route sensor that captures only the path says no method
            event(9, sensor="http-route", trace=4, capture="/old", data={"path": "/old"}, stack=self.STACK), effect(10, 4, "crypto-cipher"))
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)

    def test_the_route_is_the_path_and_the_method_is_kept_with_each_row(self):
        rows = store.graph_rows(self.env.db)["rows"]
        self.assertEqual({("/buy", "GET"), ("/buy", "POST"), ("/buy", "post"), ("/old", None)}, {(r[0], r[7]) for r in rows})

    def test_requests_that_did_the_same_with_different_methods_are_different_lines(self):
        graph = self.app.graph("/buy", split=True)["graphs"][0]
        methods = sorted(graph["line_methods"].values())
        self.assertEqual(["GET", "POST"], methods, "post and POST are one method, and so are their requests")
        self.assertEqual(2, sorted(graph["line_counts"].values())[1], "the two POST requests did the same and are drawn once")
        by_line = {line: m for line, m in graph["line_methods"].items()}
        nodes = {n["label"]: {by_line[l] for l in n["lines"]} for n in graph["nodes"]}
        nodes.update({i["sensor"]: {by_line[l] for l in i["lines"]} for n in graph["nodes"] for i in n["inner"]})
        self.assertEqual({"GET", "POST"}, nodes["/buy"], "every request came in at the route")
        self.assertEqual({"GET", "POST"}, nodes["crypto-cipher"], "both did it")
        self.assertEqual({"POST"}, nodes["sql-statement"], "only POST did it")

    def test_a_request_with_no_method_has_none_and_the_methods_seen_are_listed_in_color_order(self):
        graphs = self.app.graph(split=True)
        old = next(g for g in graphs["graphs"] if g["route"] == "/old")
        self.assertEqual([None], list(old["line_methods"].values()))
        self.assertEqual(["GET", "POST"], graphs["methods"])
        self.assertEqual(["/buy", "/old"], graphs["routes"], "a route is the path, not the whole capture text")

    def test_a_method_limits_the_graph_to_its_requests_and_any_case_will_do(self):
        for asked in ("POST", "post"):
            graph = self.app.graph("/buy", split=True, method=asked)
            self.assertEqual(["POST"], sorted(set(graph["graphs"][0]["line_methods"].values())))
            self.assertEqual(["GET", "POST"], graph["methods"], "the method filter keeps every method")
        self.assertEqual(["/buy", "/old"], [g["route"] for g in self.app.graph(split=True, method="")["graphs"]], "no method is every method")
        self.assertEqual([], self.app.graph(split=True, method="DELETE")["graphs"])
        self.assertEqual([], self.app.graph(split=True, method="x' OR '1'='1")["graphs"])

    def test_a_route_event_with_no_path_field_is_no_route_and_does_not_break_the_graph(self):
        self.env.write(event(20, sensor="http-route", trace=9, capture="/from-before", data=None, stack=self.STACK),
                       event(21, sensor="crypto-cipher", trace=9, stack=self.STACK))
        self.env.ingestor.poll()
        graphs = self.app.graph(split=True)
        self.assertEqual(["/buy", "/old"], graphs["routes"], "an event that doesn't say its path is not a route")
        self.assertIn(store.NO_REQUEST, [g["route"] for g in graphs["graphs"]], "what it did is outside a request")
        self.assertTrue(self.app.graph()["nodes"])

    def test_search_finds_a_route_by_its_path(self):
        self.assertEqual(3, self.app.search('crypto-cipher route:"/buy"')["matches"])
        self.assertEqual(1, self.app.search('crypto-cipher route:"/old"')["matches"])

    def test_over_http_the_method_is_a_parameter(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/api/graph?split=1&method=GET" % port,
                                                           headers={"Host": "127.0.0.1:%d" % port})) as r:
            body = json.load(r)
        self.assertEqual(["GET"], sorted({m for g in body["graphs"] for m in g["line_methods"].values()}))
        self.assertEqual(["GET", "POST"], body["methods"])


class GraphMethodPageTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME
    SERVLET = "jakarta.servlet.http.HttpServlet.service(HttpServlet.java:710)"
    FILTER = "org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:132)"
    JDK = "java.base/javax.crypto.Cipher.getInstance(Cipher.java:534)"

    def setUp(self):
        self.env = Env()
        self.env.ingestor.app_prefixes = ("com.acme",)
        self.app = server.App(self.env.db, self.env.ingestor)
        route = lambda i, trace, method: event(i, sensor="http-route", trace=trace, capture="path=/buy, method=" + method,
                                               data={"path": "/buy", "method": method}, stack=[self.SERVLET, self.FILTER])
        encrypt = ["com.acme.Ticket.encrypt(Ticket.java:30)", self.FILTER]
        self.env.write(
            route(1, 1, "GET"), event(2, sensor="crypto-cipher", capture="AES", trace=1, stack=[self.JDK] + encrypt),
            event(3, sensor="http-cache-header", capture="no-store", trace=1, stack=[self.JDK, "com.acme.Cache.get(Cache.java:3)", self.FILTER]),
            route(4, 2, "POST"), event(5, sensor="crypto-cipher", capture="AES", trace=2, stack=[self.JDK] + encrypt),
            event(6, sensor="crypto-hash", capture="MD5", trace=2, stack=[self.JDK, "com.acme.Order.save(Order.java:9)", self.FILTER]))
        self.env.ingestor.poll()

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_what_only_one_method_reaches_is_colored_for_it_and_what_they_share_is_not(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        page = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--virtual-time-budget=8000", "--dump-dom", "http://127.0.0.1:%d/#graph" % port],
                              capture_output=True, text=True, timeout=90).stdout
        self.assertNotIn('class="legend"', page, "there is no key, what a box or a line means is in what shows on hover")
        self.assertRegex(page, r"<title>[^<]*Only (GET|POST) requests reach this", "a line says which methods it is for")
        source = open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8").read()
        for words in ("Blocked by a rule", "Reported only", "What a sensor saw", "An entry point, where a request or a call comes in", "Click to follow its paths",
                      "Application code on the way", "reach this"):
            self.assertNotIn(words, source.split("function placeTip")[0].split("function showTip")[1], "the hover box says only what it is and how many, not " + words)
        self.assertIn('<option value="POST">POST</option>', page, "the methods can be picked")
        self.assertNotIn('id="graphMethodLabel" hidden', page, "the filter shows when a method was seen")
        marks = re.findall(r'<rect class="mark (m\d|both)"', page)
        self.assertEqual(["both", "both", "m0", "m0", "m1", "m1"], sorted(marks),
                         "the GET only cache header and its code, the POST only hash and its code, and the cipher and its code that both reach")
        for kind in ("m0", "m1", "both"):
            self.assertRegex(page, r'class="edge[^"]* %s' % kind)
        self.assertEqual(["m0", "m1"], sorted(re.findall(r'<rect class="split (m\d)"', page)), "the route's box shows its GET and POST requests as a bar")
        for name, color in (("m0", "#1fa34a"), ("m1", "#8250df"), ("mboth", "#1f6feb")):
            self.assertIn("--%s: %s" % (name, color), page, "GET is green, POST is purple and both is blue")


class GraphOptionsTests(unittest.TestCase):
    def test_the_graph_options_are_in_the_filters_and_the_long_summary_is_gone(self):
        with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
            page = fh.read()
        drawer = re.search(r'<aside id="filterDrawer".*?</aside>', page, re.S).group(0)
        tools = re.search(r'<div class="graphtools">.*?</div>', page, re.S).group(0)
        for box in ("graphDetails", "graphRare", "graphDown", "graphCollapse"):
            self.assertIn('id="%s"' % box, drawer, box + " is in the filters")
            self.assertNotIn('id="%s"' % box, tools, box + " is not on the page")
        self.assertIn('id="graphRoute"', tools)
        self.assertIn('id="graphMethod"', tools)
        self.assertNotIn("graphSummary", page)
        self.assertNotIn("busy", page.split("function drawGraph()")[1].split("function methodsOf")[0], "no message about busy routes")


class GraphEntryTests(unittest.TestCase):
    """Whatever the application declares as an entry point is where a line of the graph starts, a request or not. The code above it is
    left out, so in a large application the graph isn't a long chain of the same callers."""
    CALLERS = ["com.acme.Agent.ask(Agent.java:9)", "com.acme.Demo.run(Demo.java:3)", "com.acme.Main.main(Main.java:1)"]

    def setUp(self):
        self.env = Env()
        tool = "com.acme.Calc.add"
        under = lambda i, trace, sensor, frames: event(i, sensor=sensor, trace=trace, entry=tool, stack=frames + self.CALLERS)
        self.env.write(
            under(1, 1, "tool-called", ["com.acme.Calc.add(Calc.java:5)"]),
            under(2, 1, "sql-statement", ["com.acme.Calc.helper(Calc.java:9)", "com.acme.Calc.add(Calc.java:5)"]),
            under(3, 2, "tool-called", ["com.acme.Calc.add(Calc.java:5)"]),
            under(4, 2, "sql-statement", ["com.acme.Calc.helper(Calc.java:9)", "com.acme.Calc.add(Calc.java:5)"]),
            event(5, sensor="model-call", trace=3, stack=self.CALLERS))
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)

    def graphs(self):
        return {g["route"]: g for g in self.app.graph(split=True)["graphs"]}

    def test_an_entry_point_with_no_request_is_the_route_of_its_line(self):
        graphs = self.graphs()
        self.assertEqual({"com.acme.Calc.add", store.NO_REQUEST}, set(graphs))
        self.assertEqual(["com.acme.Calc.add"], self.app.graph(split=True)["routes"])
        self.assertEqual(2, graphs["com.acme.Calc.add"]["requests"], "each run of the entry point is a request")

    def test_the_details_of_an_event_say_its_entry_point(self):
        pk = store.run_query(self.env.db, "SELECT pk FROM events_raw WHERE id = 2")["rows"][0][0]
        self.assertEqual("com.acme.Calc.add", self.app.event(pk)["entry"])
        with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
            self.assertIn('fact("entry point", e.entry)', fh.read())

    def test_the_line_starts_at_the_entry_point_and_leaves_out_the_code_above_it(self):
        nodes = {n["id"]: n for n in self.graphs()["com.acme.Calc.add"]["nodes"]}
        self.assertEqual("Calc.add", nodes["route:com.acme.Calc.add"]["label"])
        self.assertEqual({"route:com.acme.Calc.add", "code:com.acme.Calc.helper"}, set(nodes))
        self.assertEqual({"tool-called", "sql-statement"}, {i["sensor"] for n in nodes.values() for i in n["inner"]})

    def test_what_happens_outside_every_entry_point_is_drawn_from_its_caller_only(self):
        nodes = {n["id"] for n in self.graphs()[store.NO_REQUEST]["nodes"]}
        self.assertEqual({"route:" + store.NO_REQUEST, "code:com.acme.Agent.ask"}, nodes)
        ask = next(n for n in self.graphs()[store.NO_REQUEST]["nodes"] if n["id"] == "code:com.acme.Agent.ask")
        self.assertEqual(["model-call"], [i["sensor"] for i in ask["inner"]], "the sensor is inside the method that triggered it")

    def test_a_request_keeps_its_path_and_the_whole_stack_as_before(self):
        self.env.write(event(6, sensor="http-route", trace=4, capture="/buy", entry="org.apache.Servlet.service", stack=["a"]),
                       event(7, sensor="crypto-cipher", trace=4, entry="org.apache.Servlet.service", stack=["com.acme.Ticket.encrypt(T.java:1)"] + self.CALLERS))
        self.env.ingestor.poll()
        graph = self.graphs()["/buy"]
        self.assertEqual("/buy", next(n["label"] for n in graph["nodes"] if n["kind"] == "route"))
        self.assertIn("code:com.acme.Main.main", {n["id"] for n in graph["nodes"]})


class SaveReportTests(unittest.TestCase):
    """A report can be edited and saved like a sensor, and a sensor has a report of its own with no one writing it."""

    FILE = ("# ciphers\nsensors:\n- name: cipher\n  methods:\n  - a.b.C.m\n  captures:\n    algorithm: \"#P0\"\n    bits: \"#P1\"\n"
            "- name: route\n  methods:\n  - a.b.D.n\n  captures:\n    path: \"#P0\"\n"
            "reports:\n# keep this\n- name: Ciphers\n  type: table   # trailing\n  rows: route.path\n  cols: cipher.algorithm\n"
            "- name: Other\n  type: list\n  cols: cipher.algorithm\n")

    def setUp(self):
        self.env = Env()
        self.path = os.path.join(self.env.dir, "r.jot")
        with open(self.path, "w") as f:
            f.write(self.FILE)
        self.paths = [self.env.dir]
        store.load_sensors(self.env.ingestor.db, self.paths)
        store.load_reports(self.env.ingestor.db, self.paths)
        self.app = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, editable=True)

    def shown(self, name):
        return next(r for r in self.app.jots()["reports"] if r["name"] == name)["definition"]

    def read(self):
        with open(self.path) as f:
            return f.read()

    def test_a_report_is_shown_as_written_and_a_save_changes_only_that_report(self):
        text = self.shown("Ciphers")
        self.assertIn("# trailing", text)
        done = self.app.save_report("Ciphers", text, text.replace("cipher.algorithm", "cipher.bits"))
        self.assertEqual({"saved": "r.jot", "name": "Ciphers", "reports": [], "notes": []}, done)
        self.assertEqual(self.FILE.replace("cols: cipher.algorithm\n- name: Other", "cols: cipher.bits\n- name: Other"), self.read())
        self.assertIn("cipher.bits", self.shown("Ciphers"), "the page reads the file again")

    def test_a_report_can_be_renamed_to_a_free_name_and_not_to_a_used_one(self):
        text = self.shown("Ciphers")
        self.assertEqual("Renamed", self.app.save_report("Ciphers", text, text.replace("Ciphers", "Renamed"))["name"])
        text = self.shown("Renamed")
        with self.assertRaises(store.SaveError):
            self.app.save_report("Renamed", text, text.replace("Renamed", "Other"))
        self.assertEqual([], self.app.check_report(text, "Renamed"), "its own name is not another report")
        self.assertTrue(self.app.check_report(text.replace("Renamed", "Other"), "Renamed"))

    def test_a_report_that_is_wrong_or_changed_underneath_is_not_written(self):
        text = self.shown("Ciphers")
        with self.assertRaises(store.SaveError) as e:
            self.app.save_report("Ciphers", text, text.replace("cipher.algorithm", "nobody.field"))
        self.assertEqual(400, e.exception.status)
        with open(self.path, "w") as f:
            f.write(self.FILE.replace("rows: route.path", "rows: cipher.bits"))
        with self.assertRaises(store.SaveError) as e:
            self.app.save_report("Ciphers", text, text.replace("table", "compare"))
        self.assertEqual(409, e.exception.status)
        with self.assertRaises(store.SaveError) as e:
            self.app.save_report("Missing", "x", "name: Missing\ntype: list\ncols: cipher.algorithm")
        self.assertEqual(404, e.exception.status)

    def test_saving_is_off_when_the_dashboard_is_open_to_others(self):
        app = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, editable=False)
        with self.assertRaises(store.SaveError) as e:
            app.save_report("Ciphers", "x", "x")
        self.assertEqual(403, e.exception.status)

    def test_a_new_configuration_with_empty_lists_can_be_added_to(self):
        for empty in ("[]", ""):
            with open(self.path, "w") as f:
                f.write("# new\napp:\n  packages:\n    - com.acme\n\nsensors: %s\n\n\nreports: %s   # none yet\n" % (empty, empty))
            sensor = "name: cipher\ndescription: Identifies a cipher being used\nmethods:\n- a.b.C.m\ncaptures:\n  algorithm: '#P0'\n"
            store.add_sensor(self.paths, "r.jot", sensor)
            store.add_report(self.paths, "r.jot", "name: Ciphers\ntype: list\ncols: cipher.algorithm\n", {"cipher": ["algorithm"]})
            with open(self.path) as f:
                doc = yaml.safe_load(f.read())
            self.assertEqual(["cipher"], [x["name"] for x in doc["sensors"]], repr(empty))
            self.assertEqual(["Ciphers"], [x["name"] for x in doc["reports"]])
            self.assertEqual({"packages": ["com.acme"]}, doc["app"])

    def test_an_item_written_as_a_dash_and_a_comment_can_be_added_after_saved_and_deleted(self):
        text = ("sensors:\n- name: first\n  description: Identifies a thing\n  methods:\n  - a.b.C.m\n"
                "\n- # a comment about the second\n  name: second\n  description: Identifies another thing\n  methods:\n  - a.b.C.n\n  captures:\n    v: '#P0'\n"
                "\nreports:\n- # about it\n  name: Second\n  type: list\n  cols: second.v\n")
        with open(self.path, "w") as f:
            f.write(text)
        store.add_sensor(self.paths, "r.jot", "name: third\ndescription: Identifies a third thing\nmethods:\n- a.b.C.o\ncaptures:\n  v: '#P0'\n")
        store.add_report(self.paths, "r.jot", "name: Third\ntype: list\ncols: second.v\n", {"second": ["v"]})
        with open(self.path) as f:
            doc = yaml.safe_load(f.read())
        self.assertEqual(["first", "second", "third"], [x["name"] for x in doc["sensors"]])
        self.assertEqual(["Second", "Third"], [x["name"] for x in doc["reports"]])
        original = store.sensor_spans(open(self.path).read())["second"]["text"]
        store.save_sensor(self.paths, "second", original, original.replace("another", "yet another"))
        self.assertIn("yet another", open(self.path).read())
        self.assertIn("# a comment about the second", open(self.path).read())
        original = store.sensor_spans(open(self.path).read())["second"]["text"]
        store.delete_entry(self.paths, "sensors", "second", original)
        report = store.report_spans(open(self.path).read())["Second"]["text"]
        store.delete_entry(self.paths, "reports", "Second", report)
        after = open(self.path).read()
        self.assertNotIn("a comment about the second", after, "the dash line goes with its item")
        doc = yaml.safe_load(after)
        self.assertEqual(["first", "third"], [x["name"] for x in doc["sensors"]])
        self.assertEqual(["Third"], [x["name"] for x in doc["reports"]])

    def test_a_deleted_report_is_taken_out_of_its_file_and_nothing_else_is(self):
        text = self.shown("Ciphers")
        done = self.app.delete_report("Ciphers", text)
        self.assertEqual({"deleted": "r.jot", "name": "Ciphers", "reports": [], "notes": []}, done)
        self.assertEqual(self.FILE.replace("- name: Ciphers\n  type: table   # trailing\n  rows: route.path\n  cols: cipher.algorithm\n", ""), self.read())
        self.assertNotIn("Ciphers", [r["name"] for r in self.app.jots()["reports"]])

    def test_the_last_one_in_a_list_leaves_an_empty_list_and_a_sensor_says_which_reports_read_it(self):
        other = self.shown("Other")
        self.app.delete_report("Other", other)
        self.app.delete_report("Ciphers", self.shown("Ciphers"))
        self.assertTrue(self.read().endswith("reports: []\n") or "reports: []" in self.read(), self.read())
        self.assertEqual([], yaml.safe_load(self.read())["reports"])
        self.assertEqual(2, len(yaml.safe_load(self.read())["sensors"]))
        # put the reports back to see a sensor go
        with open(self.path, "w") as f:
            f.write(self.FILE)
        store.load_sensors(self.env.ingestor.db, self.paths)
        cipher = next(s for s in self.app.jots()["sensors"] if s["name"] == "cipher")
        done = self.app.delete_jot("cipher", cipher["definition"])
        self.assertEqual(["Ciphers", "Other"], sorted(done["reports"]), "they are left alone and the page says they have lost a sensor")
        self.assertEqual(["route"], [x["name"] for x in yaml.safe_load(self.read())["sensors"]])

    def test_a_delete_that_is_stale_missing_or_not_allowed_changes_nothing(self):
        text = self.shown("Ciphers")
        with self.assertRaises(store.SaveError) as e:
            self.app.delete_report("Ciphers", text + "\n  value: x")
        self.assertEqual(409, e.exception.status)
        with self.assertRaises(store.SaveError) as e:
            self.app.delete_report("Nobody", text)
        self.assertEqual(404, e.exception.status)
        app = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, editable=False)
        with self.assertRaises(store.SaveError) as e:
            app.delete_jot("cipher", "x")
        self.assertEqual(403, e.exception.status)
        self.assertEqual(self.FILE, self.read())

    def test_every_sensor_has_a_report_with_a_row_for_each_entry_point_and_a_column_for_each_capture(self):
        self.env.write(event(1, sensor="http-route", trace=1, capture="/buy"),
                       event(2, sensor="cipher", trace=1, capture="AES", data={"algorithm": "AES", "bits": 128}),
                       event(3, sensor="cipher", trace=2, capture="DES", entry="a.b.Tool.run", data={"algorithm": "DES", "bits": 56}),
                       event(4, sensor="cipher", trace=3, capture="RSA", data={"algorithm": "RSA", "bits": 2048}))
        self.env.ingestor.poll()
        sensor = next(s for s in self.app.jots()["sensors"] if s["name"] == "cipher")
        rows = {tuple(r) for r in store.run_query(self.env.db, sensor["report_sql"])["rows"]}
        self.assertEqual({("/buy", "algorithm", "AES"), ("/buy", "bits", "128"), ("a.b.Tool.run", "algorithm", "DES"),
                          ("a.b.Tool.run", "bits", "56"), (store.NO_ENTRY, "algorithm", "RSA"), (store.NO_ENTRY, "bits", "2048")}, rows)

    def test_a_sensor_that_captures_nothing_has_a_count_of_how_often_it_ran(self):
        self.env.write(event(1, sensor="plain", trace=1, entry="a.b.Tool.run"), event(2, sensor="plain", trace=2, entry="a.b.Tool.run"))
        self.env.ingestor.poll()
        rows = store.run_query(self.env.db, store.sensor_report_sql("plain", []))["rows"]
        self.assertEqual([["a.b.Tool.run", "events", "2"]], [list(r) for r in rows])

    def test_a_rule_reads_the_events_it_names(self):
        self.env.write(event(1, sensor="rule-blocked", trace=1, entry="a.b.Tool.run", data={"x": "1"}),
                       event(2, sensor="rule-active", trace=2, entry="a.b.Tool.run", data={"x": "2"}))
        self.env.ingestor.poll()
        rows = store.run_query(self.env.db, store.sensor_report_sql("rule", ["x"], rule=True))["rows"]
        self.assertEqual([["a.b.Tool.run", "x", "1"], ["a.b.Tool.run", "x", "2"]], [list(r) for r in rows])


class PageEditTests(unittest.TestCase):
    """The JOTs and Reports pages show a result when a row is clicked, and the drawer opens from an Edit button."""

    def setUp(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"), encoding="utf-8") as f:
            self.html = f.read()

    def test_a_row_shows_its_result_and_only_the_edit_button_opens_the_drawer(self):
        self.assertIn('onclick: () => selectSensor(i.key, i.name)', self.html)
        self.assertIn('onclick: () => selectReport(i.name)', self.html)
        self.assertIn('onclick: (ev) => { ev.stopPropagation(); selectJot(item.key, item.name); }', self.html)
        self.assertIn('id="sensorResult"', self.html)

    def test_a_report_is_saved_through_its_own_endpoint(self):
        self.assertIn('"/api/reports/save"', self.html)
        self.assertIn('"/api/reports/check"', self.html)


class ReportExpressionTests(unittest.TestCase):
    """A column of a table report can be an expression like #total(ai-model-call.input_tokens)."""

    def setUp(self):
        self.env = Env()
        call = lambda i, trace, model, tin, tout: event(i, sensor="ai-model-call", trace=trace, capture="x", stack=["a"],
                                                     data={"model": model, "input_tokens": tin, "output_tokens": tout})
        # the two calls of the first request are different models, which happens when a trace holds the end of one question and the start of the next
        self.env.write(call(1, 1, "big", 100, 10), call(2, 1, "small", 7, 1), call(3, 2, "big", 50, 5), call(4, 3, "small", 3, 1))
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)

    def grid(self, cols):
        sql = store.report_sql("table", "ai-model-call.model", cols)
        return {(r[0], r[1]): r[2] for r in store.run_query(self.env.db, sql)["rows"]}

    def test_total_adds_up_each_event_once_and_does_not_read_another_models_call_from_the_same_request(self):
        g = self.grid("#total(ai-model-call.input_tokens), #count(ai-model-call)")
        self.assertEqual(150, g[("big", "#total(ai-model-call.input_tokens)")])
        self.assertEqual(10, g[("small", "#total(ai-model-call.input_tokens)")])
        self.assertEqual(2, g[("big", "#count(ai-model-call)")])
        self.assertEqual(2, g[("small", "#count(ai-model-call)")])

    def test_average_min_max_and_arithmetic(self):
        g = self.grid("#average(ai-model-call.input_tokens), #min(ai-model-call.input_tokens), #max(ai-model-call.input_tokens), "
                      "#total(ai-model-call.input_tokens) + #total(ai-model-call.output_tokens), "
                      "#total(ai-model-call.input_tokens) / #count(ai-model-call), #total(ai-model-call.input_tokens) - -(2 + 3) * 2")
        self.assertEqual(75, g[("big", "#average(ai-model-call.input_tokens)")])
        self.assertEqual(50, g[("big", "#min(ai-model-call.input_tokens)")])
        self.assertEqual(100, g[("big", "#max(ai-model-call.input_tokens)")])
        self.assertEqual(165, g[("big", "#total(ai-model-call.input_tokens) + #total(ai-model-call.output_tokens)")])
        self.assertEqual(75, g[("big", "#total(ai-model-call.input_tokens) / #count(ai-model-call)")])
        self.assertEqual(5, g[("small", "#total(ai-model-call.input_tokens) / #count(ai-model-call)")])
        self.assertEqual(160, g[("big", "#total(ai-model-call.input_tokens) - -(2 + 3) * 2")], "150 minus minus ten")

    def test_a_plain_column_still_shows_the_values_of_its_own_event(self):
        g = self.grid("ai-model-call.input_tokens")
        self.assertEqual({("big", "ai-model-call.input_tokens"), ("small", "ai-model-call.input_tokens")}, set(g))
        rows = store.run_query(self.env.db, store.report_sql("table", "ai-model-call.model", "ai-model-call.input_tokens"))["rows"]
        self.assertEqual({("big", "100"), ("big", "50"), ("small", "7"), ("small", "3")}, {(r[0], r[2]) for r in rows})

    def test_what_is_wrong_is_said(self):
        for text, said in (("#nope(a.x)", "isn't something a report can call"), ("#total(a)", "needs a field"), ("#total(a.x", "isn't a call"),
                           ("#total(a.x) +", "needs a number or a call"), ("#total(a.x) abc", "isn't understood"), ("#total(a.x) )", "doesn't belong")):
            try:
                store.parse_report_expression(text)
            except ValueError as e:
                self.assertIn(said, str(e), text)
            else:
                self.fail(text + " was accepted")
        for rtype in ("list", "compare"):
            with self.assertRaises(ValueError):
                store.report_sql(rtype, "ai-model-call.model" if rtype == "compare" else None, "#total(ai-model-call.input_tokens)")

    def test_the_editor_checks_the_sensors_and_fields_an_expression_reads(self):
        sensors = {"ai-model-call": ["model", "input_tokens"]}
        report = 'name: Tokens\ntype: table\nrows: ai-model-call.model\ncols: "%s"\n'
        self.assertEqual([], store.check_report_text(report % "#total(ai-model-call.input_tokens)", sensors))
        said = " ".join(p["message"] for p in store.check_report_text(report % "#total(ai-model-call.nope)", sensors))
        self.assertIn("doesn't capture nope", said)
        said = " ".join(p["message"] for p in store.check_report_text(report % "#total(ai-model-call.input_tokens", sensors))
        self.assertIn("isn't a call", said)

    def test_the_events_behind_a_cell_are_those_of_the_sensors_the_expression_reads(self):
        sql = store.report_events_sql("table", "ai-model-call.model", "#total(ai-model-call.input_tokens)", "big", "#total(ai-model-call.input_tokens)")
        pks = {r[0] for r in store.run_query(self.env.db, sql)["rows"]}
        ids = {r[0] for r in store.run_query(self.env.db, "SELECT pk FROM events_raw WHERE json_extract(data, '$.model') = 'big'")["rows"]}
        self.assertEqual(ids, pks)

    def test_renaming_a_sensor_renames_it_inside_an_expression(self):
        text = "name: T\ntype: table\nrows: ai-model-call.model\ncols: \"#total(ai-model-call.input_tokens)\"\n"
        doc = yaml.safe_load(text)
        before = store._report_uses({"reports": [doc]}, ("ai-model-call", "llm-call"))
        self.assertIn("#total(llm-call.input_tokens)", before[0][2][0])


class GraphBoxFillTests(unittest.TestCase):
    def test_every_kind_of_box_hides_the_line_that_passes_behind_it(self):
        with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
            page = fh.read()
        for kind in ("", ".route", ".exit", " .inner"):
            rule = re.search(r"svg\.graph \.node%s rect \{([^}]*)\}" % re.escape(kind), page)
            self.assertIsNotNone(rule, kind)
            fill = re.search(r"fill:\s*([^;]+);", rule.group(1)).group(1).strip()
            self.assertNotIn(fill, ("transparent", "none"), "a box with no fill shows the line through its label, as the dashed exit box did")


class ExpressionFunctionTests(unittest.TestCase):
    JOT = "name: sample-sensor\nmethods:\n- x.Y.z\ncaptures:\n  v: %s\n"

    def problems(self, expression):
        return [p["message"] for p in store.check_jot_text(self.JOT % json.dumps(expression))]

    def test_every_function_the_agent_has_is_known(self):
        for name in store.EXPRESSION_FUNCTIONS:
            self.assertEqual([], self.problems("#%s(#P0)" % name), name)

    def test_the_functions_are_what_the_agent_registers(self):
        root = os.path.join(os.path.dirname(server.HERE), "src", "main", "java", "org", "openolly")
        with open(os.path.join(root, "Expression.java"), encoding="utf-8") as fh:
            registered = set(re.findall(r'registerFunction\("(\w+)"', fh.read()))
        with open(os.path.join(root, "ExpressionFunctions.java"), encoding="utf-8") as fh:
            ours = set(re.findall(r"public static [\w<>\[\], ?]+ (\w+)\(", fh.read())) - {"names"}
        self.assertTrue(ours, "the functions were not found in the Java source")
        self.assertEqual(sorted(registered | ours), sorted(store.EXPRESSION_FUNCTIONS),
                         "the agent and the dashboard have to agree on what an expression can call")

    def test_a_function_that_is_not_there_is_found_with_the_line_and_what_there_is(self):
        found = store.check_jot_text("name: sample-sensor\nmethods:\n- x.Y.z\ncaptures:\n  ok: '#P0'\n  bad: \"#match(#P0, 'x')\"\n")
        self.assertEqual([6], [p["line"] for p in found])
        self.assertIn("#match() is not a function", found[0]["message"])
        for name in store.EXPRESSION_FUNCTIONS:
            self.assertIn("#" + name, found[0]["message"])

    def test_each_unknown_function_is_said_once_and_each_one_is_said(self):
        said = self.problems("#nope(#P0) + #nope(#P1) + #other(#P2)")
        self.assertEqual(2, len(said))
        self.assertTrue(said[0].startswith("#nope()") and said[1].startswith("#other()"))

    def test_a_variable_with_a_method_text_in_quotes_and_a_projection_are_not_function_calls(self):
        for expression in ("#P0.getName()", "#this.matches('x')", "#P0.cookies.?[name.matches('x')].![name]", "#P0 + '#nope(1)'",
                           '#P0 + "#nope(1)"', "#list(#P0).?[#matches(name, 'a')].![name]", "#ARGS", "#P0.toString()"):
            self.assertEqual([], self.problems(expression), expression)

    def test_the_blocking_expression_of_a_rule_is_checked_too(self):
        text = "name: some-rule\ndescription: Identifies something\nmethods:\n- x.Y.z\ncaptures:\n  v: '#P0'\nblock-when: %s\n"
        self.assertEqual([], [p["message"] for p in store.check_jot_text(text % "'#luhn(#P0)'")])
        said = [p["message"] for p in store.check_jot_text(text % "'#lunh(#P0)'")]
        self.assertEqual(1, len(said))
        self.assertIn("#lunh()", said[0])
        self.assertEqual([], [p["message"] for p in store.check_jot_text(text % "true")])

    def test_a_drafted_jot_with_a_made_up_function_goes_back_to_the_model(self):
        problems = store.check_draft("name: sample-sensor\ndescription: Identifies a thing\nmethods:\n- x.Y.z\ncaptures:\n  v: '#matchAll(#P0, \"x\")'\n")
        self.assertTrue(any("#matchAll()" in p for p in problems), problems)

    def test_the_model_is_told_about_every_function_and_that_an_empty_list_records_nothing(self):
        for name in store.EXPRESSION_FUNCTIONS:
            if name != "sort":      # it sorts a list where it is and returns nothing, so a capture has no use for it
                self.assertIn("#" + name + "(", llm.JOT_SYSTEM, name)
        self.assertIn("a list with nothing in it records nothing at all", llm.JOT_SYSTEM)
        self.assertIn("has to be two JOTs", llm.JOT_SYSTEM)
        self.assertIn("Never use T( or new", llm.JOT_SYSTEM, "and they are still not to use T(")


class GraphRowsTests(unittest.TestCase):
    """The graph is drawn from the events of each request, and there is a limit on how many are used. It must never lose what a route's
    sensors saw, whichever route is busy, since the one request that read /etc/passwd is the one that matters."""
    STACK = ["com.acme.Ticket.encrypt(Ticket.java:125)"]

    def setUp(self):
        self.env = Env()
        self.env.ingestor.app_prefixes = ("com.acme",)
        events, n = [], [0]

        def add(sensor, trace, **kw):
            n[0] += 1
            events.append(event(n[0], sensor=sensor, trace=trace, stack=self.STACK, **kw))

        for t in range(1, 31):                        # a busy route, 30 requests, in the order they came
            add("http-route", t, capture="/busy")
            add("crypto-cipher", t)
            if t == 5:
                add("file-path", t, capture="/etc/passwd")   # one old request that did something none of the others did
        for t in range(101, 104):                     # a quiet one
            add("http-route", t, capture="/quiet")
            add("auth-user", t, capture="Guest")
        add("crypto-hash", 900, capture="MD5")        # outside any request
        self.env.write(*events)
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)

    def small(self):
        import contextlib
        stack = contextlib.ExitStack()
        for name, value in (("GRAPH_ROW_LIMIT", 40), ("GRAPH_MIN_ROUTE_ROWS", 4), ("GRAPH_COVERAGE_ROWS", 1000)):
            stack.enter_context(unittest.mock.patch.object(store, name, value))
        return stack

    def by_route(self, out):
        rows = {}
        for row in out["rows"]:
            rows.setdefault(row[0], []).append(row)
        return rows

    def test_with_room_for_everything_every_event_is_used_and_nothing_is_cut(self):
        out = store.graph_rows(self.env.db)
        self.assertFalse(out["truncated"])
        rows = self.by_route(out)
        self.assertEqual(31, len(rows["/busy"]), "30 ciphers and the one file read, and the route's own events are not rows")
        self.assertEqual(3, len(rows["/quiet"]))
        self.assertEqual(1, len(rows[None]), "an event outside any request has no route")

    def test_a_busy_route_is_cut_to_its_share_and_the_graph_is_told(self):
        with self.small():
            out = store.graph_rows(self.env.db)
        self.assertTrue(out["truncated"])
        rows = self.by_route(out)
        self.assertLess(len(rows["/busy"]), 30, "the busy route was cut")
        self.assertEqual(3, len(rows["/quiet"]), "and the quiet one, which is within its share, was not")

    def test_the_newest_requests_of_a_cut_route_are_the_ones_kept(self):
        with self.small():
            traces = {row[2] for row in store.graph_rows(self.env.db)["rows"] if row[0] == "/busy"}
        self.assertIn(30, traces, "the newest")
        self.assertIn(29, traces)
        self.assertNotIn(2, traces, "an old one that did nothing special is the first to go")

    def test_every_sensor_of_a_route_stays_in_its_graph_whatever_the_cut(self):
        with self.small():
            rows = [r for r in store.graph_rows(self.env.db)["rows"] if r[0] == "/busy"]
        self.assertIn("file-path", {r[3] for r in rows}, "the one old request that read a file is kept, though it is far from the newest")
        self.assertEqual({"crypto-cipher", "file-path"}, {r[3] for r in rows if r[2] == 5}, "and it is kept whole")

    def test_a_cut_route_still_has_every_sensor_in_the_graph_the_page_is_given(self):
        with self.small():
            graph = self.app.graph(split=True)
        busy = next(g for g in graph["graphs"] if g["route"] == "/busy")
        self.assertEqual({"crypto-cipher", "file-path"}, {i["sensor"] for n in busy["nodes"] for i in n["inner"]})

    def test_the_graph_says_how_many_requests_a_cut_route_really_had(self):
        with self.small():
            graphs = {g["route"]: g for g in self.app.graph(split=True)["graphs"]}
        self.assertLess(graphs["/busy"]["requests"], 30)
        self.assertEqual(30, graphs["/busy"]["all_requests"], "so the page can say 6 of 30 and not just 6")
        self.assertEqual((3, 3), (graphs["/quiet"]["requests"], graphs["/quiet"]["all_requests"]))

    def test_one_route_asked_for_alone_gets_the_whole_limit(self):
        with self.small():
            out = store.graph_rows(self.env.db, "/busy")
        self.assertEqual(31, len(out["rows"]), "all of it, though a share of the limit among the routes would have been 13")
        self.assertFalse(out["truncated"])

    def test_the_events_outside_a_request_can_be_asked_for(self):
        out = store.graph_rows(self.env.db, store.NO_REQUEST)
        self.assertEqual(["crypto-hash"], [r[3] for r in out["rows"]])

    def test_a_method_limits_the_rows_as_before(self):
        self.assertEqual([], store.graph_rows(self.env.db, None, "POST")["rows"], "none of these requests said a method")


class EntryPointTests(unittest.TestCase):
    """The entry points are the app: entry: list of the jots file, which the dashboard edits and writes back without disturbing the rest."""
    FILE = """# my jots
jots:
  - jots   # the sensors
control: control.yaml
# The application as a scope.
app:
  entry:
    - javax.servlet.Servlet.service
    - jakarta.servlet.Servlet.service
  packages:
    - com.acme
# what the platform does is left out
ignore:
  - java.lang.ClassLoader
"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "jot.yaml")
        self.write(self.FILE)

    def write(self, text):
        with open(self.path, "w") as f:
            f.write(text)

    def text(self):
        with open(self.path) as f:
            return f.read()

    def doc(self):
        return yaml.safe_load(self.text())

    # ------------------------------------------------------------------ what is a good entry point

    def test_a_method_or_an_annotation_is_an_entry_point(self):
        good = ["javax.servlet.Servlet.service", "jakarta.servlet.http.HttpServlet.doGet", "com.acme.Main.main", "@org.springframework.web.bind.annotation.GetMapping",
                "@dev.langchain4j.agent.tool.Tool"]
        self.assertEqual([], store.entry_problems(good))
        self.assertEqual([], store.entry_problems([]), "an empty list is allowed, it means no application scope")

    def test_what_cannot_be_an_entry_point_is_said_for_the_entry_it_is_on(self):
        said = store.entry_problems(["fine.Class.method", "static foo.Bar.baz", "", "!com.acme.Skip.it", "com.acme.Thing.<init>", "fine.Class.method", 5, "NoPackage"])
        self.assertEqual([1, 2, 3, 4, 5, 6, 7], [p["index"] for p in said], "the first is fine, the rest are not")
        by = {p["index"]: p["message"] for p in said}
        self.assertIn("isn't a method name", by[1])
        self.assertIn("is empty", by[2])
        self.assertIn("can't start with !", by[3])
        self.assertIn("constructor", by[4])
        self.assertIn("listed twice", by[5])
        self.assertIn("is empty", by[6], "not text")
        self.assertIn("isn't a method name", by[7], "a class with no package")

    def test_what_is_not_a_list_is_a_problem_of_the_list(self):
        for bad in ("javax.servlet.Servlet.service", None, {"a": 1}, 3):
            self.assertEqual([None], [p["index"] for p in store.entry_problems(bad)])

    def test_the_default_is_the_one_the_agent_uses(self):
        with open(os.path.join(os.path.dirname(server.HERE), "src", "main", "java", "org", "openolly", "AppScope.java"), encoding="utf-8") as fh:
            found = re.search(r"DEFAULT_ENTRY = List\.of\(([^)]*)\)", fh.read())
        self.assertIsNotNone(found, "the default was not found in AppScope.java")
        self.assertEqual(list(store.DEFAULT_ENTRY), re.findall(r'"([^"]+)"', found.group(1)), "the agent and the dashboard have to agree on the default")

    # ------------------------------------------------------------------ reading

    def test_the_entry_points_are_read_from_the_file(self):
        self.assertEqual({"entry": ["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], "problems": []}, store.read_entry(self.path))

    def test_a_file_that_does_not_say_has_the_default_and_an_empty_list_is_not_the_default(self):
        self.write("jots: []\n")
        self.assertIsNone(store.read_entry(self.path)["entry"])
        self.write("jots: []\napp:\n  packages: [com.acme]\n")
        self.assertIsNone(store.read_entry(self.path)["entry"], "an app with no entry says nothing about it")
        self.write("jots: []\napp:\n  entry: []\n")
        self.assertEqual([], store.read_entry(self.path)["entry"], "no entry points, which is no application scope and not the default")
        self.write("")
        self.assertIsNone(store.read_entry(self.path)["entry"])

    def test_a_list_the_agent_could_not_use_is_read_as_the_default_with_the_reason(self):
        self.write("app:\n  entry: javax.servlet.Servlet.service\n")
        found = store.read_entry(self.path)
        self.assertIsNone(found["entry"])
        self.assertIn("must be a list", found["problems"][0]["message"])

    def test_a_file_with_a_bad_entry_is_read_with_its_problems(self):
        self.write("app:\n  entry:\n  - com.acme.Main.main\n  - static x.Y.z\n")
        self.assertEqual([1], [p["index"] for p in store.read_entry(self.path)["problems"]])

    # ------------------------------------------------------------------ writing

    def test_the_list_is_replaced_and_everything_else_in_the_file_stays_as_written(self):
        before = self.text()
        store.write_entry(self.path, ["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service", "@com.acme.Handler"])
        after = self.text()
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service", "@com.acme.Handler"], self.doc()["app"]["entry"])
        for kept in ("# my jots", "  - jots   # the sensors", "control: control.yaml", "# The application as a scope.", "  packages:", "    - com.acme",
                     "# what the platform does is left out", "ignore:", "  - java.lang.ClassLoader"):
            self.assertIn(kept, after, kept)
        self.assertEqual(before.replace("    - jakarta.servlet.Servlet.service\n", '    - jakarta.servlet.Servlet.service\n    - "@com.acme.Handler"\n'), after,
                         "the line added is the only difference")

    def test_an_entry_can_be_taken_away_and_the_list_made_empty(self):
        store.write_entry(self.path, ["javax.servlet.Servlet.service"])
        self.assertEqual(["javax.servlet.Servlet.service"], self.doc()["app"]["entry"])
        self.assertNotIn("jakarta.servlet.Servlet.service", self.text())
        store.write_entry(self.path, [])
        self.assertIn("  entry: []\n", self.text())
        self.assertEqual([], self.doc()["app"]["entry"])
        self.assertEqual(["com.acme"], self.doc()["app"]["packages"])

    def test_the_default_takes_the_key_out_and_leaves_the_rest_of_app_alone(self):
        store.write_entry(self.path, None)
        self.assertNotIn("entry", self.doc()["app"])
        self.assertEqual({"packages": ["com.acme"]}, self.doc()["app"])
        self.assertIn("# The application as a scope.", self.text(), "its comment stays")
        self.assertEqual(["java.lang.ClassLoader"], self.doc()["ignore"])
        self.assertIsNone(store.read_entry(self.path)["entry"])

    def test_the_default_when_the_file_has_none_changes_nothing(self):
        self.write("jots: []\n")
        store.write_entry(self.path, None)
        self.assertEqual("jots: []\n", self.text())

    def test_an_app_with_no_entry_gets_one_beside_its_other_settings(self):
        self.write("jots: []\napp:\n  packages:\n    - com.acme\nignore: []\n")
        store.write_entry(self.path, ["com.acme.Main.main"])
        self.assertEqual("jots: []\napp:\n  entry:\n    - com.acme.Main.main\n  packages:\n    - com.acme\nignore: []\n", self.text())
        self.assertEqual({"entry": ["com.acme.Main.main"], "packages": ["com.acme"]}, self.doc()["app"])

    def test_a_file_with_no_app_gets_one_at_the_end(self):
        self.write("# nothing but sensors\njots:\n  - jots\n")
        store.write_entry(self.path, ["com.acme.Main.main", "@com.acme.Handler"])
        self.assertEqual("# nothing but sensors\njots:\n  - jots\napp:\n  entry:\n    - com.acme.Main.main\n    - \"@com.acme.Handler\"\n", self.text())
        self.write("")
        store.write_entry(self.path, ["com.acme.Main.main"])
        self.assertEqual(["com.acme.Main.main"], self.doc()["app"]["entry"], "even an empty file")

    def test_an_entry_written_inline_is_replaced_by_a_list(self):
        self.write("jots: []\napp:\n  entry: [javax.servlet.Servlet.service]\n  packages: [com.acme]\n")
        store.write_entry(self.path, ["javax.servlet.Servlet.service", "com.acme.Main.main"])
        self.assertEqual({"entry": ["javax.servlet.Servlet.service", "com.acme.Main.main"], "packages": ["com.acme"]}, self.doc()["app"])

    def test_an_annotation_is_quoted_so_the_file_still_says_what_was_meant(self):
        store.write_entry(self.path, ["@dev.langchain4j.agent.tool.Tool"])
        self.assertIn('- "@dev.langchain4j.agent.tool.Tool"', self.text())
        self.assertEqual(["@dev.langchain4j.agent.tool.Tool"], store.read_entry(self.path)["entry"])

    def test_nothing_is_written_if_the_file_changed_since_the_editor_was_opened(self):
        opened = store.read_entry(self.path)["entry"]
        self.write(self.FILE.replace("    - jakarta.servlet.Servlet.service\n", ""))      # someone else
        changed = self.text()
        with self.assertRaises(store.SaveError) as e:
            store.write_entry(self.path, ["com.acme.Main.main"], original=opened)
        self.assertEqual(409, e.exception.status)
        self.assertEqual(changed, self.text())
        store.write_entry(self.path, ["com.acme.Main.main"], original=["javax.servlet.Servlet.service"])
        self.assertEqual(["com.acme.Main.main"], self.doc()["app"]["entry"], "and it is written when the editor started from what the file says")

    def test_a_default_that_was_never_written_can_be_checked_against_too(self):
        self.write("jots: []\n")
        with self.assertRaises(store.SaveError):
            store.write_entry(self.path, ["com.acme.Main.main"], original=["javax.servlet.Servlet.service"])
        store.write_entry(self.path, ["com.acme.Main.main"], original=None)
        self.assertEqual(["com.acme.Main.main"], self.doc()["app"]["entry"])

    def test_a_bad_list_is_refused_and_the_file_is_left_alone(self):
        before = self.text()
        for bad in (["static x.Y.z"], ["a.B.c", "a.B.c"], [""], ["!a.B.c"], "javax.servlet.Servlet.service", ["a.B.<init>"]):
            with self.assertRaises(store.SaveError):
                store.write_entry(self.path, bad)
        self.assertEqual(before, self.text())

    def test_an_app_written_as_a_flow_is_refused_and_left_for_a_person(self):
        self.write("jots: []\napp: {packages: [com.acme]}\n")
        with self.assertRaises(store.SaveError) as e:
            store.write_entry(self.path, ["a.B.c"])
        self.assertIn("edit it by hand", str(e.exception))
        self.assertEqual("jots: []\napp: {packages: [com.acme]}\n", self.text())

    def test_the_file_keeps_its_mode_and_no_scratch_file_is_left(self):
        os.chmod(self.path, 0o640)
        store.write_entry(self.path, ["a.B.c"])
        self.assertEqual(0o640, os.stat(self.path).st_mode & 0o777)
        self.assertEqual(["jot.yaml"], os.listdir(self.dir))

    def test_the_agent_reads_back_what_was_written(self):
        store.write_entry(self.path, ["com.acme.Main.main", "@com.acme.Handler"])
        jots, control, packages = store.read_jots_file(self.path)
        self.assertEqual(["com.acme"], packages, "the rest of what the dashboard reads from the file is as it was")
        self.assertEqual([], store.jots_file_problems(self.path))

    # ------------------------------------------------------------------ the app and the api

    def app(self, editable=True, jots_file="yes"):
        env = Env()
        return server.App(env.db, env.ingestor, jots_file=self.path if jots_file else None, editable=editable)

    def test_the_app_says_what_the_file_has_and_what_the_default_is(self):
        state = self.app().entry()
        self.assertEqual((["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], "jot.yaml", True, []),
                         (state["entry"], state["file"], state["editable"], state["problems"]))
        self.assertEqual(list(store.DEFAULT_ENTRY), state["default"])

    def test_saving_writes_the_file_and_the_app_says_the_new_state(self):
        app = self.app()
        state = app.save_entry(["com.acme.Main.main"], ["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"])
        self.assertEqual((["com.acme.Main.main"], "jot.yaml"), (state["entry"], state["saved"]))
        self.assertEqual(["com.acme.Main.main"], self.doc()["app"]["entry"])
        self.assertIsNone(app.save_entry(None, ["com.acme.Main.main"])["entry"], "the default")

    def test_a_dashboard_that_may_not_write_or_has_no_jots_file_says_so(self):
        with self.assertRaises(store.SaveError) as e:
            self.app(editable=False).save_entry(["a.B.c"], None)
        self.assertEqual(403, e.exception.status)
        self.assertFalse(self.app(editable=False).entry()["editable"])
        none = self.app(jots_file=None)
        self.assertEqual((None, None, False), (none.entry()["entry"], none.entry()["file"], none.entry()["editable"]))
        with self.assertRaises(store.SaveError) as e:
            none.save_entry(["a.B.c"], None)
        self.assertIn("--jots", str(e.exception))

    def test_the_check_says_which_entry_has_the_problem(self):
        self.assertEqual([1], [p["index"] for p in self.app().check_entry(["a.B.c", "nope"])])

    def test_over_http(self):
        app = self.app()
        httpd = server.make_server(app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        host = {"Host": "127.0.0.1:%d" % port}

        def get(path):
            with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers=host)) as r:
                return json.load(r)

        def post(path, body):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=json.dumps(body).encode(),
                                         headers=dict(host, **{"X-JOT-Dashboard": "1", "Content-Type": "application/json"}))
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                return e.code, json.load(e)

        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], get("/api/entry")["entry"])
        self.assertEqual((200, {"problems": [{"index": 0, "message": store.entry_problems(["nope"])[0]["message"]}]}), post("/api/entry/check", {"entry": ["nope"]}))
        status, body = post("/api/entry/save", {"entry": ["a.B.c"], "original": ["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"]})
        self.assertEqual((200, ["a.B.c"]), (status, body["entry"]))
        status, body = post("/api/entry/save", {"entry": ["x.Y.z"], "original": ["not what it is"]})
        self.assertEqual(409, status, "the file changed under the editor")
        self.assertIn("has changed", body["error"])
        status, body = post("/api/entry/save", {"entry": ["static x.Y.z"], "original": ["a.B.c"]})
        self.assertEqual(400, status)
        self.assertEqual(["a.B.c"], self.doc()["app"]["entry"], "and the file is as the last good save left it")


class ListSettingTests(unittest.TestCase):
    """The ignore list and the application's packages are edited the way the entry points are, only the one setting and the rest of the file as it was."""
    FILE = """# my jots
jots: []
# the application
app:
  entry:
    - javax.servlet.Servlet.service
  packages:
    - com.acme
# what the platform does is left out
ignore:
  - java.lang.ClassLoader
  - jdk.internal.loader
sensors: []
"""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "jot.yaml")
        self.write(self.FILE)

    def write(self, text):
        with open(self.path, "w") as f:
            f.write(text)

    def text(self):
        with open(self.path) as f:
            return f.read()

    def doc(self):
        return yaml.safe_load(self.text())

    def test_the_three_settings_are_read_as_written_and_none_means_the_file_does_not_say(self):
        self.assertEqual({"entry": ["javax.servlet.Servlet.service"], "ignore": ["java.lang.ClassLoader", "jdk.internal.loader"], "packages": ["com.acme"]},
                         store.read_settings(self.path))
        self.write("jots: []\n")
        self.assertEqual({"entry": None, "ignore": None, "packages": None}, store.read_settings(self.path))
        self.write("ignore: []\napp:\n  packages: []\n")
        self.assertEqual({"entry": None, "ignore": [], "packages": []}, store.read_settings(self.path), "empty is not the same as not saying")

    def test_what_can_be_in_the_ignore_list_and_in_packages(self):
        self.assertEqual([], store.ignore_problems(["java.lang.ClassLoader", "org.apache.jasper.JspCompilationContext.compile", "jdk.internal.loader"]))
        self.assertEqual([], store.ignore_problems([]), "an empty list ignores nothing")
        said = store.ignore_problems(["ok.Class", "has space", "", "ok.Class", 5, "static x.Y"])
        self.assertEqual([1, 2, 3, 4, 5], [p["index"] for p in said])
        self.assertIn("is listed twice", said[2]["message"])
        self.assertEqual([None], [p["index"] for p in store.ignore_problems("java.lang.ClassLoader")])
        self.assertEqual([], store.package_problems(["com.acme", "org.apache.jsp", "Acme"]))
        self.assertEqual([1, 2, 3], [p["index"] for p in store.package_problems(["com.acme", "com acme", "com..acme", "com.acme.*"])])

    def test_the_ignore_list_is_replaced_and_everything_else_in_the_file_is_as_it_was(self):
        store.write_ignore(self.path, ["java.lang.ClassLoader", "org.apache.catalina.loader", "org.hibernate.internal"])
        self.assertEqual(["java.lang.ClassLoader", "org.apache.catalina.loader", "org.hibernate.internal"], self.doc()["ignore"])
        for kept in ("# my jots", "# the application", "    - javax.servlet.Servlet.service", "    - com.acme", "# what the platform does is left out", "sensors: []"):
            self.assertIn(kept, self.text(), kept)
        self.assertNotIn("jdk.internal.loader", self.text())

    def test_the_ignore_list_can_be_emptied_taken_out_and_added_to_a_file_without_one(self):
        store.write_ignore(self.path, [])
        self.assertIn("ignore: []\n", self.text())
        self.assertEqual([], self.doc()["ignore"])
        store.write_ignore(self.path, None)
        self.assertNotIn("ignore", self.doc())
        self.assertIn("# what the platform does is left out", self.text(), "its comment stays")
        store.write_ignore(self.path, ["java.lang.ClassLoader"])
        self.assertEqual(["java.lang.ClassLoader"], self.doc()["ignore"])
        self.assertEqual({"entry": ["javax.servlet.Servlet.service"], "packages": ["com.acme"]}, self.doc()["app"])
        self.write("")
        store.write_ignore(self.path, ["a.B"])
        self.assertEqual({"ignore": ["a.B"]}, self.doc())

    def test_the_packages_are_replaced_under_app_and_added_when_app_has_none(self):
        store.write_packages(self.path, ["com.acme", "org.apache.jsp"])
        self.assertEqual({"entry": ["javax.servlet.Servlet.service"], "packages": ["com.acme", "org.apache.jsp"]}, self.doc()["app"])
        self.write("jots: []\napp:\n  entry:\n    - a.B.c\nignore: []\n")
        store.write_packages(self.path, ["com.acme"])
        self.assertEqual({"entry": ["a.B.c"], "packages": ["com.acme"]}, self.doc()["app"])
        self.assertEqual([], self.doc()["ignore"])
        self.write("jots: []\n")
        store.write_packages(self.path, ["com.acme"])
        self.assertEqual({"packages": ["com.acme"]}, self.doc()["app"])
        store.write_packages(self.path, None)
        self.assertEqual({"jots": []}, self.doc(), "none takes the key out, and app with it, since nothing else was in it")

    def test_a_file_changed_under_the_editor_or_a_bad_list_is_refused_and_nothing_is_written(self):
        before = self.text()
        with self.assertRaises(store.SaveError) as e:
            store.write_ignore(self.path, ["a.B"], original=["not what it says"])
        self.assertEqual(409, e.exception.status)
        for bad in (["has space"], ["a.B", "a.B"], "java.lang.ClassLoader", [""]):
            with self.assertRaises(store.SaveError):
                store.write_ignore(self.path, bad)
        for bad in (["com acme"], ["com.acme", "com.acme"], [5]):
            with self.assertRaises(store.SaveError):
                store.write_packages(self.path, bad)
        self.assertEqual(before, self.text())

    def test_the_settings_do_not_disturb_each_other(self):
        store.write_entry(self.path, ["com.acme.Main.main"])
        store.write_ignore(self.path, ["x.Y"])
        store.write_packages(self.path, ["org.example"])
        self.assertEqual({"entry": ["com.acme.Main.main"], "ignore": ["x.Y"], "packages": ["org.example"]}, store.read_settings(self.path))
        self.assertEqual([], store.jots_file_problems(self.path))


class CatalogTests(unittest.TestCase):
    """The catalog in the repository is what a new project is set up from, so every item of it has to be one the dashboard accepts as written."""
    PATH = os.path.join(server.HERE, "..", "catalog")

    def setUp(self):
        self.catalog = catalog.Catalog(self.PATH)

    def test_the_catalog_has_generic_sensors_rules_and_reports(self):
        kinds = {}
        for item in self.catalog.items():
            kinds[item["kind"]] = kinds.get(item["kind"], 0) + 1
        self.assertGreaterEqual(kinds["sensor"], 25)
        self.assertGreaterEqual(kinds["rule"], 4)
        self.assertGreaterEqual(kinds["report"], 10)
        names = [i["name"] for i in self.catalog.items()]
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual({"web", "sensitive", "crypto", "sql", "file", "network", "deserialization", "expression", "runtime", "ai"}, {i["area"] for i in self.catalog.items()})

    def test_every_sensor_and_rule_passes_the_checks_as_written(self):
        taken = set()
        for item in self.catalog.items():
            if item["kind"] == "report":
                continue
            self.assertEqual([], store.check_draft(store.stage_rule(item["text"].strip("\n")), taken), item["name"])
            taken.add(item["name"])

    def test_every_report_reads_only_what_the_catalog_sensors_capture(self):
        fields = {i["name"]: i["fields"] for i in self.catalog.items() if i["kind"] != "report"}
        taken = set()
        for item in self.catalog.items():
            if item["kind"] != "report":
                continue
            self.assertEqual([], store.check_report_draft(item["text"].strip("\n"), fields, taken), item["name"])
            taken.add(item["name"])
            self.assertTrue(item["needs"], "%s says which sensors it needs" % item["name"])

    def test_the_areas_say_what_they_are_and_what_their_reports_need(self):
        areas = {a["name"]: a for a in self.catalog.areas()}
        self.assertEqual("Web requests", areas["web"]["topic"])
        self.assertEqual("SQL", areas["sql"]["topic"])
        self.assertTrue(all(a["topic"] and not a["topic"].endswith(".") and len(a["topic"]) < 60 for a in areas.values()), "a topic is a short name")
        self.assertEqual(["web"], areas["crypto"]["needs_areas"])
        self.assertEqual([], areas["web"]["needs_areas"])
        self.assertEqual((7, 0, 1), (areas["sql"]["sensors"], areas["sql"]["rules"], areas["sql"]["reports"]))
        self.assertEqual({"sql-statement", "sql-prepared"}, {i["name"] for i in self.catalog.listing("sql")} & {"sql-statement", "sql-prepared"})
        self.assertEqual({"sql"}, {i["area"] for i in self.catalog.listing("sql")})

    def test_the_assistant_copies_catalog_items_into_a_new_configuration(self):
        env = Env()
        path = os.path.join(env.dir, ".jot", "jot.yaml")
        store.make_jot_dir(os.path.dirname(path))
        with open(path, "w") as f:
            f.write("# header\n")
        sent = []
        script = [
            [{"type": "tool_use", "id": "a", "name": "list_catalog", "input": {}}],
            [{"type": "tool_use", "id": "b", "name": "propose_from_catalog",
              "input": {"names": ["http-route", "crypto-cipher", "native-process", "Encryption Algorithms", "nonsense"], "reason": "It uses crypto."}}],
            [{"type": "tool_use", "id": "c", "name": "propose_from_catalog",
              "input": {"names": ["http-route", "crypto-cipher", "crypto-cipher-request", "native-process", "Encryption Algorithms"], "reason": "It uses crypto."}}],
            [{"type": "text", "text": "Proposed."}]]

        def model(body, timeout):
            sent.append(json.loads(json.dumps(body)))
            blocks = script.pop(0)
            return {"content": blocks, "stop_reason": "tool_use" if blocks[0]["type"] == "tool_use" else "end_turn"}

        app = server.App(env.db, env.ingestor, jot_paths=[path], jots_file=path, editable=True, assistant_post=model)
        chat = app.assistant.new_chat()
        app.assistant.send(chat, "set up")
        app.assistant.wait(chat, 10)
        listing = json.dumps(sent[1]["messages"])
        self.assertIn("crypto-cipher", listing)
        self.assertIn("needs_sensors", listing)
        self.assertIn("not in the catalog, nonsense", json.dumps(sent[2]["messages"]), "an unknown name is refused and the model is told")
        view = app.assistant.view(chat)
        card = view["proposals"][0]
        self.assertEqual(1, len(view["proposals"]))
        self.assertEqual("catalog", card["kind"])
        self.assertEqual(["native-process"], card["payload"]["rules"])
        self.assertIn("protect: false", "\n".join(card["payload"]["sensors"]), "a rule is copied as report only")
        self.assertEqual("Encryption Algorithms", card["payload"]["report_names"][0])
        self.assertEqual(["# header"], open(path).read().split("\n")[:1])
        self.assertNotIn("crypto-cipher", open(path).read(), "nothing is written before Apply")
        app.assistant.resolve(card["id"], "apply")
        doc = yaml.safe_load(open(path).read())
        self.assertEqual({"http-route", "crypto-cipher", "crypto-cipher-request", "native-process"}, {s["name"] for s in doc["sensors"]})
        self.assertEqual(["Encryption Algorithms"], [r["name"] for r in doc["reports"]])
        self.assertIs(False, next(s for s in doc["sensors"] if s["name"] == "native-process")["protect"])

    def fresh(self):
        env = Env()
        path = os.path.join(env.dir, ".jot", "jot.yaml")
        store.make_jot_dir(os.path.dirname(path))
        with open(path, "w") as f:
            f.write("# header\n")
        app = server.App(env.db, env.ingestor, jot_paths=[path], jots_file=path, editable=True)
        return app, path, app.assistant.new_chat()

    REPORT = "name: Cipher use by route\ntype: table\nrows: http-route.path\ncols: crypto-cipher.algorithm\n"

    def test_a_report_that_reads_catalog_sensors_not_yet_configured_brings_them_in_one_card(self):
        app, path, chat = self.fresh()
        out = app.assistant._propose_report(chat, self.REPORT, "by route")
        self.assertTrue(out["ok"], out)
        cards = app.assistant.view(chat)["proposals"]
        self.assertEqual(1, len(cards))
        self.assertEqual("catalog", cards[0]["kind"])
        self.assertEqual({"http-route", "crypto-cipher"}, set(cards[0]["payload"]["names"]))
        self.assertEqual(["Cipher use by route"], cards[0]["payload"]["report_names"])
        app.assistant.resolve(cards[0]["id"], "apply")
        doc = yaml.safe_load(open(path).read())
        self.assertEqual({"http-route", "crypto-cipher"}, {s["name"] for s in doc["sensors"]})
        self.assertEqual(["Cipher use by route"], [r["name"] for r in doc["reports"]])

    def test_sensors_written_by_the_model_and_a_report_that_reads_them_go_in_one_card(self):
        app, path, chat = self.fresh()
        sensor = "name: shop-checkout\ndescription: Identifies a checkout\nmethods:\n- a.B.checkout\ncaptures:\n  total: '#P0'\n"
        report = "name: Checkouts\ntype: list\ncols: shop-checkout.total\n"
        out = app.assistant._propose_from_catalog(chat, names=["http-route"], reason="r", sensors=[sensor], reports=[report])
        self.assertTrue(out["ok"], out)
        card = app.assistant.view(chat)["proposals"][0]
        self.assertEqual(["http-route", "shop-checkout"], card["payload"]["names"])
        self.assertEqual([report.strip("\n")], card["payload"]["custom"])
        self.assertEqual("Add 2 sensors, 1 reports", card["title"])
        app.assistant.resolve(card["id"], "apply")
        doc = yaml.safe_load(open(path).read())
        self.assertEqual(["Checkouts"], [r["name"] for r in doc["reports"]])
        self.assertEqual({"http-route", "shop-checkout"}, {s["name"] for s in doc["sensors"]})

    def test_a_report_that_reads_something_nothing_captures_is_still_refused(self):
        app, path, chat = self.fresh()
        out = app.assistant._propose_report(chat, "name: Odd\ntype: list\ncols: nothing-here.field\n", "x")
        self.assertFalse(out["ok"])
        self.assertEqual([], app.assistant.view(chat)["proposals"])

    def test_a_report_without_its_sensors_is_refused(self):
        env = Env()
        path = os.path.join(env.dir, "jot.yaml")
        with open(path, "w") as f:
            f.write("# header\n")
        app = server.App(env.db, env.ingestor, jot_paths=[path], jots_file=path, editable=True)
        chat = app.assistant.new_chat()
        out = app.assistant._propose_from_catalog(chat, ["Encryption Algorithms"], "x")
        self.assertFalse(out["ok"])
        self.assertIn("crypto-cipher", out["problems"][0])
        self.assertEqual([], app.assistant.view(chat)["proposals"])

    def test_nothing_in_it_belongs_to_one_application(self):
        for f in glob.glob(os.path.join(self.PATH, "*.jot")):
            text = open(f).read().lower()
            for word in ("ticketbook", "com.acme"):
                self.assertNotIn(word, text, f)

    def test_the_demo_defines_nothing_the_catalog_would_define_differently(self):
        demo = yaml.safe_load(open(os.path.join(server.HERE, "..", "demo", "ticketbook", ".jot", "jot.yaml")))
        mine = {s["name"]: s for s in demo["sensors"]}
        for item in self.catalog.items():
            if item["kind"] != "report" and item["name"] in mine:
                self.assertEqual(item["definition"].get("methods"), mine[item["name"]].get("methods"), item["name"])


class ProjectSwitchTests(unittest.TestCase):
    """The console opens another project's .jot folder without being restarted, and nothing is written into a folder until the person agrees."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.home = os.path.join(self.root, "home")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.a, self.b, self.empty = [os.path.join(self.root, n) for n in ("alpha", "beta", "empty")]
        for folder, sensor in ((self.a, "alpha-sensor"), (self.b, "beta-sensor")):
            os.makedirs(os.path.join(folder, ".jot"))
            with open(os.path.join(folder, ".jot", "jot.yaml"), "w") as f:
                f.write("sensors:\n- name: %s\n  description: Identifies a thing\n  methods:\n  - a.B.c\n  captures:\n    v: '#P0'\n" % sensor)
        os.makedirs(self.empty)
        self.handler = type("H", (server.Handler,), {})
        self.handler.app = server.build_project(self.a, say=lambda *_: None)
        self.addCleanup(lambda: self.handler.app.close())
        self.host = server.Host(self.handler, home=self.home)

    def names(self):
        return [s["name"] for s in self.handler.app.jots()["sensors"]]

    def test_opening_another_folder_swaps_everything_the_console_shows(self):
        self.assertEqual(["alpha-sensor"], self.names())
        old = self.handler.app
        out = self.host.open(self.b)
        self.assertTrue(out["opened"])
        self.assertEqual(["beta-sensor"], self.names())
        self.assertEqual((self.b, "beta"), (out["path"], out["name"]))
        self.assertEqual(os.path.join(self.b, ".jot", "dashboard.db"), self.handler.app.db_path)
        self.assertEqual(self.b, self.handler.app.scanner.root, "the assistant looks at the project that is open")
        self.assertIsNot(old, self.handler.app)
        self.assertTrue(old.ingestor._stop.is_set(), "the old project is no longer followed")
        self.assertEqual(self.a, self.host.open(self.a)["path"], "and back again")
        self.assertEqual(["alpha-sensor"], self.names())

    def test_the_jot_folder_itself_or_the_same_project_is_accepted(self):
        self.assertFalse(self.host.open(self.a)["opened"])
        self.assertTrue(self.host.open(os.path.join(self.b, ".jot"))["opened"])
        self.assertEqual(self.b, self.handler.app.project_dir)

    def test_a_folder_without_a_jot_yaml_asks_first_and_writes_nothing(self):
        out = self.host.open(self.empty)
        self.assertEqual({"needs_setup": True, "folder": self.empty}, out)
        self.assertEqual([], os.listdir(self.empty))
        self.assertEqual(["alpha-sensor"], self.names(), "the project that was open stays open")
        done = self.host.open(self.empty, create=True)
        self.assertTrue(done["opened"])
        self.assertTrue(os.path.isfile(os.path.join(self.empty, ".jot", "jot.yaml")))
        self.assertTrue(os.path.isfile(os.path.join(self.empty, ".jot", ".gitignore")))
        self.assertEqual([], self.names())

    def test_the_picker_lists_folders_marks_projects_and_hides_dot_folders(self):
        os.makedirs(os.path.join(self.root, ".hidden"))
        open(os.path.join(self.root, "a-file"), "w").close()
        out = self.host.folders(self.root)
        self.assertEqual(self.root, out["path"])
        self.assertEqual(os.path.dirname(self.root), out["parent"])
        self.assertEqual({"alpha": True, "beta": True, "empty": False}, {f["name"]: f["project"] for f in out["folders"]})
        self.assertNotIn(".hidden", [f["name"] for f in out["folders"]])
        self.assertNotIn("a-file", [f["name"] for f in out["folders"]])
        self.assertTrue(self.host.folders(self.a)["project"])
        self.assertEqual(self.a, self.host.folders(None)["path"], "it starts at the project that is open")
        self.assertIsNone(self.host.folders("/")["parent"])
        with self.assertRaises(store.QueryError):
            self.host.folders(os.path.join(self.root, "nowhere"))
        with self.assertRaises(store.SaveError):
            server.Host(self.handler, remote=True).folders(self.root)

    def test_bad_folders_and_a_remote_console_are_refused(self):
        with self.assertRaises(store.QueryError):
            self.host.open(os.path.join(self.root, "nowhere"))
        with self.assertRaises(store.QueryError):
            self.host.open("  ")
        remote = server.Host(self.handler, remote=True, home=self.home)
        with self.assertRaises(store.SaveError):
            remote.open(self.b)
        self.assertFalse(remote.info()["can_switch"])

    def test_recent_projects_are_kept_newest_first_without_the_ones_that_are_gone(self):
        self.host.open(self.b)
        self.host.open(self.a)
        self.assertEqual([self.a, self.b], self.host.recent())
        shutil.rmtree(self.b)
        self.assertEqual([self.a], self.host.recent())

    def test_the_api_opens_a_project(self):
        httpd = server.make_server(self.handler.app, "127.0.0.1", 0)
        httpd.RequestHandlerClass.host.home = self.home
        httpd.RequestHandlerClass.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        port = httpd.server_address[1]
        info = json.load(urllib.request.urlopen("http://127.0.0.1:%d/api/project" % port))
        self.assertEqual(self.a, info["path"])
        req = urllib.request.Request("http://127.0.0.1:%d/api/project/open" % port, json.dumps({"path": self.b}).encode(),
                                     {"Content-Type": "application/json", "X-JOT-Dashboard": "1"})
        out = json.load(urllib.request.urlopen(req))
        self.assertEqual((True, self.b), (out["opened"], out["path"]))
        self.assertEqual(self.b, httpd.RequestHandlerClass.app.project_dir)
        httpd.RequestHandlerClass.app.close()
        self.handler.app = httpd.RequestHandlerClass.app


class JotDirTests(unittest.TestCase):
    """Everything JOT keeps for a project is in its .jot folder, and only jot.yaml of it is meant to be committed."""

    def setUp(self):
        self.dir = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir, True)

    def touch(self, *parts):
        path = os.path.join(self.dir, *parts)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        open(path, "w").close()
        return path

    def test_the_jot_dir_file_wins_over_the_one_in_the_folder(self):
        self.assertIsNone(store.find_config(self.dir))
        plain = self.touch("jot.yaml")
        self.assertEqual(plain, store.find_config(self.dir))
        hidden = self.touch(".jot", "jot.yaml")
        self.assertEqual(hidden, store.find_config(self.dir))

    def test_the_runtime_folder_is_beside_the_file_or_the_file_s_own_folder(self):
        hidden = os.path.join(self.dir, ".jot", "jot.yaml")
        self.assertEqual(os.path.join(self.dir, ".jot"), store.jot_dir(hidden))
        self.assertEqual(os.path.join(self.dir, ".jot"), store.jot_dir(os.path.join(self.dir, "jot.yaml")))
        self.assertEqual(os.path.join(self.dir, ".jot"), store.jot_dir(None, self.dir))

    def test_a_new_file_with_only_a_comment_takes_settings_and_sensors(self):
        env = Env()
        path = os.path.join(env.dir, ".jot", "jot.yaml")
        store.make_jot_dir(os.path.dirname(path))
        with open(path, "w") as f:
            f.write("# header\n")
        app = server.App(env.db, env.ingestor, jot_paths=[path], jots_file=path, editable=True)
        app.save_setting("entry", ["a.B.c"], None)
        app.add_jot("jot.yaml", "name: x-test\ndescription: Identifies a thing\nmethods:\n- a.B.c\ncaptures:\n  v: '#P0'\n")
        doc = yaml.safe_load(open(path).read())
        self.assertEqual(["a.B.c"], doc["app"]["entry"])
        self.assertEqual(["x-test"], [s["name"] for s in doc["sensors"]])

    def test_making_it_leaves_only_the_configuration_to_commit(self):
        folder = store.make_jot_dir(os.path.join(self.dir, ".jot"))
        text = open(os.path.join(folder, ".gitignore")).read()
        self.assertIn("*\n", text)
        self.assertIn("!jot.yaml", text)
        with open(os.path.join(folder, ".gitignore"), "w") as f:
            f.write("mine\n")
        store.make_jot_dir(folder)
        self.assertEqual("mine\n", open(os.path.join(folder, ".gitignore")).read(), "a .gitignore that is there is kept")


class LibraryTests(unittest.TestCase):
    """The assistant looks at the libraries, which can do things the application's own code never mentions."""

    def jar(self, path, entries):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with zipfile.ZipFile(path, "w") as z:
            for name, data in entries.items():
                z.writestr(name, data)

    def props(self, group, artifact, version):
        return "groupId=%s\nartifactId=%s\nversion=%s\n" % (group, artifact, version)

    def setUp(self):
        self.env = Env()
        self.root = os.path.realpath(os.path.join(self.env.dir, "proj"))
        self.home = os.path.realpath(os.path.join(self.env.dir, "home"))
        os.makedirs(self.root)
        old = os.environ.get("HOME")
        os.environ["HOME"] = self.home          # the local Maven repository is looked for there
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old) if old is not None else os.environ.pop("HOME", None))
        repo = os.path.join(self.home, ".m2", "repository")
        # a declared library that needs another, in the local repository
        self.jar(os.path.join(repo, "org", "yaml", "snakeyaml", "1.33", "snakeyaml-1.33.jar"), {"org/yaml/snakeyaml/Yaml.class": b"x", "org/yaml/snakeyaml/Loader$1.class": b"x"})
        with open(os.path.join(repo, "org", "yaml", "snakeyaml", "1.33", "snakeyaml-1.33.pom"), "w") as f:
            f.write("<project><dependencies><dependency><groupId>org.apache.commons</groupId><artifactId>commons-text</artifactId><version>1.9</version></dependency>"
                    "<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4</version><scope>test</scope></dependency></dependencies></project>")
        self.jar(os.path.join(repo, "org", "apache", "commons", "commons-text", "1.9", "commons-text-1.9.jar"), {"org/apache/commons/text/StringSubstitutor.class": b"x"})
        with open(os.path.join(self.root, "pom.xml"), "w") as f:
            f.write("<project><properties><yaml.version>1.33</yaml.version></properties><dependencies>"
                    "<dependency><groupId>org.yaml</groupId><artifactId>snakeyaml</artifactId><version>${yaml.version}</version></dependency>"
                    "<dependency><groupId>junit</groupId><artifactId>junit</artifactId><version>4.13</version><scope>test</scope></dependency>"
                    "</dependencies></project>")
        # a jar the project ships, with and without Maven's own record of what it is, and one built into a Spring Boot jar
        self.jar(os.path.join(self.root, "lib", "xalan-2.7.jar"), {"META-INF/maven/xalan/xalan/pom.properties": self.props("xalan", "xalan", "2.7"),
                                                                   "org/apache/xalan/Transformer.class": b"x"})
        self.jar(os.path.join(self.root, "lib", "mystery-1.0.jar"), {"com/mystery/Thing.class": b"x"})
        inner = io.BytesIO()
        with zipfile.ZipFile(inner, "w") as z:
            z.writestr("org/h2/Driver.class", b"x")
        self.jar(os.path.join(self.root, "target", "app.jar"), {"BOOT-INF/lib/h2-2.2.jar": inner.getvalue(), "BOOT-INF/classes/com/acme/Main.class": b"x"})
        self.libs = libraries.Libraries(self.root)

    def test_it_finds_what_is_declared_what_those_need_and_what_is_shipped(self):
        out = self.libs.listing()
        self.assertEqual(["org.yaml:snakeyaml:1.33"], out["declared"], "the property is filled in and a test library is left out")
        self.assertEqual(["org.apache.commons:commons-text:1.9"], out["needed_by_those"], "from the pom of the library in the local repository, without its test library")
        self.assertIn("xalan:xalan:2.7", out["shipped"], "the group comes from the pom.properties in the jar")
        self.assertIn("?:mystery:1.0", out["shipped"], "a jar that doesn't say its group is still a library")
        self.assertIn("?:h2:2.2", out["shipped"], "and so is one built into a Spring Boot jar")
        self.assertTrue(any("Spring Boot" in n for n in out["notes"]), "which brings its own server")

    def test_it_says_what_each_kind_of_library_can_do_and_where_to_start(self):
        out = self.libs.listing()
        hints = {h["library"]: h for h in out["libraries_worth_a_look"]}
        self.assertIn("org.yaml.snakeyaml.Yaml.load", hints["org.yaml:snakeyaml"]["methods"])
        self.assertIn("org.apache.commons.text.StringSubstitutor.replace", hints["org.apache.commons:commons-text"]["methods"])
        self.assertIn("xalan:xalan", hints)
        self.assertIn("java.io.ObjectInputStream.readObject", [m for p in out["the_platform_itself"] for m in p["methods"]], "the platform too")
        self.assertNotIn("?:mystery", hints, "a library that can't do anything of interest isn't listed")

    def test_the_model_is_never_given_where_a_jar_is(self):
        text = json.dumps([self.libs.listing(), self.libs.search("."), self.libs.search("Yaml")])
        self.assertNotIn(self.env.dir, text)
        self.assertNotIn(".m2", text)
        self.assertNotIn(".jar", text.replace("Spring Boot jar", "").replace("app.jar", ""), "only names, as group:artifact:version")

    def test_classes_are_found_by_name_in_every_kind_of_jar_and_can_be_narrowed_to_one_library(self):
        found = {(m["library"], m["class"]) for m in self.libs.search("Yaml|Driver|Thing|Transformer|StringSubstitutor")["matches"]}
        self.assertEqual({("org.yaml:snakeyaml", "org.yaml.snakeyaml.Yaml"), ("?:h2", "org.h2.Driver"), ("?:mystery", "com.mystery.Thing"),
                          ("xalan:xalan", "org.apache.xalan.Transformer"), ("org.apache.commons:commons-text", "org.apache.commons.text.StringSubstitutor")}, found)
        self.assertEqual(["org.h2.Driver"], [m["class"] for m in self.libs.search("Driver", "h2")["matches"]])
        self.assertEqual([], self.libs.search("Loader")["matches"], "an anonymous inner class isn't a thing to watch")
        self.assertEqual([], self.libs.search("Yaml", "no-such-library")["matches"])
        with self.assertRaises(ValueError):
            self.libs.search("(")

    @unittest.skipUnless(shutil.which("javap"), "javap isn't installed")
    def test_it_lists_the_public_methods_of_a_class_in_the_jdk_and_refuses_what_isnt_a_class_name(self):
        text = self.libs.describe("java.lang.ProcessBuilder")["declaration"]
        self.assertIn("start()", text)
        for bad in ("java.lang.ProcessBuilder; echo x", "../etc/passwd", "-help", "", "a b"):
            with self.assertRaises(ValueError, msg=bad):
                self.libs.describe(bad)
        with self.assertRaises(ValueError):
            self.libs.describe("com.nowhere.Missing")

    def test_a_dependency_is_found_through_gradle_and_a_project_with_nothing_says_so(self):
        os.makedirs(os.path.join(self.env.dir, "g"))
        with open(os.path.join(self.env.dir, "g", "build.gradle"), "w") as f:
            f.write("dependencies {\n  implementation 'com.google.code.gson:gson:2.10'\n  testImplementation \"junit:junit:4\"\n  api(\"org.jsoup:jsoup:1.15.3\")\n}\n")
        out = libraries.Libraries(os.path.join(self.env.dir, "g")).listing()
        self.assertEqual(["com.google.code.gson:gson:2.10", "org.jsoup:jsoup:1.15.3"], out["declared"])
        os.makedirs(os.path.join(self.env.dir, "empty"))
        self.assertTrue(libraries.Libraries(os.path.join(self.env.dir, "empty")).listing()["notes"])

    def test_the_assistant_has_the_tools_only_with_a_local_folder_and_is_told_to_look_past_its_own_code(self):
        app = server.App(self.env.db, self.env.ingestor)
        scan = scanner.Scanner(app)
        scan.set_root(self.root)
        names = {t["name"] for t in scan.tools()}
        self.assertTrue({"list_libraries", "search_libraries", "describe_class"} <= names)
        self.assertEqual(3, len({"list_libraries", "search_libraries", "describe_class"} & set(scan.functions())))
        self.assertEqual([], scanner.Scanner(app, local=False).tools())
        out = scan.search_libraries("Yaml")
        self.assertIn("Searched the libraries for Yaml, 1 classes", scan.describe("search_libraries", {"pattern": "Yaml"}, out))
        prompt = assistant.system_prompt()
        for words in ("list_libraries", "search_libraries", "describe_class", "Look past the application's own code", "that no events means it"):
            self.assertIn(words, prompt)


class ScannerTests(unittest.TestCase):
    """The assistant reads a project folder, which sends files to the model, so what it may not read matters more than what it can."""

    def setUp(self):
        self.env = Env()
        self.root = os.path.realpath(os.path.join(self.env.dir, "proj"))
        self.outside = os.path.realpath(os.path.join(self.env.dir, "outside"))
        for d in ("proj/src/com/acme", "proj/target", "proj/node_modules/x", "proj/.aws", "outside"):
            os.makedirs(os.path.join(self.env.dir, d))
        files = {
            "proj/pom.xml": "<project/>",
            "proj/src/com/acme/Hello.java": "package com.acme.web;\npublic class Hello extends HttpServlet {\n}\n",
            "proj/src/com/acme/Api.java": "package com.acme.api;\n@RestController\nclass Api {\n @GetMapping(\"/x\") void x() {}\n public static void main(String[] a) {}\n}\n",
            "proj/target/Built.java": "package built;\n@RestController class B {}\n",
            "proj/node_modules/x/a.js": "RestController",
            "proj/.env": "TOKEN=abc",
            "proj/.aws/credentials": "key",
            "proj/server.pem": "-----BEGIN",
            "proj/src/app.jks": "binary",
            "proj/src/blob.bin": "a\0b",
            "outside/secret.txt": "outside the folder",
        }
        for name, text in files.items():
            with open(os.path.join(self.env.dir, name), "w") as f:
                f.write(text)
        os.symlink(self.outside, os.path.join(self.root, "link"))
        self.app = server.App(self.env.db, self.env.ingestor, jots_file=None)
        self.s = self.app.scanner
        self.s.set_root(self.root)

    def test_no_tools_without_a_folder_and_none_when_remote(self):
        self.s.set_root("")
        self.assertEqual(self.s.tools(), [])
        self.s.set_root(self.root)
        self.assertEqual(len(self.s.tools()), 8)
        remote = scanner.Scanner(self.app, local=False)
        self.assertEqual((remote.tools(), remote.functions()), ([], {}))
        with self.assertRaises(scanner.ScanError):
            remote.set_root(self.root)

    def test_the_folder_is_remembered_and_must_exist(self):
        self.assertEqual(scanner.Scanner(self.app).root, self.root)
        with self.assertRaises(scanner.ScanError):
            self.s.set_root(os.path.join(self.root, "nope"))
        with self.assertRaises(scanner.ScanError):
            self.s.set_root("/")

    def test_paths_cannot_leave_the_folder(self):
        for path in ("../outside/secret.txt", "link/secret.txt", "/etc/passwd", "src/../../outside/secret.txt"):
            with self.assertRaises(scanner.ScanError, msg=path):
                self.s.read_file(path)

    def test_credential_files_are_never_read_or_listed(self):
        for path in (".env", ".aws/credentials", "server.pem", "src/app.jks"):
            with self.assertRaises(scanner.ScanError, msg=path):
                self.s.read_file(path)
        listing = self.s.list_files(".")
        names = [e["name"] for e in listing["entries"]]
        self.assertNotIn(".env", names)
        self.assertNotIn("server.pem", names)
        self.assertNotIn("link/", [n for n in names if n != "link/"])
        self.assertGreaterEqual(listing["left_out_as_credentials"], 3)

    def test_search_skips_credentials_built_folders_binaries_and_links_out(self):
        found = self.s.search_files("TOKEN|BEGIN|outside the folder|RestController")
        self.assertEqual({m["file"] for m in found["matches"]}, {"src/com/acme/Api.java"})

    def test_read_gives_numbered_lines_and_says_when_there_is_more(self):
        out = self.s.read_file("src/com/acme/Api.java", start=2, lines=2)
        self.assertEqual((out["start"], out["end"], out["more"]), (2, 3, True))
        self.assertTrue(out["text"].startswith("2\t@RestController"))
        with self.assertRaises(scanner.ScanError):
            self.s.read_file("src/blob.bin")
        with self.assertRaises(scanner.ScanError):
            self.s.read_file("src")

    def test_a_large_file_is_not_read(self):
        with open(os.path.join(self.root, "big.txt"), "w") as f:
            f.write("x" * (scanner.MAX_FILE_BYTES + 1))
        with self.assertRaises(scanner.ScanError):
            self.s.read_file("big.txt")

    def test_a_turn_has_a_budget_and_a_new_turn_renews_it(self):
        self.s.spent = scanner.TURN_BUDGET
        with self.assertRaises(scanner.ScanError):
            self.s.read_file("pom.xml")
        self.s.begin()
        self.assertIn("project", self.s.read_file("pom.xml")["text"])

    def test_overview_and_entry_candidates(self):
        over = self.s.project_overview()
        self.assertEqual(over["build_files"][0]["file"], "pom.xml")
        self.assertEqual({p["package"] for p in over["java_packages"]}, {"com.acme.web", "com.acme.api"})
        found = self.s.find_entry_candidates()
        kinds = {s["kind"] for s in found["signals"]}
        self.assertTrue({"a servlet class", "a Spring controller", "a main method"} <= kinds)
        self.assertNotIn("built", str(found))

    def test_a_path_said_in_the_chat_sets_the_folder_and_a_url_is_declined(self):
        self.s.set_root("")
        a = self.app.assistant
        chat = a.new_chat()
        self.assertEqual((a.view(chat)["folder"], a.view(chat)["empty"]), (None, True))
        said = a.send(chat, self.root)
        self.assertEqual(self.s.root, self.root)
        self.assertIn("I can look at", said["items"][-1]["text"])
        self.assertEqual(said["folder"], self.root)
        self.assertFalse(said["running"])
        said = a.send(chat, "https://github.com/acme/shop.git")
        self.assertIn("Clone it", said["items"][-1]["text"])
        said = a.send(chat, "/")
        self.assertIn("can't use that folder", said["items"][-1]["text"])
        self.assertEqual(self.s.root, self.root)

    def test_the_assistant_offers_the_tools_and_shows_what_it_read(self):
        sent = []

        def model(body, timeout):
            sent.append(body)
            if len(sent) == 1:
                return {"content": [{"type": "tool_use", "id": "t1", "name": "read_file", "input": {"path": ".env"}},
                                    {"type": "tool_use", "id": "t2", "name": "read_file", "input": {"path": "pom.xml"}}], "stop_reason": "tool_use"}
            return {"content": [{"type": "text", "text": "Done"}], "stop_reason": "end_turn"}

        env = Env()
        app = server.App(env.db, env.ingestor, assistant_post=model)
        app.scanner.set_root(self.root)
        chat = app.assistant.new_chat()
        app.assistant.send(chat, "scan it")
        app.assistant.wait(chat, 10)
        names = {t["name"] for t in sent[0]["tools"]}
        self.assertTrue({"read_file", "find_entry_candidates", "propose_sensor"} <= names)
        steps = [i["text"] for i in app.assistant.view(chat)["items"] if i["kind"] == "step"]
        self.assertTrue(any("Read pom.xml" in s for s in steps), steps)
        self.assertTrue(any("credentials" in s for s in steps), steps)
        results = json.dumps(sent[1]["messages"])
        self.assertNotIn("TOKEN=abc", results)


class AssistantTests(unittest.TestCase):
    """The assistant is a conversation with a model that can look and can only propose, with a person who applies the proposals. The model
    here is a script of answers, so what is tested is everything around it."""
    JOTS = ("app:\n  entry:\n    - javax.servlet.Servlet.service\n  packages:\n    - com.acme\nignore:\n  - java.lang.ClassLoader\njots:\n  - lib.jot\n"
            "sensors:\n- name: crypto-cipher\n  description: Identifies a cipher being used\n  methods:\n  - javax.crypto.Cipher.init\n  captures:\n    algorithm: '#OBJ.getAlgorithm()'\n"
            "- name: http-route\n  description: Identifies the route a request came in at\n  methods:\n  - javax.servlet.Servlet.service\n  captures:\n    path: '#P0.getRequestURI()'\n")
    LIB = "sensors:\n- name: lib-sensor\n  description: Identifies a library call\n  methods:\n  - a.B.c\n  captures:\n    v: '#P0'\nreports:\n- name: Lib report\n  type: list\n  cols: lib-sensor.v\n"
    SECRET = "SECRET-VALUE-4111111111111111"

    def setUp(self):
        self.env = Env()
        self.jots = os.path.join(self.env.dir, "jot.yaml")
        with open(self.jots, "w") as f:
            f.write(self.JOTS)
        with open(os.path.join(self.env.dir, "lib.jot"), "w") as f:
            f.write(self.LIB)
        self.paths = store.config_paths(self.jots)
        store.load_sensors(self.env.ingestor.db, self.paths)
        store.load_reports(self.env.ingestor.db, self.paths)
        self.env.write(event(1, sensor="crypto-cipher", capture=self.SECRET, data={"algorithm": self.SECRET},
                             stack=["java.base/javax.crypto.Cipher.init(Cipher.java:534)", "com.acme.ticketbook.Ticket.save(Ticket.java:40)"]))
        self.env.ingestor.poll()
        self.script, self.sent, self.ids = [], [], iter(range(1, 10 ** 6))
        self.app = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, jots_file=self.jots, editable=True, assistant_post=self.model)
        self.a = self.app.assistant
        self.chat = self.a.new_chat()

    def model(self, body, timeout):
        self.sent.append(json.loads(json.dumps(body)))
        if isinstance(self.script[0], Exception):
            raise self.script.pop(0)
        return self.script.pop(0)

    def reply(self, *blocks, stop="end_turn"):
        return {"content": list(blocks), "stop_reason": stop}

    def text(self, said):
        return {"type": "text", "text": said}

    def use(self, tool, **args):
        return {"type": "tool_use", "id": "tu_%d" % next(self.ids), "name": tool, "input": args}

    def say(self, said, *script):
        self.script = list(script)
        self.a.send(self.chat, said)
        self.a.wait(self.chat)
        return self.a.view(self.chat)

    def kinds(self, view=None):
        return [i["kind"] for i in (view or self.a.view(self.chat))["items"]]

    def proposals(self):
        return self.a.view(self.chat)["proposals"]

    def written(self):
        with open(self.jots) as f:
            return yaml.safe_load(f.read())

    # ------------------------------------------------------------------ the conversation about what to look at

    def test_the_catalog_is_offered_by_area_with_what_is_already_configured(self):
        view = self.say("what can I look at", self.reply(self.use("list_catalog_areas"), stop="tool_use"), self.reply(self.text("These.")))
        result = json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])
        areas = {a["name"]: a for a in result["areas"]}
        self.assertEqual({"web", "sensitive", "crypto", "sql", "file", "network", "deserialization", "expression", "runtime", "ai"}, set(areas))
        self.assertEqual("Web requests", areas["web"]["topic"])
        self.assertEqual(1, areas["web"]["already_in_configuration"], "http-route is already there")
        self.assertIn("web", areas["sql"]["needs_areas"], "its report reads the route")
        self.assertEqual(["user", "step", "assistant"], self.kinds(view))
        self.assertEqual("Looked at what the catalog covers", view["items"][1]["text"])
        self.assertIn("Web requests", [t["topic"] for t in view["topics"]], "the opening screen offers the areas")

    def test_one_area_of_the_catalog_can_be_looked_at_alone(self):
        self.say("sql", self.reply(self.use("list_catalog", area="sql"), self.use("list_catalog", area="nope"), stop="tool_use"), self.reply(self.text("ok")))
        first, second = [json.loads(r["content"]) for r in self.sent[1]["messages"][-1]["content"]]
        self.assertEqual({"sql"}, {i["area"] for i in first["items"]})
        self.assertIn("sql-statement", [i["name"] for i in first["items"]])
        self.assertIn("there is no area called nope", second["error"])

    def test_a_question_with_choices_ends_the_turn_and_the_answer_goes_on_from_it(self):
        ask = self.use("ask_person", question="What matters most?", options=["Injection", "Sensitive data", "Not sure"])
        view = self.say("I want to look for security vulnerabilities",
                        self.reply(self.text("Security is wide, so let me narrow it."), ask, stop="tool_use"))
        self.assertEqual(["user", "assistant", "question"], self.kinds(view), "the turn ended at the question and the model was not called again")
        self.assertEqual(1, len(self.sent))
        question = json.loads(view["items"][2]["text"])
        self.assertEqual(("What matters most?", ["Injection", "Sensitive data", "Not sure"], False), (question["question"], question["options"], question["several"]))
        self.assertFalse(view["running"])
        view = self.say("Injection", self.reply(self.text("Then these areas.")))
        roles = [m["role"] for m in self.sent[1]["messages"]]
        self.assertEqual(["user", "assistant", "user", "user"], roles, "the question was answered with a result, then the person's words")
        answered = self.sent[1]["messages"][2]["content"][0]
        self.assertEqual(("tool_result", ask["id"]), (answered["type"], answered["tool_use_id"]))
        self.assertIn("Injection", self.sent[1]["messages"][3]["content"][0]["text"])
        self.assertEqual(["user", "assistant", "question", "user", "assistant"], self.kinds(view))

    def test_a_question_has_to_have_choices_and_only_one_is_asked_in_a_turn(self):
        bad = self.use("ask_person", question="Which?", options=["only one"])
        good = self.use("ask_person", question="Which?", options=["a", "b"])
        again = self.use("ask_person", question="And?", options=["c", "d"])
        view = self.say("hi", self.reply(bad, stop="tool_use"), self.reply(good, again, stop="tool_use"))
        results = [json.loads(r["content"]) for r in self.a._messages(self.chat)[-1]["content"]]
        self.assertIn("two to six", json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])["error"])
        self.assertTrue(results[0]["asked"])
        self.assertIn("wait for the answer", results[1]["error"])
        self.assertEqual(1, self.kinds(view).count("question"))

    def test_the_instructions_start_with_what_the_person_wants_and_use_the_catalog_by_area(self):
        prompt = assistant.system_prompt()
        for phrase in ("ask_person", "list_catalog_areas", "general understanding", "security vulnerabilities", "needs_areas", "a few sentences"):
            self.assertIn(phrase, prompt)

    # ------------------------------------------------------------------ a plain conversation

    def test_a_question_is_answered_and_both_are_kept_in_the_conversation(self):
        view = self.say("What is an entry point?", self.reply(self.text("It is where the application starts running.")))
        self.assertEqual(["user", "assistant"], self.kinds(view))
        self.assertEqual(["What is an entry point?", "It is where the application starts running."], [i["text"] for i in view["items"]])
        self.assertFalse(view["running"])
        self.assertEqual("What is an entry point?", view["title"])

    def test_the_model_is_sent_the_instructions_the_tools_and_the_words_with_where_the_configuration_is(self):
        self.say("hello", self.reply(self.text("hi")))
        body = self.sent[0]
        self.assertEqual(llm.model(), body["model"])
        self.assertEqual({"type": "ephemeral"}, body["system"][0]["cache_control"], "the long instructions are the same every time, so they are cached")
        self.assertIn("propose_sensor", body["system"][0]["text"])
        self.assertIn("How to write a JOT", body["system"][0]["text"])
        self.assertIn("Reaching data the watched method doesn't hand you", body["system"][0]["text"], "it is taught to walk from #OBJ, #P0 and #RET")
        self.assertIn("never propose a sensor that can't fire", body["system"][0]["text"])
        self.assertNotIn("Always answer by calling the draft tool", body["system"][0]["text"], "this is not drafting")
        self.assertEqual({"get_configuration", "get_sensor", "get_observed", "propose_setting", "propose_sensor", "propose_report", "propose_delete", "propose_restart", "propose_consolidation", "list_catalog_areas", "list_catalog", "ask_person", "get_catalog_item", "propose_from_catalog"},
                         {t["name"] for t in body["tools"]})
        first = body["messages"][0]
        self.assertEqual("user", first["role"])
        said = first["content"][0]["text"]
        self.assertIn("Jots file: jot.yaml, changes can be applied", said)
        self.assertTrue(said.endswith("hello"))

    def test_what_the_person_typed_is_what_is_shown_and_not_what_the_dashboard_added(self):
        view = self.say("hello", self.reply(self.text("hi")))
        self.assertEqual("hello", view["items"][0]["text"])

    def test_the_whole_conversation_is_sent_each_time_and_continues_where_it_was(self):
        self.say("one", self.reply(self.text("first answer")))
        self.say("two", self.reply(self.text("second answer")))
        sent = self.sent[1]["messages"]
        self.assertEqual(["user", "assistant", "user"], [m["role"] for m in sent])
        self.assertEqual("first answer", sent[1]["content"][0]["text"])
        self.assertTrue(sent[2]["content"][0]["text"].endswith("two"))

    def test_the_conversations_are_listed_and_a_new_one_starts_empty(self):
        self.say("about entry points", self.reply(self.text("ok")))
        other = self.a.new_chat()
        self.assertEqual(["New conversation", "about entry points"], [c["title"] for c in self.a.chats()][:2])
        self.assertEqual([], self.a.view(other)["items"])
        self.assertNotEqual(other, self.chat)

    def test_only_what_is_new_is_sent_to_a_page_that_has_the_rest(self):
        self.say("hello", self.reply(self.text("hi")))
        self.assertEqual([], self.a.view(self.chat, 2)["items"])
        self.assertEqual(["assistant"], [i["kind"] for i in self.a.view(self.chat, 1)["items"]])

    def test_a_conversation_is_still_there_and_can_go_on_after_a_restart(self):
        self.say("one", self.reply(self.text("first answer")))
        again = server.App(self.env.db, self.env.ingestor, jot_paths=self.paths, jots_file=self.jots, editable=True, assistant_post=self.model).assistant
        self.assertEqual(["user", "assistant"], [i["kind"] for i in again.view(self.chat)["items"]])
        self.script = [self.reply(self.text("second answer"))]
        again.send(self.chat, "two")
        again.wait(self.chat)
        self.assertEqual(["user", "assistant", "user"], [m["role"] for m in self.sent[-1]["messages"]])

    def test_nothing_or_far_too_much_is_refused_and_so_is_a_conversation_that_is_not_there(self):
        for bad in ("", "   ", "x" * 8001):
            with self.assertRaises(store.QueryError):
                self.a.send(self.chat, bad)
        with self.assertRaises(LookupError):
            self.a.send(9999, "hello")
        with self.assertRaises(LookupError):
            self.a.view(9999)
        self.assertEqual([], self.sent)

    # ------------------------------------------------------------------ looking

    def test_the_model_can_look_at_the_configuration_and_is_told_what_it_found(self):
        view = self.say("what is set up?", self.reply(self.use("get_configuration"), stop="tool_use"), self.reply(self.text("A cipher sensor and a route.")))
        self.assertEqual(["user", "step", "assistant"], self.kinds(view))
        self.assertEqual("Looked at the configuration", view["items"][1]["text"])
        result = json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])
        self.assertEqual(["crypto-cipher", "http-route", "lib-sensor"], [s["name"] for s in result["sensors"]])
        self.assertEqual((["javax.servlet.Servlet.service"], ["java.lang.ClassLoader"], ["com.acme"]), (result["entry"], result["ignore"], result["packages"]))
        self.assertEqual(("jot.yaml", True), (result["jots_file"], result["can_be_changed"]))
        self.assertEqual(["Lib report"], [r["name"] for r in result["reports"]])
        self.assertEqual(["algorithm"], result["sensors"][0]["fields"])

    def test_the_answer_to_a_tool_goes_back_with_the_id_of_the_call_and_what_the_model_said_is_kept_exactly(self):
        thinking = {"type": "thinking", "thinking": "", "signature": "sig-abc"}
        call = self.use("get_configuration")
        self.say("look", self.reply(thinking, self.text("Let me look."), call, stop="tool_use"), self.reply(self.text("Done.")))
        again = self.sent[1]["messages"]
        self.assertEqual(["user", "assistant", "user"], [m["role"] for m in again])
        self.assertEqual([thinking, {"type": "text", "text": "Let me look."}, call], again[1]["content"], "thinking blocks go back unchanged, or the model rejects the conversation")
        self.assertEqual(call["id"], again[2]["content"][0]["tool_use_id"])
        self.assertEqual("tool_result", again[2]["content"][0]["type"])

    def test_several_tool_calls_at_once_are_answered_together_in_one_message(self):
        one, two = self.use("get_configuration"), self.use("get_observed")
        self.say("look", self.reply(one, two, stop="tool_use"), self.reply(self.text("Done.")))
        results = self.sent[1]["messages"][-1]["content"]
        self.assertEqual([one["id"], two["id"]], [r["tool_use_id"] for r in results])

    def test_what_has_been_seen_is_names_and_never_what_was_captured(self):
        self.say("what runs?", self.reply(self.use("get_observed"), stop="tool_use"), self.reply(self.text("ok")))
        said = self.sent[1]["messages"][-1]["content"][0]["content"]
        self.assertNotIn(self.SECRET, said)
        self.assertNotIn("4111", said)
        seen = json.loads(said)
        self.assertEqual("javax.crypto.Cipher.getInstance", seen["methods"][0]["method"], "the method the event says it was seen at")
        self.assertEqual("com.acme.ticketbook", seen["application_packages"][0]["package"])
        self.assertEqual(("crypto-cipher", 1), (seen["sensors"][0]["sensor"], seen["sensors"][0]["events"]))
        for sent in self.sent:
            self.assertNotIn(self.SECRET, json.dumps(sent), "nothing the application captured goes to the model")

    def test_one_sensors_definition_can_be_read_and_one_that_is_not_there_is_an_error_the_model_sees(self):
        self.say("show it", self.reply(self.use("get_sensor", name="crypto-cipher"), self.use("get_sensor", name="nope"), stop="tool_use"), self.reply(self.text("ok")))
        results = self.sent[1]["messages"][-1]["content"]
        self.assertIn("Identifies a cipher being used", json.loads(results[0]["content"])["yaml"])
        self.assertTrue(results[1].get("is_error"))
        self.assertIn("no sensor or rule called nope", json.loads(results[1]["content"])["error"])
        self.assertNotIn("error", self.kinds(), "the model can recover, so the person isn't told")

    def test_a_tool_that_is_not_there_or_given_the_wrong_arguments_is_an_error_the_model_sees(self):
        self.say("go", self.reply(self.use("delete_everything"), self.use("get_sensor"), stop="tool_use"), self.reply(self.text("ok")))
        results = self.sent[1]["messages"][-1]["content"]
        self.assertTrue(all(r.get("is_error") for r in results))
        self.assertIn("no tool called delete_everything", json.loads(results[0]["content"])["error"])

    # ------------------------------------------------------------------ proposing

    def test_a_setting_is_proposed_as_a_card_and_nothing_is_changed(self):
        before = open(self.jots).read()
        view = self.say("set the entry points", self.reply(self.use("propose_setting", setting="entry", values=["javax.servlet.Servlet.service", "@com.acme.Handler"],
                                                                      reason="Handlers are entry points too."), stop="tool_use"), self.reply(self.text("I have proposed it.")))
        self.assertEqual(["user", "proposal", "assistant"], self.kinds(view))
        card = view["proposals"][0]
        self.assertEqual(("setting", "pending", "Change entry points", "Handlers are entry points too."), (card["kind"], card["status"], card["title"], card["reason"]))
        self.assertEqual((["javax.servlet.Servlet.service", "@com.acme.Handler"], ["javax.servlet.Servlet.service"]), (card["payload"]["values"], card["payload"]["before"]))
        self.assertEqual(before, open(self.jots).read(), "a proposal changes nothing")
        self.assertEqual(str(card["id"]), view["items"][1]["text"], "the card is where it was made in the conversation")
        told = json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])
        self.assertEqual((True, card["id"]), (told["ok"], told["proposal"]))

    def test_a_proposal_with_problems_is_not_shown_and_the_model_is_told_what_they_are_to_mend_it(self):
        view = self.say("go", self.reply(self.use("propose_setting", setting="entry", values=["static x.Y.z", "fine.Class.method"], reason="r"), stop="tool_use"),
                        self.reply(self.use("propose_setting", setting="entry", values=["fine.Class.method"], reason="r"), stop="tool_use"), self.reply(self.text("Fixed.")))
        self.assertEqual(1, len(view["proposals"]), "only the mended one is a card")
        first = json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])
        self.assertFalse(first["ok"])
        self.assertIn("isn't a method name", first["problems"][0])
        self.assertIn("entry 1", first["problems"][0])
        self.assertEqual(["user", "step", "proposal", "assistant"], self.kinds(view))

    def test_the_default_can_be_proposed_with_no_values(self):
        view = self.say("go", self.reply(self.use("propose_setting", setting="ignore", values=None, reason="the default is fine"), stop="tool_use"), self.reply(self.text("ok")))
        card = view["proposals"][0]
        self.assertEqual("Use the default for the ignore list", card["title"])
        self.assertIsNone(card["payload"]["values"])

    def test_a_setting_that_does_not_exist_is_an_error_for_the_model(self):
        self.say("go", self.reply(self.use("propose_setting", setting="colour", values=["red"], reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        self.assertTrue(self.sent[1]["messages"][-1]["content"][0].get("is_error"))
        self.assertEqual([], self.proposals())

    def test_a_sensor_is_proposed_and_a_rule_starts_out_only_reporting(self):
        rule = "name: http-block-thing\ndescription: Identifies a thing\nmethods:\n- a.B.run\ncaptures:\n  v: '#P0'\nblock-when: true\n"
        view = self.say("block it", self.reply(self.use("propose_sensor", yaml=rule, reason="it is dangerous"), stop="tool_use"), self.reply(self.text("Proposed.")))
        card = view["proposals"][0]
        self.assertEqual(("sensor", "Add the rule http-block-thing"), (card["kind"], card["title"]))
        self.assertTrue(card["payload"]["rule"])
        self.assertIn("protect: false", card["payload"]["yaml"], "so it only reports until someone turns it on")

    def test_a_sensor_with_a_name_in_use_or_a_mistake_is_not_shown(self):
        taken = "name: crypto-cipher\ndescription: Identifies a thing\nmethods:\n- a.B.run\ncaptures:\n  v: '#P0'\n"
        self.say("go", self.reply(self.use("propose_sensor", yaml=taken, reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        said = json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])
        self.assertFalse(said["ok"])
        self.assertIn("already used", " ".join(said["problems"]))
        self.assertEqual([], self.proposals())

    def test_a_change_to_a_sensor_that_exists_keeps_what_it_was_so_a_change_made_meanwhile_is_noticed(self):
        new = "name: crypto-cipher\ndescription: Identifies a cipher being used\nmethods:\n- javax.crypto.Cipher.init\ncaptures:\n  algorithm: '#OBJ.getAlgorithm()'\n  mode: '#P0'\n"
        view = self.say("add the mode", self.reply(self.use("propose_sensor", yaml=new, replaces="crypto-cipher", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        card = view["proposals"][0]
        self.assertEqual("Change the sensor crypto-cipher", card["title"])
        self.assertEqual("crypto-cipher", card["payload"]["replaces"])
        self.assertIn("algorithm", card["payload"]["original"])
        self.say("again", self.reply(self.use("propose_sensor", yaml=new, replaces="nothing-like-it", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        self.assertIn("no sensor or rule called nothing-like-it", " ".join(json.loads(self.sent[-1]["messages"][-1]["content"][0]["content"])["problems"]))

    def test_a_report_is_proposed_when_it_reads_fields_that_exist_and_not_when_it_does_not(self):
        good = "name: Ciphers\ntype: list\ncols: crypto-cipher.algorithm\n"
        bad = "name: Ciphers\ntype: list\ncols: crypto-cipher.nothing\n"
        view = self.say("report", self.reply(self.use("propose_report", yaml=bad, reason="r"), stop="tool_use"), self.reply(self.use("propose_report", yaml=good, reason="r"), stop="tool_use"),
                        self.reply(self.text("ok")))
        self.assertEqual(["Add the report Ciphers"], [p["title"] for p in view["proposals"]])
        self.assertIn("doesn't capture nothing", " ".join(json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])["problems"]))

    def test_combining_the_files_is_proposed_with_what_it_would_do_and_not_when_there_is_nothing_to_combine(self):
        view = self.say("one file please", self.reply(self.use("propose_consolidation", reason="one file is simpler"), stop="tool_use"), self.reply(self.text("ok")))
        card = view["proposals"][0]
        self.assertEqual((1, 1, ["lib.jot"]), (card["payload"]["summary"]["sensors"] - 2, card["payload"]["summary"]["reports"], card["payload"]["summary"]["from"]))
        self.assertEqual(self.JOTS, open(self.jots).read(), "only a proposal")
        view = self.say("keep it", self.reply(self.use("propose_consolidation", keep=["lib.jot"], reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        self.assertEqual(1, len(view["proposals"]), "with the library kept there is nothing to combine, so there is no second card")

    # ------------------------------------------------------------------ applying

    def propose_entry(self, values=("com.acme.Main.main",)):
        self.say("entry", self.reply(self.use("propose_setting", setting="entry", values=list(values), reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        return self.proposals()[-1]["id"]

    def test_applying_a_setting_writes_it_into_the_jots_file_and_says_so(self):
        pid = self.propose_entry()
        done = self.a.resolve(pid, "apply")
        self.assertEqual("applied", done["status"])
        self.assertEqual(["com.acme.Main.main"], self.written()["app"]["entry"])
        self.assertIn("Written to jot.yaml. The agent reads it when the application starts.", done["result"])
        self.assertEqual("applied", self.kinds()[-1])
        self.assertEqual(["com.acme"], self.written()["app"]["packages"], "the rest of the file is as it was")

    def test_what_happened_to_a_proposal_is_told_to_the_model_with_the_next_message_once(self):
        pid = self.propose_entry()
        self.a.resolve(pid, "apply")
        self.say("thanks", self.reply(self.text("welcome")))
        self.assertIn("Proposal %d, Change entry points, was applied by the person." % pid, self.sent[-1]["messages"][-1]["content"][0]["text"])
        self.say("and again", self.reply(self.text("ok")))
        self.assertNotIn("was applied", self.sent[-1]["messages"][-1]["content"][0]["text"], "it was said once")

    def test_discarding_a_proposal_changes_nothing_and_is_told_too(self):
        pid = self.propose_entry()
        before = open(self.jots).read()
        done = self.a.resolve(pid, "discard")
        self.assertEqual("discarded", done["status"])
        self.assertEqual(before, open(self.jots).read())
        self.say("ok", self.reply(self.text("fine")))
        self.assertIn("was discarded by the person", self.sent[-1]["messages"][-1]["content"][0]["text"])

    def test_a_proposal_is_applied_or_discarded_once_and_one_that_is_not_there_is_not_found(self):
        pid = self.propose_entry()
        self.a.resolve(pid, "apply")
        for action in ("apply", "discard"):
            with self.assertRaises(store.QueryError):
                self.a.resolve(pid, action)
        with self.assertRaises(LookupError):
            self.a.resolve(9999, "apply")
        other = self.propose_entry(["com.acme.Other.run"])
        with self.assertRaises(store.QueryError):
            self.a.resolve(other, "explode")

    def test_a_proposal_is_refused_if_the_file_changed_since_it_was_made_and_stays_open(self):
        pid = self.propose_entry()
        store.write_entry(self.jots, ["somebody.Else.changed"])
        with self.assertRaises(store.SaveError) as e:
            self.a.resolve(pid, "apply")
        self.assertEqual(409, e.exception.status)
        self.assertEqual("pending", self.proposals()[0]["status"], "so it can be made again")
        self.assertEqual(["somebody.Else.changed"], self.written()["app"]["entry"])

    def test_a_dashboard_that_may_not_write_applies_nothing(self):
        pid = self.propose_entry()
        self.app.editable = False
        with self.assertRaises(store.SaveError) as e:
            self.a.resolve(pid, "apply")
        self.assertEqual(403, e.exception.status)
        self.assertEqual("pending", self.proposals()[0]["status"])
        self.assertIn("changes can't be applied here", self.say("hello", self.reply(self.text("hi"))) and self.sent[-1]["messages"][-1]["content"][0]["text"])

    def test_applying_a_sensor_adds_it_to_the_jots_file_and_the_dashboard_has_it(self):
        text = "name: http-new-thing\ndescription: Identifies a thing\nmethods:\n- a.B.run\ncaptures:\n  v: '#P0'\n"
        self.say("add", self.reply(self.use("propose_sensor", yaml=text, reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        done = self.a.resolve(self.proposals()[0]["id"], "apply")
        self.assertIn("Added to jot.yaml", done["result"])
        self.assertIn("http-new-thing", [s["name"] for s in self.written()["sensors"]])
        self.assertIn("http-new-thing", [s["name"] for s in self.app.jots()["sensors"]])

    def test_applying_a_change_to_a_sensor_saves_it_in_place(self):
        new = "name: crypto-cipher\ndescription: Identifies a cipher being used\nmethods:\n- javax.crypto.Cipher.init\ncaptures:\n  algorithm: '#OBJ.getAlgorithm()'\n  mode: '#P0'\n"
        self.say("change", self.reply(self.use("propose_sensor", yaml=new, replaces="crypto-cipher", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        done = self.a.resolve(self.proposals()[0]["id"], "apply")
        self.assertIn("Saved to jot.yaml", done["result"])
        self.assertEqual(["algorithm", "mode"], list(next(s for s in self.written()["sensors"] if s["name"] == "crypto-cipher")["captures"]))

    def test_applying_a_report_adds_it(self):
        self.say("report", self.reply(self.use("propose_report", yaml="name: Ciphers\ntype: list\ncols: crypto-cipher.algorithm\n", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        done = self.a.resolve(self.proposals()[0]["id"], "apply")
        self.assertIn("Added to jot.yaml", done["result"])
        self.assertIn("Ciphers", [r["name"] for r in self.written()["reports"]])

    def add_reader(self):
        with open(self.jots, "a") as f:
            f.write("reports:\n- name: Ciphers\n  type: list\n  cols: crypto-cipher.algorithm\n")
        self.app.reload_jots(force=True)

    def test_a_sensor_says_which_reports_read_it_and_the_assistant_is_told(self):
        self.add_reader()
        sensors = {s["name"]: s for s in self.app.jots()["sensors"]}
        self.assertEqual(["Ciphers"], sensors["crypto-cipher"]["used_by"])
        self.assertEqual([], sensors["http-route"]["used_by"])
        self.assertEqual(["Ciphers"], self.a._get_configuration()["read_by"]["crypto-cipher"])

    def test_a_removal_is_proposed_with_what_it_breaks_and_applying_it_deletes(self):
        self.add_reader()
        view = self.say("remove it", self.reply(self.use("propose_delete", kind="sensor", name="crypto-cipher", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        card = view["proposals"][0]
        self.assertEqual(("delete", "Remove the sensor crypto-cipher", ["Ciphers"]), (card["kind"], card["title"], card["payload"]["used_by"]))
        self.assertIn("crypto-cipher", [s["name"] for s in self.written()["sensors"]], "only a proposal")
        done = self.a.resolve(card["id"], "apply")
        self.assertIn("Removed from jot.yaml", done["result"])
        self.assertEqual(["http-route"], [s["name"] for s in self.written()["sensors"]])

    def test_a_report_can_be_changed_or_removed_by_a_proposal_and_a_missing_one_is_not_shown(self):
        self.add_reader()
        new = "name: Ciphers\ntype: list\ncols: http-route.path\n"
        view = self.say("fix", self.reply(self.use("propose_report", yaml=new, replaces="Ciphers", reason="r"), stop="tool_use"),
                        self.reply(self.use("propose_delete", kind="report", name="Nope", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        self.assertEqual(["Change the report Ciphers"], [p["title"] for p in view["proposals"]])
        self.assertIn("no report called Nope", " ".join(json.loads(self.sent[2]["messages"][-1]["content"][0]["content"])["problems"]))
        done = self.a.resolve(view["proposals"][0]["id"], "apply")
        self.assertIn("Saved to jot.yaml", done["result"])
        self.assertEqual("http-route.path", self.written()["reports"][0]["cols"])
        self.say("remove", self.reply(self.use("propose_delete", kind="report", name="Ciphers", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        self.a.resolve(self.proposals()[-1]["id"], "apply")
        self.assertEqual([], self.written()["reports"])

    def test_a_restart_is_proposed_only_when_the_console_knows_the_command_and_applying_it_restarts_with_that_command(self):
        folder = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, folder, True)
        agent = os.path.join(folder, "jot.jar")
        open(agent, "w").close()
        script = os.path.join(folder, "run.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\necho started $$\nsleep 30\n")
        os.chmod(script, 0o755)
        self.app.launcher = launcher.Launcher(folder, self.app.jots_file, agent=agent)
        self.addCleanup(self.app.launcher.close)
        view = self.say("restart the app", self.reply(self.use("propose_restart", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        self.assertEqual([], view["proposals"], "the console doesn't know how it starts, so there is no card")
        self.assertIn("start it once from the Run page", " ".join(json.loads(self.sent[1]["messages"][-1]["content"][0]["content"])["problems"]))
        self.app.launcher.start("./run.sh")
        before = self.app.launcher.state()["pid"]
        view = self.say("restart the app", self.reply(self.use("propose_restart", reason="the sensors changed", command="echo injected"), stop="tool_use"),
                        self.reply(self.text("ok")))
        card = view["proposals"][-1]
        self.assertEqual(("restart", "Restart the application", "./run.sh"), (card["kind"], card["title"], card["payload"]["command"]),
                         "the command is the one the person used, whatever the model sent")
        self.assertEqual(before, self.app.launcher.state()["pid"], "only a proposal")
        done = self.a.resolve(card["id"], "apply")
        self.assertIn("Restarted with ./run.sh", done["result"])
        self.assertNotEqual(before, self.app.launcher.state()["pid"])
        self.assertTrue(self.app.launcher.running())

    def test_applying_the_combining_of_the_files_does_it_and_keeps_a_copy(self):
        self.say("combine", self.reply(self.use("propose_consolidation", reason="r"), stop="tool_use"), self.reply(self.text("ok")))
        done = self.a.resolve(self.proposals()[0]["id"], "apply")
        self.assertIn("Everything is in jot.yaml now", done["result"])
        self.assertIn("jot.yaml.bak", done["result"])
        self.assertNotIn("jots", self.written())
        self.assertIn("lib-sensor", [s["name"] for s in self.written()["sensors"]])

    # ------------------------------------------------------------------ when it goes wrong

    def test_a_failure_of_the_model_is_said_to_the_person_and_the_conversation_can_go_on(self):
        view = self.say("hello", llm.LLMError("the model API returned 529. Overloaded"))
        self.assertEqual(["user", "error"], self.kinds(view))
        self.assertIn("Overloaded", view["items"][-1]["text"])
        self.assertFalse(view["running"])
        view = self.say("again", self.reply(self.text("hi")))
        self.assertEqual("assistant", self.kinds(view)[-1])

    def test_an_answer_that_ran_out_of_room_or_was_declined_is_said(self):
        view = self.say("big", self.reply(self.text("part of it"), stop="max_tokens"))
        self.assertIn("ran out of room", view["items"][-1]["text"])
        view = self.say("no", self.reply(stop="refusal"))
        self.assertIn("declined", view["items"][-1]["text"])

    def test_a_model_that_keeps_asking_for_things_is_stopped_after_a_number_of_steps(self):
        with unittest.mock.patch.object(assistant, "MAX_STEPS", 3):
            view = self.say("loop", *[self.reply(self.use("get_configuration"), stop="tool_use") for _ in range(5)])
        self.assertEqual(3, len(self.sent))
        self.assertIn("stopped after 3 steps", view["items"][-1]["text"])

    def test_a_bug_in_the_dashboard_is_said_and_does_not_leave_the_turn_running(self):
        self.script = [RuntimeError("boom")]
        self.a.send(self.chat, "hello")
        self.a.wait(self.chat)
        view = self.a.view(self.chat)
        self.assertFalse(view["running"])
        self.assertIn("went wrong in the dashboard", view["items"][-1]["text"])
        self.assertNotIn("boom", view["items"][-1]["text"], "what the exception said stays in the log")

    def test_only_one_turn_runs_at_a_time_and_a_turn_can_be_stopped(self):
        gate = threading.Event()
        steps = [self.reply(self.use("get_configuration"), stop="tool_use"), self.reply(self.use("get_configuration"), stop="tool_use"), self.reply(self.text("never"))]
        def slow(body, timeout):
            self.sent.append(body)
            gate.wait(10)
            return steps.pop(0)
        self.a.post = slow
        self.a.send(self.chat, "go")
        self.assertTrue(self.a.view(self.chat)["running"])
        with self.assertRaises(store.QueryError):
            self.a.send(self.chat, "and this")
        self.a.stop(self.chat)
        gate.set()
        self.a.wait(self.chat)
        view = self.a.view(self.chat)
        self.assertFalse(view["running"])
        self.assertEqual("Stopped", view["items"][-1]["text"])
        self.assertLess(len(self.sent), 3, "it stopped before the end")

    # ------------------------------------------------------------------ over http

    def test_over_http_a_conversation_is_started_answered_and_a_proposal_applied(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        host = {"Host": "127.0.0.1:%d" % port}

        def get(path):
            try:
                with urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers=host)) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                return e.code, json.load(e)

        def post(path, body):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=json.dumps(body).encode(), headers=dict(host, **{"X-JOT-Dashboard": "1", "Content-Type": "application/json"}))
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                return e.code, json.load(e)

        status, home = get("/api/assistant")
        self.assertEqual(200, status)
        self.assertEqual([self.chat], [c["id"] for c in home["chats"]])
        status, fresh = post("/api/assistant/new", {})
        self.assertEqual((200, []), (status, fresh["items"]))
        self.script = [self.reply(self.use("propose_setting", setting="packages", values=["com.acme", "org.apache.jsp"], reason="r"), stop="tool_use"), self.reply(self.text("Proposed."))]
        status, started = post("/api/assistant/send", {"chat": fresh["chat"], "text": "the packages"})
        self.assertEqual(200, status)
        self.a.wait(fresh["chat"])
        status, view = get("/api/assistant/chat?id=%d&after=0" % fresh["chat"])
        self.assertEqual(["user", "proposal", "assistant"], [i["kind"] for i in view["items"]])
        status, done = post("/api/assistant/proposal", {"id": view["proposals"][0]["id"], "action": "apply"})
        self.assertEqual((200, "applied"), (status, done["status"]))
        self.assertEqual(["com.acme", "org.apache.jsp"], self.written()["app"]["packages"])
        self.assertEqual(404, get("/api/assistant/chat?id=9999")[0])
        self.assertEqual(404, post("/api/assistant/proposal", {"id": 9999, "action": "apply"})[0])
        self.assertEqual(400, post("/api/assistant/send", {"chat": fresh["chat"], "text": ""})[0])
        self.assertEqual(404, post("/api/assistant/send", {"chat": 9999, "text": "hi"})[0])
        status, again = post("/api/assistant/proposal", {"id": view["proposals"][0]["id"], "action": "apply"})
        self.assertEqual(400, status, "applied once")


class AssistantPageTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME
    FILE = "app:\n  entry:\n    - javax.servlet.Servlet.service\n  packages:\n    - com.acme\nsensors:\n- name: crypto-cipher\n  description: Identifies a cipher being used\n  methods:\n  - javax.crypto.Cipher.init\n  captures:\n    algorithm: '#OBJ.getAlgorithm()'\n"

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const q = (s) => document.querySelector(s);
      const all = (s) => [...document.querySelectorAll(s)];
      const out = {};
      try {
        location.hash = "#assistant";
        await until(() => q("#assistantLog .tips button"));
        out.tips = all("#assistantLog .tips button").map((b) => b.textContent);
        out.model = q("#assistantStatus").textContent;
        out.nav = q("#navAssistant").className;
        out.sendEnabled = !q("#assistantSend").disabled;
        q("#assistantInput").value = "set the entry points to servlets and handlers";
        q("#assistantSend").click();
        await until(() => q("#assistantLog .proposal") && all("#assistantLog .bot").length === 2 && !q("#assistantLog .typing"));
        out.user = q("#assistantLog .you").textContent;
        out.card = { title: q(".proposal h3").textContent, why: q(".proposal .why").textContent, lists: q(".proposal .lists").textContent,
                     buttons: all(".proposal button").map((b) => b.textContent), enabled: all(".proposal button").every((b) => !b.disabled) };
        out.bot = all("#assistantLog .bot")[1].textContent;
        out.first = all("#assistantLog .bot")[0].textContent;
        out.code = all("#assistantLog .bot code").map((c) => c.textContent);
        out.noMarkup = !q("#assistantLog .bot b") && !q("#assistantLog .bot script");
        out.step = all("#assistantLog .step").map((s) => s.textContent);
        out.workingGone = !q("#assistantLog .typing");
        out.sendBack = !q("#assistantSend").disabled;
        all(".proposal button").find((b) => b.textContent === "Apply").click();
        await until(() => q(".proposal.applied"));
        out.applied = q(".proposal .state").textContent;
        out.appliedLine = q("#assistantLog .applied").textContent;
        out.applyGone = all(".proposal button").length;
        // a new conversation starts empty, and the first is still there
        q("#assistantNew").click();
        await until(() => all("#assistantChats option").length === 2 && q("#assistantLog .tips"));
        out.options = all("#assistantChats option").map((o) => o.textContent);
        out.newEmpty = !q("#assistantLog .proposal");
        const first = all("#assistantChats option").find((o) => /set the entry points/.test(o.textContent)).value;
        q("#assistantChats").value = first;
        q("#assistantChats").dispatchEvent(new Event("change"));
        await until(() => q("#assistantLog .proposal.applied"));
        out.restored = all("#assistantLog .you, #assistantLog .bot").length;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    def serve(self, app, script):
        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        httpd.RequestHandlerClass.port = httpd.server_address[1]
        httpd.RequestHandlerClass.host = server.Host(httpd.RequestHandlerClass)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--window-size=1400,1100", "--virtual-time-budget=60000", "--dump-dom", "http://127.0.0.1:%d/" % httpd.server_address[1]],
                              capture_output=True, text=True, timeout=180)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        return json.loads(htmllib.unescape(found.group(1)))

    def make(self, key, script=None):
        saved = os.environ.get("ANTHROPIC_API_KEY")
        if key:
            os.environ["ANTHROPIC_API_KEY"] = "test-key"
        else:
            os.environ.pop("ANTHROPIC_API_KEY", None)
        self.addCleanup(lambda: os.environ.__setitem__("ANTHROPIC_API_KEY", saved) if saved else os.environ.pop("ANTHROPIC_API_KEY", None))
        env = Env()
        path = os.path.join(env.dir, "jot.yaml")
        with open(path, "w") as f:
            f.write(self.FILE)
        store.load_sensors(env.ingestor.db, [path])
        answers = [{"content": [{"type": "text", "text": "Let me propose that."}, {"type": "tool_use", "id": "tu_1", "name": "propose_setting",
                                 "input": {"setting": "entry", "values": ["javax.servlet.Servlet.service", "@com.acme.Handler"], "reason": "Handlers are entry points too."}}], "stop_reason": "tool_use"},
                   {"content": [{"type": "text", "text": "I have proposed `@com.acme.Handler` as well.\n\n- servlets\n- <b>handlers</b><script>window.hacked = 1</script>"}], "stop_reason": "end_turn"}]
        answers = script if script is not None else answers
        app = server.App(env.db, env.ingestor, jot_paths=[path], jots_file=path, editable=True, assistant_post=lambda body, timeout: answers.pop(0))
        app.scanner.set_root(env.dir)
        return app, path

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_opening_screen_asks_what_to_find_out_and_a_question_is_answered_with_a_button(self):
        asked = [{"content": [{"type": "text", "text": "Security is wide."}, {"type": "tool_use", "id": "q1", "name": "ask_person",
                                 "input": {"question": "What worries you most?", "options": ["Injection", "Sensitive data", "Not sure"]}}], "stop_reason": "tool_use"},
                 {"content": [{"type": "text", "text": "Then I will look at SQL and expressions."}], "stop_reason": "end_turn"}]
        app, path = self.make(key=True, script=asked)
        script = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const q = (s) => document.querySelector(s);
      const all = (s) => [...document.querySelectorAll(s)];
      const out = {};
      try {
        location.hash = "#assistant";
        await until(() => q("#assistantLog .tips button"));
        out.welcome = q("#assistantLog .bot").textContent;
        out.goals = all("#assistantLog .tips button").slice(0, 3).map((b) => b.textContent);
        out.topics = all("#assistantLog .tips button").slice(3).map((b) => b.textContent);
        all("#assistantLog .tips button").find((b) => /security/.test(b.textContent)).click();
        await until(() => q("#assistantLog .question .choices button"));
        out.you = q("#assistantLog .you").textContent;
        out.ask = q("#assistantLog .question .ask").textContent;
        out.choices = all("#assistantLog .question .choices button").map((b) => b.textContent);
        out.answeredBefore = !!q("#assistantLog .question.answered");
        out.welcomeGone = all("#assistantLog .tips").length === 0;
        all("#assistantLog .question .choices button")[0].click();
        await until(() => q("#assistantLog .question.answered") && all("#assistantLog .bot").length === 2 && !q("#assistantLog .typing"));
        out.answeredAfter = !!q("#assistantLog .question.answered");
        out.chosen = all("#assistantLog .question .chosen").map((b) => b.textContent);
        out.said = all("#assistantLog .you").map((e) => e.textContent);
        out.last = all("#assistantLog .bot")[1].textContent;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """
        out = self.serve(app, script)
        self.assertNotIn("error", out, out)
        self.assertEqual("What would you like to find out about this application?", out["welcome"])
        self.assertEqual(["Get a general understanding", "Look for security vulnerabilities", "I'm not sure where to start"], out["goals"])
        self.assertIn("SQL", out["topics"])
        self.assertEqual("I want to look for security vulnerabilities in this application.", out["you"])
        self.assertEqual(("What worries you most?", ["Injection", "Sensitive data", "Not sure"]), (out["ask"], out["choices"]))
        self.assertFalse(out["answeredBefore"])
        self.assertTrue(out["welcomeGone"])
        self.assertTrue(out["answeredAfter"])
        self.assertEqual(["Injection"], out["chosen"])
        self.assertEqual("Injection", out["said"][1])
        self.assertEqual("Then I will look at SQL and expressions.", out["last"])

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_project_menu_fits_and_its_picker_opens_a_folder(self):
        app, path = self.make(key=False)
        script = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const q = (s) => document.querySelector(s);
      const out = {};
      try {
        q("#projectBtn").click();
        await until(() => q("#pickerList button"));
        const box = (s) => q(s).getBoundingClientRect();
        out.input = box("#projectInput").width;
        out.go = box("#projectOpen").width;
        out.open = box("#pickerOpen").width;
        out.menu = box("#projectList").width;
        out.up = box("#pickerUp").width;
        out.names = [...document.querySelectorAll("#pickerList button")].map((b) => b.textContent);
        out.path = q("#pickerPath").textContent;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
"""
        out = self.serve(app, script)
        self.assertNotIn("error", out, out)
        self.assertGreater(out["input"], 150, "the path field has room, " + str(out))
        self.assertLess(out["go"], 120, "the button is a button and not a bar, " + str(out))
        self.assertLess(out["open"], 220, str(out))
        self.assertLess(out["up"], 120, str(out))
        self.assertLessEqual(out["menu"], 490)
        self.assertTrue(out["names"], "folders are listed")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_person_asks_gets_a_proposal_applies_it_and_has_the_conversation_back_later(self):
        app, path = self.make(key=True)
        out = self.serve(app, self.SCRIPT)
        self.assertNotIn("error", out, out)
        self.assertEqual(["Get a general understanding", "Look for security vulnerabilities", "I'm not sure where to start"], out["tips"][:3],
                         "an empty conversation asks what the person wants to find out")
        self.assertIn("Web requests", out["tips"], "and offers the catalog's areas to look at")
        self.assertIn("Cryptography", out["tips"])
        self.assertEqual("active", out["nav"])
        self.assertTrue(out["sendEnabled"])
        self.assertEqual("set the entry points to servlets and handlers", out["user"])
        self.assertEqual(("Change entry points", "Handlers are entry points too."), (out["card"]["title"], out["card"]["why"]))
        self.assertIn("Now", out["card"]["lists"])
        self.assertIn("javax.servlet.Servlet.service", out["card"]["lists"])
        self.assertIn("@com.acme.Handler", out["card"]["lists"], "what would be written is on the card")
        self.assertEqual(["Apply", "Discard"], out["card"]["buttons"])
        self.assertTrue(out["card"]["enabled"])
        self.assertIn("I have proposed", out["bot"])
        self.assertEqual(["@com.acme.Handler"], out["code"], "code in a reply is shown as code")
        self.assertTrue(out["noMarkup"], "a reply is text, so markup in it is shown and never run")
        self.assertTrue(out["workingGone"])
        self.assertTrue(out["sendBack"], "and the person can say the next thing")
        self.assertIn("Written to jot.yaml. The agent reads it when the application starts.", out["applied"])
        self.assertIn("Change entry points", out["appliedLine"])
        self.assertEqual(0, out["applyGone"], "an applied proposal has nothing left to press")
        self.assertEqual(2, len(out["options"]))
        self.assertTrue(out["newEmpty"])
        self.assertEqual("Let me propose that.", out["first"], "what the assistant said before it proposed is shown too")
        self.assertEqual(3, out["restored"], "the first conversation is back with what was said in it, the person's words and both replies")
        with open(path) as f:
            self.assertEqual(["javax.servlet.Servlet.service", "@com.acme.Handler"], yaml.safe_load(f.read())["app"]["entry"])

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_without_a_model_the_page_says_so_and_cannot_send(self):
        app, path = self.make(key=False)
        script = """
        (async () => {
          const wait = (ms) => new Promise((r) => setTimeout(r, ms));
          const until = async (f, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
          const out = {};
          try {
            location.hash = "#assistant";
            await until(() => document.querySelector("#assistantNotice .notice"));
            out.notice = document.querySelector("#assistantNotice .notice").textContent;
            out.send = document.getElementById("assistantSend").disabled;
          } catch (e) { out.error = String(e); }
          const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
        })();
        """
        out = self.serve(app, script)
        self.assertNotIn("error", out, out)
        self.assertIn("ANTHROPIC_API_KEY", out["notice"])
        self.assertTrue(out["send"])


class EntryPointPageTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME
    FILE = "jots: []\n# the application\napp:\n  entry:\n    - javax.servlet.Servlet.service\n    - jakarta.servlet.Servlet.service\n  packages:\n    - com.acme\n"

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const button = (id) => document.getElementById(id);
      const type = (value) => { const box = button("entryInput"); box.value = value; };
      const values = () => [...document.querySelectorAll("#entryList input")].map((i) => i.value);
      const status = () => document.getElementById("entryStatus").textContent;
      const out = {};
      try {
        location.hash = "#jots";
        await until(() => document.querySelectorAll("#entryList input").length);
        out.summary = document.getElementById("entrySummary").textContent;
        out.start = values();
        out.startButtons = ["entrySave", "entryRevert", "entryDefault"].map((id) => button(id).disabled);
        // add one, which can be saved
        type("@com.acme.Handler");
        button("entryAdd").click();
        await until(() => values().length === 3);
        out.added = values();
        out.addedButtons = ["entrySave", "entryRevert"].map((id) => button(id).disabled);
        out.addedStatus = status();
        // an entry that is wrong is said, on its row, and can't be saved until it is mended
        type("static foo.Bar.baz");
        button("entryAdd").click();
        await until(() => document.querySelectorAll("#entryList .editstatus:not([hidden])").length);
        out.problem = document.querySelector("#entryList .editstatus:not([hidden])").textContent;
        out.problemSave = button("entrySave").disabled;
        const bad = document.querySelectorAll("#entryList input")[3];
        bad.value = "com.acme.Main.main";
        bad.dispatchEvent(new Event("input"));
        await until(() => !document.querySelector("#entryList .editstatus:not([hidden])"));
        out.mendedSave = button("entrySave").disabled;
        out.mended = values();
        // remove the first and save
        document.querySelector('#entryList button[aria-label^="Remove javax"]').click();
        await until(() => values().length === 3);
        button("entrySave").click();
        await until(() => /^Saved to/.test(status()));
        out.saved = status();
        out.savedValues = values();
        out.savedButtons = ["entrySave", "entryRevert"].map((id) => button(id).disabled);
        // the default takes the list out of the file
        button("entryDefault").click();
        await until(() => /the default/.test(document.getElementById("entrySummary").textContent));
        out.defaultShown = values();
        out.defaultSummary = document.getElementById("entrySummary").textContent;
        button("entrySave").click();
        await until(() => /^Saved to/.test(status()));
        out.defaultSavedSummary = document.getElementById("entrySummary").textContent;
        // and revert goes back to what the file says
        type("com.acme.Other.run");
        button("entryAdd").click();
        await until(() => values().length === 3);
        button("entryRevert").click();
        await until(() => values().length === 2);
        out.reverted = values();
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    def serve(self, app, script):
        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        httpd.RequestHandlerClass.port = httpd.server_address[1]
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--window-size=1400,1000", "--virtual-time-budget=40000", "--dump-dom", "http://127.0.0.1:%d/" % httpd.server_address[1]],
                              capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        return json.loads(htmllib.unescape(found.group(1)))

    SETTINGS_SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const button = (id) => document.getElementById(id);
      const values = (name) => [...document.querySelectorAll("#" + name + "List input")].map((i) => i.value);
      const status = (name) => button(name + "Status").textContent;
      const out = {};
      try {
        location.hash = "#jots";
        await until(() => values("packages").length);
        out.packagesStart = values("packages");
        out.packagesSummary = button("packagesSummary").textContent;
        out.ignoreSummary = button("ignoreSummary").textContent;
        button("packagesInput").value = "com.other";
        button("packagesAdd").click();
        await until(() => values("packages").length === 2);
        button("packagesInput").value = "not valid!";
        button("packagesAdd").click();
        await until(() => document.querySelector("#packagesList .editstatus:not([hidden])"));
        out.packagesProblem = document.querySelector("#packagesList .editstatus:not([hidden])").textContent;
        out.packagesSaveBlocked = button("packagesSave").disabled;
        document.querySelector('#packagesList button[aria-label="Remove not valid!"]').click();
        await until(() => values("packages").length === 2 && !document.querySelector("#packagesList .editstatus:not([hidden])") && !button("packagesSave").disabled);
        button("packagesSave").click();
        await until(() => /^Saved to/.test(status("packages")));
        out.packagesSaved = status("packages");
        out.packagesAfter = values("packages");
        button("ignoreInput").value = "org.libs.Thing";
        button("ignoreAdd").click();
        await until(() => values("ignore").includes("org.libs.Thing"));
        button("ignoreSave").click();
        await until(() => /^Saved to/.test(status("ignore")));
        out.ignoreSaved = status("ignore");
        out.entryUntouched = values("entry");
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    BANNER_SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 15000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const bar = document.getElementById("restartBanner");
      const out = {};
      try {
        await until(() => !bar.hidden);
        out.shown = !bar.hidden;
        out.text = document.getElementById("restartText").textContent;
        out.button = document.getElementById("restartNow").hidden;
        document.getElementById("restartNow").click();
        await until(() => bar.hidden);
        out.hiddenAfter = bar.hidden;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_banner_says_the_application_needs_a_restart_and_a_button_does_it(self):
        env = Env()
        path = os.path.join(env.dir, "jot.yaml")
        with open(path, "w") as f:
            f.write(self.FILE)
        agent = os.path.join(env.dir, "jot.jar")
        open(agent, "w").close()
        script = os.path.join(env.dir, "run.sh")
        with open(script, "w") as f:
            f.write("#!/bin/sh\nsleep 60\n")
        os.chmod(script, 0o755)
        app = server.App(env.db, env.ingestor, jots_file=path, editable=True)
        app.launcher = launcher.Launcher(env.dir, path, agent=agent)
        self.addCleanup(app.launcher.close)
        app.launcher.start("./run.sh")
        before = app.launcher.state()["pid"]
        app.launcher.started -= 30000       # it has been running for half a minute, and the configuration is saved now
        os.utime(path)
        out = self.serve(app, self.BANNER_SCRIPT)
        self.assertNotIn("error", out, out)
        self.assertTrue(out["shown"])
        self.assertIn("Restart your application", out["text"])
        self.assertFalse(out["button"], "the console knows the command, so it can do it")
        self.assertTrue(out["hiddenAfter"], "and the banner goes once it has")
        self.assertNotEqual(before, app.launcher.state()["pid"])

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_packages_and_the_ignore_list_are_edited_and_saved_like_the_entry_points(self):
        env = Env()
        path = os.path.join(env.dir, "jot.yaml")
        with open(path, "w") as f:
            f.write(self.FILE)
        out = self.serve(server.App(env.db, env.ingestor, jots_file=path, editable=True), self.SETTINGS_SCRIPT)
        self.assertNotIn("error", out, out)
        self.assertEqual(["com.acme"], out["packagesStart"])
        self.assertEqual(("1", True), (out["packagesSummary"], out["ignoreSummary"].startswith("the default")))
        self.assertIn("isn't a package", out["packagesProblem"])
        self.assertTrue(out["packagesSaveBlocked"], "it can't be saved while a row is wrong")
        self.assertEqual(["com.acme", "com.other"], out["packagesAfter"])
        self.assertIn("Saved to jot.yaml", out["packagesSaved"])
        self.assertIn("Saved to jot.yaml", out["ignoreSaved"])
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], out["entryUntouched"])
        with open(path) as f:
            doc = yaml.safe_load(f.read())
        self.assertEqual(["com.acme", "com.other"], doc["app"]["packages"])
        self.assertEqual("org.libs.Thing", doc["ignore"][-1], "it started from the default list and added to it")
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], doc["app"]["entry"])

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_person_adds_mends_removes_and_saves_entry_points_and_goes_back_to_the_default(self):
        env = Env()
        path = os.path.join(env.dir, "jot.yaml")
        with open(path, "w") as f:
            f.write(self.FILE)
        out = self.serve(server.App(env.db, env.ingestor, jots_file=path, editable=True), self.SCRIPT)
        self.assertNotIn("error", out, out)
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], out["start"])
        self.assertEqual("2", out["summary"])
        self.assertEqual([True, True, False], out["startButtons"], "nothing to save or revert at first, and the default is there to go back to")
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service", "@com.acme.Handler"], out["added"])
        self.assertEqual([False, False], out["addedButtons"], "something to save, and to revert")
        self.assertEqual("Not saved", out["addedStatus"])
        self.assertIn("isn't a method name", out["problem"], "said on the row it is on")
        self.assertTrue(out["problemSave"], "and it can't be saved like that")
        self.assertFalse(out["mendedSave"], "but it can once it is mended")
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service", "@com.acme.Handler", "com.acme.Main.main"], out["mended"])
        self.assertEqual(["jakarta.servlet.Servlet.service", "@com.acme.Handler", "com.acme.Main.main"], out["savedValues"])
        self.assertIn("Saved to jot.yaml. The agent reads it when the application starts.", out["saved"])
        self.assertEqual([True, True], out["savedButtons"], "saved, so nothing is left to save")
        self.assertEqual(list(store.DEFAULT_ENTRY), out["defaultShown"])
        self.assertTrue(out["defaultSummary"].startswith("the default"))
        self.assertTrue(out["defaultSavedSummary"].startswith("the default"))
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], out["reverted"], "revert goes back to what the file says, which is the default list shown")
        with open(path) as f:
            saved = f.read()
        self.assertEqual({"packages": ["com.acme"]}, yaml.safe_load(saved)["app"], "the default took the key out and nothing else")
        self.assertIn("# the application", saved)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_dashboard_that_may_not_write_shows_them_and_cannot_change_them(self):
        env = Env()
        path = os.path.join(env.dir, "jot.yaml")
        with open(path, "w") as f:
            f.write(self.FILE)
        script = """
        (async () => {
          const wait = (ms) => new Promise((r) => setTimeout(r, ms));
          const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
          const out = {};
          try {
            location.hash = "#jots";
            await until(() => document.querySelectorAll("#entryList input").length);
            out.values = [...document.querySelectorAll("#entryList input")].map((i) => i.value);
            out.disabled = [...document.querySelectorAll("#entryList input, #entryList button, #entryInput, #entryAdd, #entrySave, #entryDefault")].every((x) => x.disabled);
            out.status = document.getElementById("entryStatus").textContent;
          } catch (e) { out.error = String(e); }
          const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
        })();
        """
        out = self.serve(server.App(env.db, env.ingestor, jots_file=path, editable=False), script)
        self.assertNotIn("error", out, out)
        self.assertEqual(["javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service"], out["values"])
        self.assertTrue(out["disabled"])
        self.assertIn("Can't be changed here", out["status"])


class ConsolidateTests(unittest.TestCase):
    """One file for all the configuration. The sensors and reports of the files a jots file lists are moved into it, and what is loaded is the same."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "rules", "deep"))
        os.makedirs(os.path.join(self.dir, "lib"))
        self.write("a.jot", "---\n# the observe set\n# Every one of these only records.\n\nsensors:\n\n##### the first part #####\n\n- name: one-a\n  description: Identifies a\n  methods:\n  - a.B.c\n"
                            "  captures:\n    v: '#P0'   # the argument\n\n- name: two-a\n  methods:\n  - a.B.d\n  captures:\n    v: '#P0'\nreports:\n- name: Report A\n  type: list\n  cols: one-a.v\n")
        self.write("rules/deep/r.jot", "# the rules\nsensors:\n- name: rule-r\n  description: Identifies a thing\n  methods:\n  - a.B.e\n  block-when: true\n  protect: false\n")
        self.write("lib/l.jot", "sensors:\n- name: lib-l\n  methods:\n  - a.B.f\n  captures:\n    v: '#P0'\n")
        self.main = self.write("jot.yaml", "# my jots\njots:\n  - a.jot\n  - rules\n  - lib\ncontrol: control.yaml\n# the application\napp:\n  entry:\n    - javax.servlet.Servlet.service\n  packages:\n    - com.acme\nignore:\n  - java.lang.ClassLoader\n")

    def write(self, name, text):
        path = os.path.join(self.dir, name)
        with open(path, "w") as f:
            f.write(text)
        return path

    def read(self, name="jot.yaml"):
        with open(os.path.join(self.dir, name)) as f:
            return f.read()

    def loaded(self, jots):
        db = store.connect(os.path.join(tempfile.mkdtemp(), "t.db"))
        store.init(db)
        paths = store.config_paths(jots)
        n = store.load_sensors(db, paths)
        r = store.load_reports(db, paths)
        sensors = {row[0]: row[1:] for row in db.execute("SELECT name, description, methods, scopes, captures, blocks, protect, matchers, excludes, enabled FROM sensors")}
        reports = {row[0]: row[1:] for row in db.execute("SELECT name, type, rows, cols, value, by FROM reports")}
        return n, r, sensors, reports

    def test_the_jots_file_is_first_so_what_it_says_is_used_over_what_a_listed_file_says(self):
        paths = store.config_paths(self.main)
        self.assertEqual(self.main, paths[0])
        self.assertEqual(3, len(paths) - 1)

    def test_everything_listed_is_moved_into_the_jots_file_and_what_is_loaded_is_the_same(self):
        before = self.loaded(self.main)
        done = store.consolidate(self.main)
        self.assertEqual((4, 1), (done["sensors"], done["reports"]))
        self.assertEqual(["a.jot", os.path.join("rules", "deep", "r.jot"), os.path.join("lib", "l.jot")], done["from"])
        after = self.loaded(self.main)
        self.assertEqual(before[:2], after[:2])
        self.assertEqual(before[2], after[2], "every sensor and rule is defined as it was")
        self.assertEqual(before[3], after[3], "and every report")
        self.assertNotIn("jots", yaml.safe_load(self.read()), "nothing is listed any more")

    def test_the_comments_of_the_files_come_with_their_sensors_and_the_rest_of_the_jots_file_is_as_it_was(self):
        store.consolidate(self.main)
        text = self.read()
        for kept in ("# my jots", "control: control.yaml", "# the application", "app:", "    - javax.servlet.Servlet.service", "    - com.acme", "ignore:", "  - java.lang.ClassLoader"):
            self.assertIn(kept, text, kept)
        for travelled in ("# ---- from a.jot ----", "# the observe set", "# Every one of these only records.", "##### the first part #####", "# the argument",
                          "# ---- from %s ----" % os.path.join("rules", "deep", "r.jot"), "# the rules"):
            self.assertIn(travelled, text, travelled)
        self.assertLess(text.index("# ---- from a.jot"), text.index("name: one-a"))
        self.assertLess(text.index("name: two-a"), text.index("reports:"))

    def test_the_first_definition_of_a_name_wins_as_it_does_for_the_agent_and_what_was_left_out_is_said(self):
        self.write("rules/dup.jot", "sensors:\n- name: one-a\n  description: Identifies the later one\n  methods:\n  - z.Z.z\n  captures:\n    v: '#P0'\nreports:\n- name: Report A\n  type: list\n  cols: two-a.v\n")
        before = self.loaded(self.main)
        done = store.consolidate(self.main)
        self.assertEqual(sorted([("sensor", "one-a"), ("report", "Report A")]), sorted((x["kind"], x["name"]) for x in done["skipped"]))
        self.assertEqual(before[2], self.loaded(self.main)[2])
        self.assertIn("Identifies a\n", self.read(), "the first one is the one that is kept")
        self.assertNotIn("the later one", self.read())

    def test_a_jots_file_that_already_has_sensors_keeps_them_first_and_the_rest_follow_after_them(self):
        self.write("jot.yaml", "jots:\n  - lib\nsensors:\n  - name: own-sensor\n    methods:\n      - a.B.own\n    captures:\n      v: '#P0'\nreports:\n  - name: Own\n    type: list\n    cols: own-sensor.v\n")
        done = store.consolidate(self.main)
        doc = yaml.safe_load(self.read())
        self.assertEqual(["own-sensor", "lib-l"], [x["name"] for x in doc["sensors"]], "its own first, which is also how a name that is in both is settled")
        self.assertEqual(["Own"], [x["name"] for x in doc["reports"]])
        self.assertIn("  # ---- from %s ----" % os.path.join("lib", "l.jot"), self.read(), "lined up with the list that was there")

    def test_what_is_named_to_keep_stays_listed_and_is_still_loaded(self):
        done = store.consolidate(self.main, keep=["lib"])
        self.assertEqual(["lib"], done["kept"])
        self.assertEqual(["lib"], yaml.safe_load(self.read())["jots"])
        n, r, sensors, reports = self.loaded(self.main)
        self.assertIn("lib-l", sensors, "a kept library is read as before")
        self.assertNotIn("lib-l", [x["name"] for x in yaml.safe_load(self.read())["sensors"]], "and its sensors are not copied")
        self.assertEqual(4, n)

    def test_a_listed_file_that_is_not_there_is_said_and_the_rest_is_combined(self):
        self.write("jot.yaml", self.read().replace("  - lib\n", "  - lib\n  - nowhere\n"))
        done = store.consolidate(self.main)
        self.assertEqual([os.path.join(self.dir, "nowhere")], done["missing"])
        self.assertEqual(4, done["sensors"])

    def test_it_is_written_over_the_jots_file_with_a_copy_of_what_was_there_or_somewhere_else_and_nothing_is_touched(self):
        original = self.read()
        files = {n: self.read(n) for n in ("a.jot", os.path.join("rules", "deep", "r.jot"), os.path.join("lib", "l.jot"))}
        done = store.consolidate(self.main, out=os.path.join(self.dir, "one.yaml"))
        self.assertIsNone(done["backup"])
        self.assertEqual(original, self.read(), "the jots file is not touched when the result goes elsewhere")
        self.assertEqual(4, yaml.safe_load(self.read("one.yaml")) and len(yaml.safe_load(self.read("one.yaml"))["sensors"]))
        done = store.consolidate(self.main)
        self.assertEqual(self.main + ".bak", done["backup"])
        with open(done["backup"]) as f:
            self.assertEqual(original, f.read())
        for name, text in files.items():
            self.assertEqual(text, self.read(name), "the files that were listed are left as they were")

    def test_a_dry_run_writes_nothing_and_says_what_would_be_written(self):
        original = self.read()
        done = store.consolidate(self.main, write=False)
        self.assertEqual(original, self.read())
        self.assertFalse(os.path.exists(self.main + ".bak"))
        self.assertIn("name: lib-l", done["text"])

    def test_doing_it_again_changes_nothing(self):
        store.consolidate(self.main)
        once = self.read()
        again = store.consolidate(self.main)
        self.assertEqual(once, self.read())
        self.assertEqual([], again["from"])
        self.assertIsNone(again["backup"], "there was nothing to change, so no copy")

    def test_what_is_not_a_jots_file_is_refused(self):
        self.write("odd.yaml", "- just\n- a list\n")
        with self.assertRaises(store.SaveError):
            store.consolidate(os.path.join(self.dir, "odd.yaml"))

    def test_the_jots_file_with_sensors_in_it_is_not_a_mistake_to_the_dashboard(self):
        store.consolidate(self.main)
        self.assertEqual([], store.jots_file_problems(self.main))

    def test_the_command_line_says_what_it_did_and_a_dry_run_changes_nothing(self):
        import consolidate
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, consolidate.main([self.main, "--keep", "lib", "--dry-run"]))
        said = out.getvalue()
        self.assertIn("Would write 3 sensors and rules and 1 reports", said, "the library is kept where it is, so its sensor isn't one of them")
        self.assertIn("left as they are, listed in jots: lib", said)
        self.assertIn("jots:", self.read(), "a dry run left the file alone")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(0, consolidate.main([self.main]))
        self.assertIn("Wrote 4 sensors and rules and 1 reports", out.getvalue())
        self.assertIn(".bak", out.getvalue())
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertEqual(1, consolidate.main([os.path.join(self.dir, "missing.yaml")]))

    def test_a_sensor_added_to_the_jots_file_goes_into_it_and_is_read_back(self):
        store.consolidate(self.main)
        text = "name: added-here\ndescription: Identifies a thing\nmethods:\n- a.B.added\ncaptures:\n  v: '#P0'\n"
        written = store.add_sensor(store.config_paths(self.main), "jot.yaml", text)
        self.assertEqual(self.main, written)
        self.assertIn("added-here", [x["name"] for x in yaml.safe_load(self.read())["sensors"]])
        self.assertIn("added-here", self.loaded(self.main)[2])


class PageIdTests(unittest.TestCase):
    def test_no_id_is_used_twice_in_the_page(self):
        with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
            page = fh.read()
        ids = re.findall(r'\bid="([^"]+)"', page.split("<script>", 1)[0].split("</style>", 1)[-1])
        twice = sorted({i for i in ids if ids.count(i) > 1})
        self.assertEqual([], twice, "getElementById finds the first, so a repeat is drawn into the wrong place")


class HiddenJotTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.env.write(
            event(1, sensor="http-cache-header", capture="no-store", trace=1),
            event(2, sensor="crypto-hash", capture="MD5", trace=1),
            event(3, sensor="native-process-active", capture="x", trace=1),
            event(4, sensor="native-process-blocked", capture="id", action="blocked", trace=1),
            event(5, sensor="jot-control", capture="protect=off", trace=1))
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)

    def seen(self):
        return sorted(r[0] for r in store.run_query(self.env.db, "SELECT sensor FROM events")["rows"])

    def test_a_hidden_jot_shows_none_of_its_events_and_a_filter_is_only_what_it_says(self):
        self.assertEqual(["crypto-hash", "http-cache-header", "jot-control", "native-process-active", "native-process-blocked"], self.seen())
        status = self.app.set_hidden_jots(["http-cache-header", "native-process"])
        self.assertEqual(["http-cache-header", "native-process"], status["hidden_jots"])
        self.assertEqual(["crypto-hash", "jot-control"], self.seen(), "its -active event and its block are both its events, so both are hidden")
        self.assertEqual(5, store.run_query(self.env.db, "SELECT COUNT(*) FROM events_raw")["rows"][0][0], "nothing is deleted")
        self.assertEqual([], self.app.set_hidden_jots([])["hidden_jots"])
        self.assertEqual(5, len(self.seen()))

    def test_what_a_hidden_rule_blocked_can_still_be_found_by_showing_only_blocked_and_hiding_nothing_else(self):
        self.app.set_hidden_jots(["native-process"])
        self.app.set_filters(actions=["blocked"])
        self.assertEqual([], self.seen(), "hidden is hidden, whatever else is shown")
        self.app.set_hidden_jots([])
        self.assertEqual(["native-process-blocked"], self.seen())

    def test_the_agents_own_events_are_in_the_list_and_hidden_like_the_rest(self):
        self.app.set_hidden_jots(["jot-control"])
        self.assertNotIn("jot-control", self.seen())
        self.assertEqual(["crypto-hash", "http-cache-header", "native-process-active", "native-process-blocked"], self.seen())

    def test_a_report_still_sees_a_hidden_jot_because_it_names_the_sensors_it_needs(self):
        jot = os.path.join(self.env.dir, "r.jot")
        with open(jot, "w") as f:
            f.write("reports:\n- name: Ciphers\n  type: list\n  cols: crypto-hash.algorithm\n")
        store.load_reports(self.env.ingestor.db, [jot])
        self.env.write(event(6, sensor="crypto-hash", capture="SHA-256", data={"algorithm": "SHA-256"}, trace=9))
        self.env.ingestor.poll()
        self.app.set_hidden_jots(["crypto-hash"])
        self.assertNotIn("crypto-hash", self.seen(), "gone from the events")
        sql = next(r for r in self.app.reports() if r["name"] == "Ciphers")["sql"]
        self.assertEqual(["SHA-256"], sorted({r[2] for r in self.app.sql(sql)["rows"]}), "but not from the report")

    def test_the_list_of_jots_has_what_is_in_the_files_and_the_events_with_counts(self):
        with open(os.path.join(self.env.dir, "a.jot"), "w") as f:
            f.write("sensors:\n- name: never-fires\n  methods:\n  - a.b.C.m\n")
        store.load_sensors(self.env.ingestor.db, [self.env.dir])
        jots = {j["name"]: j["events"] for j in self.app.filter_jots()}
        self.assertEqual(0, jots["never-fires"])
        self.assertEqual(2, jots["native-process"], "its -active and -blocked events are one JOT")
        self.assertEqual(1, jots["http-cache-header"])
        self.assertEqual(1, jots["jot-control"], "the agent's own events are a JOT of the list, so there is one way to hide them")

    def test_bad_names_are_refused(self):
        with self.assertRaises(ValueError):
            self.app.set_hidden_jots("http-cache-header")
        with self.assertRaises(ValueError):
            self.app.set_hidden_jots(["x" * 300])

    def test_it_is_remembered_across_a_restart(self):
        self.app.set_hidden_jots(["crypto-hash"])
        again = store.Ingestor(self.env.db, [self.env.log])
        self.assertEqual(["crypto-hash"], store.get_hidden_jots(self.env.db))
        self.assertNotIn("crypto-hash", self.seen())


class FilterDrawerTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const out = {};
      try {
        await until(() => document.getElementById("filtersBtn"));
        out.barHasFilters = !!document.querySelector("#sharedBar #filterActions, #sharedBar #filterOrigins");
        out.barHasClear = !!document.querySelector("#sharedBar #clearBtn");
        out.startsClosed = document.getElementById("filterDrawer").hidden;
        document.getElementById("filtersBtn").click();
        await until(() => document.querySelectorAll("#filterJotList label").length >= 2);
        out.open = !document.getElementById("filterDrawer").hidden;
        out.visible = [...document.querySelectorAll("#filterJotList label")].every((l) => l.offsetHeight > 0 && l.offsetWidth > 0);
        out.listed = [...document.querySelectorAll("#filterJotList label span:not(.n)")].map((x) => x.textContent);
        const box = [...document.querySelectorAll("#filterJotList label")].find((l) => l.textContent.indexOf("http-cache-header") >= 0).querySelector("input");
        out.allTicked = [...document.querySelectorAll("#filterJotList input")].every((b) => b.checked);
        out.startButton = document.getElementById("filtersBtn").textContent;
        out.startShowAllHidden = document.getElementById("showAllBtn").hidden;
        out.startResetOff = document.getElementById("filtersReset").disabled;
        out.startNote = document.getElementById("filtersNote").textContent;
        await until(() => document.querySelectorAll("#filterActions label .n").length === 3 && document.querySelector("#filterOrigins label .n").textContent !== "");
        out.startChecks = [...document.querySelectorAll("#filterActions input, #filterOrigins input")].map((b) => b.checked);
        out.actionLabels = [...document.querySelectorAll("#filterActions label")].map((l) => l.firstElementChild.nextSibling.textContent);
        out.originLabels = [...document.querySelectorAll("#filterOrigins label")].map((l) => l.firstElementChild.nextSibling.textContent);
        out.counts = [...document.querySelectorAll("#filterActions .n, #filterOrigins .n")].map((n) => n.textContent);
        out.paragraphs = document.querySelectorAll("#filterDrawer p").length;
        out.startSince = document.getElementById("filterSince").value;
        // an outcome is unticked to stop showing it, and ticked to show it again
        document.querySelector('#filterActions input[data-value="observed"]').click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters (1)");
        out.afterObserved = { button: document.getElementById("filtersBtn").textContent, shown: (await (await fetch("/api/status")).json()).shown_actions,
          ticked: [...document.querySelectorAll("#filterActions input")].map((b) => b.checked) };
        document.querySelector('#filterActions input[data-value="observed"]').click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters");
        // so is a source
        document.querySelector('#filterOrigins input[data-value="platform"]').click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters (1)");
        out.afterPlatform = (await (await fetch("/api/status")).json()).shown_origins;
        document.getElementById("filtersReset").click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters");
        out.afterOriginReset = [...document.querySelectorAll("#filterOrigins input")].map((b) => b.checked);
        // and the time is a choice of how far back, which reads as Since and the time once it is made
        const since = document.getElementById("filterSince");
        since.value = String(3600000);
        since.dispatchEvent(new Event("change"));
        await until(() => document.getElementById("filtersBtn").textContent === "Filters (1)");
        out.afterTime = { option: document.getElementById("filterSince").selectedOptions[0].textContent, value: document.getElementById("filterSince").value,
          since: (await (await fetch("/api/status")).json()).since };
        document.getElementById("filtersReset").click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters");
        out.afterTimeReset = { value: document.getElementById("filterSince").value, since: (await (await fetch("/api/status")).json()).since };
        await wait(400);       // the list of JOTs is drawn again after each reset, so the box is found again
        [...document.querySelectorAll("#filterJotList label")].find((l) => l.textContent.indexOf("http-cache-header") >= 0).querySelector("input").click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters (1)");
        out.button = document.getElementById("filtersBtn").textContent;
        out.showAllShown = !document.getElementById("showAllBtn").hidden;
        // Show all takes off every filter, not only Clear, and the drawer says so
        document.getElementById("showAllBtn").click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters");
        out.afterReset = (await (await fetch("/api/status")).json()).hidden_jots;
        out.afterResetShowAllHidden = document.getElementById("showAllBtn").hidden;
        await setJotsShown(["http-cache-header"], false);      // and the rest of the test goes on with it hidden
        await until(() => document.getElementById("filtersBtn").textContent === "Filters (1)");
        document.getElementById("filterJotSearch").value = "hash";
        document.getElementById("filterJotSearch").dispatchEvent(new Event("input"));
        out.found = [...document.querySelectorAll("#filterJotList label span:not(.n)")].map((x) => x.textContent);
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" }));
        out.closedByEscape = document.getElementById("filterDrawer").hidden;
        // pointing at a kind of event and pressing H hides its JOT, with a way back
        hoverNode = { kind: "effect", label: "crypto-hash-blocked", events: 1, captures: [] };
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "h" }));
        await wait(300);
        out.blockedKept = document.getElementById("hideToast").hidden;
        hoverNode = { kind: "effect", label: "crypto-hash", events: 1, captures: [] };
        document.dispatchEvent(new KeyboardEvent("keydown", { key: "h" }));
        await until(() => !document.getElementById("hideToast").hidden);
        out.toast = document.getElementById("hideToast").textContent;
        out.hiddenAfterH = (await (await fetch("/api/status")).json()).hidden_jots;
        [...document.querySelectorAll("#hideToast button")].find((b) => b.textContent === "Undo").click();
        await until(async () => true);
        await wait(400);
        out.hiddenAfterUndo = (await (await fetch("/api/status")).json()).hidden_jots;
        // a method of the application becomes a JOT to start from, in the editor of the JOTs page
        out.frame = JotGraph.frameMethod("org.hsqldb.jdbc.JDBCStatement.executeUpdate(Unknown Source)");
        await sensorFromNode({ full: "com.acme.Ticket.encrypt" });
        await until(() => draft.editor);
        out.page = currentPage;
        out.started = draft.editor.get();
        out.cells = [["true"], ["false"], ["true", "false"], ["AES"], ["X"]].map((v) => gridCell(v).className);
        out.items = [...gridCell(["true", "false"]).querySelectorAll("li")].map((li) => li.className);
        out.named = [...gridCell(["false", "true"], { true: ["UserB"], false: ["UserA", "UserC"] }).querySelectorAll("li")].map((li) => li.textContent);
        out.namedOthers = gridCell(["AES"], { AES: ["UserA", "UserB"] }).textContent;
        location.hash = "#graph";
        await wait(300);
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_filters_are_in_a_drawer_and_a_jot_can_be_hidden_from_it(self):
        env = Env()
        env.write(event(1, sensor="http-cache-header", capture="no-store"), event(2, sensor="crypto-hash", capture="MD5"))
        env.ingestor.poll()
        app = server.App(env.db, env.ingestor)
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--virtual-time-budget=20000", "--dump-dom", "http://127.0.0.1:%d/" % port],
                              capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        self.assertFalse(out["barHasFilters"], "the filters moved off the bar")
        self.assertTrue(out["barHasClear"], "Clear stays on the bar")
        self.assertTrue(out["startsClosed"])
        self.assertTrue(out["open"])
        self.assertTrue(out["visible"], "the checkboxes are on screen, not in some other list")
        self.assertEqual(["crypto-hash", "http-cache-header"], out["listed"])
        self.assertTrue(out["allTicked"], "every JOT starts ticked, which is shown")
        self.assertEqual("Filters", out["startButton"], "with no filter on the button has no count")
        self.assertEqual((True, True), (out["startShowAllHidden"], out["startResetOff"]), "and there is nothing to take off")
        self.assertEqual("Showing everything", out["startNote"])
        self.assertEqual([True] * 7, out["startChecks"], "every outcome and every source is ticked before anything is chosen, so every event shows")
        self.assertEqual(["Observed", "Reported only", "Blocked"], out["actionLabels"])
        self.assertEqual(["Application", "Libraries", "JDK and server", "No stack"], out["originLabels"])
        self.assertTrue(all(c for c in out["counts"]), "each choice says how many events it covers, %s" % out["counts"])
        self.assertEqual(0, out["paragraphs"], "and nothing needs a paragraph to explain it")
        self.assertEqual("", out["startSince"], "the time starts at all of it")
        self.assertEqual(("Filters (1)", ["monitored", "blocked"], [False, True, True]),
                         (out["afterObserved"]["button"], out["afterObserved"]["shown"], out["afterObserved"]["ticked"]), "unticking an outcome stops showing it")
        self.assertEqual(["app", "library", "none"], out["afterPlatform"])
        self.assertEqual([True] * 4, out["afterOriginReset"], "Show everything ticks them all again")
        self.assertTrue(out["afterTime"]["option"].startswith("Since "), out["afterTime"])
        self.assertEqual(("since", True), (out["afterTime"]["value"], out["afterTime"]["since"] is not None))
        self.assertEqual(("", None), (out["afterTimeReset"]["value"], out["afterTimeReset"]["since"]))
        self.assertEqual("Filters (1)", out["button"], "the button says how many filters are on")
        self.assertTrue(out["showAllShown"], "and Show all is there whenever one is")
        self.assertEqual(([], True), (out["afterReset"], out["afterResetShowAllHidden"]), "Show all takes off a hidden JOT too")
        self.assertEqual(["crypto-hash"], out["found"])
        self.assertTrue(out["closedByEscape"])
        self.assertTrue(out["blockedKept"], "what a rule blocked can't be hidden")
        self.assertIn("Hid crypto-hash", out["toast"])
        self.assertEqual(["crypto-hash", "http-cache-header"], out["hiddenAfterH"])
        self.assertEqual(["http-cache-header"], out["hiddenAfterUndo"])
        self.assertEqual(["http-cache-header"], store.get_hidden_jots(env.db))
        self.assertEqual(["on vals yes", "on vals no", "on vals mixed", "on vals ", "on"], out["cells"], "true is green and false is red")
        self.assertEqual(["yes", "no"], out["items"])
        self.assertEqual(["false", "true (UserB)"], out["named"], "who is named for true, not for false")
        self.assertEqual("AES (UserA, UserB)", out["namedOthers"], "and for every value that isn't an answer")
        self.assertEqual("jots", out["page"])
        self.assertTrue(out["started"].startswith("name: ticket-encrypt\ndescription: Identifies calls to Ticket.encrypt\n"), out["started"])
        self.assertEqual([], store.check_draft(out["started"]), "what it starts with passes the same checks as a draft")


class JotEventsLinkTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const out = {};
      try {
        location.hash = "#jots/crypto-cipher/edit";
        await until(() => (document.querySelector("#jotDetail h2") || {}).textContent === "crypto-cipher");
        [...document.querySelectorAll("#jotDetail button")].find((b) => b.textContent === "Show its events").click();
        // the events page already lists recent events, so wait for the result this button asked for
        await until(() => (document.querySelector("#results h2") || {}).textContent === "Events from crypto-cipher");
        out.rows = document.querySelectorAll("#results tr").length - 1;
        out.clickable = document.querySelectorAll("#results tr.clickable").length;
        out.columns = [...document.querySelectorAll("#results th")].map((th) => th.textContent);
        const withData = [...document.querySelectorAll("#results tr.clickable")].find((tr) => tr.textContent.indexOf("bits=128") >= 0);
        withData.click();
        await until(() => location.hash.indexOf("#event/") === 0);
        await until(() => { const d = document.getElementById("eventDrawer"); return d && !d.hidden && d.innerText.indexOf("crypto-cipher") >= 0; });
        out.hash = location.hash;
        out.drawer = document.getElementById("eventDrawer").innerText;
        // each frame that is a method can start a JOT
        const marks = [...document.querySelectorAll("#eventDrawer .frames .mk")];
        out.marks = marks.length;
        marks[0].click();
        await until(() => typeof draft !== "undefined" && draft.editor);
        out.page = currentPage;
        out.started = draft.editor.get();
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_show_its_events_lists_events_that_open_the_event_drawer_when_clicked(self):
        env = Env()
        with open(os.path.join(env.dir, "a.jot"), "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Records ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n  captures:\n    value: '#P0'\n")
        store.load_sensors(env.ingestor.db, [env.dir])
        env.write(event(1, capture="algorithm=AES, bits=128", data={"algorithm": "AES", "bits": 128, "modes": ["CBC", "GCM"]},
                  stack=["org.hsqldb.jdbc.JDBCStatement.executeUpdate(Unknown Source)", "com.acme.Ticket.encrypt(Ticket.java:125)", "a"]), event(2, capture="DES"))
        env.ingestor.poll()
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir])
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--virtual-time-budget=20000", "--dump-dom", "http://127.0.0.1:%d/" % port],
                              capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        self.assertEqual(2, out["rows"], "the two events of that sensor")
        self.assertEqual(2, out["clickable"], "every row opens its event")
        self.assertNotIn("pk", out["columns"], "the id is used and not shown")
        self.assertTrue(out["hash"].startswith("#event/"))
        self.assertIn("crypto-cipher", out["drawer"])
        self.assertEqual(2, out["marks"], "the two frames that are methods, not the one called a")
        self.assertEqual("jots", out["page"])
        self.assertTrue(out["started"].startswith("name: jdbc-statement-execute-update\n"), out["started"])
        self.assertIn("- org.hsqldb.jdbc.JDBCStatement.executeUpdate\n", out["started"])
        for shown in ("algorithm", "AES", "bits", "128", "modes", "CBC", "GCM"):
            self.assertIn(shown, out["drawer"], "the drawer shows each captured field by name")


class AlwaysCurrentTests(unittest.TestCase):
    def test_the_page_refreshes_itself_every_three_seconds_with_nothing_to_switch_on_or_press(self):
        with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
            page = fh.read()
        for gone in ('id="refreshBtn"', 'id="live"', 'id="updated"', 'id="graphRefresh"', "Refresh every 3 seconds", ">Refresh<", "jot-live"):
            self.assertNotIn(gone, page)
        self.assertIn("timer = setInterval(tick, 3000);", page)
        self.assertNotIn("setInterval(tick, 6000)", page)


class SaveFlowTests(unittest.TestCase):
    CHROME = DraftUiTests.CHROME

    # runs in the page. It edits a sensor in the editor, presses Save, and says what the page looks like afterwards
    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const button = (text) => [...document.querySelectorAll("#jotDetail button")].find((b) => b.textContent === text);
      const out = {};
      try {
        location.hash = "#jots/crypto-cipher/edit";
        await until(() => document.querySelector("#jotDetail .cm-content"));
        const first = keptEditor.editor;
        keptEditor.editor.set(keptEditor.editor.get().replace("Records ciphers", "Records every cipher"));
        await until(() => button("Save") && !button("Save").disabled);
        out.saveWasOn = !!button("Save") && !button("Save").disabled;
        button("Save").click();
        await until(() => /Saved to/.test(document.getElementById("jotDetail").innerText));
        await wait(3500);                      // past a refresh of the page too
        const status = document.querySelector("#jotDetail .editstatus");
        out.status = status ? status.textContent : null;
        out.dirty = editorDirty();
        out.replacedEditor = keptEditor.editor !== first;
        out.text = keptEditor.editor.get();
        out.saveDisabled = button("Save").disabled;
        out.revertHidden = [...document.querySelectorAll("#jotDetail button")].find((b) => b.textContent === "Revert").hidden;
        // and leaving is allowed now
        button("Close").click();
        await wait(300);
        out.closed = document.getElementById("jotDetail").hidden;
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    HEAD = """
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 5000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const button = (text) => [...document.querySelectorAll("#jotDetail button")].find((b) => b.textContent === text);
    """

    def page(self, body, extra=""):
        """Opens the dashboard in Chrome on a file with one sensor, and extra after it, runs body in the page, and returns what it put in out, and the path."""
        env = Env()
        path = os.path.join(env.dir, "a.jot")
        with open(path, "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Records ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n  captures:\n    value: '#P0'\n" + extra)
        store.load_sensors(env.ingestor.db, [env.dir])
        store.load_reports(env.ingestor.db, [env.dir])
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir], editable=True)
        script = "(async () => { %s const out = {}; try { %s } catch (e) { out.error = String(e); } " \
                 "const pre = document.createElement('pre'); pre.id = 'testResult'; pre.textContent = JSON.stringify(out); document.body.append(pre); })();" % (self.HEAD, body)

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--virtual-time-budget=40000", "--dump-dom", "http://127.0.0.1:%d/" % port],
                              capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        return out, path

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_typed_changes_survive_a_refresh_and_hold_you_until_they_are_saved_or_reverted(self):
        out, path = self.page("""
          location.hash = "#jots/crypto-cipher/edit";
          await until(() => document.querySelector("#jotDetail .cm-content"));
          const first = keptEditor.editor;
          first.set(first.get().replace("Records ciphers", "Typed but not saved"));
          await wait(3800);                                   // the page refreshes its data and draws the drawer again
          out.sameEditor = keptEditor.editor === first;
          out.text = keptEditor.editor.get();
          button("Close").click();
          await wait(300);
          out.stillOpen = !document.getElementById("jotDetail").hidden;
          out.warned = /aren't saved/.test(document.querySelector("#jotDetail .editstatus").textContent);
          button("Revert").click();
          await wait(200);
          out.reverted = keptEditor.editor.get().indexOf("Records ciphers") >= 0;
          button("Close").click();
          await wait(300);
          out.closedAfterRevert = document.getElementById("jotDetail").hidden;
        """)
        self.assertTrue(out["sameEditor"], "a refresh doesn't throw the typing away")
        self.assertIn("Typed but not saved", out["text"])
        self.assertTrue(out["stillOpen"], "unsaved typing holds you in the drawer")
        self.assertTrue(out["warned"])
        self.assertTrue(out["reverted"])
        self.assertTrue(out["closedAfterRevert"], "and Revert lets you go")
        with open(path) as f:
            self.assertIn("Records ciphers", f.read(), "nothing was written")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_sensor_row_shows_its_report_and_the_edit_button_opens_the_drawer(self):
        out, path = self.page("""
          location.hash = "#jots";
          await until(() => document.querySelector("#jotList tbody tr"));
          document.querySelector("#jotList tbody tr").click();
          await until(() => !document.getElementById("sensorResult").hidden && document.querySelector("#sensorResult .explain"));
          out.result = document.querySelector("#sensorResult h2").textContent;
          out.explain = document.querySelector("#sensorResult .explain").textContent;
          out.hash = location.hash;
          out.drawerShut = document.getElementById("jotDetail").hidden;
          [...document.querySelectorAll("#jotList tbody button")].find((b) => b.textContent === "Edit").click();
          await until(() => document.querySelector("#jotDetail .cm-content"));
          out.drawerOpen = !document.getElementById("jotDetail").hidden;
          out.editHash = location.hash;
          button("Close").click();
          await wait(300);
          out.closedHash = location.hash;
          out.resultStays = !document.getElementById("sensorResult").hidden;
        """)
        self.assertEqual("crypto-cipher", out["result"])
        self.assertIn("One row for each entry point", out["explain"])
        self.assertIn("value", out["explain"], "and a column for each capture")
        self.assertEqual("#jots/crypto-cipher", out["hash"])
        self.assertTrue(out["drawerShut"], "a click on the row doesn't open the drawer")
        self.assertTrue(out["drawerOpen"])
        self.assertEqual("#jots/crypto-cipher/edit", out["editHash"])
        self.assertEqual("#jots/crypto-cipher", out["closedHash"])
        self.assertTrue(out["resultStays"])

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_report_can_be_edited_and_saved_from_its_edit_button(self):
        out, path = self.page("""
          location.hash = "#reports";
          await until(() => document.querySelector("#reportList tbody tr"));
          document.querySelector("#reportList tbody tr").click();
          await until(() => !document.getElementById("reportResult").hidden);
          out.drawerShut = document.getElementById("jotDetail").hidden;
          [...document.querySelectorAll("#reportList tbody button")].find((b) => b.textContent === "Edit").click();
          await until(() => document.querySelector("#jotDetail .cm-content"));
          out.title = document.querySelector("#jotDetail h2").textContent;
          keptEditor.editor.set(keptEditor.editor.get().replace("Codes", "Renamed Codes"));
          await until(() => button("Save") && !button("Save").disabled);
          button("Save").click();
          await until(() => /Renamed Codes/.test(document.getElementById("jotDetail").innerText) && /Saved to|Renamed to/.test(document.getElementById("jotDetail").innerText));
          out.status = document.querySelector("#jotDetail .editstatus").textContent;
          out.hash = location.hash;
          await wait(500);
          out.shown = document.querySelector("#reportResult h2").textContent;
        """, extra="reports:\n- name: Codes\n  type: list\n  cols: crypto-cipher.value\n")
        self.assertTrue(out["drawerShut"])
        self.assertEqual("Codes", out["title"])
        self.assertIn("Renamed to Renamed Codes", out["status"])
        self.assertEqual("#reports/Renamed%20Codes/edit", out["hash"])
        self.assertEqual("Renamed Codes", out["shown"], "the result under the list follows the rename")
        with open(path) as f:
            self.assertIn("name: Renamed Codes", f.read())

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_deleting_a_sensor_that_a_report_reads_warns_and_offers_the_assistant(self):
        out, path = self.page("""
          location.hash = "#jots/crypto-cipher/edit";
          await until(() => document.querySelector("#jotDetail .cm-content"));
          button("Delete").click();
          await wait(200);
          const box = [...document.querySelectorAll("#jotDetail .notice")].find((n) => /breaks/.test(n.textContent));
          out.warning = box && !box.hidden ? box.textContent : null;
          out.buttons = box ? [...box.querySelectorAll("button")].map((b) => b.textContent) : [];
          out.stillOpen = !document.getElementById("jotDetail").hidden;
          button("Cancel").click();
          await wait(100);
          out.hidden = box.hidden;
        """, extra="reports:\n- name: Codes\n  type: list\n  cols: crypto-cipher.value\n")
        self.assertIn("Deleting crypto-cipher breaks a report. Codes reads it", out["warning"])
        self.assertEqual(["Delete anyway", "Ask the Assistant to clean up", "Cancel"], out["buttons"])
        self.assertTrue(out["stillOpen"], "nothing is deleted until the person says so")
        self.assertTrue(out["hidden"])
        with open(path) as f:
            self.assertIn("name: crypto-cipher", f.read())

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_delete_asks_twice_and_then_removes_the_report(self):
        out, path = self.page("""
          location.hash = "#reports/Codes/edit";
          await until(() => document.querySelector("#jotDetail .cm-content"));
          button("Delete").click();
          await wait(200);
          out.asked = button("Click again to delete") ? document.querySelector("#jotDetail .editstatus").textContent : null;
          out.stillThere = !!document.querySelector("#reportList tbody tr");
          button("Click again to delete").click();
          await until(() => document.getElementById("jotDetail").hidden);
          await wait(500);
          out.rows = document.querySelectorAll("#reportList tbody tr").length;
          out.note = document.getElementById("reportSummary").textContent;
          out.resultHidden = document.getElementById("reportResult").hidden;
        """, extra="reports:\n- name: Codes\n  type: list\n  cols: crypto-cipher.value\n")
        self.assertIn("removes Codes from a.jot", out["asked"])
        self.assertTrue(out["stillThere"], "one click deletes nothing")
        self.assertEqual(0, out["rows"])
        self.assertIn("Deleted Codes from a.jot", out["note"])
        self.assertTrue(out["resultHidden"])
        with open(path) as f:
            self.assertNotIn("Codes", f.read())

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_rename_ends_clean_on_the_new_name(self):
        out, path = self.page("""
          location.hash = "#jots/crypto-cipher/edit";
          await until(() => document.querySelector("#jotDetail .cm-content"));
          keptEditor.editor.set(keptEditor.editor.get().replace("name: crypto-cipher", "name: crypto-cipher-use"));
          await until(() => button("Save") && !button("Save").disabled);
          button("Save").click();
          await until(() => /Renamed to crypto-cipher-use/.test(document.getElementById("jotDetail").innerText));
          await wait(3500);
          out.title = document.querySelector("#jotDetail h2").textContent;
          out.hash = location.hash;
          out.dirty = editorDirty();
          out.status = document.querySelector("#jotDetail .editstatus").textContent;
          button("Close").click();
          await wait(300);
          out.closed = document.getElementById("jotDetail").hidden;
        """)
        self.assertEqual("crypto-cipher-use", out["title"])
        self.assertEqual("#jots/crypto-cipher-use/edit", out["hash"])
        self.assertFalse(out["dirty"])
        self.assertIn("Renamed to crypto-cipher-use", out["status"])
        self.assertTrue(out["closed"])
        with open(path) as f:
            self.assertIn("name: crypto-cipher-use", f.read())

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_after_a_save_the_editor_is_clean_says_saved_and_lets_you_leave(self):
        env = Env()
        path = os.path.join(env.dir, "a.jot")
        with open(path, "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Records ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n  captures:\n    value: '#P0'\n")
        store.load_sensors(env.ingestor.db, [env.dir])
        app = server.App(env.db, env.ingestor, jot_paths=[env.dir], editable=True)
        script = self.SCRIPT

        class Injected(server.Handler):
            def do_GET(self):
                if self.path.split("?")[0] in ("/", "/index.html"):
                    with open(os.path.join(server.HERE, "static", "index.html"), encoding="utf-8") as fh:
                        html = fh.read().replace("</body>", "<script>" + script + "</script></body>")
                    return self._send(200, html.encode(), "text/html; charset=utf-8")
                return super().do_GET()

        httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), type("H", (Injected,), {"app": app, "port": 0, "enforce_host": True}))
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run", "--user-data-dir=" + tempfile.mkdtemp(),
                               "--virtual-time-budget=30000", "--dump-dom", "http://127.0.0.1:%d/" % port],
                              capture_output=True, text=True, timeout=120)
        found = re.search(r'<pre id="testResult">(.*?)</pre>', done.stdout, re.S)
        self.assertIsNotNone(found, done.stdout[-600:])
        import html as htmllib
        out = json.loads(htmllib.unescape(found.group(1)))
        self.assertNotIn("error", out, out)
        self.assertTrue(out["saveWasOn"])
        with open(path) as f:
            self.assertIn("Records every cipher", f.read(), "it was written")
        self.assertIn("Saved to a.jot", out["status"], "the editor says so, and doesn't say there is something unsaved")
        self.assertNotIn("aren't saved", out["status"])
        self.assertFalse(out["dirty"], "what is in the editor is what the file says")
        self.assertTrue(out["replacedEditor"], "it is drawn again from the file")
        self.assertIn("Records every cipher", out["text"])
        self.assertTrue(out["saveDisabled"])
        self.assertTrue(out["revertHidden"])
        self.assertTrue(out["closed"], "nothing holds you in the drawer")


class AgentProblemsTests(unittest.TestCase):
    def test_what_the_agent_left_out_is_listed_with_the_issues(self):
        env = Env()
        env.write(event(1, sensor="jot-config", capture="lock=none", trace=None),
                  event(2, sensor="jot-config", capture="loaded=http-route", trace=None),
                  event(3, sensor="jot-config", capture="problem=old.jot old-rule exception is no longer a setting, use block-when", trace=None))
        env.ingestor.poll()
        app = server.App(env.db, env.ingestor)
        self.assertEqual(["old.jot old-rule exception is no longer a setting, use block-when"], app.agent_state()["problems"])
        texts = [i["text"] for i in app.jots()["issues"]]
        self.assertIn("the agent left something out, old.jot old-rule exception is no longer a setting, use block-when", texts)


class BlockWhenStoreTests(unittest.TestCase):
    def test_the_condition_of_a_rule_is_kept_and_a_sensor_has_none(self):
        env = Env()
        with open(os.path.join(env.dir, "r.jot"), "w") as f:
            f.write("sensors:\n- name: always\n  methods:\n  - a.b.C.m\n  block-when: true\n"
                    "- name: small\n  methods:\n  - a.b.C.n\n  block-when: '#P0 < 2048'\n"
                    "- name: plain\n  methods:\n  - a.b.C.p\n")
        store.load_sensors(env.ingestor.db, [env.dir])
        rows = dict(store.run_query(env.db, "SELECT name, blocks FROM sensors")["rows"])
        self.assertEqual({"always": "true", "small": "#P0 < 2048", "plain": None}, rows)
        app = server.App(env.db, env.ingestor)
        kinds = {s["name"]: (s["kind"], s["block_when"]) for s in app.jots()["sensors"]}
        self.assertEqual({"always": ("rule", "true"), "small": ("rule", "#P0 < 2048"), "plain": ("sensor", None)}, kinds)


class CheckJotTests(unittest.TestCase):
    ROOT = os.path.join(os.path.dirname(__file__), "..", "..")

    def test_a_sensor_on_its_own_and_a_whole_file_are_both_fine(self):
        one = "name: http-route\nmethods:\n- javax.servlet.Servlet.service\ncaptures:\n  value: '#P0'\n"
        self.assertEqual([], store.check_jot_text(one))
        self.assertEqual([], store.check_jot_text("sensors:\n- " + one.replace("\n", "\n  ").rstrip(" ")))

    def test_every_real_jot_passes_as_it_is_shown_and_as_a_file(self):
        found = 0
        real = [p for where in ("cves", "src/main/resources") for p in glob.glob(os.path.join(self.ROOT, where, "*.jot"))]
        real.append(os.path.join(self.ROOT, "demo", "ticketbook", ".jot", "jot.yaml"))      # the demo's configuration is one file
        for path in real:
            with open(path) as fh:
                text = fh.read()
            problems = store.check_jot_text(text)
            if "src/main/resources" in path:   # get-header is defined twice in ticketbook.jot, the agent skips the second
                problems = [p for p in problems if "used twice" not in p["message"]]
            self.assertEqual([], problems, path)
            for sensor in (yaml.safe_load(text) or {}).get("sensors") or []:
                if sensor.get("name") != "example":
                    self.assertEqual([], store.check_jot_text(yaml.safe_dump(sensor, sort_keys=False)), sensor["name"])
                    found += 1
        self.assertGreater(found, 20)

    def test_a_missing_quote_that_changes_the_meaning_is_found(self):
        text = ("name: ok\nmethods:\n- a.b.C.m\ncaptures:\n  a: #P0\n  b: !null\n  c: 123\n  d: yes\nmatchers:\n  a:\n  - null\n"
                "  - '!null'\n  - \"#P0\"\ndescription: 5\n")
        problems = store.check_jot_text(text)
        self.assertEqual({5, 6, 7, 8, 11, 14}, {p["line"] for p in problems}, "the quoted ones on lines 12 and 13 are fine")
        self.assertTrue(all("quotes" in p["message"] for p in problems))
        with self.assertRaises(store.SaveError):
            store.save_sensor([], "ok", text, text)

    def test_captures_and_matchers_are_fields(self):
        base = "name: r\nmethods:\n- a.b.C.m\n"
        self.assertEqual([], store.check_jot_text(base + "captures:\n  path: '#P0'\n  size: '#P1'\nmatchers:\n  path:\n  - '!null'\n"))
        said = lambda text: " | ".join(p["message"] for p in store.check_jot_text(base + text))
        self.assertIn("captures must be names and expressions", said("captures:\n- '#P0'\n"))
        self.assertIn("Path should be a lower case name", said("captures:\n  Path: '#P0'\n"))
        self.assertIn("name is not a captured field, the fields are path", said("captures:\n  path: '#P0'\nmatchers:\n  name:\n  - x\n"))
        self.assertIn("matchers must be a captured field", said("captures:\n  path: '#P0'\nmatchers:\n- x\n"))
        self.assertIn("isn't a valid pattern", said("captures:\n  path: '#P0'\nmatchers:\n  path:\n  - '(open'\n"))

    def test_block_when_is_a_rule_whether_true_or_an_expression(self):
        for text in ("name: r\nmethods:\n- a.b.C.m\nblock-when: true\n",
                     "name: r\nmethods:\n- a.b.C.m\ncaptures:\n  value: '#P0'\nblock-when: '#P0 < 2048'\nprotect: false\n"):
            self.assertEqual([], store.check_jot_text(text), text)
        for text, line in (("name: r\nmethods:\n- a.b.C.m\nblock-when:\n", 4), ("name: r\nmethods:\n- a.b.C.m\nblock-when: 5\n", 4),
                           ("name: r\nmethods:\n- a.b.C.m\nprotect: false\n", 4)):
            problems = store.check_jot_text(text)
            self.assertEqual([line], [p["line"] for p in problems], text)

    def test_the_removed_exception_key_is_flagged_in_the_editor_and_when_loading(self):
        text = "name: r\nmethods:\n- a.b.C.m\nexception: Not allowed\n"
        problems = store.check_jot_text(text)
        self.assertEqual([4], [p["line"] for p in problems], "the editor won't save it")
        self.assertIn("exception isn't something a sensor has", problems[0]["message"])
        env = Env()
        with open(os.path.join(env.dir, "old.jot"), "w") as f:
            f.write("sensors:\n- name: old-rule\n  methods:\n  - a.b.C.m\n  exception: Not allowed\n")
        store.load_sensors(env.ingestor.db, [env.dir])
        issues = [t for (t,) in store.run_query(env.db, "SELECT text FROM jot_issues")["rows"]]
        self.assertTrue(any("old-rule has exception, which is no longer a setting" in t and "block-when" in t for t in issues), issues)
        rule = next(s for s in server.App(env.db, env.ingestor).jots()["sensors"] if s["name"] == "old-rule")
        self.assertEqual("sensor", rule["kind"], "it only observes, as the agent will treat it")

    def test_problems_are_found_on_their_lines(self):
        problems = store.check_jot_text("name: Bad_Name\nmethods:\n- foo\nmatchers:\n  value:\n  - '(open'\nenabled: maybe\ncolour: red\n")
        self.assertEqual({1, 3, 6, 7, 8}, {p["line"] for p in problems})
        self.assertEqual("is empty", store.check_jot_text("")[0]["message"])
        self.assertIn(store.check_jot_text("name: x\nmethods: [a.b.C.m\n- y\n")[0]["line"], (3, 4), "a YAML mistake is marked where it is found")


class LocalOnlyTests(unittest.TestCase):
    def test_a_host_other_than_localhost_is_refused_without_allow_remote(self):
        for host in ("0.0.0.0", "192.168.1.5", "::"):
            with self.assertRaises(SystemExit) as raised, contextlib.redirect_stderr(io.StringIO()) as err:
                server.main(["--host", host, "--db", ":memory:"])
            self.assertEqual(2, raised.exception.code)
            self.assertIn("--allow-remote", err.getvalue())


class OriginTests(unittest.TestCase):
    PREFIXES = ["com.acme", "org.apache.jsp"]

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = os.path.join(self.dir, "e.jsonl")
        self.db = os.path.join(self.dir, "t.db")
        open(self.log, "w").close()

    def ingestor(self, prefixes=None):
        return store.Ingestor(self.db, [self.log], app_prefixes=self.PREFIXES if prefixes is None else prefixes)

    def write(self, *events):
        with open(self.log, "a") as f:
            for e in events:
                f.write(json.dumps(e) + "\n")

    def origins(self, view="events_raw"):
        return dict(store.run_query(self.db, "SELECT id, origin FROM %s ORDER BY id" % view)["rows"])

    def test_classify(self):
        c = lambda stack: store.classify(stack, self.PREFIXES)
        self.assertEqual(c(JDK_ONLY), ("platform", None))
        self.assertEqual(c(LIBRARY_ONLY), ("library", None))
        self.assertEqual(c(VIA_LIBRARY)[0], "app")
        self.assertEqual(c(VIA_LIBRARY)[1], "com.acme.ticketbook.Ticket.save(Ticket.java:40)")
        self.assertEqual(c(JSP)[0], "app", "a compiled page is the application, not the server")
        self.assertEqual(c(None), ("none", None))
        self.assertEqual(c([]), ("none", None))
        request = ["jakarta.servlet.http.HttpServlet.service(HttpServlet.java:710)",
                   "org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:132)"]
        self.assertEqual(c(request)[0], "app", "a request handed to a servlet is the application's")

    def test_class_loading_and_page_compiling_by_the_platform_are_not_the_application(self):
        c = lambda stack: store.classify(stack, self.PREFIXES)
        self.assertEqual(("platform", None), c(CLASSLOAD), "the application is further out, but it did nothing")
        self.assertEqual(c(CLASSLOAD_AFTER_LIBRARY)[0], "app", "a library's own code ran first, so it is not just the platform")
        self.assertEqual(c(CLASSLOAD_AFTER_APP)[0], "app", "the application's class initializer ran first")
        self.assertEqual(c(CLASSLOAD_AFTER_APP)[1], "com.acme.ticketbook.Ticket.<clinit>(Ticket.java:12)")

    def test_the_ignore_list_from_the_jots_file_says_what_counts_as_platform_work(self):
        self.addCleanup(store.set_ignore, None)
        c = lambda stack: store.classify(stack, ["com.acme"])
        self.assertEqual("platform", c(CLASSLOAD)[0], "the default list")
        store.set_ignore(["javax.vendor"])
        self.assertNotEqual("platform", c(CLASSLOAD)[0], "a list replaces the default")
        store.set_ignore([])
        self.assertNotEqual("platform", c(CLASSLOAD)[0], "an empty list ignores nothing")
        store.set_ignore(None)
        self.assertEqual("platform", c(CLASSLOAD)[0])
        # an entry matches itself and what is inside it, not a name that merely starts the same
        store.set_ignore(["java.lang.ClassLoader"])
        self.assertTrue(store._is_work("java.lang.ClassLoader.loadClass"))
        self.assertTrue(store._is_work("java.lang.ClassLoader$Inner.run"))
        self.assertFalse(store._is_work("java.lang.ClassLoaderHelper.load"))

    def test_read_ignore_gives_the_list_or_none_so_the_default_is_used(self):
        with tempfile.TemporaryDirectory() as d:
            def write(text):
                path = os.path.join(d, "jot.yaml")
                with open(path, "w") as f:
                    f.write(text)
                return path
            self.assertEqual(["a.B", "c.D.e"], store.read_ignore(write("jots: []\nignore:\n- a.B\n- ' c.D.e '\n")))
            self.assertEqual([], store.read_ignore(write("ignore: []\n")))
            self.assertIsNone(store.read_ignore(write("jots: []\n")), "no list is the default")
            self.assertIsNone(store.read_ignore(write("ignore: a.B\n")), "not a list, the agent says so and uses the default")
            self.assertIsNone(store.read_ignore(write("ignore:\n- 5\n")))

    def test_changing_the_ignore_list_tags_the_stored_events_again(self):
        self.addCleanup(store.set_ignore, None)
        env = Env()
        env.write(event(1, sensor="crypto-hash", capture="SHA-256", stack=CLASSLOAD))
        env.ingestor.poll()
        origin = lambda: store.run_query(env.db, "SELECT origin FROM events_raw")["rows"][0][0]
        self.assertEqual("platform", origin())
        store.set_ignore([])
        store.retag(env.ingestor.db, ["com.acme"])
        self.assertNotEqual("platform", origin(), "what was ignored before no longer is")

    def test_tls_the_application_started_stays_but_tls_for_class_loading_does_not(self):
        c = lambda stack: store.classify(stack, self.PREFIXES)
        self.assertEqual("app", c(TLS)[0], "a page fetched an https address, so the handshake is its doing")
        self.assertEqual(c(TLS)[1], "org.apache.jsp.ssrf_jsp._jspService(ssrf_jsp.java:156)")
        self.assertEqual(("platform", None), c(TLS_FOR_CLASSLOADING), "the same handshake, but the JDK was loading a class")
        self.assertEqual("app", c(DIRECT_HASH)[0])
        self.assertEqual("app", c(JAR_FROM_URL)[0], "a page opening a jar from a url is worth seeing")
        direct = ["java.base/java.lang.ClassLoader.defineClass(ClassLoader.java:1)", "org.apache.jsp.a_jsp._jspService(a.java:1)"]
        self.assertEqual("app", c(direct)[0], "the call the sensor watches is never the work, a page can ask for it directly")

    def test_without_packages_anything_but_the_platform_is_the_application(self):
        self.assertEqual(store.classify(LIBRARY_ONLY)[0], "app")
        self.assertEqual(store.classify(JDK_ONLY)[0], "platform")

    def test_events_are_tagged_when_stored(self):
        ing = self.ingestor()
        self.write(event(1, stack=JDK_ONLY), event(2, stack=VIA_LIBRARY), event(3, stack=LIBRARY_ONLY), event(4, stack=JSP),
                   event(5, stack=CLASSLOAD), event(6, stack=TLS), event(7, stack=DIRECT_HASH),
                   event(8, stack=TLS_FOR_CLASSLOADING))
        ing.poll()
        self.assertEqual(self.origins(), {1: "platform", 2: "app", 3: "library", 4: "app", 5: "platform", 6: "app", 7: "app",
                                          8: "platform"})

    def test_every_origin_is_shown_until_it_is_hidden_and_each_is_hidden_on_its_own(self):
        ing = self.ingestor()
        self.write(event(1, stack=JDK_ONLY), event(2, stack=VIA_LIBRARY), event(3, stack=LIBRARY_ONLY),
                   event(4, stack=JDK_ONLY, action="blocked", sensor="block-x"),
                   event(5, stack=JDK_ONLY, action="monitored", sensor="block-y"),
                   event(6, stack=None, sensor="jot-config"))
        ing.poll()
        self.assertEqual(list(store.ORIGINS), store.get_shown_origins(self.db), "all four are shown, so every event is")
        self.assertEqual([1, 2, 3, 4, 5, 6], sorted(self.origins("events")))
        for shown, expected in ((["app", "library", "none"], [2, 3, 6]), (["app", "none"], [2, 6]), (["platform"], [1, 4, 5]),
                                (["library"], [3]), (["none"], [6]), ([], []), (list(store.ORIGINS), [1, 2, 3, 4, 5, 6])):
            store.set_shown_origins(ing.db, shown)
            self.assertEqual(shown, store.get_shown_origins(self.db))
            self.assertEqual(expected, sorted(self.origins("events")), "showing %s" % shown)

    def test_an_origin_filter_hides_what_a_rule_blocked_too_since_each_filter_is_only_what_it_says(self):
        ing = self.ingestor()
        self.write(event(1, stack=JDK_ONLY, action="blocked", sensor="block-x"), event(2, stack=JSP, action="blocked", sensor="block-x"))
        ing.poll()
        store.set_shown_origins(ing.db, ["app"])
        self.assertEqual([2], sorted(self.origins("events")), "hiding the JDK hides every event from it, a block included")

    def test_each_action_is_shown_until_it_is_hidden_and_each_is_hidden_on_its_own(self):
        ing = self.ingestor()
        self.write(event(1, stack=JSP), event(2, stack=JSP, action="blocked", sensor="block-x"),
                   event(3, stack=JDK_ONLY, action="monitored", sensor="block-y"), event(4, stack=JSP, sensor="auth-user"))
        ing.poll()
        self.assertEqual(list(store.ACTIONS), store.get_shown_actions(self.db), "all three are shown, so every event is")
        self.assertEqual([1, 2, 3, 4], sorted(self.origins("events")))
        for shown, expected in ((["blocked"], [2]), (["monitored", "blocked"], [2, 3]), (["observed", "monitored"], [1, 3, 4]),
                                (["observed"], [1, 4]), (["monitored"], [3]), ([], []), (list(store.ACTIONS), [1, 2, 3, 4])):
            store.set_shown_actions(ing.db, shown)
            self.assertEqual(shown, store.get_shown_actions(self.db))
            self.assertEqual(expected, sorted(self.origins("events")), "showing %s" % shown)

    def test_a_filter_is_refused_values_it_does_not_have_and_what_is_not_a_list(self):
        ing = self.ingestor()
        for bad in (["observd"], "observed", None, [1], ["observed", "everything"]):
            with self.assertRaises(ValueError):
                store.set_shown_actions(ing.db, bad)
            with self.assertRaises(ValueError):
                store.set_shown_origins(ing.db, bad)
        self.assertEqual(list(store.ACTIONS), store.get_shown_actions(self.db), "and nothing was changed")

    def test_the_agents_own_events_are_a_jot_like_any_other_and_hidden_like_one(self):
        ing = self.ingestor()
        self.write(event(1, stack=JSP), event(2, stack=None, sensor="jot-control", capture="rule-a=monitor"))
        ing.poll()
        self.assertEqual([1, 2], sorted(self.origins("events")), "shown, with no setting")
        store.set_hidden_jots(ing.db, ["jot-control"])
        self.assertEqual([1], sorted(self.origins("events")))
        store.set_hidden_jots(ing.db, [])
        self.assertEqual([1, 2], sorted(self.origins("events")))

    def test_the_filters_leave_the_reports_alone_except_for_the_time_the_outcome_and_the_source(self):
        ing = self.ingestor()
        self.write(event(1, stack=JSP, sensor="a-sensor"), event(2, stack=JSP, sensor="b-sensor", action="blocked"), event(3, stack=JDK_ONLY, sensor="c-sensor"))
        ing.poll()
        shown = lambda: sorted(self.origins("events_shown"))
        store.set_hidden_jots(ing.db, ["a-sensor"])
        self.assertEqual([1, 2, 3], shown(), "a hidden JOT is still there for a report that names its sensor")
        self.assertEqual([2, 3], sorted(self.origins("events")))
        store.set_shown_actions(ing.db, ["blocked"])
        self.assertEqual([2], shown(), "but an outcome that is not shown is not there for a report either")
        store.set_shown_actions(ing.db, list(store.ACTIONS))
        store.set_shown_origins(ing.db, ["app"])
        self.assertEqual([1, 2], shown())

    def test_every_filter_is_off_with_nothing_set_and_reset_takes_them_all_off(self):
        ing = self.ingestor()
        self.write(event(1, stack=JSP), event(2, stack=JDK_ONLY), event(3, stack=None, sensor="jot-control", capture="x"),
                   event(4, stack=JSP, sensor="hidden-one"), event(5, stack=JSP, action="blocked", sensor="block-x"))
        ing.poll()
        everything = [1, 2, 3, 4, 5]
        self.assertEqual(everything, sorted(self.origins("events")), "a database with no settings shows every event")
        self.assertEqual([], [r for r in ing.db.execute("SELECT key FROM settings WHERE key IN (%s)" % ", ".join("'%s'" % k for k in store.FILTER_SETTINGS))])
        app = server.App(self.db, ing)
        app.set_since(1792111134000 + 2)
        app.set_filters(actions=["observed", "blocked"], origins=["app", "none"])
        app.set_hidden_jots(["hidden-one", "jot-control"])
        self.assertEqual([5], sorted(self.origins("events")), "the JDK, the agent's events and the hidden JOT are not shown, and neither is what was before the start")
        store.reset_filters(ing.db, keep=("since",))
        self.assertEqual(1792111134000 + 2, store.get_since(self.db), "Clear stays when a restart takes the rest off")
        self.assertEqual((list(store.ACTIONS), list(store.ORIGINS), []),
                         (store.get_shown_actions(self.db), store.get_shown_origins(self.db), store.get_hidden_jots(self.db)))
        s = app.reset_filters()
        self.assertEqual(everything, sorted(self.origins("events")))
        self.assertEqual((None, list(store.ACTIONS), list(store.ORIGINS), []),
                         (s["since"], s["shown_actions"], s["shown_origins"], s["hidden_jots"]))

    def test_the_settings_of_the_filters_there_used_to_be_are_removed_when_the_database_is_opened(self):
        ing = self.ingestor()
        for key in store.LEGACY_FILTER_SETTINGS:
            ing.db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, '1')", (key,))
        ing.db.commit()
        self.assertTrue(ing.db.execute("SELECT COUNT(*) FROM settings WHERE key = 'app_only'").fetchone()[0])
        self.ingestor()
        self.assertEqual(0, ing.db.execute("SELECT COUNT(*) FROM settings WHERE key IN (%s)" % ", ".join("'%s'" % k for k in store.LEGACY_FILTER_SETTINGS)).fetchone()[0],
                         "they do nothing now, and an old app_only must not leave the events narrowed by something that can't be seen")

    def test_changing_the_packages_tags_the_stored_events_again(self):
        self.write(event(1, stack=VIA_LIBRARY), event(2, stack=LIBRARY_ONLY))
        self.ingestor(["com.acme"]).poll()
        self.assertEqual(self.origins(), {1: "app", 2: "library"})
        ing = self.ingestor(["org.hsqldb"])
        self.assertEqual(self.origins(), {1: "app", 2: "app"})
        self.assertEqual(ing.db.execute("SELECT app_frame FROM events_raw WHERE id = 2").fetchone()[0],
                         "org.hsqldb.rights.GranteeManager.getDigester(Unknown Source)")

    def test_a_database_from_before_the_origin_existed_is_tagged_on_start(self):
        db = sqlite3.connect(self.db)
        db.executescript("""CREATE TABLE events_raw (pk INTEGER PRIMARY KEY, time TEXT, ts INTEGER, run TEXT, host TEXT,
            pid INTEGER, app TEXT, id INTEGER, trace INTEGER, thread TEXT, thread_id INTEGER, sensor TEXT, action TEXT,
            capture TEXT, message TEXT, method TEXT, method_name TEXT, call_site TEXT, call_site_name TEXT, stack TEXT,
            UNIQUE (run, id));""")
        db.execute("INSERT INTO events_raw (ts, run, id, sensor, action, stack) VALUES (1, 'r', 1, 's', 'observed', ?)",
                   (json.dumps(JDK_ONLY),))
        db.execute("INSERT INTO events_raw (ts, run, id, sensor, action, stack) VALUES (2, 'r', 2, 's', 'observed', ?)",
                   (json.dumps(JSP),))
        db.commit()
        db.close()
        store.set_shown_origins(self.ingestor().db, ["app", "none"])
        self.assertEqual(self.origins(), {1: "platform", 2: "app"})
        self.assertEqual(sorted(self.origins("events")), [2])

    def test_the_filters_and_the_counts_over_the_api(self):
        ing = self.ingestor()
        self.write(event(1, stack=JDK_ONLY), event(2, stack=JDK_ONLY), event(3, stack=JSP), event(4, stack=JSP, action="blocked", sensor="block-x"))
        ing.poll()
        app = server.App(self.db, ing)
        s = app.status()
        self.assertEqual((s["events"], s["filtered"]), (4, 0), "nothing is left out until a filter says so")
        self.assertEqual((list(store.ACTIONS), list(store.ORIGINS)), (s["shown_actions"], s["shown_origins"]))
        self.assertEqual({"actions": {"observed": 3, "monitored": 0, "blocked": 1}, "origins": {"app": 2, "library": 0, "platform": 2, "none": 0}}, app.filter_counts())
        s = app.set_filters(origins=["app", "none"])
        self.assertEqual((s["events"], s["filtered"], s["shown_origins"]), (2, 2, ["app", "none"]))
        self.assertEqual(list(store.ACTIONS), s["shown_actions"], "an actions list left out is left as it was")
        s = app.set_filters(actions=["blocked"])
        self.assertEqual((s["events"], s["shown_actions"], s["shown_origins"]), (1, ["blocked"], ["app", "none"]), "each filter is its own, and an event shows when every one lets it")
        self.assertEqual(app.filter_counts()["actions"]["observed"], 3, "the counts are of what there is and not of what is shown, so a choice says what it would add")
        s = app.set_filters(actions=list(store.ACTIONS), origins=list(store.ORIGINS))
        self.assertEqual((s["events"], s["filtered"]), (4, 0))
        app.set_since(1792111134000 + 3)
        app.set_filters(origins=["app", "none"])
        s = app.status()
        self.assertEqual((s["events"], s["hidden"], s["filtered"]), (2, 2, 0), "the start time and the filters are counted apart")
        self.assertEqual({"app": 2, "library": 0, "platform": 0, "none": 0}, app.filter_counts()["origins"], "and the counts are of since the start time")

    def test_a_filter_the_api_is_given_that_is_not_valid_is_refused_and_changes_nothing(self):
        ing = self.ingestor()
        app = server.App(self.db, ing)
        for bad in ({"actions": ["blocked", "everything"]}, {"origins": "app"}, {"actions": [3]}):
            with self.assertRaises((ValueError, TypeError)):
                app.set_filters(**bad)
        s = app.status()
        self.assertEqual((list(store.ACTIONS), list(store.ORIGINS)), (s["shown_actions"], s["shown_origins"]))


class EventViewerTests(unittest.TestCase):
    STACK = ["java.base/java.lang.Runtime.exec(Runtime.java:678)",
             "org.apache.jsp.cmd_jsp._jspService(cmd_jsp.java:154)",
             "org.hsqldb.Foo.bar(Unknown Source)",
             "org.apache.catalina.core.StandardWrapperValve.invoke(StandardWrapperValve.java:164)"]

    def setUp(self):
        self.env = Env()
        self.env.ingestor.app_prefixes = ("org.apache.jsp",)
        self.app = server.App(self.env.db, self.env.ingestor)
        self.env.write(event(1, sensor="http-route", capture="/cmd.jsp", trace=7, ts=1792111135000, stack=self.STACK),
                       event(2, sensor="block-exec", capture="[[open]]", action="blocked", trace=7, ts=1792111135100,
                             message="stopped", stack=self.STACK),
                       event(3, sensor="http-route", capture="/other.jsp", trace=8, stack=self.STACK))
        self.env.ingestor.poll()

    def pk_of(self, event_id):
        return self.env.ingestor.db.execute("SELECT pk FROM events_raw WHERE id = ?", (event_id,)).fetchone()[0]

    def test_an_event_comes_back_with_everything_recorded_about_it(self):
        e = self.app.event(self.pk_of(2))
        self.assertEqual(("block-exec", "blocked", "[[open]]", "stopped"), (e["sensor"], e["action"], e["capture"], e["message"]))
        for key in ("run", "host", "pid", "trace", "thread", "method", "call_site", "origin", "app_frame", "time", "ts"):
            self.assertIn(key, e)

    def test_each_frame_says_whether_it_is_the_application_a_library_or_the_platform(self):
        kinds = [f["kind"] for f in self.app.event(self.pk_of(1))["stack"]]
        self.assertEqual(["platform", "app", "library", "platform"], kinds)

    def test_the_other_events_of_the_same_request_are_listed_and_only_those(self):
        related = self.app.event(self.pk_of(1))["related"]
        self.assertEqual([(1, "http-route"), (2, "block-exec")], [(r[0] and self.env.ingestor.db.execute(
            "SELECT id FROM events_raw WHERE pk = ?", (r[0],)).fetchone()[0], r[3]) for r in related])

    def test_an_event_the_filter_hides_can_still_be_opened(self):
        self.app.set_filters(origins=["app", "none"])
        self.env.write(event(9, stack=["java.base/a.B.c(B.java:1)"]))
        self.env.ingestor.poll()
        hidden = self.pk_of(9)
        self.assertEqual(0, store.run_query(self.env.db, "SELECT COUNT(*) FROM events WHERE pk = %d" % hidden)["rows"][0][0])
        self.assertEqual(9, self.app.event(hidden)["id"])

    def test_an_event_that_does_not_exist_is_not_found(self):
        with self.assertRaises(LookupError):
            self.app.event(999999)

    def test_over_http(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        url = "http://127.0.0.1:%d/api/event?pk=%d" % (port, self.pk_of(2))
        with urllib.request.urlopen(urllib.request.Request(url, headers={"Host": "127.0.0.1:%d" % port})) as r:
            self.assertEqual("block-exec", json.load(r)["sensor"])
        for bad in ("pk=999999", "pk=abc", "pk=1;DROP%20TABLE%20events_raw"):
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d/api/event?%s" % (port, bad),
                                                              headers={"Host": "127.0.0.1:%d" % port}))
            self.assertIn(ctx.exception.code, (400, 404))
        self.assertEqual(3, store.run_query(self.env.db, "SELECT COUNT(*) FROM events_raw")["rows"][0][0])

    CHROME = JotsViewChrome = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                               shutil.which("google-chrome") or "", shutil.which("chromium") or "") if c and os.path.exists(c)), None)

    def render(self, address):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run",
                               "--user-data-dir=" + tempfile.mkdtemp(), "--virtual-time-budget=8000", "--dump-dom",
                               "http://127.0.0.1:%d/%s" % (port, address)], capture_output=True, text=True, timeout=90)
        return done.stdout

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_viewer_opens_from_a_link_and_shows_the_stack_with_the_application_frame_marked(self):
        page = self.render("#event/%d" % self.pk_of(2))
        drawer = re.search(r'<aside id="eventDrawer"([^>]*)>(.*?)</aside>', page, re.S)
        self.assertNotIn("hidden", drawer.group(1))
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", drawer.group(2)))
        for expected in ("block-exec", "[[open]]", "stopped", "cmd_jsp._jspService", "Same request (2 events)"):
            self.assertIn(expected, text)
        self.assertRegex(drawer.group(2), r'<li class="app"[^>]*>.*?cmd_jsp')
        self.assertNotIn("null", text.lower())
        self.assertNotIn("undefined", text.lower())
        closed = self.render("#events")
        self.assertRegex(closed, r'<aside id="eventDrawer"[^>]*hidden')

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_rows_with_a_pk_column_are_clickable_and_do_not_show_it(self):
        page = self.render("")
        self.assertIn('class="clickable"', page)
        head = re.search(r"<thead>(.*?)</thead>", page, re.S).group(1)
        self.assertNotIn(">pk<", head)
        self.assertIn(">sensor<", head)


class SearchTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        self.env.ingestor.app_prefixes = ("com.acme",)
        self.app = server.App(self.env.db, self.env.ingestor)
        app_stack = ["java.base/java.security.MessageDigest.getInstance(M.java:1)", "com.acme.Ticket.save(Ticket.java:9)"]
        jdk_stack = ["java.base/sun.security.rsa.RSASignature.<init>(RSASignature.java:81)", "java.base/java.lang.Thread.run(Thread.java:833)"]
        self.env.write(event(1, sensor="crypto-hash", capture="SHA-256", stack=app_stack),
                       event(2, sensor="crypto-hash", capture="MD5", stack=app_stack),
                       event(3, sensor="crypto-hash", capture="SHA-256", stack=jdk_stack),
                       event(4, sensor="block-exec", capture="[[/usr/bin/open]]", action="blocked", message="100% stopped", stack=app_stack),
                       event(5, sensor="crypto-cipher", capture="RSA/ECB", trace=2, stack=app_stack))
        self.env.ingestor.poll()
        self.app.set_filters(origins=["app", "none"])     # everything is shown unless a filter says otherwise, and these are about what it leaves out

    def pks(self, sql):
        return ",".join(str(r[0]) for r in self.app.sql(sql)["rows"]) or "-1"

    def found(self, query):
        rows = self.env.ingestor.db.execute("SELECT id FROM events_raw WHERE pk IN (%s)" % self.pks(self.app.search(query)["sql"])).fetchall()
        return sorted(r[0] for r in rows)

    def test_a_word_is_found_in_the_capture_the_message_and_the_stack(self):
        self.assertEqual([1], self.found("sha-256"), "event 3 matches too, but has no frame from the application")
        self.assertEqual([4], self.found("stopped"))
        self.assertEqual([5], self.found("ecb"))
        self.assertEqual([1, 2, 4, 5], self.found("Ticket.save"))

    def test_every_word_must_match_and_a_dash_excludes(self):
        self.assertEqual([1], self.found("hash sha"))
        self.assertEqual([2], self.found("hash -sha"))
        self.assertEqual([], self.found("sha md5"))

    def test_a_field_narrows_the_search(self):
        self.assertEqual([4], self.found("action:blocked"))
        self.assertEqual([1, 2], self.found("sensor:hash"))
        self.assertEqual([5], self.found("trace:2"))
        self.assertEqual([], self.found("action:block"), "equals, not contains")

    def test_quotes_percent_and_underscore_are_plain_text(self):
        self.assertEqual([4], self.found("100%"))
        self.assertEqual([], self.found("o'brien"))
        self.assertEqual([], self.found("get_hashes"), "an underscore is not a wildcard")
        self.assertEqual([1, 2], self.found("crypto-hash"))
        before = self.env.ingestor.db.execute("SELECT COUNT(*) FROM events_raw").fetchone()[0]
        self.found("x'; DROP TABLE events_raw; --")
        self.assertEqual(before, self.env.ingestor.db.execute("SELECT COUNT(*) FROM events_raw").fetchone()[0])

    def test_matches_the_filters_leave_out_are_counted(self):
        r = self.app.search("sha-256")
        self.assertEqual((1, 1), (r["matches"], r["left_out"]))
        self.app.set_filters(origins=list(store.ORIGINS))
        r = self.app.search("sha-256")
        self.assertEqual((2, 0), (r["matches"], r["left_out"]))
        self.app.set_filters(actions=["blocked"])
        r = self.app.search("sha-256")
        self.assertEqual((0, 2), (r["matches"], r["left_out"]), "left out by any filter, an outcome as well as a source")

    def test_nothing_to_search_for_is_refused(self):
        for q in ("", "   ", "trace:abc"):
            with self.assertRaises(ValueError):
                self.app.search(q)

    def test_over_http(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        get = lambda path: urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers={"Host": "127.0.0.1:%d" % port}))
        with get("/api/search?q=md5") as r:
            self.assertEqual(1, json.load(r)["matches"])
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            get("/api/search?q=")
        self.assertEqual(400, ctx.exception.code)


class GraphTests(unittest.TestCase):
    PREFIXES = ["com.acme", "org.apache.jsp"]
    LIST_PAGE = "org.apache.jsp.list_jsp._jspService(list_jsp.java:10)"
    GET = "com.acme.Database.getTickets(Database.java:20)"
    ENCRYPT = "com.acme.Ticket.encrypt(Ticket.java:30)"
    SERVLET = "jakarta.servlet.http.HttpServlet.service(HttpServlet.java:710)"
    FILTER = "org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:132)"

    def setUp(self):
        self.env = Env()
        self.env.ingestor.app_prefixes = tuple(self.PREFIXES)
        self.app = server.App(self.env.db, self.env.ingestor)
        jdk = "java.base/javax.crypto.Cipher.getInstance(Cipher.java:534)"
        chain = [jdk, self.ENCRYPT, self.GET, self.LIST_PAGE, self.FILTER]
        self.env.write(
            event(1, sensor="http-route", capture="/app/list.jsp", trace=1, stack=[self.SERVLET, self.FILTER]),
            event(2, sensor="auth-user", capture="Guest", trace=1, stack=[self.SERVLET, self.FILTER]),
            event(3, sensor="crypto-cipher", capture="AES", trace=1, stack=chain),
            event(4, sensor="crypto-cipher", capture="DES", trace=1, stack=chain),
            event(5, sensor="http-route", capture="/app/profile", trace=2, stack=[self.SERVLET, self.FILTER]),
            event(6, sensor="http-forward", capture="/list.jsp", trace=2,
                  stack=["jakarta.servlet.RequestDispatcher.forward(R.java:1)", "com.acme.ProfileController.doPost(P.java:28)", self.FILTER]),
            event(7, sensor="crypto-hash", capture="SHA-256", trace=99, stack=["java.base/a.B.c(B.java:1)", "com.acme.Startup.run(S.java:1)"]),
            event(8, sensor="block-exec", action="blocked", capture="[[open]]", trace=1,
                  stack=["java.base/java.lang.Runtime.exec(R.java:1)", self.LIST_PAGE, self.FILTER]))
        self.env.ingestor.poll()

    def graph(self, **kw):
        g = self.app.graph(**kw)
        return g, {n["id"]: n for n in g["nodes"]}, {(e["from"], e["to"]): e["events"] for e in g["edges"]}

    @staticmethod
    def inner(nodes, node_id):
        """The sensors inside one box, by name, in the order they were first seen."""
        return {i["sensor"]: i for i in nodes[node_id]["inner"]}

    def test_a_path_runs_from_the_route_through_the_application_code_to_what_the_sensor_saw(self):
        g, nodes, edges = self.graph()
        self.assertEqual(2, edges[("route:/app/list.jsp", "code:com.acme.Database.getTickets")])
        self.assertEqual(2, edges[("code:com.acme.Database.getTickets", "code:com.acme.Ticket.encrypt")])
        cipher = self.inner(nodes, "code:com.acme.Ticket.encrypt")["crypto-cipher"]
        self.assertEqual(2, cipher["events"], "what a sensor saw is inside the method that triggered it")
        self.assertEqual([("AES", 1), ("DES", 1)], sorted(cipher["captures"]))

    def test_a_route_whose_events_all_fired_in_the_page_itself_is_still_drawn_and_so_is_one_with_no_events(self):
        self.env.write(
            event(50, sensor="http-route", capture="/app/el.jsp", trace=50, stack=[self.SERVLET, self.FILTER]),
            event(51, sensor="expression-el-evaluate", action="monitored", capture="${x}", trace=50,
                  stack=["jakarta.el.ValueExpression.getValue(V.java:1)", "org.apache.jsp.el_jsp._jspService(el_jsp.java:10)", self.FILTER]))
        self.env.write(event(52, sensor="http-route", capture="/app/style.css", trace=51, stack=[self.SERVLET, self.FILTER]))
        self.env.ingestor.poll()
        graphs = {g["route"]: g for g in self.app.graph(split=True)["graphs"]}
        self.assertIn("/app/el.jsp", graphs, "the sensor fired in the page, which is the route, so it is the route's own")
        route = next(n for n in graphs["/app/el.jsp"]["nodes"] if n["kind"] == "route")
        self.assertEqual(["expression-el-evaluate"], [i["sensor"] for i in route["inner"]])
        self.assertEqual(1, route["inner"][0]["monitored"])
        self.assertIn("/app/style.css", graphs, "every entry is drawn, even one that no sensor fired in")
        self.assertEqual([], graphs["/app/style.css"]["nodes"][0]["inner"])
        self.assertEqual(1, graphs["/app/style.css"]["nodes"][0]["events"], "with the requests that came in at it")
        only = {g["route"] for g in self.app.graph(route="/app/style.css", split=True)["graphs"]}
        self.assertEqual({"/app/style.css"}, only, "an entry that is picked is the only one")
        self.assertNotIn("/app/style.css", {g["route"] for g in self.app.graph(method="GET", split=True)["graphs"]}, "and a method leaves out what it can't count")

    def test_the_jsp_page_is_the_route_and_is_not_drawn_twice(self):
        g, nodes, edges = self.graph()
        self.assertFalse([i for i in nodes if "list_jsp" in i])

    def test_jdk_and_server_frames_are_not_drawn(self):
        g, nodes, edges = self.graph()
        self.assertFalse([i for i in nodes if "java.base" in i or "catalina" in i or "Cipher" in i])

    def test_a_blocked_event_marks_its_effect(self):
        g, nodes, edges = self.graph()
        self.assertEqual(1, self.inner(nodes, "route:/app/list.jsp")["block-exec"]["blocked"])
        self.assertEqual(0, self.inner(nodes, "code:com.acme.Ticket.encrypt")["crypto-cipher"]["blocked"])
        self.assertEqual(1, nodes["route:/app/list.jsp"]["blocked"], "and the box that holds it says so")

    def test_a_method_holds_what_happened_directly_in_it_and_calls_lead_on_to_what_it_called(self):
        self.env.write(
            event(30, sensor="http-route", capture="/app/order.jsp", trace=30, stack=[self.SERVLET, self.FILTER]),
            event(31, sensor="crypto-hash", capture="MD5", trace=30, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]),
            event(32, sensor="crypto-cipher", capture="AES", trace=30, stack=["java.base/a.B.c(B.java:1)", self.ENCRYPT, self.GET, self.FILTER]),
            event(33, sensor="crypto-cipher", capture="DES", trace=30, stack=["java.base/a.B.c(B.java:1)", self.ENCRYPT, self.GET, self.FILTER]),
            event(34, sensor="crypto-hash", capture="SHA", trace=30, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph(route="/app/order.jsp")
        get, enc = "code:com.acme.Database.getTickets", "code:com.acme.Ticket.encrypt"
        self.assertEqual({("route:/app/order.jsp", get): 4, (get, enc): 2}, edges, "the lines are who called whom, counted by the events through them")
        self.assertEqual(2, self.inner(nodes, get)["crypto-hash"]["events"])
        self.assertEqual(2, self.inner(nodes, enc)["crypto-cipher"]["events"], "the repeat is one inner box, both events are counted")
        self.assertEqual(["crypto-hash"], list(self.inner(nodes, get)))
        self.assertEqual(["crypto-cipher"], list(self.inner(nodes, enc)))

    def test_a_method_the_line_is_already_inside_is_not_entered_again(self):
        self.env.write(
            event(40, sensor="http-route", capture="/app/inside.jsp", trace=40, stack=[self.SERVLET, self.FILTER]),
            event(41, sensor="crypto-hash", capture="MD5", trace=40, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]),
            event(42, sensor="crypto-cipher", capture="AES", trace=40, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph(route="/app/inside.jsp")
        get = "code:com.acme.Database.getTickets"
        self.assertEqual(["crypto-hash", "crypto-cipher"], list(self.inner(nodes, get)), "both in the one method, in the order they happened")
        self.assertEqual({("route:/app/inside.jsp", get): 2}, edges)

    def test_requests_that_did_the_same_things_in_the_same_order_share_a_line(self):
        for trace, base in ((60, 60), (61, 70)):
            self.env.write(
                event(base, sensor="http-route", capture="/app/twice.jsp", trace=trace, stack=[self.SERVLET, self.FILTER]),
                event(base + 1, sensor="crypto-cipher", capture="AES", trace=trace, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]),
                event(base + 2, sensor="crypto-hash", capture="MD5", trace=trace, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph(route="/app/twice.jsp")
        get = self.inner(nodes, "code:com.acme.Database.getTickets")
        self.assertEqual(["crypto-cipher", "crypto-hash"], list(get))
        self.assertEqual([2, 2], [i["events"] for i in get.values()])
        self.assertEqual(1, len({tuple(i["lines"]) for i in get.values()}), "two requests, one line")

    def test_a_forward_and_a_redirect_lead_to_their_route(self):
        base = 60
        self.env.write(
            event(base, sensor="http-route", capture="/app/profile", trace=base, stack=[self.SERVLET, self.FILTER]),
            event(base + 1, sensor="http-forward", capture="/list.jsp", trace=base,
                  stack=["jakarta.servlet.RequestDispatcher.forward(R.java:1)", "com.acme.ProfileController.doPost(P.java:28)", self.FILTER]),
            event(base + 2, sensor="http-route", capture="/app/other", trace=base + 1, stack=[self.SERVLET, self.FILTER]),
            event(base + 3, sensor="http-redirect", capture="/app/list.jsp", trace=base + 1,
                  stack=["jakarta.servlet.http.HttpServletResponse.sendRedirect(R.java:1)", "com.acme.OtherController.doGet(O.java:9)", self.FILTER]))
        self.env.ingestor.poll()
        g = self.app.graph()
        for route in ("/app/profile", "/app/other"):
            self.assertIn(route, g["routes"])
        exits = {n["id"] for n in g["nodes"] if n["kind"] == "exit"}
        self.assertIn("exit:/app/list.jsp", exits, "a route out, for the forward and for the redirect")

    def test_every_node_and_edge_says_which_lines_use_it(self):
        # one request does a hash and a cipher, another only the hash, and they share the hash
        for trace, base, route, ciphers in ((80, 80, "/app/one.jsp", True), (81, 90, "/app/two.jsp", False)):
            self.env.write(event(base, sensor="http-route", capture=route, trace=trace, stack=[self.SERVLET, self.FILTER]),
                           event(base + 1, sensor="crypto-hash", capture="MD5", trace=trace, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
            if ciphers:
                self.env.write(event(base + 2, sensor="crypto-cipher", capture="AES", trace=trace,
                                     stack=["java.base/a.B.c(B.java:1)", self.ENCRYPT, self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g = self.app.graph()
        lines = {n["id"]: set(n["lines"]) for n in g["nodes"]}
        edge_lines = {(e["from"], e["to"]): set(e["lines"]) for e in g["edges"]}
        one, two = lines["route:/app/one.jsp"], lines["route:/app/two.jsp"]
        self.assertTrue(one and two and not one & two, "each route is its own kind of request")
        get = self.inner({n["id"]: n for n in g["nodes"]}, "code:com.acme.Database.getTickets")
        self.assertTrue((one | two) <= set(get["crypto-hash"]["lines"]), "both used the hash")
        enc = "code:com.acme.Ticket.encrypt"
        cipher_edge = edge_lines[("code:com.acme.Database.getTickets", enc)]
        self.assertTrue(one & cipher_edge and not two & cipher_edge, "only the first request reached the method with the cipher")
        cipher = set(self.inner({n["id"]: n for n in g["nodes"]}, enc)["crypto-cipher"]["lines"])
        self.assertTrue(cipher >= one and not (cipher & two))

    def test_request_details_are_left_out_unless_asked_for(self):
        g, nodes, edges = self.graph()
        self.assertNotIn("auth-user", self.inner(nodes, "route:/app/list.jsp"))
        g, nodes, edges = self.graph(details=True)
        self.assertEqual(1, self.inner(nodes, "route:/app/list.jsp")["auth-user"]["events"])

    def test_a_forward_leads_on_to_the_route_it_names(self):
        g, nodes, edges = self.graph()
        self.assertEqual(1, edges[("code:com.acme.ProfileController.doPost", "exit:/app/list.jsp")])
        self.assertEqual("exit", nodes["exit:/app/list.jsp"]["kind"])
        self.assertIn("http-forward", self.inner(nodes, "code:com.acme.ProfileController.doPost"))

    def test_events_outside_a_request_start_from_their_own_route(self):
        g, nodes, edges = self.graph()
        self.assertIn(("route:(outside a request)", "code:com.acme.Startup.run"), edges)

    def test_one_route_can_be_picked(self):
        g, nodes, edges = self.graph(route="/app/profile")
        self.assertEqual(["route:/app/profile"], [n["id"] for n in g["nodes"] if n["kind"] == "route"])
        self.assertIn("/app/list.jsp", g["routes"], "the list of routes is of all of them")

    def test_the_blocked_and_monitored_filters_apply_to_the_graph_and_keep_each_event_on_its_route(self):
        g, nodes, edges = self.graph()
        everything = {i["sensor"] for n in g["nodes"] for i in n["inner"]}
        self.app.set_filters(actions=["blocked"])
        g, nodes, edges = self.graph()
        effects = [i for n in g["nodes"] for i in n["inner"]]
        self.assertTrue(effects)
        self.assertLess(len(effects), len(everything))
        self.assertTrue(all(n["blocked"] for n in effects), "only blocked effects are left")
        routes = {n["label"] for n in g["nodes"] if n["kind"] == "route"}
        self.assertNotIn("(outside a request)", routes, "the http-route events are hidden by the filter but still name the route")
        self.assertTrue(routes)
        self.assertIn("/app/list.jsp", g["routes"], "the route list isn't narrowed by the filter")

    def test_it_follows_the_filters(self):
        self.app.set_filters(origins=["app", "none"])
        self.env.write(event(20, sensor="crypto-hash", capture="MD5", trace=50, stack=["java.base/a.B.c(B.java:1)", "java.base/d.E.f(E.java:1)"]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph()
        self.assertNotIn("MD5", [c for n in nodes.values() for i in n["inner"] for c, _ in i["captures"]])
        self.app.set_since(int(time.time() * 1000) + 100000)
        g, nodes, edges = self.graph()
        self.assertEqual([], g["nodes"])

    CHROME = next((c for c in ("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                               shutil.which("google-chrome") or "", shutil.which("chromium") or "") if c and os.path.exists(c)), None)

    def render(self, address):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        done = subprocess.run([self.CHROME, "--headless=new", "--disable-gpu", "--no-first-run",
                               "--user-data-dir=" + tempfile.mkdtemp(), "--virtual-time-budget=8000", "--dump-dom",
                               "http://127.0.0.1:%d/%s" % (port, address)], capture_output=True, text=True, timeout=90)
        return done.stdout

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_graph_page_draws_the_paths(self):
        page = self.render("#graph")
        self.assertEqual(1, len(re.findall(r'<aside class="card" id="graphDetail"[^>]* hidden', page)), "nothing is picked, so no panel")
        self.assertIn('<svg class="graph"', page)
        for expected in ("/app/list.jsp", "Database.getTickets", "Ticket.encrypt", "crypto-cipher"):
            self.assertIn(expected, page)
        self.assertNotIn("_jspService", page, "the page is the route")
        self.assertNotIn("route out", page, "there is no key to read, a box says what it is when it is hovered")
        self.assertNotIn(">null<", page)
        self.assertRegex(page, r'<g class="inner blocked"', "what a rule blocked is a box inside the method that did it")
        self.assertRegex(page, r'<div id="graphTip"[^>]* hidden', "the hover box is there and hidden until a node is hovered")
        self.assertNotRegex(page, r'<g class="node[^>]*><title>', "the hover box replaces the browser's own tooltip")
        self.assertNotRegex(page, r'<svg class="graph"[^>]*><title>', "and a route's graph has no tooltip of its own")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_sensor_is_drawn_as_a_box_inside_the_method_that_triggered_it(self):
        page = self.render("#graph")
        self.assertNotRegex(page, r'<g class="node effect', "a sensor is not a box of its own")
        encrypt = re.search(r'<g class="node code[^"]*"[^>]*data-id="code:com\.acme\.Ticket\.encrypt"[^>]*>(.*?)</g></g>', page, re.S)
        self.assertIsNotNone(encrypt, "the method is drawn")
        self.assertRegex(encrypt.group(1), r'<g class="inner[^"]*"[^>]*data-sensor="crypto-cipher"', "and its sensor is in it")
        route = re.search(r'<g class="node route[^"]*"[^>]*data-id="route:/app/list\.jsp"[^>]*>(.*?)</g>', page, re.S)
        self.assertIsNotNone(route)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_clicking_a_sensor_lights_it_wherever_it_fired(self):
        page = self.render("#graph/effect%3Acrypto-hash")
        picked = re.findall(r'<g class="inner[^"]*picked[^"]*"[^>]*data-sensor="([^"]+)"', page)
        self.assertTrue(picked and set(picked) == {"crypto-hash"}, "only the sensor that was picked is marked")
        self.assertNotIn('data-id="effect:', page)

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_picked_node_follows_its_paths_and_dims_the_rest(self):
        page = self.render("#graph/effect%3Acrypto-cipher")
        self.assertRegex(page, r'<g class="inner picked"')
        panel = re.search(r'<aside class="card" id="graphDetail"([^>]*)>(.*?)</aside>', page, re.S)
        self.assertNotIn("hidden", panel.group(1))
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", panel.group(2)))
        for expected in ("crypto-cipher", "AES", "DES", "Fired in", "Ticket.encrypt", "Show these events"):
            self.assertIn(expected, text)
        self.assertNotIn("null", text.lower())
        self.assertNotIn("routegraph off", page, "only the route the node is in is lit, others are left alone")
        self.assertRegex(page, r'class="edge( spine)? on"')

    def test_search_can_be_limited_to_one_route(self):
        every = self.app.search("crypto-cipher")["matches"]
        here = self.app.search('crypto-cipher route:"/app/list.jsp"')["matches"]
        elsewhere = self.app.search('crypto-cipher -route:"/app/list.jsp"')["matches"]
        self.assertTrue(0 < here <= every)
        self.assertEqual(every, here + elsewhere, "an event is in one route or not")
        self.assertEqual(0, self.app.search("route:/nowhere")["matches"])
        self.assertEqual(0, self.app.search("route:\"'; DROP TABLE events_raw;--\"")["matches"])

    def test_rule_events_count_against_their_rule(self):
        self.assertEqual("cve-x", store.rule_name("cve-x-blocked"))
        self.assertEqual("cve-x", store.rule_name("cve-x-blocked"))
        self.assertEqual("cve-x", store.rule_name("cve-x-monitored"))
        self.assertEqual("cve-x", store.rule_name("cve-x-active"), "a JOT reports its scope being active under its own name")
        self.assertEqual("crypto-cipher", store.rule_name("crypto-cipher"))

    def test_over_http(self):
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        get = lambda path: urllib.request.urlopen(urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers={"Host": "127.0.0.1:%d" % port}))
        with get("/api/graph") as r:
            self.assertTrue(json.load(r)["nodes"])
        with get("/api/graph?split=1") as r:
            graphs = json.load(r)["graphs"]
            routes = [g["route"] for g in graphs]
            self.assertTrue(graphs and all(g["nodes"] for g in graphs))
            self.assertEqual(sorted(routes, key=lambda x: (x == store.NO_REQUEST, x.lower())), routes)
            for g in graphs:   # a route's graph has only its own route in it
                self.assertEqual([g["route"]], [n["label"] for n in g["nodes"] if n["kind"] == "route"])
                route = next(n for n in g["nodes"] if n["kind"] == "route")
                self.assertEqual(g["requests"], route["events"], "a route counts requests, so it agrees with the route's own total")
        with get("/api/graph?route=%27%3B%20DROP%20TABLE%20events_raw%3B--") as r:
            self.assertEqual([], json.load(r)["nodes"])
        with get("/graph.js") as r:
            self.assertIn(b"layout", r.read())
        self.assertEqual(8, store.run_query(self.env.db, "SELECT COUNT(*) FROM events_raw")["rows"][0][0])


class JotsFileTests(unittest.TestCase):
    def test_jots_file_lists_jots_recursively_and_resolves_paths(self):
        with tempfile.TemporaryDirectory() as d:
            os.makedirs(os.path.join(d, "rules", "deep"))
            for rel in ("base.jot", "rules/deep/r.jot"):
                with open(os.path.join(d, rel), "w") as fh:
                    fh.write("sensors: []\n")
            jots_file = os.path.join(d, "jot.yaml")
            with open(jots_file, "w") as fh:
                fh.write("jots:\n- base.jot\n- rules\ncontrol: ctl.json\napp:\n  entry:\n  - javax.servlet.Servlet.service\n  packages:\n  - com.acme\n  - org.apache.jsp\n")
            jots, ctl, app = store.read_jots_file(jots_file)
            self.assertEqual(os.path.join(d, "ctl.json"), ctl)
            self.assertEqual(["com.acme", "org.apache.jsp"], app, "the packages, and the entry points are the agent's")
            self.assertEqual([os.path.join(d, "base.jot"), os.path.join(d, "rules", "deep", "r.jot")],
                             store.jot_files(jots))
            self.assertEqual([], store.jots_file_problems(jots_file))

    def test_the_old_list_under_app_has_no_packages_and_is_said_out_loud(self):
        with tempfile.TemporaryDirectory() as d:
            def check(text):
                path = os.path.join(d, "jot.yaml")
                with open(path, "w") as fh:
                    fh.write(text)
                return store.read_jots_file(path)[2], store.jots_file_problems(path)
            packages, problems = check("jots: []\napp:\n- com.acme\n")
            self.assertEqual([], packages)
            self.assertTrue(any("app must be a mapping with packages and entry" in p for p in problems), problems)
            packages, problems = check("jots: []\napp:\n  packages: com.acme\n  entrys: []\nignorr: []\n")
            self.assertEqual(["com.acme"], packages, "one package can be written without a list")
            self.assertTrue(any("entrys" in p for p in problems) and any("ignorr is not a setting" in p for p in problems), problems)


SENSOR_FIELDS = {"http-route": ["path", "method"], "auth-role-check": ["role", "allowed"],
                 "http-cookie-set": ["name", "secure", "http_only"], "crypto-cipher": ["algorithm"]}


class ReportPromptTests(unittest.TestCase):
    def examples(self):
        text = llm.REPORT_SYSTEM[llm.REPORT_SYSTEM.index("Examples that were run"):llm.REPORT_SYSTEM.index("Always answer by calling")]
        return [e.strip("\n") for e in re.split(r"\n\n(?=name: )", text[text.index("name: "):]) if e.strip()]

    def test_every_example_in_the_prompt_passes_the_checks_a_report_must_pass(self):
        found = self.examples()
        self.assertEqual(["Encryption Usage", "Route role checks", "Route cookies"], [yaml.safe_load(e)["name"] for e in found])
        for example in found:
            self.assertEqual([], store.check_report_draft(example, SENSOR_FIELDS), example)

    def test_the_model_is_sent_the_fields_of_each_jot_and_the_names_taken_but_no_events(self):
        prompt = llm.build_report_prompt("who can do what", [{"name": "auth-role-check", "description": "Identifies a role check",
                                                              "fields": ["role", "allowed"]}, {"name": "bare", "fields": []}],
                                         ["Encryption Usage"], [{"request": "before", "yaml": "name: x"}], ["name is used"])
        for text in ("auth-role-check: Identifies a role check (fields role, allowed)", "bare (fields none", "Encryption Usage",
                     "Request: before", "Request: who can do what", "name is used"):
            self.assertIn(text, prompt)


class CheckReportTests(unittest.TestCase):
    def problems(self, text, taken=()):
        return [p["message"] for p in store.check_report_text(text, SENSOR_FIELDS, taken)]

    def test_a_good_report_of_each_type_has_no_problems(self):
        for text in ("name: Ciphers\ntype: list\ncols: crypto-cipher.algorithm\n",
                     "name: Roles\ntype: compare\nrows: http-route.path\ncols: auth-role-check.role\nvalue: auth-role-check.allowed\nby: auth-role-check.role\n",
                     "name: Cookies\ntype: table\nrows: http-route.path\ncols: 'http-cookie-set.name, http-cookie-set.secure'\n",
                     "name: Plain\ntype: compare\nrows: http-route.path\ncols: auth-role-check\n"):
            self.assertEqual([], self.problems(text), text)

    def test_a_field_or_a_jot_that_does_not_exist_is_found_with_what_there_is(self):
        said = self.problems("name: A\ntype: list\ncols: crypto-cipher.algo\n")
        self.assertEqual(["crypto-cipher doesn't capture algo, its fields are algorithm"], said)
        said = self.problems("name: A\ntype: list\ncols: crypto-ciphr.algorithm\n")
        self.assertEqual(["crypto-ciphr is not a JOT that is defined, did you mean crypto-cipher"], said)

    def test_the_line_of_each_problem_is_the_line_it_is_on(self):
        found = store.check_report_text("name: A\ntype: compare\nrows: http-route.nope\ncols: auth-role-check.role\n", SENSOR_FIELDS)
        self.assertEqual([3], [p["line"] for p in found])

    def test_what_each_type_needs_and_cannot_have(self):
        self.assertIn("needs a type", " ".join(self.problems("name: A\ncols: crypto-cipher.algorithm\n")))
        self.assertIn("type must be one of list, compare, table, not series", " ".join(self.problems("name: A\ntype: series\ncols: crypto-cipher.algorithm\n")))
        self.assertIn("compare report needs rows", " ".join(self.problems("name: A\ntype: compare\ncols: auth-role-check.role\n")))
        self.assertIn("list report has no rows", " ".join(self.problems("name: A\ntype: list\nrows: http-route.path\ncols: crypto-cipher.algorithm\n")))
        self.assertIn("only a compare report has value", " ".join(self.problems("name: A\ntype: table\nrows: http-route.path\ncols: auth-role-check.role\nvalue: auth-role-check.allowed\n")))
        self.assertIn("reads one column", " ".join(self.problems("name: A\ntype: compare\nrows: http-route.path\ncols: 'auth-role-check.role, auth-role-check.allowed'\n")))
        self.assertIn("needs value", " ".join(self.problems("name: A\ntype: compare\nrows: http-route.path\ncols: auth-role-check.role\nby: auth-role-check.role\n")))
        self.assertIn("needs cols", " ".join(self.problems("name: A\ntype: list\n")))

    def test_value_and_by_must_come_from_the_cols_jot(self):
        said = self.problems("name: A\ntype: compare\nrows: http-route.path\ncols: auth-role-check.role\nvalue: http-route.method\n")
        self.assertEqual(["value is a field of the cols sensor, auth-role-check"], said)

    def test_a_taken_name_a_stray_key_a_list_of_reports_and_bad_yaml_are_refused(self):
        self.assertIn("already used", " ".join(self.problems("name: Ciphers\ntype: list\ncols: crypto-cipher.algorithm\n", ["Ciphers"])))
        self.assertIn("title isn't something a report has", " ".join(self.problems("name: A\ntitle: x\ntype: list\ncols: crypto-cipher.algorithm\n")))
        self.assertIn("write just the one report", " ".join(self.problems("reports:\n- name: A\n")))
        self.assertTrue(self.problems("name: [unclosed\n"))
        self.assertEqual(["is empty"], self.problems(""))
        self.assertEqual(["is too large to be one report"], self.problems("x" * 20000))


class DraftReportTests(unittest.TestCase):
    GOOD = "name: Route roles\ntype: compare\nrows: http-route.path\ncols: auth-role-check.role\nvalue: auth-role-check.allowed\n"

    def setUp(self):
        self.env = Env()
        with open(os.path.join(self.env.dir, "a.jot"), "w") as f:
            f.write("sensors:\n- name: http-route\n  description: Identifies a route\n  methods:\n  - a.B.c\n  captures:\n    path: '#P0'\n"
                    "- name: auth-role-check\n  description: Identifies a role check\n  methods:\n  - a.B.d\n  captures:\n    role: '#P0'\n    allowed: '#RET'\n"
                    "reports:\n- name: Routes\n  type: list\n  cols: http-route.path\n")
        store.load_sensors(self.env.ingestor.db, [self.env.dir])
        store.load_reports(self.env.ingestor.db, [self.env.dir])
        self.env.write(event(1, sensor="http-route"))
        self.env.ingestor.poll()
        self.calls = []

    def app(self, *replies, editable=True):
        replies = list(replies)
        def fake(request, sensors, reports, history, problems):
            self.calls.append({"request": request, "sensors": {x["name"]: x["fields"] for x in sensors}, "reports": reports,
                               "history": history, "problems": problems})
            return replies.pop(0) if len(replies) > 1 else replies[0]
        return server.App(self.env.db, self.env.ingestor, jot_paths=[self.env.dir], editable=editable, draft_report=fake)

    def test_a_good_draft_is_checked_and_says_which_jots_have_recorded_nothing(self):
        out = self.app({"yaml": self.GOOD, "explanation": "Roles by route."}).draft_report("who can do what")
        self.assertEqual(([], "Roles by route.", ["auth-role-check"]), (out["problems"], out["explanation"], out["quiet"]))
        call = self.calls[0]
        self.assertEqual({"http-route": ["path"], "auth-role-check": ["role", "allowed"]}, call["sensors"], "the fields, so it can only use real ones")
        self.assertEqual(["Routes"], call["reports"], "the names in use")

    def test_a_draft_with_problems_goes_back_to_the_model_and_the_repair_is_used(self):
        bad = "name: Routes\ntype: compare\nrows: http-route.nope\ncols: auth-role-check.role\n"
        out = self.app({"yaml": bad, "explanation": "first"}, {"yaml": self.GOOD, "explanation": "second"}).draft_report("x")
        self.assertEqual(([], "second", 2), (out["problems"], out["explanation"], len(self.calls)))
        said = " ".join(self.calls[1]["problems"])
        self.assertIn("http-route doesn't capture nope", said)
        self.assertIn("already used", said)

    def test_a_draft_that_stays_wrong_comes_back_with_its_problems(self):
        bad = "name: A\ntype: list\ncols: nope.x\n"
        out = self.app({"yaml": bad, "explanation": "tried"}).draft_report("x")
        self.assertEqual(server.MAX_REPAIRS + 1, len(self.calls))
        self.assertTrue(out["problems"])
        self.assertEqual(bad.strip("\n"), out["yaml"])

    def test_a_request_that_needs_a_jot_that_is_not_there_comes_back_empty_with_the_reason(self):
        out = self.app({"yaml": "", "explanation": "No JOT captures SQL. Make one with New JOT."}).draft_report("sql by route")
        self.assertEqual(("", "No JOT captures SQL. Make one with New JOT.", []), (out["yaml"], out["explanation"], out["problems"]))

    def test_an_empty_or_huge_request_is_refused_and_the_conversation_is_trimmed(self):
        app = self.app({"yaml": self.GOOD, "explanation": "x"})
        for request in ("", "  ", "x" * 2001):
            with self.assertRaises(store.QueryError):
                app.draft_report(request)
        self.assertEqual([], self.calls)
        app.draft_report("again", [{"request": "r", "yaml": self.GOOD}] * 5)
        self.assertEqual(3, len(self.calls[0]["history"]))

    def test_the_editor_check_includes_names_in_use(self):
        app = self.app({"yaml": self.GOOD, "explanation": "x"})
        self.assertEqual([], app.check_report(self.GOOD))
        self.assertIn("already used", app.check_report(self.GOOD.replace("Route roles", "Routes"))[0]["message"])

    def test_a_drafted_report_is_added_after_the_last_one_and_shows_on_the_page(self):
        app = self.app({"yaml": self.GOOD, "explanation": "x"})
        before = open(os.path.join(self.env.dir, "a.jot")).read()
        self.assertEqual({"added": "Route roles", "file": "a.jot"}, app.add_report("a.jot", self.GOOD))
        after = open(os.path.join(self.env.dir, "a.jot")).read()
        self.assertTrue(after.startswith(before.rstrip("\n")), "nothing before it changed")
        saved = yaml.safe_load(after)
        self.assertEqual(["Routes", "Route roles"], [r["name"] for r in saved["reports"]])
        self.assertEqual(2, len(saved["sensors"]))
        self.assertIn("Route roles", [r["name"] for r in app.jots()["reports"]])

    def test_a_report_can_go_in_a_file_that_has_no_reports_or_a_new_file(self):
        with open(os.path.join(self.env.dir, "b.jot"), "w") as f:
            f.write("# my sensors\nsensors:\n- name: other\n  methods:\n  - a.B.e\n  captures:\n    v: '#P0'\n")
        store.load_sensors(self.env.ingestor.db, [self.env.dir])
        app = self.app({"yaml": self.GOOD, "explanation": "x"})
        app.add_report("b.jot", self.GOOD)
        text = open(os.path.join(self.env.dir, "b.jot")).read()
        self.assertTrue(text.startswith("# my sensors\n"))
        self.assertEqual(["Route roles"], [r["name"] for r in yaml.safe_load(text)["reports"]])
        self.assertEqual("roles.jot", app.add_report("roles.jot", self.GOOD.replace("Route roles", "Other roles"))["file"])
        self.assertEqual({"reports": [yaml.safe_load(self.GOOD.replace("Route roles", "Other roles"))]},
                         yaml.safe_load(open(os.path.join(self.env.dir, "roles.jot")).read()))

    def test_adding_refuses_a_bad_report_a_taken_name_and_a_dashboard_that_may_not_write(self):
        app = self.app({"yaml": self.GOOD, "explanation": "x"})
        with self.assertRaises(store.SaveError) as e:
            app.add_report("a.jot", self.GOOD.replace("Route roles", "Routes"))
        self.assertIn("already used", str(e.exception))
        with self.assertRaises(store.SaveError):
            app.add_report("a.jot", "name: A\ntype: list\ncols: nope.x\n")
        with self.assertRaises(store.SaveError) as e:
            self.app({"yaml": self.GOOD, "explanation": "x"}, editable=False).add_report("a.jot", self.GOOD)
        self.assertEqual(403, e.exception.status)

    def test_adding_a_jot_still_leaves_the_reports_in_the_file_alone(self):
        app = self.app({"yaml": self.GOOD, "explanation": "x"})
        app.add_jot("a.jot", "name: crypto-new\ndescription: Identifies new\nmethods:\n- a.B.f\ncaptures:\n  v: '#P0'\n")
        saved = yaml.safe_load(open(os.path.join(self.env.dir, "a.jot")).read())
        self.assertEqual(["http-route", "auth-role-check", "crypto-new"], [x["name"] for x in saved["sensors"]])
        self.assertEqual(["Routes"], [r["name"] for r in saved["reports"]])


class RunTests(unittest.TestCase):
    """The console starts the application with the agent attached, shows what it prints, and stops it."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.project = os.path.join(self.root, "my app")
        os.makedirs(os.path.join(self.project, ".jot"))
        self.jots = os.path.join(self.project, ".jot", "jot.yaml")
        with open(self.jots, "w") as f:
            f.write("sensors: []\nreports: []\n")
        self.agent = os.path.join(self.root, "jot.jar")
        open(self.agent, "w").close()

    def script(self, name, body):
        path = os.path.join(self.project, name)
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return "./" + name

    def make(self, agent=True):
        run = launcher.Launcher(self.project, self.jots, agent=self.agent if agent else "")
        self.addCleanup(run.close)
        return run

    def wait(self, run, until, seconds=10):
        end = time.time() + seconds
        while time.time() < end:
            state = run.state()
            if until(state):
                return state
            time.sleep(0.05)
        self.fail("timed out, the output was %r" % run.state()["lines"])

    def text(self, state):
        return "\n".join(t for _, t in state["lines"])

    def test_it_suggests_how_the_project_starts(self):
        self.script("run.sh", "true\n")
        open(os.path.join(self.project, "pom.xml"), "w").write("<project><parent><artifactId>spring-boot-starter-parent</artifactId></parent></project>")
        open(os.path.join(self.project, "mvnw"), "w").close()
        os.makedirs(os.path.join(self.project, "target"))
        for jar in ("app-1.0.jar", "original-app-1.0.jar", "app-1.0-sources.jar"):
            open(os.path.join(self.project, "target", jar), "w").close()
        found = launcher.suggest(self.project)
        self.assertEqual(["./run.sh", "./mvnw spring-boot:run", "java -jar target/app-1.0.jar"], [c["command"] for c in found])
        self.assertTrue(all(c["why"] for c in found))
        self.assertEqual([], launcher.suggest(self.root), "nothing is guessed for a folder that holds no project")

    def test_the_application_starts_with_the_agent_on_its_jvm_and_its_output_is_kept(self):
        run = self.make()
        command = self.script("app.sh", 'echo "opts=$JAVA_TOOL_OPTIONS"\necho ready\nsleep 30\n')
        state = run.start(command)
        self.assertTrue(state["running"])
        state = self.wait(run, lambda s: "ready" in self.text(s))
        self.assertIn('"-javaagent:%s=%s"' % (self.agent, self.jots), self.text(state), "the project folder has a space in its name, so the option is quoted")
        self.assertEqual("$ " + command, state["lines"][0][1], "the first line is the command that was run")
        later = run.state(state["next"] - 1)
        self.assertEqual(["ready"], [t for _, t in later["lines"]], "a poll gets only what is new")

    def test_an_option_the_person_already_had_is_kept(self):
        run = self.make()
        command = self.script("app.sh", 'echo "opts=$JAVA_TOOL_OPTIONS"\n')
        with unittest.mock.patch.dict(os.environ, {"JAVA_TOOL_OPTIONS": "-Xmx64m"}):
            run.start(command)
        state = self.wait(run, lambda s: s["exit_code"] is not None)
        self.assertIn('opts=-Xmx64m "-javaagent:', self.text(state))
        self.assertEqual(0, state["exit_code"])
        self.assertFalse(state["running"])

    def test_stop_ends_what_the_script_started_too(self):
        run = self.make()
        run.start(self.script("app.sh", "sleep 60 &\necho child=$!\nwait\n"))
        state = self.wait(run, lambda s: "child=" in self.text(s))
        child = int(re.search(r"child=(\d+)", self.text(state)).group(1))
        stopped = run.stop()
        self.assertFalse(stopped["running"])
        end = time.time() + 5
        while time.time() < end:
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("the process the script started is still running")

    def test_what_cannot_be_started_is_said_plainly(self):
        run = self.make()
        with self.assertRaisesRegex(store.QueryError, "type the command"):
            run.start("  ")
        with self.assertRaisesRegex(store.QueryError, "wasn't found"):
            run.start("no-such-program --flag")
        with self.assertRaisesRegex(store.QueryError, "can't read that command"):
            run.start("echo 'unclosed")
        with self.assertRaisesRegex(store.QueryError, "agent jar wasn't found"):
            self.make(agent=False).start("true")
        run.agent = os.path.join(self.root, 'a"quote.jar')
        with self.assertRaisesRegex(store.QueryError, "double quote"):
            run.start("true")

    def test_a_second_start_is_refused_until_the_first_is_stopped(self):
        run = self.make()
        command = self.script("app.sh", "sleep 30\n")
        run.start(command)
        with self.assertRaises(store.SaveError) as caught:
            run.start(command)
        self.assertEqual(409, caught.exception.status)
        run.stop()
        self.assertTrue(run.start(command)["running"])

    def test_the_command_is_remembered_for_the_project(self):
        run = self.make()
        run.start(self.script("app.sh", "true\n"))
        self.wait(run, lambda s: s["exit_code"] is not None)
        self.assertEqual("./app.sh", launcher.Launcher(self.project, self.jots, agent=self.agent).state()["command"])
        self.assertTrue(os.path.isfile(os.path.join(self.project, ".jot", "run.json")))

    def test_the_console_runs_it_over_http_and_ending_the_project_ends_the_application(self):
        app = server.build_project(self.project, say=lambda *_: None)
        self.addCleanup(app.close)
        app.launcher.agent = self.agent
        httpd = server.make_server(app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        host = {"Host": "127.0.0.1:%d" % port}

        def call(path, body=None):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers=host if body is None else
                                         dict(host, **{"X-JOT-Dashboard": "1", "Content-Type": "application/json"}),
                                         data=None if body is None else json.dumps(body).encode())
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                return e.code, json.load(e)

        command = self.script("run.sh", "echo hello\nsleep 30\n")
        self.assertEqual(400, call("/api/run/start", {"command": ""})[0])
        status, out = call("/api/run/start", {"command": command})
        self.assertEqual((200, True), (status, out["running"]))
        end = time.time() + 10
        while time.time() < end and "hello" not in self.text(call("/api/run")[1]):
            time.sleep(0.05)
        self.assertIn("hello", self.text(call("/api/run")[1]))
        self.assertEqual([command], [s["command"] for s in call("/api/run")[1]["suggestions"]])
        pid = call("/api/run")[1]["pid"]
        app.close()
        end = time.time() + 5
        while time.time() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.05)
        else:
            self.fail("the application kept running after the console closed it")

    def test_an_application_started_some_other_way_can_be_found_and_stopped(self):
        import socket
        fake = os.path.join(self.root, "java")
        with open(fake, "w") as f:
            f.write("#!/bin/sh\nwhile :; do sleep 1; done\n")
        os.chmod(fake, 0o755)
        proc = subprocess.Popen([fake])
        self.addCleanup(proc.kill)
        other = subprocess.Popen(["/bin/sleep", "60"])
        self.addCleanup(other.kill)
        env = Env()
        host, now = socket.gethostname(), int(time.time() * 1000)
        env.write(event(1, pid=proc.pid, host=host, ts=now, run="mine", app="org.apache.catalina.startup.Bootstrap"),
                  event(2, pid=other.pid, host=host, ts=now, run="notjava"),
                  event(3, pid=proc.pid + 100000, host=host, ts=now, run="gone"),
                  event(4, pid=proc.pid, host="some-other-machine", ts=now, run="elsewhere"))
        env.ingestor.poll()
        found = launcher.running_elsewhere(env.db)
        self.assertEqual([proc.pid], [f["pid"] for f in found], "only a live Java process on this host counts")
        self.assertEqual("org.apache.catalina.startup.Bootstrap", found[0]["app"])
        old = os.path.join(self.root, "reused.db")
        stale = store.Ingestor(old, [])
        with stale.lock:
            stale.db.execute("INSERT INTO events_raw (ts, run, host, pid, sensor) VALUES (?, 'old', ?, ?, 'x')", (now - 3600 * 1000, host, proc.pid))
            stale.db.commit()
        self.assertEqual([], launcher.running_elsewhere(old), "a process that started after the events ended is not the application that wrote them")
        with self.assertRaises(store.SaveError) as caught:
            launcher.stop_elsewhere(env.db, other.pid)
        self.assertEqual(404, caught.exception.status)
        self.assertIsNone(other.poll(), "a process the console doesn't recognize is left alone")
        threading.Thread(target=proc.wait, daemon=True).start()     # a real application's parent collects it when it ends
        self.assertTrue(launcher.stop_elsewhere(env.db, proc.pid))
        self.assertIsNotNone(proc.poll())

    def test_a_configuration_change_after_the_application_started_says_a_restart_is_needed(self):
        app = server.build_project(self.project, say=lambda *_: None)
        self.addCleanup(app.close)
        run = app.launcher
        run.agent = self.agent
        self.assertEqual({"needed": False, "command": None, "running": False}, {k: app.restart_state()[k] for k in ("needed", "command", "running")},
                         "nothing is running, so nothing needs restarting")
        command = self.script("run.sh", "sleep 30\n")
        run.start(command)
        app._restart_cache = None
        self.assertFalse(app.restart_state()["needed"], "it started after the configuration was last written")
        run.started -= 30000                # it has been running for half a minute, and the configuration is saved now
        os.utime(self.jots)
        app._restart_cache = None
        state = app.restart_state()
        self.assertEqual((True, command, True), (state["needed"], state["command"], state["running"]))
        self.assertTrue(app.status()["restart"]["needed"], "the page reads it from the status")
        control = os.path.join(self.project, ".jot", "control.yaml")
        with open(control, "w") as f:
            f.write("master: true\n")
        os.utime(control)
        app._restart_cache = None
        self.assertEqual(state["changed"], app.restart_state()["changed"], "the protection settings are read while it runs, so they don't count")
        old = run.state()["pid"]
        app.restart_application()
        self.assertNotEqual(old, run.state()["pid"])
        self.assertFalse(app.restart_state()["needed"], "restarting cleared it, the new process started after the change")

    def test_an_application_started_some_other_way_counts_too(self):
        app = server.build_project(self.project, say=lambda *_: None)
        self.addCleanup(app.close)
        later = time.time() + 30
        os.utime(self.jots, (later, later))
        app._restart_cache = None
        with unittest.mock.patch.object(launcher, "running_elsewhere", return_value=[{"pid": 1, "started": time.time() - 5}]):
            self.assertTrue(app.restart_state()["needed"])
        app._restart_cache = None
        with unittest.mock.patch.object(launcher, "running_elsewhere", return_value=[{"pid": 1, "started": later + 10}]):
            self.assertFalse(app.restart_state()["needed"], "it started after the change")

    def test_a_console_other_machines_can_reach_has_no_launcher(self):
        app = server.build_project(self.project, remote=True, say=lambda *_: None)
        self.addCleanup(app.close)
        self.assertIsNone(app.launcher)

    def test_the_run_page_is_there_and_a_new_console_opens_on_it(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"), encoding="utf-8") as f:
            html = f.read()
        for needle in ('id="runPage"', 'href="#run"', '"/api/run/start"', '"/api/run/stop"', "chooseFirstPage();", 'id="restartBanner"', 'id="restartNow"',
                       '"/api/run/restart"'):
            self.assertIn(needle, html)


class ResetTests(unittest.TestCase):
    """Start over puts a project back to how it was before JOT, for demos."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.project = os.path.join(self.root, "demo")
        self.where = os.path.join(self.project, ".jot")
        os.makedirs(self.where)
        with open(os.path.join(self.where, "jot.yaml"), "w") as f:
            f.write("app:\n  packages:\n    - com.acme\n  entry:\n    - a.B.c\nsensors:\n- name: s1\n  description: A sensor\n  methods:\n  - a.B.c\n"
                    "  captures:\n    v: '#P0'\nreports:\n- name: R1\n  type: list\n  cols: s1.v\n")
        self.keep = os.path.join(self.root, "outside.txt")
        with open(self.keep, "w") as f:
            f.write("mine")
        for name in ("events.jsonl", "control.yaml", "agent.log", "run.json"):
            with open(os.path.join(self.where, name), "w") as f:
                f.write("x")
        os.makedirs(os.path.join(self.where, "sub"))
        open(os.path.join(self.where, "sub", "deep.txt"), "w").close()
        os.symlink(self.keep, os.path.join(self.where, "link"))
        self.handler = type("H", (server.Handler,), {})
        self.handler.app = server.build_project(self.project, say=lambda *_: None)
        self.addCleanup(lambda: self.handler.app.close())
        self.host = server.Host(self.handler, home=os.path.join(self.root, "home"))

    def seed(self):
        """Two events in the log that the console has taken in."""
        with open(os.path.join(self.where, "events.jsonl"), "w") as f:
            for i in (1, 2):
                f.write(json.dumps(event(i, sensor="s1", capture="x", data={"v": "x"})) + "\n")
        self.handler.app.ingestor.poll()

    def test_the_preview_says_what_would_go(self):
        self.seed()
        p = self.handler.app.reset_preview()
        self.assertEqual((2, 1, 1, 1), (p["events"], p["sensors"], p["reports"], p["entry"]))
        self.assertIn("events.jsonl", p["files"])
        self.assertEqual([], p["kept"])
        self.assertFalse(p["running"])

    def test_a_reset_leaves_an_empty_project_and_nothing_else(self):
        self.seed()
        old = self.handler.app
        out = self.host.reset()
        self.assertTrue(out["reset"])
        self.assertIsNot(old, self.handler.app)
        app = self.handler.app
        self.assertEqual(0, app.reset_preview()["events"])
        self.assertEqual([], app.jots()["sensors"])
        self.assertEqual([], app.jots()["reports"])
        self.assertIsNone(app.entry()["entry"], "the entry points are the default again")
        with open(os.path.join(self.where, "jot.yaml")) as f:
            self.assertEqual(store.FRESH_CONFIG, f.read(), "the same file a new project gets")
        self.assertLessEqual(set(os.listdir(self.where)), {".gitignore", "jot.yaml", "dashboard.db", "dashboard.db-shm", "dashboard.db-wal", "events.jsonl"},
                             "only what a new project has")
        for gone in ("control.yaml", "agent.log", "run.json", "sub", "link"):
            self.assertFalse(os.path.lexists(os.path.join(self.where, gone)), gone)

    def test_a_symbolic_link_is_removed_and_never_followed(self):
        self.host.reset()
        self.assertTrue(os.path.isfile(self.keep))
        with open(self.keep) as f:
            self.assertEqual("mine", f.read())

    def test_a_sensor_file_the_configuration_points_at_from_elsewhere_stays(self):
        other = os.path.join(self.project, "mine.jot")
        with open(other, "w") as f:
            f.write("sensors:\n- name: s2\n  description: Another\n  methods:\n  - a.B.d\n  captures:\n    v: '#P0'\n")
        with open(os.path.join(self.where, "jot.yaml"), "a") as f:
            f.write("jots:\n- ../mine.jot\n")
        self.handler.app.close()
        self.handler.app = server.build_project(self.project, say=lambda *_: None)
        self.assertEqual([other], self.handler.app.reset_preview()["kept"])
        self.host.reset()
        self.assertTrue(os.path.isfile(other), "files the person wrote are left alone")

    def test_it_is_refused_for_a_console_others_can_reach(self):
        with self.assertRaises(store.SaveError) as caught:
            server.Host(self.handler, remote=True).reset()
        self.assertEqual(403, caught.exception.status)

    def test_an_application_started_some_other_way_is_stopped_first_and_if_it_will_not_end_nothing_is_deleted(self):
        running = [{"pid": 4242, "app": "x", "run": "r", "last_ts": 1}]
        with unittest.mock.patch.object(launcher, "running_elsewhere", return_value=running), \
                unittest.mock.patch.object(launcher, "stop_elsewhere", return_value=False) as stop:
            with self.assertRaises(store.SaveError) as caught:
                self.host.reset()
        stop.assert_called_once_with(self.handler.app.db_path, 4242)
        self.assertEqual(409, caught.exception.status)
        self.assertTrue(os.path.isfile(os.path.join(self.where, "events.jsonl")), "nothing was deleted")
        self.assertEqual(1, len(self.handler.app.jots()["sensors"]), "and the project is still open")
        with unittest.mock.patch.object(launcher, "running_elsewhere", return_value=running), \
                unittest.mock.patch.object(launcher, "stop_elsewhere", return_value=True) as stop:
            self.host.reset()
        stop.assert_called_once()
        self.assertEqual([], self.handler.app.jots()["sensors"])

    def test_it_stops_the_application_the_console_started(self):
        run = self.handler.app.launcher
        run.agent = os.path.join(self.root, "jot.jar")
        open(run.agent, "w").close()
        path = os.path.join(self.project, "run.sh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\nsleep 60\n")
        os.chmod(path, 0o755)
        run.start("./run.sh")
        self.assertTrue(run.running())
        self.assertTrue(self.handler.app.reset_preview()["running"])
        self.host.reset()
        self.assertFalse(run.running())

    def test_the_console_asks_for_a_confirmation_over_http(self):
        httpd = server.make_server(self.handler.app, "127.0.0.1", 0)
        port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)
        self.handler = httpd.RequestHandlerClass
        host = {"Host": "127.0.0.1:%d" % port}

        def call(path, body=None):
            req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), headers=host if body is None else
                                         dict(host, **{"X-JOT-Dashboard": "1", "Content-Type": "application/json"}),
                                         data=None if body is None else json.dumps(body).encode())
            try:
                with urllib.request.urlopen(req) as r:
                    return r.status, json.load(r)
            except urllib.error.HTTPError as e:
                return e.code, json.load(e)

        self.assertEqual(1, call("/api/reset")[1]["sensors"])
        self.assertEqual(400, call("/api/reset", {})[0])
        self.assertEqual(400, call("/api/reset", {"confirm": "yes"})[0], "only a real true counts")
        self.assertEqual(1, call("/api/reset")[1]["sensors"], "nothing was reset")
        self.assertEqual(200, call("/api/reset", {"confirm": True})[0])
        self.assertEqual(0, call("/api/reset")[1]["sensors"])

    def test_the_page_has_the_start_over_panel(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"), encoding="utf-8") as f:
            html = f.read()
        for needle in ('id="resetOpen"', 'id="resetPanel"', '"/api/reset"', "confirm: true"):
            self.assertIn(needle, html)


class SettingsTests(unittest.TestCase):
    """The packages and the ignore list are edited on the JOTs page like the entry points, and saving them sorts the recorded events again."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)
        self.where = os.path.join(self.root, ".jot")
        os.makedirs(self.where)
        self.file = os.path.join(self.where, "jot.yaml")
        with open(self.file, "w") as f:
            f.write("# my notes\napp:\n  entry:\n    - a.B.c\nsensors: []\nreports: []\n")
        with open(os.path.join(self.where, "events.jsonl"), "w") as f:
            f.write(json.dumps(event(1, stack=["org.libs.Util.run(Util.java:1)"])) + "\n")
        self.app = server.build_project(self.root, say=lambda *_: None)
        self.addCleanup(self.app.close)
        self.addCleanup(store.set_ignore, None)

    def origin(self, n=1):
        return store.run_query(self.app.db_path, "SELECT origin FROM events_raw WHERE id = %d" % n)["rows"][0][0]

    def test_each_setting_is_read_with_its_default_and_whether_it_can_be_changed(self):
        got = {n: self.app.setting(n) for n in ("entry", "ignore", "packages")}
        self.assertEqual((["a.B.c"], None, None), (got["entry"]["values"], got["ignore"]["values"], got["packages"]["values"]))
        self.assertEqual(store.DEFAULT_IGNORE, tuple(got["ignore"]["default"]) if isinstance(store.DEFAULT_IGNORE, tuple) else got["ignore"]["default"])
        self.assertEqual([], got["packages"]["default"])
        self.assertTrue(all(g["editable"] and g["file"] == "jot.yaml" for g in got.values()))
        with self.assertRaises(store.QueryError):
            self.app.setting("nothing")

    def test_what_is_typed_is_checked(self):
        self.assertEqual([{"index": 1, "message": "isn't a package, write it like com.acme"}], self.app.check_setting("packages", ["com.acme", "not a package"]))
        self.assertEqual([{"index": 1, "message": "is listed twice"}], self.app.check_setting("ignore", ["java.lang.ClassLoader", "java.lang.ClassLoader"]))
        self.assertEqual([], self.app.check_setting("packages", ["com.acme"]))

    def test_saving_packages_writes_the_file_keeps_the_rest_and_sorts_the_events_again(self):
        self.assertEqual("app", self.origin(), "with no packages named, anything that isn't the platform is the application")
        done = self.app.change_setting("packages", ["com.acme"], None)
        self.assertEqual((["com.acme"], "jot.yaml"), (done["values"], done["saved"]))
        text = open(self.file).read()
        self.assertIn("# my notes", text)
        self.assertIn("- a.B.c", text, "the entry points are untouched")
        self.assertEqual("library", self.origin(), "the library frame is no longer the application's")
        self.app.change_setting("packages", None, ["com.acme"])
        self.assertEqual("app", self.origin())
        self.assertNotIn("packages", open(self.file).read())

    def test_saving_the_ignore_list_applies_at_once(self):
        # the application asked for nothing here, a server frame between the call and the application frame is work the platform did on its own
        with open(os.path.join(self.where, "events.jsonl"), "a") as f:
            f.write(json.dumps(event(2, stack=["java.lang.String.valueOf(String.java:1)", "org.apache.catalina.Foo.bar(Foo.java:1)",
                                                 "com.acme.App.run(App.java:1)"])) + "\n")
        self.app.ingestor.poll()
        self.assertEqual("app", self.origin(2))
        self.app.change_setting("ignore", ["org.apache.catalina.Foo"], None)
        self.assertEqual(["org.apache.catalina.Foo"], self.app.setting("ignore")["values"])
        self.assertEqual("platform", self.origin(2), "what is ignored is platform work, not the application")
        self.app.change_setting("ignore", None, ["org.apache.catalina.Foo"])
        self.assertEqual("app", self.origin(2), "and taking the list out brings the default back")

    def test_a_file_changed_since_it_was_opened_is_not_overwritten(self):
        self.app.change_setting("packages", ["com.acme"], None)
        with self.assertRaises(store.SaveError) as caught:
            self.app.change_setting("packages", ["com.other"], None)
        self.assertEqual(409, caught.exception.status)
        self.assertEqual(["com.acme"], self.app.setting("packages")["values"])

    def test_it_is_refused_where_the_console_cannot_write(self):
        self.app.editable = False
        with self.assertRaises(store.SaveError) as caught:
            self.app.change_setting("packages", ["com.acme"], None)
        self.assertEqual(403, caught.exception.status)
        self.assertFalse(self.app.setting("packages")["editable"])

    def test_the_page_has_an_editor_for_each(self):
        with open(os.path.join(os.path.dirname(__file__), "..", "static", "index.html"), encoding="utf-8") as f:
            html = f.read()
        for name in ("entry", "ignore", "packages"):
            for part in ("Card", "Summary", "List", "Input", "Add", "Save", "Revert", "Default", "Status"):
                self.assertIn('id="%s%s"' % (name, part), html)
        for needle in ('"/api/setting/save"', '"/api/setting/check"', '"/api/setting?name="'):
            self.assertIn(needle, html)


class GraphKeysTests(unittest.TestCase):
    """The arrow keys move the pick over the graph, to the nearest box on the side that was pressed."""
    CHROME = DraftUiTests.CHROME
    SERVLET, FILTER, JDK = GraphMethodPageTests.SERVLET, GraphMethodPageTests.FILTER, GraphMethodPageTests.JDK
    setUp = GraphMethodPageTests.setUp
    serve = EntryPointPageTests.serve

    SCRIPT = """
    (async () => {
      const wait = (ms) => new Promise((r) => setTimeout(r, ms));
      const until = async (f, ms = 8000) => { const t = Date.now(); while (Date.now() - t < ms) { const v = f(); if (v) return v; await wait(40); } return null; };
      const out = {};
      try {
        location.hash = "#graph";
        await until(() => document.querySelector("g.node"));
        const key = async (k, target) => {
          const ev = new KeyboardEvent("keydown", { key: k, bubbles: true, cancelable: true });
          (target || document.body).dispatchEvent(ev);
          await wait(150);
          return ev.defaultPrevented;
        };
        const picked = () => { const g = document.querySelector("g.node.picked"); return g ? g.querySelector("text").textContent : null; };
        out.start = picked();
        out.first = [await key("ArrowRight"), picked()];
        out.focused = !!document.activeElement && document.activeElement.classList.contains("picked");
        out.detail = !document.getElementById("graphDetail").hidden;
        out.hash = location.hash;
        out.right = [await key("ArrowRight"), picked()];
        out.back = [await key("ArrowLeft"), picked()];
        out.nothingLeft = [await key("ArrowLeft"), picked()];
        out.inSelect = [await key("ArrowRight", document.getElementById("graphRoute")), picked()];
        out.withShift = [await (async () => { const ev = new KeyboardEvent("keydown", { key: "ArrowRight", shiftKey: true, bubbles: true, cancelable: true }); document.body.dispatchEvent(ev); await wait(100); return ev.defaultPrevented; })(), picked()];
      } catch (e) { out.error = String(e); }
      const pre = document.createElement("pre"); pre.id = "testResult"; pre.textContent = JSON.stringify(out); document.body.append(pre);
    })();
    """

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_arrow_keys_pick_the_nearest_box_on_that_side(self):
        out = self.serve(self.app, self.SCRIPT)
        self.assertNotIn("error", out, out)
        self.assertIsNone(out["start"], "nothing is picked until a key or a click")
        self.assertEqual(True, out["first"][0], "the key is the graph's, the page doesn't scroll")
        self.assertIn("/buy", out["first"][1], "the first key picks the entry box")
        self.assertTrue(out["focused"], "and the box has the focus, so the keys go on working")
        self.assertTrue(out["detail"], "the detail follows the pick, as it does for a click")
        self.assertRegex(out["hash"], r"^#graph/.+", "and the address follows, so it can be linked to")
        self.assertNotEqual(out["first"][1], out["right"][1], "right moves on to a box the entry leads to")
        self.assertEqual(out["first"][1], out["back"][1], "and left comes back")
        self.assertEqual((True, out["first"][1]), tuple(out["nothingLeft"]), "nothing is left of the entry, so the pick stays and the key is still taken")
        self.assertEqual((False, out["first"][1]), tuple(out["inSelect"]), "a key typed in a field or a menu belongs to it")
        self.assertFalse(out["withShift"][0], "a key with a modifier is left to the browser")


if __name__ == "__main__":
    unittest.main()
