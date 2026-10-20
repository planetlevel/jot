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
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import control
import llm
import server
import store


def event(i, sensor="crypto-cipher", capture="AES", action="observed", trace=1, run="r1", **extra):
    e = {"v": 1, "time": "2026-10-16T00:00:00Z", "ts": 1792111134000 + i, "run": run, "host": "h", "pid": 1,
         "app": "App", "id": i, "trace": trace, "thread": "main", "thread_id": 1, "sensor": sensor,
         "action": action, "capture": capture,
         "method": "java.base/javax.crypto.Cipher.getInstance(Cipher.java:531)",
         "call_site": "com.acme.Ticket.encrypt(Ticket.java:125)", "stack": ["a", "b"]}
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

    def test_a_field_that_isnt_a_name_cannot_break_the_query(self):
        with self.assertRaises(ValueError):
            store.report_sql("table", "http-route.path", "a.b'); DROP TABLE events; --")

    def test_list_is_call_sites_with_what_they_captured(self):
        self.assertEqual([("com.acme.Ticket.encrypt(Ticket.java:125)", "crypto-cipher.algorithm", "DES")], self.rows("Encryption Usage"))

    def test_table_has_a_column_per_sensor(self):
        self.assertEqual([("/buy", "crypto-cipher.algorithm", "DES")], self.rows("Cipher Table"))

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
        page = self.render("#jots/never-fires")
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
        self.assertGreaterEqual(drawer.count('href="#jots/http-route"'), 2, "linked in the heading and in the details")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_the_panel_has_previous_and_next_buttons_with_the_position_in_the_list(self):
        page = self.render("#jots/http-route")
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
        panel = re.search(r'<div class="card wide" id="protectionCard"[^>]*>(.*?)</div>\s*<div class="card wide" id="sensorsCard"', page, re.S).group(1)
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
                       event(2, sensor="jot-config", capture="jots=/x/jots.yaml", ts=now, run="r9"),
                       event(3, sensor="jot-config", capture="loaded=rule-a", ts=now, run="r9"))
        self.env.ingestor.poll()
        state = self.app.control_state()
        self.assertTrue(state["agent"]["locked"])
        self.assertEqual("/x/jots.yaml", state["agent"]["jots"])
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
        self.assertEqual(["file-log-write", "http-cookie-set", "native-process"], [yaml.safe_load(e)["name"] for e in found])
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

    def test_a_hidden_jot_shows_nothing_it_observed_but_what_it_blocked(self):
        self.assertEqual(["crypto-hash", "http-cache-header", "native-process-active", "native-process-blocked"], self.seen())
        status = self.app.set_hidden_jots(["http-cache-header", "native-process"])
        self.assertEqual(["http-cache-header", "native-process"], status["hidden_jots"])
        self.assertEqual(["crypto-hash", "native-process-blocked"], self.seen(), "its -active event is hidden, its block is not")
        self.assertEqual(5, store.run_query(self.env.db, "SELECT COUNT(*) FROM events_raw")["rows"][0][0], "nothing is deleted")
        self.assertEqual([], self.app.set_hidden_jots([])["hidden_jots"])
        self.assertEqual(4, len(self.seen()))

    def test_the_list_of_jots_has_what_is_in_the_files_and_the_events_with_counts(self):
        with open(os.path.join(self.env.dir, "a.jot"), "w") as f:
            f.write("sensors:\n- name: never-fires\n  methods:\n  - a.b.C.m\n")
        store.load_sensors(self.env.ingestor.db, [self.env.dir])
        jots = {j["name"]: j["events"] for j in self.app.filter_jots()}
        self.assertEqual(0, jots["never-fires"])
        self.assertEqual(2, jots["native-process"], "its -active and -blocked events are one JOT")
        self.assertEqual(1, jots["http-cache-header"])
        self.assertNotIn("jot-control", jots)

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
        out.barHasFilters = !!document.querySelector("#sharedBar #appOnly");
        out.barHasClear = !!document.querySelector("#sharedBar #clearBtn");
        out.startsClosed = document.getElementById("filterDrawer").hidden;
        document.getElementById("filtersBtn").click();
        await until(() => document.querySelectorAll("#filterJotList label").length >= 2);
        out.open = !document.getElementById("filterDrawer").hidden;
        out.visible = [...document.querySelectorAll("#filterJotList label")].every((l) => l.offsetHeight > 0 && l.offsetWidth > 0);
        out.listed = [...document.querySelectorAll("#filterJotList label span:not(.n)")].map((x) => x.textContent);
        const box = [...document.querySelectorAll("#filterJotList label")].find((l) => l.textContent.indexOf("http-cache-header") >= 0).querySelector("input");
        out.allTicked = [...document.querySelectorAll("#filterJotList input")].every((b) => b.checked);
        box.click();
        await until(() => document.getElementById("filtersBtn").textContent === "Filters (1)");
        out.button = document.getElementById("filtersBtn").textContent;
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
        self.assertEqual("Filters (1)", out["button"], "the button says how many filters are on")
        self.assertEqual(["crypto-hash"], out["found"])
        self.assertTrue(out["closedByEscape"])
        self.assertTrue(out["blockedKept"], "what a rule blocked can't be hidden")
        self.assertIn("Hid crypto-hash", out["toast"])
        self.assertEqual(["crypto-hash", "http-cache-header"], out["hiddenAfterH"])
        self.assertEqual(["http-cache-header"], out["hiddenAfterUndo"])
        self.assertEqual(["http-cache-header"], store.get_hidden_jots(env.db))
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
        location.hash = "#jots/crypto-cipher";
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
        location.hash = "#jots/crypto-cipher";
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

    def page(self, body):
        """Opens the dashboard in Chrome on a file with one sensor, runs body in the page, and returns what it put in out, and the path."""
        env = Env()
        path = os.path.join(env.dir, "a.jot")
        with open(path, "w") as f:
            f.write("sensors:\n- name: crypto-cipher\n  description: Records ciphers\n  methods:\n  - javax.crypto.Cipher.getInstance\n  captures:\n    value: '#P0'\n")
        store.load_sensors(env.ingestor.db, [env.dir])
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
          location.hash = "#jots/crypto-cipher";
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
    def test_a_rename_ends_clean_on_the_new_name(self):
        out, path = self.page("""
          location.hash = "#jots/crypto-cipher";
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
        self.assertEqual("#jots/crypto-cipher-use", out["hash"])
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
        for where in ("cves", "demo/ticketbook/jots", "demo/ticketbook/rules", "src/main/resources"):
            for path in glob.glob(os.path.join(self.ROOT, where, "*.jot")):
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
                path = os.path.join(d, "jots.yaml")
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

    def test_app_only_is_on_by_default_and_hides_only_observed_events_without_an_app_frame(self):
        ing = self.ingestor()
        self.write(event(1, stack=JDK_ONLY), event(2, stack=VIA_LIBRARY), event(3, stack=LIBRARY_ONLY),
                   event(4, stack=JDK_ONLY, action="blocked", sensor="block-x"),
                   event(5, stack=JDK_ONLY, action="monitored", sensor="block-y"),
                   event(6, stack=None, sensor="jot-config"))
        ing.poll()
        self.assertTrue(store.get_app_only(self.db))
        self.assertEqual(sorted(self.origins("events")), [2, 4, 5, 6])
        store.set_app_only(ing.db, False)
        self.assertEqual(sorted(self.origins("events")), [1, 2, 3, 4, 5, 6])
        store.set_app_only(ing.db, True)
        self.assertEqual(sorted(self.origins("events")), [2, 4, 5, 6])

    def test_the_blocked_and_monitored_filters_keep_only_those_events(self):
        ing = self.ingestor()
        self.write(event(1, stack=JSP), event(2, stack=JSP, action="blocked", sensor="block-x"),
                   event(3, stack=JDK_ONLY, action="monitored", sensor="block-y"), event(4, stack=JSP, sensor="auth-user"))
        ing.poll()
        self.assertEqual({"blocked": False, "monitored": False}, store.get_action_filter(self.db))
        self.assertEqual(sorted(self.origins("events")), [1, 2, 3, 4])
        store.set_action_filter(ing.db, blocked=True)
        self.assertEqual({"blocked": True, "monitored": False}, store.get_action_filter(self.db))
        self.assertEqual(sorted(self.origins("events")), [2])
        store.set_action_filter(ing.db, monitored=True)
        self.assertEqual(sorted(self.origins("events")), [2, 3])
        store.set_action_filter(ing.db, blocked=False)
        self.assertEqual(sorted(self.origins("events")), [3])
        store.set_action_filter(ing.db, monitored=False)
        self.assertEqual(sorted(self.origins("events")), [1, 2, 3, 4])

    def test_jot_control_events_are_left_out_until_asked_for(self):
        ing = self.ingestor()
        self.write(event(1, stack=JSP), event(2, stack=None, sensor="jot-control", capture="rule-a=monitor"))
        ing.poll()
        self.assertFalse(store.get_show_jot_control(self.db))
        self.assertEqual(sorted(self.origins("events")), [1])
        store.set_show_jot_control(ing.db, True)
        self.assertEqual(sorted(self.origins("events")), [1, 2])

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
        self.ingestor()
        self.assertEqual(self.origins(), {1: "platform", 2: "app"})
        self.assertEqual(sorted(self.origins("events")), [2])

    def test_the_toggle_and_the_counts_over_http(self):
        ing = self.ingestor()
        self.write(event(1, stack=JDK_ONLY), event(2, stack=JDK_ONLY), event(3, stack=JSP))
        ing.poll()
        app = server.App(self.db, ing)
        s = app.status()
        self.assertEqual((s["events"], s["filtered"], s["app_only"]), (1, 2, True))
        s = app.set_app_only(False)
        self.assertEqual((s["events"], s["filtered"], s["app_only"]), (3, 0, False))
        app.set_since(1792111134000 + 3)
        app.set_app_only(True)
        s = app.status()
        self.assertEqual((s["events"], s["hidden"], s["filtered"]), (1, 2, 0), "the start time and the filter are counted apart")


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

    def test_matches_the_filter_leaves_out_are_counted(self):
        r = self.app.search("sha-256")
        self.assertEqual((1, 1), (r["matches"], r["left_out"]))
        self.app.set_app_only(False)
        r = self.app.search("sha-256")
        self.assertEqual((2, 0), (r["matches"], r["left_out"]))

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

    def test_a_path_runs_from_the_route_through_the_application_code_to_what_the_sensor_saw(self):
        g, nodes, edges = self.graph()
        self.assertEqual(2, edges[("route:/app/list.jsp", "code:com.acme.Database.getTickets")])
        self.assertEqual(2, edges[("code:com.acme.Database.getTickets", "code:com.acme.Ticket.encrypt")])
        self.assertEqual(2, edges[("code:com.acme.Ticket.encrypt", "effect:crypto-cipher")])
        self.assertEqual(2, nodes["effect:crypto-cipher"]["events"])
        self.assertEqual([("AES", 1), ("DES", 1)], sorted(nodes["effect:crypto-cipher"]["captures"]))

    def test_the_jsp_page_is_the_route_and_is_not_drawn_twice(self):
        g, nodes, edges = self.graph()
        self.assertFalse([i for i in nodes if "list_jsp" in i])

    def test_jdk_and_server_frames_are_not_drawn(self):
        g, nodes, edges = self.graph()
        self.assertFalse([i for i in nodes if "java.base" in i or "catalina" in i or "Cipher" in i])

    def test_a_blocked_event_marks_its_effect(self):
        g, nodes, edges = self.graph()
        self.assertEqual(1, nodes["effect:block-exec"]["blocked"])
        self.assertEqual(0, nodes["effect:crypto-cipher"]["blocked"])
        self.assertIn(("effect:crypto-cipher", "effect:block-exec"), edges, "it came after the ciphers in that request")

    def test_a_request_is_one_line_with_a_stop_for_each_event_in_the_order_they_happened(self):
        self.env.write(
            event(30, sensor="http-route", capture="/app/order.jsp", trace=30, stack=[self.SERVLET, self.FILTER]),
            event(31, sensor="crypto-hash", capture="MD5", trace=30, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]),
            event(32, sensor="crypto-cipher", capture="AES", trace=30, stack=["java.base/a.B.c(B.java:1)", self.ENCRYPT, self.GET, self.FILTER]),
            event(33, sensor="crypto-cipher", capture="DES", trace=30, stack=["java.base/a.B.c(B.java:1)", self.ENCRYPT, self.GET, self.FILTER]),
            event(34, sensor="crypto-hash", capture="SHA", trace=30, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph(route="/app/order.jsp")
        get, enc = "code:com.acme.Database.getTickets", "code:com.acme.Ticket.encrypt"
        self.assertEqual({("route:/app/order.jsp", get): 1, (get, "effect:crypto-hash"): 1,
                          ("effect:crypto-hash", enc): 2, (enc, "effect:crypto-cipher"): 2,
                          ("effect:crypto-cipher", "effect:crypto-hash"): 1}, edges)
        self.assertEqual(2, nodes["effect:crypto-cipher"]["events"], "the repeat is one stop, both events are counted")

    def test_a_method_the_line_is_already_inside_is_not_entered_again(self):
        self.env.write(
            event(40, sensor="http-route", capture="/app/inside.jsp", trace=40, stack=[self.SERVLET, self.FILTER]),
            event(41, sensor="crypto-hash", capture="MD5", trace=40, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]),
            event(42, sensor="crypto-cipher", capture="AES", trace=40, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph(route="/app/inside.jsp")
        self.assertIn(("effect:crypto-hash", "effect:crypto-cipher"), edges)
        self.assertNotIn(("effect:crypto-hash", "code:com.acme.Database.getTickets"), edges)

    def test_requests_that_did_the_same_things_in_the_same_order_share_a_line(self):
        for trace, base in ((60, 60), (61, 70)):
            self.env.write(
                event(base, sensor="http-route", capture="/app/twice.jsp", trace=trace, stack=[self.SERVLET, self.FILTER]),
                event(base + 1, sensor="crypto-cipher", capture="AES", trace=trace, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]),
                event(base + 2, sensor="crypto-hash", capture="MD5", trace=trace, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph(route="/app/twice.jsp")
        self.assertEqual(2, edges[("effect:crypto-cipher", "effect:crypto-hash")])

    def test_a_forward_and_a_redirect_lead_to_their_route_under_every_name_they_have_had(self):
        for base, (route_sensor, forward, redirect) in ((60, ("http-route", "http-forward", "http-redirect")),
                                                         (70, ("get-route", "get-forward", "get-redirect")),
                                                         (80, ("get-routes", "get-forwards", "get-redirects"))):
            self.env.write(
                event(base, sensor=route_sensor, capture="/app/profile%d" % base, trace=base, stack=[self.SERVLET, self.FILTER]),
                event(base + 1, sensor=forward, capture="/list.jsp", trace=base,
                      stack=["jakarta.servlet.RequestDispatcher.forward(R.java:1)", "com.acme.ProfileController.doPost(P.java:28)", self.FILTER]),
                event(base + 2, sensor=route_sensor, capture="/app/other%d" % base, trace=base + 1, stack=[self.SERVLET, self.FILTER]),
                event(base + 3, sensor=redirect, capture="/app/list.jsp", trace=base + 1,
                      stack=["jakarta.servlet.http.HttpServletResponse.sendRedirect(R.java:1)", "com.acme.OtherController.doGet(O.java:9)", self.FILTER]))
        self.env.ingestor.poll()
        g = self.app.graph()
        for route in ("/app/profile60", "/app/profile70", "/app/profile80", "/app/other60", "/app/other70", "/app/other80"):
            self.assertIn(route, g["routes"], "a route is found whatever the route sensor was called")
        exits = {n["id"] for n in g["nodes"] if n["kind"] == "exit"}
        self.assertIn("exit:/app/list.jsp", exits, "a route out, for the forwards and the redirects under every name")

    def test_route_search_and_one_route_graphs_work_for_events_from_the_old_names(self):
        self.env.write(event(90, sensor="get-routes", capture="/app/old.jsp", trace=90, stack=[self.SERVLET, self.FILTER]),
                       event(91, sensor="crypto-hash", capture="MD5", trace=90, stack=["java.base/a.B.c(B.java:1)", self.GET, self.FILTER]))
        self.env.ingestor.poll()
        self.assertEqual(["/app/old.jsp"], [x["route"] for x in self.app.graph("/app/old.jsp", split=True)["graphs"]])
        self.assertEqual(1, self.app.search('route:"/app/old.jsp" crypto-hash')["matches"])

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
        self.assertTrue((one | two) <= lines["effect:crypto-hash"], "both used the hash")
        cipher_edge = edge_lines[("code:com.acme.Ticket.encrypt", "effect:crypto-cipher")]
        self.assertTrue(one & cipher_edge and not two & cipher_edge, "only the first request reached the cipher")
        self.assertTrue(lines["effect:crypto-cipher"] >= one and not (lines["effect:crypto-cipher"] & two))

    def test_request_details_are_left_out_unless_asked_for(self):
        g, nodes, edges = self.graph()
        self.assertNotIn("effect:auth-user", nodes)
        g, nodes, edges = self.graph(details=True)
        self.assertEqual(1, edges[("route:/app/list.jsp", "effect:auth-user")])

    def test_a_forward_leads_on_to_the_route_it_names(self):
        g, nodes, edges = self.graph()
        self.assertEqual(1, edges[("effect:http-forward", "exit:/app/list.jsp")])
        self.assertEqual("exit", nodes["exit:/app/list.jsp"]["kind"])
        self.assertIn(("code:com.acme.ProfileController.doPost", "effect:http-forward"), edges)

    def test_events_outside_a_request_start_from_their_own_route(self):
        g, nodes, edges = self.graph()
        self.assertIn(("route:(outside a request)", "code:com.acme.Startup.run"), edges)

    def test_one_route_can_be_picked(self):
        g, nodes, edges = self.graph(route="/app/profile")
        self.assertEqual(["route:/app/profile"], [n["id"] for n in g["nodes"] if n["kind"] == "route"])
        self.assertIn("/app/list.jsp", g["routes"], "the list of routes is of all of them")

    def test_the_blocked_and_monitored_filters_apply_to_the_graph_and_keep_each_event_on_its_route(self):
        g, nodes, edges = self.graph()
        everything = {n["id"] for n in g["nodes"] if n["kind"] == "effect"}
        self.app.set_action_filter(True, None)
        g, nodes, edges = self.graph()
        effects = [n for n in g["nodes"] if n["kind"] == "effect"]
        self.assertTrue(effects)
        self.assertLess(len(effects), len(everything))
        self.assertTrue(all(n["blocked"] for n in effects), "only blocked effects are left")
        routes = {n["label"] for n in g["nodes"] if n["kind"] == "route"}
        self.assertNotIn("(outside a request)", routes, "the http-route events are hidden by the filter but still name the route")
        self.assertTrue(routes)
        self.assertIn("/app/list.jsp", g["routes"], "the route list isn't narrowed by the filter")

    def test_it_follows_the_filters(self):
        self.env.write(event(20, sensor="crypto-hash", capture="MD5", trace=50, stack=["java.base/a.B.c(B.java:1)", "java.base/d.E.f(E.java:1)"]))
        self.env.ingestor.poll()
        g, nodes, edges = self.graph()
        self.assertNotIn("effect:crypto-hash", [e[1] for e in edges if e[1] == "effect:crypto-hash" and "MD5" in str(nodes[e[1]]["captures"])])
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
        self.assertIn("route out", page)
        self.assertNotIn(">null<", page)
        self.assertRegex(page, r'class="node effect blocked"')
        self.assertRegex(page, r'<div id="graphTip"[^>]* hidden', "the hover box is there and hidden until a node is hovered")
        self.assertNotRegex(page, r'<g class="node[^>]*><title>', "the hover box replaces the browser's own tooltip")
        self.assertNotRegex(page, r'<svg class="graph"[^>]*><title>', "and a route's graph has no tooltip of its own")

    @unittest.skipUnless(CHROME, "Chrome is not installed")
    def test_a_picked_node_follows_its_paths_and_dims_the_rest(self):
        page = self.render("#graph/effect%3Acrypto-cipher")
        self.assertRegex(page, r'<g class="node effect picked"')
        panel = re.search(r'<aside class="card" id="graphDetail"([^>]*)>(.*?)</aside>', page, re.S)
        self.assertNotIn("hidden", panel.group(1))
        text = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", panel.group(2)))
        for expected in ("crypto-cipher", "AES", "DES", "Comes from", "Ticket.encrypt", "Show these events"):
            self.assertIn(expected, text)
        self.assertNotIn("null", text.lower())
        self.assertNotIn("routegraph off", page, "only the route the node is in is lit, others are left alone")
        self.assertRegex(page, r'class="edge on"')

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
            jots_file = os.path.join(d, "jots.yaml")
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
                path = os.path.join(d, "jots.yaml")
                with open(path, "w") as fh:
                    fh.write(text)
                return store.read_jots_file(path)[2], store.jots_file_problems(path)
            packages, problems = check("jots: []\napp:\n- com.acme\n")
            self.assertEqual([], packages)
            self.assertTrue(any("app must be a mapping with packages and entry" in p for p in problems), problems)
            packages, problems = check("jots: []\napp:\n  packages: com.acme\n  entrys: []\nignorr: []\n")
            self.assertEqual(["com.acme"], packages, "one package can be written without a list")
            self.assertTrue(any("entrys" in p for p in problems) and any("ignorr is not a setting" in p for p in problems), problems)


if __name__ == "__main__":
    unittest.main()
