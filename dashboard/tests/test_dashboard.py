import contextlib
import http.server
import io
import json
import os
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


def event(i, sensor="get-ciphers", capture="AES", action="observed", trace=1, run="r1", **extra):
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
            f.write("sensors:\n- name: 'get-ciphers'\n  description: 'Identifies ciphers'\n  methods:\n"
                    "  - 'javax.crypto.Cipher.getInstance'\n- name: 'block-it'\n  exception: 'no'\n")
        self.assertEqual(2, store.load_sensors(self.env.ingestor.db, [self.env.dir]))
        app = server.App(self.env.db, self.env.ingestor)
        by_name = {s["name"]: s for s in app.sensors()}
        self.assertEqual("Identifies ciphers", by_name["get-ciphers"]["description"])
        self.assertEqual("no", by_name["block-it"]["blocks"])


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
- name: 'get-routes'
reports:
- name: 'Access Control Matrix'
  type: 'compare'
  rows: 'get-routes'
  cols: 'get-role'
- name: 'Test Coverage Matrix'
  type: 'compare'
  rows: 'get-routes'
  cols: 'get-users'
- name: 'Encryption Usage'
  type: 'list'
  cols: 'get-ciphers'
- name: 'Cipher Table'
  type: 'table'
  rows: 'get-routes'
  cols: 'get-ciphers, get-hashes'
- name: 'Old Timeseries'
  type: 'series'
  rows: 'x'
  cols: 'y'
- name: 'Broken'
  type: 'table'
  cols: 'get-ciphers'
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
            event(1, sensor="get-routes", capture="/buy", trace=7),
            event(2, sensor="get-role", capture="RoleA", trace=7),
            event(3, sensor="get-role", capture="RoleB", trace=7),
            event(4, sensor="get-role", capture="RoleB", trace=7),
            event(5, sensor="get-ciphers", capture="DES", trace=7),
            event(6, sensor="get-routes", capture="/home", trace=8),
            event(7, sensor="get-role", capture="RoleA", trace=8),
            event(8, sensor="get-users", capture="alice:Role1", trace=8),
            event(9, sensor="get-routes", capture="/other", trace=9, run="r2"),
            event(10, sensor="get-role", capture="RoleC", trace=9, run="r1"))  # a different run, must not join
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
        self.assertEqual([("/buy", "RoleA", "X"), ("/buy", "RoleB", "X"), ("/home", "RoleA", "X")],
                         self.rows("Access Control Matrix"))

    def test_compare_uses_name_and_value_from_a_name_colon_value_capture(self):
        self.assertEqual([("/home", "alice", "Role1")], self.rows("Test Coverage Matrix"))

    def test_list_is_call_sites_with_what_they_captured(self):
        self.assertEqual([("com.acme.Ticket.encrypt(Ticket.java:125)", "get-ciphers", "DES")], self.rows("Encryption Usage"))

    def test_table_has_a_column_per_sensor(self):
        self.assertEqual([("/buy", "get-ciphers", "DES")], self.rows("Cipher Table"))

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
        self.assertIn("grid", llm.SYSTEM)
        self.assertIn("Never ask the user for values", llm.SYSTEM)
        self.assertIn("grid", llm.TOOL["input_schema"]["properties"]["chart"]["enum"])
        prompt = llm.build_prompt("recreate it", "s", [], reports=self.app.report_summaries())
        self.assertIn("Access Control Matrix (compare, rows get-routes, cols get-role)", prompt)
        self.assertIn("Encryption Usage (list, rows none, cols get-ciphers)", prompt)

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
        self.env.write(event(1, sensor="get-routes", capture="/buy", trace=7),
                       event(2, sensor="get-ciphers", capture="DES", trace=7),
                       event(3, sensor="get-ciphers", capture="AES", trace=8))
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
            "ON r.run = c.run AND r.trace = c.trace WHERE r.sensor='get-routes' AND c.sensor='get-ciphers'"))
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
        self.assertIn("get-ciphers (2)", r["hint"])
        self.assertIn("get-routes (1)", r["hint"])

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
            [{"name": "get-ciphers", "description": "Identifies ciphers",
              "methods": ["javax.crypto.Cipher.getInstance"], "scopes": [], "blocks": None},
             {"name": "blocker", "description": None, "methods": [], "scopes": ["a.B.c"], "blocks": "denied"}],
            [{"question": "before", "sql": "SELECT 1"}], error="boom")
        for text in ("get-ciphers: Identifies ciphers", "watches javax.crypto.Cipher.getInstance",
                     "only inside a.B.c", "blocks, message: denied", "Q: before", "SQL: SELECT 1",
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
  exception: 'no a'
- name: 'rule-b'
  exception: 'no b'
  enforce: false
- name: 'just-watching'
"""


JOTS_A = """
sensors:
- name: 'get-routes'
  description: 'Identifies the route'
  methods: ['javax.servlet.Servlet.service']
  captures: ['#P0.getRequestURI()']
  matchers: ['!null']
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
  exception: 'no processes'
- name: 'example'
  methods: ['a.b.c.Class.method']
reports:
- name: 'Routes by users'
  type: 'compare'
  rows: 'get-routes'
  cols: 'get-users'
- name: 'Old series'
  type: 'series'
  rows: 'get-routes'
  cols: 'get-routes'
"""

JOTS_B = """
sensors:
- name: 'get-routes'
  methods: ['x.Y.z']
- name: 'block-staged'
  methods: ['java.net.Socket.<init>']
  exception: 'no sockets'
  enforce: false
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
        self.env.write(event(1, sensor="get-routes", capture="/a", ts=now),
                       event(2, sensor="get-routes", capture="/b", ts=now - 7200 * 1000),
                       event(3, sensor="block-exec", action="blocked", ts=now),
                       event(4, sensor="block-exec", action="monitored", ts=now),
                       event(5, sensor="mystery", ts=now),
                       event(6, sensor="jot-control", capture="x=block", ts=now))
        self.env.ingestor.poll()
        self.app = server.App(self.env.db, self.env.ingestor)
        self.view = self.app.jots()
        self.by_name = {s["name"]: s for s in self.view["sensors"]}

    def test_lists_sensors_rules_and_reports_with_their_definitions(self):
        self.assertEqual({"get-routes", "never-fires", "no-methods", "bad-method", "block-exec", "block-staged"},
                         set(self.by_name))
        routes = self.by_name["get-routes"]
        self.assertEqual(("sensor", "observe"), (routes["kind"], routes["mode"]))
        self.assertEqual(["javax.servlet.Servlet.service"], routes["methods"])
        self.assertEqual(["#P0.getRequestURI()"], routes["captures"])
        self.assertEqual(["!null"], routes["matchers"])
        self.assertIn("name: get-routes", routes["definition"])
        self.assertEqual(["Routes by users"], [r["name"] for r in self.view["reports"]])

    def test_the_first_definition_wins_like_the_agent_and_the_duplicate_is_reported(self):
        self.assertEqual("a.jot", self.by_name["get-routes"]["file"])
        self.assertEqual(["javax.servlet.Servlet.service"], self.by_name["get-routes"]["methods"])
        self.assertTrue(any("get-routes is defined again in b.jot" in i["text"] and "a.jot" in i["text"]
                            for i in self.view["issues"]))

    def test_rules_show_their_mode_and_a_staged_rule_is_monitor(self):
        self.assertEqual(("rule", "block"), (self.by_name["block-exec"]["kind"], self.by_name["block-exec"]["mode"]))
        self.assertEqual("monitor", self.by_name["block-staged"]["mode"])
        self.assertEqual("no processes", self.by_name["block-exec"]["exception"])

    def test_activity_counts(self):
        routes = self.by_name["get-routes"]
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
        self.assertIn("report Routes by users uses get-users, which no loaded sensor defines", texts)
        self.assertIn("Old series is type series", texts)
        self.assertIn("mystery, which isn't in the loaded .jot files", texts)
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

    def test_rule_modes_follow_the_control_file_when_there_is_one(self):
        path = os.path.join(self.env.dir, "control.json")
        control_store = control.ControlStore(path, token="t")
        control_store.write(rules={"block-exec": False}, known_rules=["block-exec", "block-staged"])
        app = server.App(self.env.db, self.env.ingestor, control=control_store)
        modes = {s["name"]: s["mode"] for s in app.jots()["sensors"]}
        self.assertEqual("monitor", modes["block-exec"])


class ControlStoreTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.path = os.path.join(self.dir, "control.json")
        self.control = control.ControlStore(self.path, token="s3cret-token")
        self.known = ["rule-a", "rule-b"]

    def files(self):
        return sorted(os.listdir(self.dir))

    def test_a_missing_file_means_the_defaults(self):
        state = self.control.read()
        self.assertEqual((True, {}, False), (state["enforce"], state["rules"], state["exists"]))

    def test_writes_merge_and_null_goes_back_to_the_jot_setting(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known)
        self.control.write(master=False, rules={"rule-b": True}, known_rules=self.known)
        state = self.control.read()
        self.assertEqual((False, {"rule-a": False, "rule-b": True}), (state["enforce"], state["rules"]))
        self.control.write(rules={"rule-a": None}, known_rules=self.known)
        self.assertEqual({"rule-b": True}, self.control.read()["rules"])

    def test_the_file_has_the_format_the_agent_reads(self):
        self.control.write(master=True, rules={"rule-a": False}, known_rules=self.known, who="jeff")
        with open(self.path) as f:
            doc = json.load(f)
        self.assertEqual(1, doc["v"])
        self.assertEqual({"rule-a": False}, doc["rules"])
        self.assertEqual("jeff", doc["by"])
        self.assertEqual(0o644, os.stat(self.path).st_mode & 0o777)

    def test_writing_leaves_no_temporary_files_behind(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known)
        self.assertEqual(["control.json", "control.json.audit"], self.files())

    def test_every_change_is_logged_with_before_and_after(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known, who="jeff")
        self.control.write(master=False, known_rules=self.known, who="jeff")
        with open(self.control.audit_path) as f:
            entries = [json.loads(line) for line in f]
        self.assertEqual(2, len(entries))
        self.assertEqual({"enforce": True, "rules": {}}, entries[0]["before"])
        self.assertEqual({"enforce": True, "rules": {"rule-a": False}}, entries[0]["after"])
        self.assertEqual(False, entries[1]["after"]["enforce"])

    def test_bad_changes_are_refused_and_change_nothing(self):
        self.control.write(rules={"rule-a": False}, known_rules=self.known)
        for kwargs in [{"rules": {"nobody": False}}, {"rules": {"rule-a": "no"}}, {"rules": []}, {"master": "off"}]:
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(control.ControlError):
                    self.control.write(known_rules=self.known, **kwargs)
        self.assertEqual({"rule-a": False}, self.control.read()["rules"])

    def test_a_corrupt_file_reads_as_the_defaults(self):
        with open(self.path, "w") as f:
            f.write("not json")
        self.assertEqual((True, False), (self.control.read()["enforce"], self.control.read()["exists"]))

    def test_the_token_is_checked(self):
        self.control.check_token("s3cret-token")
        for wrong in ["wrong", "", None, "s3cret-toke"]:
            with self.assertRaises(control.ControlError):
                self.control.check_token(wrong)

    def test_whitespace_picked_up_when_pasting_is_ignored_but_nothing_else(self):
        for pasted in ["s3cret-token ", " s3cret-token", "s3cret-token\n", "\ts3cret-token\r\n"]:
            self.control.check_token(pasted)
        for wrong in ["s3cret token", "s3cret-token x", "S3CRET-TOKEN", "s3cret-token\ns3cret-token"]:
            with self.assertRaises(control.ControlError):
                self.control.check_token(wrong)

    def test_without_a_token_nothing_can_change(self):
        read_only = control.ControlStore(self.path, token=None)
        self.assertFalse(read_only.writable)
        with self.assertRaises(control.ControlError):
            read_only.check_token("anything")

    def test_repeated_wrong_tokens_lock_writing_even_for_the_right_one(self):
        for _ in range(control.MAX_FAILURES):
            with self.assertRaises(control.ControlError):
                self.control.check_token("wrong")
        with self.assertRaises(control.ControlError) as c:
            self.control.check_token("s3cret-token")
        self.assertIn("too many", str(c.exception))


class ControlApiTests(unittest.TestCase):
    def setUp(self):
        self.env = Env()
        jot = os.path.join(self.env.dir, "rules.jot")
        with open(jot, "w") as f:
            f.write(RULES_JOT)
        store.load_sensors(self.env.ingestor.db, [jot])
        self.control_path = os.path.join(self.env.dir, "control.json")
        self.control = control.ControlStore(self.control_path, token="s3cret-token")
        self.app = server.App(self.env.db, self.env.ingestor, control=self.control)
        httpd = server.make_server(self.app, "127.0.0.1", 0)
        self.port = httpd.server_address[1]
        httpd.RequestHandlerClass.port = self.port
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        self.addCleanup(httpd.shutdown)

    def call(self, body=None, token="s3cret-token"):
        headers = {"Host": "127.0.0.1:%d" % self.port}
        if body is not None:
            headers.update({"Content-Type": "application/json", "X-JOT-Dashboard": "1"})
            if token is not None:
                headers["X-JOT-Admin"] = token
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
        self.assertTrue(state["writable"])

    def test_switching_a_rule_changes_the_file_and_the_mode(self):
        code, state = self.call({"rules": {"rule-a": False, "rule-b": True}})
        self.assertEqual(200, code)
        self.assertEqual({"rule-a": "monitor", "rule-b": "block"}, self.modes(state))
        self.assertEqual({"rule-a": False, "rule-b": True}, self.control.read()["rules"])

    def test_the_master_switch_makes_everything_monitor(self):
        _, state = self.call({"master": False, "rules": {"rule-b": True}})
        self.assertEqual({"rule-a": "monitor", "rule-b": "monitor"}, self.modes(state))
        self.assertFalse(state["master"])

    def test_changes_need_the_right_token(self):
        for token in [None, "wrong", ""]:
            code, body = self.call({"master": False}, token=token)
            self.assertEqual(403, code)
        self.assertFalse(self.control.read()["exists"])

    def test_too_many_wrong_tokens_gets_429(self):
        codes = [self.call({"master": False}, token="wrong")[0] for _ in range(control.MAX_FAILURES + 1)]
        self.assertEqual(429, codes[-1])
        self.assertEqual(429, self.call({"master": False})[0])

    def test_unknown_rules_and_sensors_that_are_not_rules_are_refused(self):
        for rule in ["nobody", "just-watching"]:
            code, body = self.call({"rules": {rule: False}})
            self.assertEqual(400, code, rule)
        self.assertFalse(self.control.read()["exists"])

    def test_without_a_control_file_the_panel_is_off(self):
        app = server.App(self.env.db, self.env.ingestor)
        self.assertEqual({"enabled": False}, app.control_state())

    def test_read_only_when_no_token_was_given(self):
        app = server.App(self.env.db, self.env.ingestor, control=control.ControlStore(self.control_path, token=None))
        self.assertFalse(app.control_state()["writable"])
        with self.assertRaises(control.ControlError):
            app.change_control("anything", False, None)

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


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class GridScriptTests(unittest.TestCase):
    def test_grid_pivot_logic(self):
        here = os.path.dirname(__file__)
        result = subprocess.run(["node", "--test", os.path.join(here, "grid.test.js"), os.path.join(here, "recent.test.js")],
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
        self.assertIn(b'id="policyPage" hidden', page)
        self.assertNotIn(b'id="feed"', page)       # the Latest events panel became a view
        # recent questions live in the top menu, not on the page
        self.assertIn(b'id="recentMenu"', page)
        self.assertNotIn(b'id="history"', page)
        self.assertIn(b'src="/recent.js"', page)
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
        self.assertEqual([["get-ciphers"]], r["rows"])

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


if __name__ == "__main__":
    unittest.main()
