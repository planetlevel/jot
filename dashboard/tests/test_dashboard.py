import contextlib
import http.server
import io
import json
import os
import ssl
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

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

        def generate(question, schema, sensors, history, error):
            self.calls.append({"question": question, "schema": schema, "history": history, "error": error})
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


class HttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.env = Env()
        cls.env.write(event(1, action="blocked", message="denied"), event(2))
        cls.env.ingestor.poll()
        app = server.App(cls.env.db, cls.env.ingestor, lambda *a: {
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

    def test_serves_the_page(self):
        code, page = self.call("/")
        self.assertEqual(200, code)
        self.assertIn(b"JOT Dashboard", page)

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
