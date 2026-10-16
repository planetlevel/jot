"""SQLite storage for JOT events, a log tailer that fills it, and a safe read-only query runner."""

import glob
import json
import os
import re
import sqlite3
import threading
import time

import yaml

SCHEMA = """
CREATE TABLE IF NOT EXISTS events_raw (
  pk INTEGER PRIMARY KEY,
  time TEXT,            -- ISO 8601, UTC
  ts INTEGER,           -- epoch milliseconds
  run TEXT,             -- one JVM start. With host and pid it identifies the process
  host TEXT,
  pid INTEGER,
  app TEXT,
  id INTEGER,           -- event number, unique within a run
  trace INTEGER,        -- events with the same run and trace came from the same request or thread
  thread TEXT,
  thread_id INTEGER,
  sensor TEXT,          -- the sensor that produced the event
  action TEXT,          -- observed, monitored or blocked
  capture TEXT,         -- what the sensor captured
  message TEXT,         -- for blocked and monitored events, the sensor's exception message
  method TEXT,          -- the instrumented method as a stack frame, with module and line
  method_name TEXT,     -- the instrumented method, like javax.crypto.Cipher.getInstance
  call_site TEXT,       -- the code that called it, as a stack frame with line
  call_site_name TEXT,  -- the code that called it, like com.acme.Ticket.encrypt
  stack TEXT,           -- JSON array of stack frames, starting at the instrumented method
  UNIQUE (run, id)
);
CREATE INDEX IF NOT EXISTS events_ts ON events_raw (ts);
CREATE INDEX IF NOT EXISTS events_sensor ON events_raw (sensor, action);
CREATE INDEX IF NOT EXISTS events_trace ON events_raw (run, trace);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT
);

-- What every query and view reads. Everything recorded since the start time, or all of it if none is set.
-- The start time is how the dashboard is cleared, nothing is deleted and Show all brings it back.
CREATE VIEW IF NOT EXISTS events AS
  SELECT * FROM events_raw WHERE ts >= COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'since'), 0);

CREATE TABLE IF NOT EXISTS sensors (
  name TEXT PRIMARY KEY,
  description TEXT,
  methods TEXT,         -- JSON array
  scopes TEXT,          -- JSON array. The sensor only fires inside these methods
  captures TEXT,        -- JSON array of expressions
  blocks TEXT,          -- the exception message if the sensor is a rule, otherwise null
  enforce TEXT,         -- 'false' if the .jot file stages the rule as report only, otherwise null
  source TEXT,          -- the .jot file it came from
  matchers TEXT,        -- JSON array
  excludes TEXT,        -- JSON array
  definition TEXT       -- the sensor as written, as YAML
);

CREATE TABLE IF NOT EXISTS jot_issues (
  level TEXT,           -- warning or info
  text TEXT,
  source TEXT
);

CREATE TABLE IF NOT EXISTS reports (
  name TEXT PRIMARY KEY,
  type TEXT,            -- list, compare, table or graph
  rows TEXT,            -- the sensor whose captures are the rows
  cols TEXT,            -- the sensor, or comma separated sensors, for the columns
  source TEXT
);

CREATE TABLE IF NOT EXISTS sources (
  path TEXT PRIMARY KEY,
  inode INTEGER,
  offset INTEGER,
  bad_lines INTEGER DEFAULT 0,
  head TEXT             -- hex of the first bytes of the file, to notice when it has been replaced
);
"""

# bytes from the start of a log kept to recognise it again
HEAD_BYTES = 256

# the part of the schema the model is told about
MODEL_TABLES = ("events", "sensors")

EVENT_COLUMNS = ("time", "ts", "run", "host", "pid", "app", "id", "trace", "thread", "thread_id", "sensor",
                 "action", "capture", "message", "method", "method_name", "call_site", "call_site_name", "stack")

_FRAME = re.compile(r"^(?:[\w.@-]+/)?([^(]*)\(")


def frame_name(frame):
    """'java.base/javax.crypto.Cipher.getInstance(Cipher.java:531)' becomes 'javax.crypto.Cipher.getInstance'."""
    if not frame:
        return None
    m = _FRAME.match(frame)
    return m.group(1) if m else frame


def connect(path):
    db = sqlite3.connect(path, check_same_thread=False, timeout=10)
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    return db


def init(db):
    # a database from before the start time existed has the events in a table called events, which becomes the raw one
    old = db.execute("SELECT type FROM sqlite_master WHERE name = 'events'").fetchone()
    if old and old[0] == "table":
        db.execute("ALTER TABLE events RENAME TO events_raw")
    # these two are filled again from the .jot files at every start, so an older layout can simply be replaced
    db.execute("DROP TABLE IF EXISTS sensors")
    db.execute("DROP TABLE IF EXISTS reports")
    db.execute("DROP TABLE IF EXISTS jot_issues")
    db.executescript(SCHEMA)
    db.commit()


def row_from_event(e):
    """The values for EVENT_COLUMNS from one parsed JSON log line."""
    stack = e.get("stack")
    values = {k: e.get(k) for k in EVENT_COLUMNS}
    values["stack"] = json.dumps(stack) if stack is not None else None
    values["method_name"] = frame_name(e.get("method"))
    values["call_site_name"] = frame_name(e.get("call_site"))
    return tuple(values[k] for k in EVENT_COLUMNS)


INSERT = "INSERT OR IGNORE INTO events_raw (%s) VALUES (%s)" % (",".join(EVENT_COLUMNS), ",".join("?" * len(EVENT_COLUMNS)))


class Ingestor:
    """Follows one or more JSONL event logs and stores each new event. Safe to restart, it remembers
    how far it read each file, and ignores events it has already stored."""

    def __init__(self, db_path, log_patterns, interval=1.0):
        self.db = connect(db_path)
        init(self.db)
        self.patterns = log_patterns
        self.interval = interval
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def files(self):
        found = []
        for pattern in self.patterns:
            found.extend(sorted(glob.glob(pattern)))
        return found

    def poll(self):
        """Read whatever was added since last time. Returns the number of events stored."""
        stored = 0
        with self.lock:
            for path in self.files():
                try:
                    stored += self._poll_file(path)
                except OSError:
                    pass
            self.db.commit()
        return stored

    def _poll_file(self, path):
        st = os.stat(path)
        row = self.db.execute("SELECT inode, offset, bad_lines, head FROM sources WHERE path=?", (path,)).fetchone()
        inode, offset, bad, head = row if row else (st.st_ino, 0, 0, "")
        with open(path, "rb") as f:
            # a different file, a shorter one, or one that starts differently was replaced, so start again
            if st.st_ino != inode or st.st_size < offset or f.read(len(head) // 2).hex() != head:
                offset = 0
            if st.st_size == offset and row:
                return 0
            f.seek(offset)
            chunk = f.read()
            f.seek(0)
            start = f.read(HEAD_BYTES)
        end = chunk.rfind(b"\n")
        if end < 0:
            return 0  # no complete line yet
        rows = []
        for line in chunk[: end + 1].splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(row_from_event(json.loads(line)))
            except (ValueError, AttributeError):
                bad += 1
        self.db.executemany(INSERT, rows)
        new_offset = offset + end + 1
        self.db.execute("INSERT OR REPLACE INTO sources (path, inode, offset, bad_lines, head) VALUES (?,?,?,?,?)",
                        (path, st.st_ino, new_offset, bad, start[:min(new_offset, HEAD_BYTES)].hex()))
        return len(rows)

    def start(self):
        def run():
            while not self._stop.is_set():
                try:
                    self.poll()
                except Exception as e:  # keep following the log whatever happens
                    print("[dashboard] ingest error:", e)
                self._stop.wait(self.interval)
        self._thread = threading.Thread(target=run, name="ingest", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._thread:
            self._thread.join(2)


def jot_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "*.jot"))))
        elif os.path.exists(p):
            files.append(p)
    return files


def _read_jot(path):
    try:
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as e:
        print("[dashboard] can't read", path, e)
        return {}


_METHOD = re.compile(r"^(static )?!?[\w$]+(\.[\w$<>]+)+$")


def _issue(db, level, text, source):
    db.execute("INSERT INTO jot_issues VALUES (?,?,?)", (level, text, source))


def load_sensors(db, paths):
    """Read sensor definitions from .jot files, or directories of them, so the model knows what they mean and
    the JOTs view can show them. Like the agent, the first definition of a name wins and a later one is skipped."""
    db.execute("DELETE FROM sensors")
    db.execute("DELETE FROM jot_issues")
    loaded = 0
    for f in jot_files(paths):
        source = os.path.basename(f)
        for s in _read_jot(f).get("sensors") or []:
            if not isinstance(s, dict) or not s.get("name") or s["name"] == "example":
                continue
            name = s["name"]
            first = db.execute("SELECT source FROM sensors WHERE name = ?", (name,)).fetchone()
            if first:
                _issue(db, "warning", "%s is defined again in %s, the agent skips it and keeps the one in %s"
                       % (name, source, first[0]), source)
                continue
            methods = s.get("methods") or []
            if not methods:
                _issue(db, "warning", "%s has no methods, so it can never fire" % name, source)
            for m in list(methods) + list(s.get("scopes") or []):
                if not _METHOD.match(str(m).strip()):
                    _issue(db, "warning", "%s has %r, which doesn't look like Class.method" % (name, m), source)
            staged = "false" if s.get("enforce") is False else None
            db.execute("""INSERT INTO sensors (name, description, methods, scopes, captures, blocks, enforce, source,
                                               matchers, excludes, definition) VALUES (?,?,?,?,?,?,?,?,?,?,?)""", (
                name, s.get("description"), json.dumps(methods), json.dumps(s.get("scopes") or []),
                json.dumps(s.get("captures") or []), s.get("exception"), staged, source,
                json.dumps(s.get("matchers") or []), json.dumps(s.get("excludes") or []),
                yaml.safe_dump(s, sort_keys=False, default_flow_style=False, allow_unicode=True).rstrip()))
            loaded += 1
    db.commit()
    return loaded


def load_reports(db, paths):
    """Read the reports: sections of .jot files. Each becomes a view the dashboard can build from events.
    The old series type has no equivalent, the event log does that job."""
    db.execute("DELETE FROM reports")
    loaded = 0
    for f in jot_files(paths):
        for r in _read_jot(f).get("reports") or []:
            if not isinstance(r, dict) or not r.get("name") or r["name"] == "example":
                continue
            source = os.path.basename(f)
            rtype = str(r.get("type", "")).lower()
            if rtype not in ("list", "compare", "table"):
                _issue(db, "info", "report %s is type %s, which the dashboard doesn't build. series reports are "
                       "replaced by the event log" % (r["name"], rtype or "(none)"), source)
                continue
            db.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?)", (
                r["name"], rtype, r.get("rows"), r.get("cols"), source))
            used = ([r["rows"]] if r.get("rows") else []) + [c.strip() for c in str(r.get("cols") or "").split(",") if c.strip()]
            for sensor in used:
                if not db.execute("SELECT 1 FROM sensors WHERE name = ?", (sensor,)).fetchone():
                    _issue(db, "warning", "report %s uses %s, which no loaded sensor defines" % (r["name"], sensor), source)
            loaded += 1
    db.commit()
    return loaded


def _lit(text):
    """A SQL string literal."""
    return "'" + str(text).replace("'", "''") + "'"


# the name:value convention of the original compare report. A capture with no colon is all name.
_NAME = "CASE WHEN instr({c}, ':') > 0 THEN substr({c}, 1, instr({c}, ':') - 1) ELSE {c} END"
_VALUE = "CASE WHEN instr({c}, ':') > 0 THEN substr({c}, instr({c}, ':') + 1) ELSE 'X' END"


def report_sql(rtype, rows, cols):
    """The query for a report, as rows of (row, column, value) which the dashboard turns into a grid.
    These are the original JOT reports. A row and a column are related when they were observed in the
    same request, which is the same run and trace."""
    sensors = [c.strip() for c in (cols or "").split(",") if c.strip()]
    if not sensors:
        raise ValueError("a report needs cols")
    if rtype == "list":
        return ("SELECT DISTINCT call_site AS call_site, sensor AS sensor, capture AS value\n"
                "FROM events WHERE sensor = %s AND call_site IS NOT NULL AND capture <> ''\n"
                "ORDER BY call_site" % _lit(sensors[0]))
    if not rows:
        raise ValueError("a %s report needs rows" % rtype)
    join = "FROM events r JOIN events c ON r.run = c.run AND r.trace = c.trace\nWHERE r.sensor = %s" % _lit(rows)
    row = _NAME.format(c="r.capture")
    if rtype == "compare":
        return ("SELECT DISTINCT %s AS row, %s AS col, %s AS value\n%s AND c.sensor = %s\nORDER BY 1, 2"
                % (row, _NAME.format(c="c.capture"), _VALUE.format(c="c.capture"), join, _lit(sensors[0])))
    if rtype == "table":
        return ("SELECT DISTINCT %s AS row, c.sensor AS col, c.capture AS value\n%s AND c.sensor IN (%s)\nORDER BY 1, 2"
                % (row, join, ", ".join(_lit(x) for x in sensors)))
    raise ValueError("unknown report type %s" % rtype)


# ---------------------------------------------------------------------------- queries

class QueryError(Exception):
    pass


_ALLOWED = {sqlite3.SQLITE_SELECT, sqlite3.SQLITE_READ, sqlite3.SQLITE_FUNCTION, sqlite3.SQLITE_RECURSIVE}
_BLOCKED_FUNCTIONS = {"load_extension", "readfile", "writefile", "edit", "fts3_tokenizer"}


def _authorizer(action, arg1, arg2, dbname, source):
    if action not in _ALLOWED:
        return sqlite3.SQLITE_DENY
    if action == sqlite3.SQLITE_FUNCTION and (arg2 or "").lower() in _BLOCKED_FUNCTIONS:
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


def run_query(db_path, sql, limit=1000, timeout=5.0):
    """Run one read-only SELECT. Returns {"columns", "rows", "truncated", "ms"}. Raises QueryError.
    Anything that isn't a plain read is refused by SQLite itself, whatever the SQL says."""
    sql = (sql or "").strip().rstrip(";").strip()
    if not sql:
        raise QueryError("no SQL to run")
    db = sqlite3.connect(db_path, check_same_thread=False)
    try:
        db.execute("PRAGMA query_only=ON")
        db.set_authorizer(_authorizer)
        deadline = time.monotonic() + timeout
        db.set_progress_handler(lambda: 1 if time.monotonic() > deadline else 0, 10000)
        started = time.monotonic()
        try:
            cur = db.execute("SELECT * FROM (\n%s\n) LIMIT %d" % (sql, limit + 1))
            rows = cur.fetchall()
        except sqlite3.Error as e:
            if "interrupted" in str(e):
                raise QueryError("the query took longer than %d seconds" % timeout)
            raise QueryError(str(e))
        columns = [d[0] for d in cur.description]
        truncated = len(rows) > limit
        return {
            "columns": columns,
            "rows": [list(r) for r in rows[:limit]],
            "truncated": truncated,
            "ms": int((time.monotonic() - started) * 1000),
        }
    finally:
        db.close()


def schema_for_model():
    """The tables the model may query, as the DDL with its comments. The events are presented under the name the model
    queries, which is the view that honours the start time."""
    names = {"events_raw": "events", "sensors": "sensors"}
    out = []
    for block in SCHEMA.split(";\n"):
        if block.strip().startswith("CREATE TABLE IF NOT EXISTS") and block.split()[5] in names:
            ddl = block.strip().replace(" IF NOT EXISTS", "").replace("events_raw", "events")
            out.append(ddl + ";")
    return "\n\n".join(out)


def get_since(db_path):
    """The start time in epoch milliseconds, or None when everything is shown."""
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT value FROM settings WHERE key = 'since'").fetchone()
        return int(row[0]) if row else None
    finally:
        db.close()


def set_since(db, value):
    """Show only events from this time on, as epoch milliseconds. None shows everything again."""
    if value is None:
        db.execute("DELETE FROM settings WHERE key = 'since'")
    else:
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('since', ?)", (str(int(value)),))
    db.commit()
