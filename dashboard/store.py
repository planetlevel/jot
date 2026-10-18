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
  origin TEXT,          -- app if the stack has a frame from the application, library if it has only library frames, platform if it is all JDK and server, none if there is no stack
  app_frame TEXT,       -- the innermost application frame, like com.acme.Ticket.encrypt(Ticket.java:125)
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
-- Unless the app_only setting is 0, an observed event that has no frame from the application is left out.
-- Blocked and reported events are never left out by that. If filter_blocked or filter_monitored is 1, only events
-- of the ticked kinds are kept. The agent's own jot-control events, which record a rule being switched, are left out
-- unless the show_jot_control setting is 1.
CREATE VIEW IF NOT EXISTS events AS
  SELECT * FROM events_raw
  WHERE ts >= COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'since'), 0)
    AND (COALESCE((SELECT value FROM settings WHERE key = 'app_only'), '1') <> '1'
         OR origin IS NULL OR origin IN ('app', 'none') OR action <> 'observed')
    AND ((COALESCE((SELECT value FROM settings WHERE key = 'filter_blocked'), '0') <> '1'
          AND COALESCE((SELECT value FROM settings WHERE key = 'filter_monitored'), '0') <> '1')
         OR (action = 'blocked' AND COALESCE((SELECT value FROM settings WHERE key = 'filter_blocked'), '0') = '1')
         OR (action = 'monitored' AND COALESCE((SELECT value FROM settings WHERE key = 'filter_monitored'), '0') = '1'))
    AND (sensor <> 'jot-control' OR COALESCE((SELECT value FROM settings WHERE key = 'show_jot_control'), '0') = '1');

CREATE TABLE IF NOT EXISTS sensors (
  name TEXT PRIMARY KEY,
  description TEXT,
  methods TEXT,         -- JSON array
  scopes TEXT,          -- JSON array. The sensor only fires inside these methods
  captures TEXT,        -- JSON array of expressions
  blocks TEXT,          -- the exception message if the sensor is a rule, otherwise null
  protect TEXT,         -- 'false' if the .jot file stages the rule as report only, otherwise null
  enabled TEXT,         -- 'false' if the .jot file writes enabled: false, otherwise null
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
                 "action", "capture", "message", "method", "method_name", "call_site", "call_site_name", "stack",
                 "origin", "app_frame")

_FRAME = re.compile(r"^(?:[\w.@-]+/)?([^(]*)\(")


def frame_name(frame):
    """'java.base/javax.crypto.Cipher.getInstance(Cipher.java:531)' becomes 'javax.crypto.Cipher.getInstance'."""
    if not frame:
        return None
    m = _FRAME.match(frame)
    return m.group(1) if m else frame


# Code that belongs to the JDK or the application server, never to the application. Everything else is the
# application or a library it uses. Jasper compiles a page to org.apache.jsp, which is the application.
PLATFORM_PREFIXES = ("java.", "javax.", "jdk.", "sun.", "com.sun.", "jakarta.", "org.w3c.", "org.xml.", "org.ietf.",
                     "org.apache.catalina.", "org.apache.coyote.", "org.apache.tomcat.", "org.apache.jasper.",
                     "org.apache.el.", "org.apache.naming.", "org.eclipse.jdt.", "org.openolly.")


# raise this when classify changes, so events stored under the old rules are tagged again
CLASSIFIER_VERSION = 2
SERVLET_API = ("javax.servlet.", "jakarta.servlet.")


def frame_kind(frame, app_prefixes=()):
    """platform for JDK and server code, app for the application, library for everything else. With no application
    packages given, anything that is not the platform counts as the application."""
    name = frame_name(frame) or ""
    if name.startswith(PLATFORM_PREFIXES) or frame.startswith(("java.", "jdk.")) and "/" in frame.split("(")[0]:
        return "platform"
    prefixes = tuple(p if p.endswith(".") else p + "." for p in app_prefixes)
    return "app" if not prefixes or name.startswith(prefixes) else "library"


def classify(stack, app_prefixes=()):
    """Where an event came from, as (origin, app_frame). The origin is app when any frame is application code,
    library when the stack has code that is neither the application nor the platform, and platform otherwise.
    With no application packages given, any frame that is not the platform counts as the application.
    A servlet's service method is the application being asked to handle a request. The container calls it, so the
    stack holds only server frames, but the request is the application's. Those events count as the application."""
    if not stack:
        return "none", None
    if (frame_name(stack[0]) or "").startswith(SERVLET_API):
        return "app", stack[0]
    library = False
    for frame in stack:
        kind = frame_kind(frame, app_prefixes)
        if kind == "app":
            return "app", frame
        library = library or kind == "library"
    return ("library" if library else "platform"), None


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
    # the view is rebuilt every start, so a changed definition takes effect
    db.execute("DROP VIEW IF EXISTS events")
    db.executescript(SCHEMA)
    have = {r[1] for r in db.execute("PRAGMA table_info(events_raw)")}
    for column in ("origin", "app_frame"):
        if column not in have:
            db.execute("ALTER TABLE events_raw ADD COLUMN %s TEXT" % column)
    db.commit()


def retag(db, app_prefixes):
    """Work out the origin of every stored event again. Done when the application packages change and for events that
    were stored before the origin was recorded. Returns the number of events tagged."""
    wanted = json.dumps([CLASSIFIER_VERSION] + sorted(app_prefixes))
    row = db.execute("SELECT value FROM settings WHERE key = 'app_prefixes'").fetchone()
    where = "WHERE origin IS NULL" if row and row[0] == wanted else ""
    rows = db.execute("SELECT pk, stack FROM events_raw %s" % where).fetchall()
    updates = []
    for pk, stack in rows:
        origin, frame = classify(json.loads(stack) if stack else None, app_prefixes)
        updates.append((origin, frame, pk))
    db.executemany("UPDATE events_raw SET origin = ?, app_frame = ? WHERE pk = ?", updates)
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('app_prefixes', ?)", (wanted,))
    db.commit()
    return len(updates)


def row_from_event(e, app_prefixes=()):
    """The values for EVENT_COLUMNS from one parsed JSON log line."""
    stack = e.get("stack")
    values = {k: e.get(k) for k in EVENT_COLUMNS}
    values["origin"], values["app_frame"] = classify(stack, app_prefixes)
    values["stack"] = json.dumps(stack) if stack is not None else None
    values["method_name"] = frame_name(e.get("method"))
    values["call_site_name"] = frame_name(e.get("call_site"))
    return tuple(values[k] for k in EVENT_COLUMNS)


INSERT = "INSERT OR IGNORE INTO events_raw (%s) VALUES (%s)" % (",".join(EVENT_COLUMNS), ",".join("?" * len(EVENT_COLUMNS)))


class Ingestor:
    """Follows one or more JSONL event logs and stores each new event. Safe to restart, it remembers
    how far it read each file, and ignores events it has already stored."""

    def __init__(self, db_path, log_patterns, interval=1.0, app_prefixes=()):
        self.db = connect(db_path)
        init(self.db)
        self.app_prefixes = tuple(app_prefixes)
        retag(self.db, self.app_prefixes)
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
                rows.append(row_from_event(json.loads(line), self.app_prefixes))
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


def read_jots_file(path):
    """The jots file the agent also reads. Returns (jot paths, control file path or None, application packages).
    Every entry is included. Relative paths are relative to the jots file. The packages are the app: list, which the
    agent ignores."""
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    base = os.path.dirname(os.path.abspath(path))
    def resolve(p):
        return p if os.path.isabs(p) else os.path.normpath(os.path.join(base, p))
    jots = []
    for item in doc.get("jots") or []:
        p = item if isinstance(item, str) else (item or {}).get("path")
        if p:
            jots.append(resolve(p))
    control = doc.get("control")
    app = doc.get("app") or []
    app = [app] if isinstance(app, str) else [str(a) for a in app]
    return jots, resolve(control) if control else None, app


def jot_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "**", "*.jot"), recursive=True)))
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
            staged = "false" if s.get("protect") is False else None
            off = "false" if s.get("enabled") is False else None
            db.execute("""INSERT INTO sensors (name, description, methods, scopes, captures, blocks, protect, enabled, source,
                                               matchers, excludes, definition) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", (
                name, s.get("description"), json.dumps(methods), json.dumps(s.get("scopes") or []),
                json.dumps(s.get("captures") or []), s.get("exception"), staged, off, source,
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


# ---------------------------------------------------------------------------- search

# word:value narrows by a field, for example sensor:get-hashes or action:blocked
SEARCH_FIELDS = {"sensor": "contains", "action": "equals", "origin": "equals", "app": "equals", "run": "equals",
                 "host": "equals", "trace": "number", "pid": "number"}
# a plain word is looked for in all of these
SEARCH_COLUMNS = ("capture", "message", "sensor", "action", "method_name", "call_site", "app_frame", "stack")
SEARCH_TEXT = " || ' ' || ".join("COALESCE(%s, '')" % c for c in SEARCH_COLUMNS)
MAX_TERMS = 10


def search_terms(query):
    """The words of a search, as (negated, field, text). Quotes keep a phrase together and a leading - excludes."""
    words = re.findall(r'-?(?:\w+:)?"[^"]*"|\S+', query or "")
    terms = []
    for word in words[:MAX_TERMS]:
        negated = word.startswith("-") and len(word) > 1
        if negated:
            word = word[1:]
        field = None
        m = re.match(r"^(\w+):(.*)$", word)
        if m and m.group(1).lower() in SEARCH_FIELDS:
            field, word = m.group(1).lower(), m.group(2)
        word = word.strip().strip('"')
        if word:
            terms.append((negated, field, word))
    return terms


def _like(text):
    return _lit("%" + text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%") + " ESCAPE '\\'"


def search_where(query):
    """The condition for a search, every word must match. Raises ValueError when there is nothing to look for."""
    terms = search_terms(query)
    if not terms:
        raise ValueError("type something to search for")
    parts = []
    for negated, field, text in terms:
        if field is None:
            cond = "(%s) LIKE %s" % (SEARCH_TEXT, _like(text))
        elif SEARCH_FIELDS[field] == "number":
            if not text.isdigit():
                raise ValueError("%s: needs a number" % field)
            cond = "%s = %d" % (field, int(text))
        elif SEARCH_FIELDS[field] == "equals":
            cond = "lower(COALESCE(%s, '')) = %s" % (field, _lit(text.lower()))
        else:
            cond = "COALESCE(%s, '') LIKE %s" % (field, _like(text))
        parts.append("NOT " + cond if negated else cond)
    return "\n  AND ".join(parts)


# ---------------------------------------------------------------------------- graph

NO_REQUEST = "(outside a request)"
JUMPS = ("get-forwards", "get-redirects")   # sensors whose capture is another route


def _short(name):
    """com.acme.ticketbook.Ticket.encrypt becomes Ticket.encrypt."""
    return ".".join(name.split(".")[-2:])


def _page_of(route):
    """/ticketbook/ssrf.jsp is compiled to ssrf_jsp."""
    last = (route or "").rsplit("/", 1)[-1]
    return last.replace(".", "_") if last else None


def graph_rows(db_path, route=None):
    """The events of the graph in the order they happened, request by request. The route is the first request the
    event happened in, as the get-routes sensor saw it. Events of one request are together and in the agent's own
    order, which is the order the application caused them."""
    where = "WHERE sensor <> 'get-routes' AND stack IS NOT NULL"
    sql = """SELECT route, run, trace, sensor, action, capture, stack FROM (
               SELECT (SELECT r.capture FROM events_raw r WHERE r.run = e.run AND r.trace = e.trace AND r.sensor = 'get-routes'
                       ORDER BY r.pk LIMIT 1) AS route, e.run, e.trace, e.id, e.sensor, e.action, e.capture, e.stack
               FROM events e %s) %s ORDER BY run, trace, id""" % (where, "WHERE route = %s" % _lit(route) if route else "")
    return run_query(db_path, sql, limit=GRAPH_ROW_LIMIT)


GRAPH_ROW_LIMIT = 50000


def _requests(rows):
    """The rows grouped into requests. An event with no trace is a request of its own."""
    group, key = [], None
    for i, row in enumerate(rows):
        k = (row[1], row[2]) if row[2] is not None else ("event", i)
        if group and k != key:
            yield group
            group = []
        key = k
        group.append(row)
    if group:
        yield group


def build_graph(rows, routes_seen, app_prefixes=(), details=False, truncated=False):
    """Nodes and edges for the paths through the application, drawn like subway lines. A request is one line. It starts
    at the route, and each event is a stop along it in the order the events happened. Between stops it passes through
    the application methods that were newly entered, since the stack of the last stop is still in force for the methods
    the two have in common. Lines that reach the same stop share its node, so drawn together they show where requests
    agree and where they part. Events in a row that are the same stop, like three get-role calls from one method,
    are one stop. A forward or a redirect also leads on to the route it names, which is an exit. Plumbing that only
    describes the request, like who the user is, is left out unless details is set."""
    nodes, edges = {}, {}

    def node(kind, key, label, full=None):
        n = nodes.setdefault((kind, key), {"id": "%s:%s" % (kind, key), "kind": kind, "label": label, "full": full or key,
                                           "events": 0, "blocked": 0, "monitored": 0, "captures": {}})
        return n

    def link(a, b, count):
        e = edges.setdefault((a["id"], b["id"]), {"from": a["id"], "to": b["id"], "events": 0})
        e["events"] += count
        return e

    route_names = sorted(routes_seen)

    def walk(route, events, count):
        route = route or NO_REQUEST
        start = node("route", route, route)
        # the page the route names is compiled to a class, and every method of it, like the tag helpers Jasper
        # generates, is that page. The route already stands for it, so it isn't drawn again
        page = _page_of(route)
        here, held, last_edges = start, [], []   # where the line is, the methods it is inside, the edges into that stop
        for sensor, action, capture, stack in events:
            frames = json.loads(stack) if stack else []
            if not frames:
                continue
            first = frame_name(frames[0]) or ""
            # a sensor on a servlet's service method describes the request. One on sendRedirect or forward is something done
            metadata = first.startswith(SERVLET_API) and first.endswith(".service")
            if metadata and not details:
                continue
            names = []
            if not metadata:
                for f in reversed(frames):
                    if frame_kind(f, app_prefixes) != "app":
                        continue
                    name = frame_name(f)
                    if name and (not names or names[-1] != name) and not name.startswith(SERVLET_API):
                        names.append(name)
                if page:
                    names = [x for x in names if not x.startswith("org.apache.jsp.%s." % page)]
            start["events"] += count
            effect = node("effect", sensor, sensor)
            shared = 0
            while shared < min(len(held), len(names)) and held[shared] == names[shared]:
                shared += 1
            entering = [node("code", name, _short(name), name) for name in names[shared:]]
            if here is effect and not entering:
                # the same stop again, so the events add to the edges that led into it
                if names == held:
                    for e in last_edges:
                        e["events"] += count
            else:
                path = [here] + entering + [effect]
                last_edges = [link(a, b, count) for a, b in zip(path, path[1:])]
            for name in names:
                nodes[("code", name)]["events"] += count
            effect["events"] += count
            if action in ("blocked", "monitored"):
                effect[action] += count
            effect["captures"][capture or ""] = effect["captures"].get(capture or "", 0) + count
            if sensor in JUMPS and capture:
                target = capture.strip()
                match = next((r for r in route_names if r == target or r.endswith("/" + target.lstrip("/"))), None)
                exit_node = node("exit", match or target.lstrip("/"), match or target.lstrip("/"))
                exit_node["events"] += count
                link(effect, exit_node, count)
            here, held = effect, names

    # requests that did the same things in the same order are drawn once, and counted
    same = {}
    for group in _requests(rows):
        key = (group[0][0], tuple((r[3], r[4], r[5], r[6]) for r in group))
        same[key] = same.get(key, 0) + 1
    for (route, events), count in same.items():
        walk(route, events, count)

    out_nodes = sorted(nodes.values(), key=lambda n: (-n["events"], n["label"]))
    for n in out_nodes:
        n["captures"] = sorted(n["captures"].items(), key=lambda kv: -kv[1])[:25]
    return {"nodes": out_nodes, "edges": sorted(edges.values(), key=lambda e: -e["events"]),
            "routes": route_names, "truncated": truncated}


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


def get_app_only(db_path):
    """True unless the application only filter has been switched off."""
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT value FROM settings WHERE key = 'app_only'").fetchone()
        return not row or row[0] == "1"
    finally:
        db.close()


def get_action_filter(db_path):
    """Which kinds of event the toolbar is limited to, as {"blocked": bool, "monitored": bool}. With neither on,
    every kind shows. Both off unless they have been switched on."""
    db = sqlite3.connect(db_path)
    try:
        rows = dict(db.execute("SELECT key, value FROM settings WHERE key IN ('filter_blocked', 'filter_monitored')"))
        return {"blocked": rows.get("filter_blocked") == "1", "monitored": rows.get("filter_monitored") == "1"}
    finally:
        db.close()


def get_show_jot_control(db_path):
    """True if the agent's own jot-control events are shown. They are left out unless it has been switched on."""
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT value FROM settings WHERE key = 'show_jot_control'").fetchone()
        return bool(row) and row[0] == "1"
    finally:
        db.close()


def set_show_jot_control(db, on):
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('show_jot_control', ?)", ("1" if on else "0",))
    db.commit()


def set_action_filter(db, blocked=None, monitored=None):
    """Limit what is shown to blocked events, to monitored ones, or to both. A kind that is None is left as it is."""
    for key, on in (("filter_blocked", blocked), ("filter_monitored", monitored)):
        if on is not None:
            db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, "1" if on else "0"))
    db.commit()


def set_app_only(db, on):
    """Leave out observed events that have no frame from the application, or show them again."""
    db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('app_only', ?)", ("1" if on else "0",))
    db.commit()
