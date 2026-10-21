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
  capture TEXT,         -- what the sensor captured, as one line
  data TEXT,            -- JSON object of the named values it captured, read with json_extract(data, '$.field')
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
-- unless the show_jot_control setting is 1. That is events_shown, which the reports read. The events view also leaves out the
-- observed events of a JOT in the hidden_jots setting, a JSON list of JOT names, and what a hidden rule blocked or reported still
-- shows. A report names the sensors it needs, so hiding one from the event list doesn't blank a column of it.
CREATE VIEW IF NOT EXISTS events_shown AS
  SELECT * FROM events_raw
  WHERE ts >= COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'since'), 0)
    AND (COALESCE((SELECT value FROM settings WHERE key = 'app_only'), '1') <> '1'
         OR origin IS NULL OR origin IN ('app', 'none') OR action <> 'observed')
    AND ((COALESCE((SELECT value FROM settings WHERE key = 'filter_blocked'), '0') <> '1'
          AND COALESCE((SELECT value FROM settings WHERE key = 'filter_monitored'), '0') <> '1')
         OR (action = 'blocked' AND COALESCE((SELECT value FROM settings WHERE key = 'filter_blocked'), '0') = '1')
         OR (action = 'monitored' AND COALESCE((SELECT value FROM settings WHERE key = 'filter_monitored'), '0') = '1'))
    AND (sensor <> 'jot-control' OR COALESCE((SELECT value FROM settings WHERE key = 'show_jot_control'), '0') = '1');

CREATE VIEW IF NOT EXISTS events AS
  SELECT * FROM events_shown
  WHERE 1
    AND (action <> 'observed' OR (CASE WHEN sensor LIKE '%-active' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 7) WHEN sensor LIKE '%-blocked' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 8) WHEN sensor LIKE '%-monitored' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 10) ELSE sensor END) NOT IN (SELECT value FROM json_each(COALESCE((SELECT value FROM settings WHERE key = 'hidden_jots'), '[]'))));

CREATE TABLE IF NOT EXISTS sensors (
  name TEXT PRIMARY KEY,
  description TEXT,
  methods TEXT,         -- JSON array
  scopes TEXT,          -- JSON array. The sensor only fires inside these methods
  captures TEXT,        -- JSON object of field name to expression
  blocks TEXT,          -- the block-when condition if the sensor is a rule, true for every call, otherwise null
  protect TEXT,         -- 'false' if the .jot file stages the rule as report only, otherwise null
  enabled TEXT,         -- 'false' if the .jot file writes enabled: false, otherwise null
  source TEXT,          -- the .jot file it came from
  path TEXT,            -- the full path of that file
  matchers TEXT,        -- JSON object of field name to a list of patterns
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
  rows TEXT,            -- the sensor.field whose values are the rows
  cols TEXT,            -- the sensor.field, or comma separated, for the columns
  value TEXT,           -- compare only, the sensor.field that fills the cells
  by TEXT,              -- compare only, the sensor.field that says who had each value
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

# A JOT names the events it reports about itself, cve-x-active when its scope is first entered, and a rule names what it did,
# cve-x-blocked or cve-x-monitored. This is the JOT's own name in SQL, so what happened can be counted against the JOT.
RULE_SUFFIXES = ("-active", "-blocked", "-monitored")


def rule_name(sensor):
    for suffix in RULE_SUFFIXES:
        if sensor and sensor.endswith(suffix):
            return sensor[:-len(suffix)]
    return sensor


JOT_NAME_SQL = ("CASE WHEN sensor LIKE '%-active' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 7) "
                "WHEN sensor LIKE '%-blocked' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 8) "
                "WHEN sensor LIKE '%-monitored' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 10) ELSE sensor END")

# the part of the schema the model is told about
MODEL_TABLES = ("events", "sensors")

EVENT_COLUMNS = ("time", "ts", "run", "host", "pid", "app", "id", "trace", "thread", "thread_id", "sensor",
                 "action", "capture", "data", "message", "method", "method_name", "call_site", "call_site_name", "stack",
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
CLASSIFIER_VERSION = 6
SERVLET_API = ("javax.servlet.", "jakarta.servlet.")

# The platform doing work that nothing in the application asked for. Loading a class opens jars to check their
# signatures, and compiling a page reads and parses source. What they do along the way isn't the application's.
# Work the application starts, like fetching an https address, is left out on purpose, it stays whatever the
# platform does to carry it out.
# The jots file's ignore list says what counts as that work, and the agent reads the same list, so it leaves out the
# same calls. An entry is a package, a class or a class and method and matches itself and everything inside it.
DEFAULT_IGNORE = ["java.lang.ClassLoader", "java.net.URLClassLoader", "jdk.internal.loader", "org.apache.catalina.loader",
                  "org.apache.jasper.compiler", "org.apache.jasper.JspCompilationContext.compile", "org.eclipse.jdt"]
IGNORE = list(DEFAULT_IGNORE)


def set_ignore(entries):
    """Use this ignore list, from the jots file. None is the default and an empty list ignores nothing."""
    global IGNORE
    IGNORE = list(DEFAULT_IGNORE) if entries is None else list(entries)


def _is_work(name):
    return any(name == e or name.startswith(e + ".") or name.startswith(e + "$") for e in IGNORE)


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
    stack holds only server frames, but the request is the application's. Those events count as the application.
    An event is the platform's, whatever is further out, when the way from it out to a class loader or the page
    compiler is nothing but JDK and server code. That work happens in the middle of a request, so an application
    frame is always further out, but the application did nothing. Code that is the application's or a library's,
    closer in than that work, like a class initializer, still counts. So does work the application asked for, such as
    a page fetching an https address, where the platform does a handshake on its behalf.
    The event's own frame, the call the sensor watches, doesn't count as the work, an application can call it."""
    if not stack:
        return "none", None
    if (frame_name(stack[0]) or "").startswith(SERVLET_API):
        return "app", stack[0]
    library = False
    only_platform = True
    for position, frame in enumerate(stack):
        kind = frame_kind(frame, app_prefixes)
        if kind == "platform":
            if only_platform and position > 0 and _is_work(frame_name(frame) or ""):
                return "platform", None
        else:
            only_platform = False
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
    db.execute("DROP VIEW IF EXISTS events_shown")
    db.executescript(SCHEMA)
    have = {r[1] for r in db.execute("PRAGMA table_info(events_raw)")}
    for column in ("origin", "app_frame", "data"):
        if column not in have:
            db.execute("ALTER TABLE events_raw ADD COLUMN %s TEXT" % column)
    db.commit()


def retag(db, app_prefixes):
    """Work out the origin of every stored event again. Done when the application packages change and for events that
    were stored before the origin was recorded. Returns the number of events tagged."""
    wanted = json.dumps([CLASSIFIER_VERSION] + sorted(app_prefixes) + ["ignore"] + sorted(IGNORE))
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
    values["data"] = json.dumps(e["data"]) if isinstance(e.get("data"), dict) else None
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


def read_ignore(path):
    """The ignore list of the jots file, or None when it has none, which is the default list. An entry that isn't text,
    or a list that isn't one, is not used, and the agent says so."""
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    entries = doc.get("ignore") if isinstance(doc, dict) else None
    if not isinstance(entries, list) or not all(isinstance(e, str) and e.strip() for e in entries):
        return None
    return [e.strip() for e in entries]


def read_jots_file(path):
    """The jots file the agent also reads. Returns (jot paths, control file path or None, application packages).
    Every entry is included. Relative paths are relative to the jots file. The packages are app: packages:, which the
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
    # the application's own packages. The entry points in the same mapping are the agent's, the dashboard has no use for them
    app = doc.get("app")
    packages = app.get("packages") if isinstance(app, dict) else None
    packages = [packages] if isinstance(packages, str) else [str(a) for a in packages or []]
    return jots, resolve(control) if control else None, packages


JOTS_FILE_KEYS = ("jots", "control", "app", "ignore")


def jots_file_problems(path):
    """Mistakes in the jots file that the agent says out loud as well, as messages, so the dashboard can too. The old list under
    app: has no packages in it now, they are under app: packages:."""
    with open(path) as fh:
        doc = yaml.safe_load(fh) or {}
    if not isinstance(doc, dict):
        return ["the jots file must be a mapping"]
    problems = ["%s is not a setting of a jots file, the settings are %s" % (k, ", ".join(JOTS_FILE_KEYS)) for k in doc if k not in JOTS_FILE_KEYS]
    app = doc.get("app")
    if app is not None and not isinstance(app, dict):
        problems.append("app must be a mapping with packages and entry, so no packages are used and the agent uses its default entry points")
    elif isinstance(app, dict):
        problems += ["app has %s, which is not a setting, the settings are packages and entry" % k for k in app if k not in ("packages", "entry")]
    return problems


def jot_files(paths):
    files = []
    for p in paths:
        if os.path.isdir(p):
            files.extend(sorted(glob.glob(os.path.join(p, "**", "*.jot"), recursive=True)))
        elif os.path.exists(p):
            files.append(p)
    return files


SENSOR_KEYS = ("name", "description", "methods", "scopes", "excludes", "captures", "matchers", "block-when",
               "protect", "enabled", "debug")
_SENSOR_NAME = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")
_LISTS = ("methods", "scopes", "excludes")
_FIELD = re.compile(r"^[a-z][a-z0-9_]*$")
_BOOLEANS = ("protect", "enabled", "debug")


# things Java patterns have that Python's don't, so a pattern with one can't be judged here and is left alone
_JAVA_ONLY = re.compile(r"\\[pPhRQEXZzGbB]\{|\\[hRQEXG]|[*+?}]\+|\(\?>|\(\?[a-zA-Z]*[uU]")


def _pattern_problem(pattern):
    """Why a matcher is not a pattern, or None. The agent uses Java's patterns, so only mistakes both would call
    mistakes are reported, like an unclosed group."""
    if _JAVA_ONLY.search(pattern):
        return None
    try:
        re.compile(re.sub(r"\(\?<([A-Za-z][A-Za-z0-9]*)>", r"(?P<\1>", pattern))
    except re.error as e:
        return str(e)
    return None


_TEXTS = ("name", "description")
_NOT_TEXT = {"null": "empty", "bool": "true or false", "int": "a number", "float": "a number", "timestamp": "a date"}


def _must_be_text(node, add):
    """Plain text that YAML would read as something else is a quoting mistake, like #P0, which starts a comment, !null,
    which starts a tag, or yes and 123, which are a boolean and a number. The fix is always quotes."""
    if not isinstance(node, yaml.ScalarNode):
        add(node, "must be text, not a list or a block")
        return
    kind = node.tag.rsplit(":", 1)[-1]
    if node.tag.startswith("!"):
        add(node, "starts with ! which YAML reads as a tag, put it in quotes")
    elif node.tag.startswith("tag:yaml.org,2002:") and kind != "str":
        shown = "an empty item, # starts a comment" if kind == "null" and not node.value else "%s" % _NOT_TEXT.get(kind, kind)
        add(node, "is read as %s, not text, put it in quotes" % shown)


def check_jot_text(text):
    """What is wrong with a sensor or rule as written, as a list of {"line", "message"}, line counting from 1. The
    same things the agent would complain about at startup, found before anything is saved. Nothing wrong is []."""
    if len(text or "") > 64 * 1024:
        return [{"line": 1, "message": "is too large to be one sensor"}]
    try:
        root = yaml.compose(text or "")
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        what = (getattr(e, "problem", None) or "isn't valid YAML").strip()
        return [{"line": mark.line + 1 if mark else 1, "message": what}]
    if root is None:
        return [{"line": 1, "message": "is empty"}]
    problems = []

    def add(node, message):
        problems.append({"line": node.start_mark.line + 1, "message": message})

    def text_of(node):
        return node.value if isinstance(node, yaml.ScalarNode) else None

    def entries(node):
        return {text_of(k): (k, v) for k, v in node.value} if isinstance(node, yaml.MappingNode) else {}

    # one sensor on its own, as the drawer shows it, or a whole file with a sensors list
    top = entries(root)
    if isinstance(root, yaml.MappingNode) and "sensors" not in top and "reports" in top:
        return problems      # a file of reports, which this doesn't check
    if isinstance(root, yaml.MappingNode) and "sensors" not in top:
        sensor_nodes = [root]
    elif isinstance(root, yaml.MappingNode) and isinstance(top["sensors"][1], yaml.SequenceNode):
        sensor_nodes = top["sensors"][1].value
    elif isinstance(root, yaml.MappingNode):
        add(top["sensors"][1], "sensors must be a list, with each sensor starting with  - name:")
        return problems
    else:
        add(root, "must be a sensor, with a name and methods")
        return problems
    seen = set()
    for node in sensor_nodes:
        keys = entries(node)
        if not isinstance(node, yaml.MappingNode):
            add(node, "each sensor must be a block of name, methods and so on")
            continue
        for k, (key, _) in keys.items():
            if k not in SENSOR_KEYS:
                add(key, "%s isn't something a sensor has. These are %s" % (k, ", ".join(SENSOR_KEYS)))
        name = text_of(keys["name"][1]) if "name" in keys else None
        if not name:
            add(node, "needs a name")
        else:
            if not _SENSOR_NAME.match(name):
                add(keys["name"][1], "%s should be lower case words joined with -, like crypto-hash" % name)
            if name in seen:
                add(keys["name"][1], "%s is used twice" % name)
            seen.add(name)
        for k in _LISTS:
            if k in keys and not isinstance(keys[k][1], yaml.SequenceNode):
                add(keys[k][0], "%s must be a list, each item starting with -" % k)
            elif k in keys:
                for item in keys[k][1].value:
                    _must_be_text(item, add)
        for k in _TEXTS:
            if k in keys:
                _must_be_text(keys[k][1], add)
        for k in _BOOLEANS:
            if k in keys and text_of(keys[k][1]) not in ("true", "false"):
                add(keys[k][1], "%s must be true or false" % k)
        if "methods" in keys and isinstance(keys["methods"][1], yaml.SequenceNode):
            if not keys["methods"][1].value:
                add(keys["methods"][0], "has no methods, so it can never fire")
            scopes = keys["scopes"][1].value if isinstance(keys.get("scopes", (0, 0))[1], yaml.SequenceNode) else []
            for ok, items in ((True, keys["methods"][1].value), (False, scopes)):
                for m in items:
                    problem = method_problem(text_of(m), annotation_ok=ok)
                    if problem:
                        add(m, problem)
        elif "methods" not in keys:
            add(node, "needs methods, the calls it watches")
        fields = set()
        if "captures" in keys:
            captures = keys["captures"][1]
            if not isinstance(captures, yaml.MappingNode):
                add(keys["captures"][0], "captures must be names and expressions, like path: \"#P0\"")
            else:
                for field, expression in captures.value:
                    fields.add(text_of(field))
                    if not _FIELD.match(text_of(field) or ""):
                        add(field, "%s should be a lower case name like path or remote_ip" % text_of(field))
                    _must_be_text(expression, add)
        if "matchers" in keys:
            matchers = keys["matchers"][1]
            if not isinstance(matchers, yaml.MappingNode):
                add(keys["matchers"][0], "matchers must be a captured field and a list of patterns, like path: [ '\\.php$' ]")
            else:
                for field, patterns in matchers.value:
                    if "captures" in keys and isinstance(keys["captures"][1], yaml.MappingNode) and text_of(field) not in fields:
                        add(field, "%s is not a captured field, the fields are %s" % (text_of(field), ", ".join(sorted(fields))))
                    if not isinstance(patterns, yaml.SequenceNode):
                        add(field, "%s must be a list, each item starting with -" % text_of(field))
                        continue
                    for m in patterns.value:
                        _must_be_text(m, add)
                        value = text_of(m) or ""
                        problem = _pattern_problem(value[1:] if value.startswith("!") else value)
                        if problem:
                            add(m, "isn't a valid pattern, %s" % problem)
        if "block-when" in keys:
            node = keys["block-when"][1]
            kind = node.tag.rsplit(":", 1)[-1] if isinstance(node, yaml.ScalarNode) else None
            if kind not in ("bool", "str") or (kind == "str" and not node.value.strip()):
                add(node, "must be true, or an expression for when the call is blocked, like #P0 < 2048")
        if "protect" in keys and "block-when" not in keys:
            add(keys["protect"][0], "protect only matters for a rule, which has a block-when")
    return problems


def _read_jot(path):
    try:
        with open(path) as fh:
            return yaml.safe_load(fh) or {}
    except (OSError, yaml.YAMLError) as e:
        print("[dashboard] can't read", path, e)
        return {}


_METHOD = re.compile(r"^!?[\w$]+(\.[\w$]+)*\.(<init>|[\w$]+)$")
_ANNOTATION = re.compile(r"^@[\w$]+(\.[\w$]+)*$")


def method_problem(value, annotation_ok=False):
    """Why a method of a JOT can't be matched by the agent, or None. A method is package.Class.method, with <init> for a
    constructor, and nothing else. Static, parameters and a return type are not part of the name, and a method is matched whether it
    is static or not. In methods, @package.Annotation names every method that carries it. A scope can't be an annotation."""
    value = (value or "").strip()
    bare = value[1:] if value.startswith("!") else value
    if _METHOD.match(value) or (annotation_ok and _ANNOTATION.match(bare)):
        return None
    return ("%r isn't a method name, write package.Class.method with no static or other modifiers, parameters or return type, "
            "and <init> for a constructor%s" % (value, ", or @package.Annotation" if annotation_ok else ""))


def _issue(db, level, text, source):
    db.execute("INSERT INTO jot_issues VALUES (?,?,?)", (level, text, source))


def _last_end(node):
    """Where the last thing written inside a YAML node ends, not counting the blank lines and comments after it."""
    if isinstance(node, yaml.MappingNode) and node.value:
        return _last_end(node.value[-1][1])
    if isinstance(node, yaml.SequenceNode) and node.value:
        return _last_end(node.value[-1])
    return node.end_mark.index


def sensor_spans(text):
    """Where each sensor is written in a .jot file, as {name: {"start", "end", "column", "text"}}. The text is the sensor as
    written, comments and quotes included, moved to the left edge. The first sensor of a name wins, like the agent."""
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return {}
    spans = {}
    if not isinstance(root, yaml.MappingNode):
        return spans
    for key, value in root.value:
        if key.value != "sensors" or not isinstance(value, yaml.SequenceNode):
            continue
        for item in value.value:
            if not isinstance(item, yaml.MappingNode):
                continue
            name = next((v.value for k, v in item.value if k.value == "name" and isinstance(v, yaml.ScalarNode)), None)
            if not name or name in spans:
                continue
            start, end, column = item.start_mark.index, _last_end(item), item.start_mark.column
            lines = text[start:end].split("\n")
            body = [lines[0]] + [l[column:] if l[:column].strip() == "" else l for l in lines[1:]]
            spans[name] = {"start": start, "end": end, "column": column, "text": "\n".join(body).rstrip()}
    return spans


class SaveError(Exception):
    """A sensor could not be saved. status is the HTTP status that says why."""
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def rename_in_reports(text, old, new):
    """The .jot text with the sensor name old changed to new in the rows and cols of every report that uses it, and the names
    of those reports. Only the name changes, the comments, quotes and layout around it stay as written."""
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return text, []
    if not isinstance(root, yaml.MappingNode):
        return text, []
    token = re.compile(r"(?<![\w.-])%s(?![\w-])" % re.escape(old))
    edits, changed = [], []
    for key, value in root.value:
        if key.value != "reports" or not isinstance(value, yaml.SequenceNode):
            continue
        for report in value.value:
            if not isinstance(report, yaml.MappingNode):
                continue
            fields = {k.value: v for k, v in report.value if isinstance(k, yaml.ScalarNode)}
            used = False
            for field in ("rows", "cols", "value", "by"):
                node = fields.get(field)
                if not isinstance(node, yaml.ScalarNode):
                    continue
                raw = text[node.start_mark.index:node.end_mark.index]
                if "\n" in raw or not token.search(node.value):
                    continue
                edits.append((node.start_mark.index, node.end_mark.index, token.sub(new, raw)))
                used = True
            if used:
                changed.append(str(fields["name"].value) if "name" in fields else "(unnamed)")
    for start, end, replacement in sorted(edits, reverse=True):
        text = text[:start] + replacement + text[end:]
    return text, changed


def _report_uses(doc, rename=None):
    """Each report of a parsed file as (the whole report, its rows, its cols as a list), with old to new applied to the names
    when rename is (old, new). Used to check that editing the text changed the names and nothing else."""
    out = []

    def swap(ref):
        sensor, dot, field = str(ref).partition(".")
        return (rename[1] if rename and sensor == rename[0] else sensor) + dot + field if ref else ref

    for r in (doc or {}).get("reports") or []:
        if isinstance(r, dict):
            rest = {k: v for k, v in r.items() if k not in ("rows", "cols", "value", "by")}
            out.append((rest, swap(r.get("rows")), [swap(c.strip()) for c in str(r.get("cols") or "").split(",") if c.strip()],
                        swap(r.get("value")), swap(r.get("by"))))
    return out


_FORBIDDEN_IN_EXPRESSIONS = re.compile(r"\bT\(|\bnew\s")


def check_draft(text, taken=()):
    """What is wrong with a JOT a model wrote, as messages. The checks of the editor, and more. It must be one JOT and not a file
    with a sensors list, its name must be free, a sensor must record something, a rule needs a message, and an expression
    can't reach out with T( or new."""
    problems = ["line %d %s" % (p["line"], p["message"]) for p in check_jot_text(text)]
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return problems or ["isn't valid YAML"]
    if not isinstance(doc, dict):
        return problems or ["must be one JOT, a mapping with a name and methods"]
    if "sensors" in doc or "reports" in doc:
        problems.append("must be one JOT, not a file with a sensors list")
        return problems
    if doc.get("name") in set(taken):
        problems.append("the name %s is already used by another JOT" % doc["name"])
    captures = doc.get("captures")
    expressions = [str(c) for c in (captures.values() if isinstance(captures, dict) else [])]
    if doc.get("block-when") not in (None, True, False):
        expressions.append(str(doc["block-when"]))
    if any(_FORBIDDEN_IN_EXPRESSIONS.search(e) for e in expressions):
        problems.append("an expression can't use T( or new")
    if not str(doc.get("description") or "").startswith("Identifies "):
        problems.append('the description says what the JOT identifies and starts with "Identifies", like "Identifies starting a native process"')
    if "block-when" in doc:
        if not doc.get("description"):
            problems.append("a rule needs a description, it is the message")
    elif not doc.get("captures"):
        problems.append("a sensor needs at least one capture, or it records nothing")
    return problems


def stage_rule(text):
    """A drafted rule starts with protect: false, so it only reports until someone turns it on. Written into the text,
    with everything else as it was."""
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return text
    if not isinstance(doc, dict) or "block-when" not in doc or doc.get("protect") is False:
        return text
    lines = text.split("\n")
    if "protect" in doc:
        return "\n".join("protect: false" if re.match(r"^protect\s*:", l) else l for l in lines)
    for i, line in enumerate(lines):
        if re.match(r"^block-when\s*:", line):
            return "\n".join(lines[:i + 1] + ["protect: false"] + lines[i + 1:])
    return text


def add_sensor(paths, file, text):
    """Adds a JOT to a file, after the last one in it, and leaves everything else in the file as it was. file is the name of a file
    that is loaded. A name that isn't loaded and ends in .jot makes a new file in the first directory that was listed. Returns the
    path written."""
    names = set()
    sources = {}
    for path in jot_files(paths):
        with open(path, encoding="utf-8") as fh:
            for found in sensor_spans(fh.read()):
                names.add(found)
                sources.setdefault(found, os.path.basename(path))
    problems = check_draft(text, names)
    if problems:
        raise SaveError("not added, " + problems[0])
    written = yaml.safe_load(text)
    new_text = text.strip("\n") + "\n"

    matches = [p for p in jot_files(paths) if os.path.basename(p) == file]
    if len(matches) > 1:
        raise SaveError("not added, %s names more than one file, add it by hand" % file)
    if not matches:
        if not file or not file.endswith(".jot") or os.sep in file or file.startswith("."):
            raise SaveError("not added, %r isn't a loaded file, and a new file needs a plain name ending in .jot" % file)
        directory = next((p for p in paths if os.path.isdir(p)), None)
        if directory is None:
            raise SaveError("not added, there is no directory in the jots file to put a new file in")
        target = os.path.join(directory, file)
        if os.path.exists(target):
            raise SaveError("not added, %s already exists but isn't loaded" % target, 409)
        result = "sensors:\n" + "- " + new_text.replace("\n", "\n  ").rstrip(" ")
        if yaml.safe_load(result) != {"sensors": [written]}:
            raise SaveError("not added, the new file would not have said what was meant")
        with open(target, "x", encoding="utf-8") as fh:
            fh.write(result)
        return target

    path = matches[0]
    with open(path, encoding="utf-8") as fh:
        text_before = fh.read()
    before = yaml.safe_load(text_before) or {}
    if not isinstance(before, dict):
        raise SaveError("not added, %s isn't a file of sensors and reports" % file)
    root = yaml.compose(text_before) if text_before.strip() else None
    items = None
    if isinstance(root, yaml.MappingNode):
        for key, value in root.value:
            if key.value == "sensors" and isinstance(value, yaml.SequenceNode) and value.value:
                items = value.value
    if items:
        last = items[-1]
        line_start = text_before.rfind("\n", 0, last.start_mark.index) + 1
        prefix = text_before[line_start:last.start_mark.index]
        if not re.match(r"^\s*-\s+$", prefix):
            raise SaveError("not added, the sensors in %s aren't written as a block list, add it by hand" % file)
        pad = " " * len(prefix)
        lines = new_text.rstrip("\n").split("\n")
        block = prefix + lines[0] + "".join("\n" + (pad + l if l.strip() else l) for l in lines[1:]) + "\n"
        end = _last_end(last)
        eol = text_before.find("\n", end)
        at = len(text_before) if eol < 0 else eol + 1
        lead = "" if eol >= 0 else "\n"
        result = text_before[:at] + lead + "\n" + block + text_before[at:]
    elif isinstance(root, yaml.MappingNode) and "sensors" in before:
        raise SaveError("not added, the sensors list in %s is empty or written inline, add it by hand" % file)
    else:
        base = text_before if not text_before.strip() else text_before.rstrip("\n") + "\n\n"
        result = base + "sensors:\n- " + new_text.replace("\n", "\n  ").rstrip(" ")
    after = yaml.safe_load(result) or {}
    if after.get("sensors") != (before.get("sensors") or []) + [written] or \
            {k: v for k, v in after.items() if k != "sensors"} != {k: v for k, v in before.items() if k != "sensors"}:
        raise SaveError("not added, putting this in %s would have changed something else in it" % file)
    mode = os.stat(path).st_mode
    tmp = path + ".saving"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(result)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return path


def save_sensor(paths, name, original, new_text):
    """Writes the new text of one sensor into the .jot file that has it, leaving everything else in the file as it was,
    comments and the other sensors included. original is what the editor started from. If the file no longer says that,
    someone else changed it and nothing is written. The name can be changed to one that isn't taken, and then the reports that use the old name are changed to the new one. Returns the path written and the names of the reports changed."""
    new_text = (new_text or "").rstrip() + "\n"
    problems = check_jot_text(new_text)
    if problems:
        raise SaveError("not saved, line %d %s" % (problems[0]["line"], problems[0]["message"]))
    written = yaml.safe_load(new_text)
    new_name = written.get("name") if isinstance(written, dict) else None
    if new_name != name:
        for path in jot_files(paths):
            with open(path, encoding="utf-8") as fh:
                if new_name in sensor_spans(fh.read()):
                    raise SaveError("not saved, %s is already the name of a sensor, in %s" % (new_name, os.path.basename(path)))
    for path in jot_files(paths):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        span = sensor_spans(text).get(name)
        if not span:
            continue
        if (original or "").rstrip() != span["text"]:
            raise SaveError("not saved, %s has changed since this was opened. Close it and open it again" % os.path.basename(path), 409)
        line_start = text.rfind("\n", 0, span["start"]) + 1
        if not re.match(r"^\s*-\s+$", text[line_start:span["start"]]):
            raise SaveError("not saved, this sensor isn't written as a block in the list, edit the file by hand")
        pad = " " * span["column"]
        lines = new_text.rstrip().split("\n")
        body = "\n".join([lines[0]] + [pad + l if l.strip() else l for l in lines[1:]])
        result = text[:span["start"]] + body + text[span["end"]:]
        # the file must still say what was meant, this sensor as written and every other one as before
        before, after = yaml.safe_load(text) or {}, yaml.safe_load(result) or {}
        expected = [written if x.get("name") == name else x for x in before.get("sensors") or []]
        if after.get("sensors") != expected or {k: v for k, v in after.items() if k != "sensors"} != {k: v for k, v in before.items() if k != "sensors"}:
            raise SaveError("not saved, putting this in the file would have changed something else in it")
        # a new name is also written into the reports that use the old one, in this file and in any other
        writes, updated = {path: result}, []
        if new_name != name:
            for other in jot_files(paths):
                with open(other, encoding="utf-8") as fh:
                    base = result if other == path else fh.read()
                edited, reports = rename_in_reports(base, name, new_name)
                if reports:
                    before_doc, after_doc = yaml.safe_load(base), yaml.safe_load(edited)
                    if _report_uses(after_doc) != _report_uses(before_doc, (name, new_name)) or \
                            {k: v for k, v in (after_doc or {}).items() if k != "reports"} != {k: v for k, v in (before_doc or {}).items() if k != "reports"}:
                        raise SaveError("not saved, changing the reports that use %s would have changed something else in %s" % (name, os.path.basename(other)))
                    writes[other] = edited
                    updated.extend(reports)
        for target, content in writes.items():
            mode = os.stat(target).st_mode
            tmp = target + ".saving"
            with open(tmp, "w", encoding="utf-8") as fh:
                fh.write(content)
            os.chmod(tmp, mode)
            os.replace(tmp, target)
        return path, updated
    raise SaveError("not saved, no loaded file has a sensor called %s" % name, 404)


def _block_condition(sensor):
    """The condition of a rule as text, true for every call, or None for a sensor."""
    value = sensor.get("block-when")
    if value is None:
        return None
    return str(value).lower() if isinstance(value, bool) else str(value)


def load_sensors(db, paths):
    """Read sensor definitions from .jot files, or directories of them, so the model knows what they mean and
    the JOTs view can show them. Like the agent, the first definition of a name wins and a later one is skipped."""
    db.execute("DELETE FROM sensors")
    db.execute("DELETE FROM jot_issues")
    loaded = 0
    for f in jot_files(paths):
        source = os.path.basename(f)
        try:
            with open(f, encoding="utf-8") as fh:
                written = sensor_spans(fh.read())
        except OSError:
            written = {}
        for s in _read_jot(f).get("sensors") or []:
            if not isinstance(s, dict) or not s.get("name") or s["name"] == "example":
                continue
            name = s["name"]
            first = db.execute("SELECT source FROM sensors WHERE name = ?", (name,)).fetchone()
            if first:
                _issue(db, "warning", "%s is defined again in %s, the agent skips it and keeps the one in %s"
                       % (name, source, first[0]), source)
                continue
            for key in s:
                if key not in SENSOR_KEYS:
                    _issue(db, "warning", ("%s has exception, which is no longer a setting. Use block-when, until then it only observes"
                                           if key == "exception" else "%s has " + key + ", which is not a setting and is ignored") % name, source)
            methods = s.get("methods") or []
            if not methods:
                _issue(db, "warning", "%s has no methods, so it can never fire" % name, source)
            for ok, items in ((True, methods), (False, s.get("scopes") or [])):
                for m in items:
                    if method_problem(str(m), annotation_ok=ok):
                        _issue(db, "warning", "%s has %r, which isn't a method name the agent can match" % (name, m), source)
            staged = "false" if s.get("protect") is False else None
            off = "false" if s.get("enabled") is False else None
            db.execute("""INSERT INTO sensors (name, description, methods, scopes, captures, blocks, protect, enabled, source, path,
                                               matchers, excludes, definition) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                name, s.get("description"), json.dumps(methods), json.dumps(s.get("scopes") or []),
                json.dumps(s.get("captures") or {}), _block_condition(s), staged, off, source, f,
                json.dumps(s.get("matchers") or {}), json.dumps(s.get("excludes") or []),
                (written.get(name) or {}).get("text")
                or yaml.safe_dump(s, sort_keys=False, default_flow_style=False, allow_unicode=True).rstrip()))
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
            db.execute("INSERT OR REPLACE INTO reports VALUES (?,?,?,?,?,?,?)", (
                r["name"], rtype, r.get("rows"), r.get("cols"), r.get("value"), r.get("by"), source))
            used = ([r["rows"]] if r.get("rows") else []) + [c.strip() for c in str(r.get("cols") or "").split(",") if c.strip()] \
                + ([r["value"]] if r.get("value") else []) + ([r["by"]] if r.get("by") else [])
            for ref in used:
                sensor, _, field = ref.partition(".")
                have = db.execute("SELECT captures FROM sensors WHERE name = ?", (sensor,)).fetchone()
                if not have:
                    _issue(db, "warning", "report %s uses %s, which no loaded sensor defines" % (r["name"], sensor), source)
                elif field and field not in json.loads(have[0] or "{}"):
                    _issue(db, "warning", "report %s uses %s, but %s doesn't capture %s" % (r["name"], ref, sensor, field), source)
            loaded += 1
    db.commit()
    return loaded


def _lit(text):
    """A SQL string literal."""
    return "'" + str(text).replace("'", "''") + "'"


def _values(alias, ref, n):
    """How a report reads sensor.field from the events called alias, as (what to join, an SQL expression for the value).
    A list is one value for each item, and a bare sensor name is what it captured as one line. n makes the names unique."""
    sensor, _, field = ref.partition(".")
    if not field:
        return "", "%s.capture" % alias
    if not re.match(r"^[a-z][a-z0-9_]*$", field):
        raise ValueError("%s isn't sensor.field, a field is a lower case name" % ref)
    each = "j%d" % n
    return (", json_each(%s.data, '$.%s') %s" % (alias, field, each),
            "CASE %s.type WHEN 'true' THEN 'true' WHEN 'false' THEN 'false' ELSE CAST(%s.value AS TEXT) END" % (each, each))


def _ident(text):
    """A name to use as a column heading in SQL."""
    return '"' + str(text).replace('"', '""') + '"'


def report_sql(rtype, rows, cols, value=None, by=None):
    """The query for a report, as rows of (row, column, value) which the dashboard turns into a grid. What it reads is
    written sensor.field. A row and a column are related when they were observed in the same request, which is the same
    run and trace."""
    refs = [c.strip() for c in (cols or "").split(",") if c.strip()]
    if not refs:
        raise ValueError("a report needs cols")
    if rtype == "list":
        join, expr = _values("e", refs[0], 0)
        return ("SELECT DISTINCT e.call_site AS call_site, %s AS sensor, %s AS value\n"
                "FROM events_shown e%s WHERE e.sensor = %s AND e.call_site IS NOT NULL AND %s <> ''\n"
                "ORDER BY call_site" % (_lit(refs[0]), expr, join, _lit(refs[0].partition(".")[0]), expr))
    if not rows:
        raise ValueError("a %s report needs rows" % rtype)
    row_join, row_expr = _values("r", rows, 1)
    start = "FROM events_shown r%s, events_shown c" % row_join
    relate = "r.run = c.run AND r.trace = c.trace AND r.sensor = %s" % _lit(rows.partition(".")[0])
    if rtype == "compare":
        col_join, col_expr = _values("c", refs[0], 2)
        if value:
            if value.partition(".")[0] != refs[0].partition(".")[0]:
                raise ValueError("value is a field of the cols sensor")
            val_join, val_expr = _values("c", value, 3)
            by_join, by_expr = "", None
            if by:
                if by.partition(".")[0] != refs[0].partition(".")[0]:
                    raise ValueError("by is a field of the cols sensor")
                by_join, by_expr = _values("c", by, 4)
            return ("SELECT DISTINCT %s AS %s, %s AS col, %s AS value%s\n%s%s%s%s WHERE %s AND c.sensor = %s\nORDER BY 1, 2"
                    % (row_expr, _ident(rows), col_expr, val_expr, ", %s AS who" % by_expr if by else "", start, col_join, val_join, by_join, relate,
                       _lit(refs[0].partition(".")[0])))
        return ("SELECT DISTINCT %s AS %s, %s AS col, 'x' AS value\n%s%s WHERE %s AND c.sensor = %s\nORDER BY 1, 2"
                % (row_expr, _ident(rows), col_expr, start, col_join, relate, _lit(refs[0].partition(".")[0])))
    if rtype == "table":
        parts = []
        for i, ref in enumerate(refs):
            col_join, col_expr = _values("c", ref, 2)
            parts.append("SELECT DISTINCT %s AS %s, %s AS col, %s AS value\n%s%s WHERE %s AND c.sensor = %s"
                         % (row_expr, _ident(rows), _lit(ref), col_expr, start, col_join, relate, _lit(ref.partition(".")[0])))
        return "\nUNION\n".join(parts) + "\nORDER BY 1, 2"
    raise ValueError("unknown report type %s" % rtype)


_CELL_COLUMNS = ("c.pk AS pk, strftime('%Y-%m-%d %H:%M:%S', c.ts/1000, 'unixepoch', 'localtime') AS time, c.action AS action, "
                 "c.sensor AS sensor, c.call_site_name AS call_site, c.capture AS capture")


def report_events_sql(rtype, rows, cols, row=None, col=None):
    """The query for the events behind part of a report, which is a cell with a row and a column, a whole row when there is
    no column, or a whole column when there is no row. They are the events of the column's sensor, from the requests that
    the report relates to that row, so they are what put the values in the cell. Each is a row of pk, time, action, sensor,
    call_site and capture, with pk first so a row of the result opens its event."""
    refs = [c.strip() for c in (cols or "").split(",") if c.strip()]
    if not refs:
        raise ValueError("a report needs cols")
    if rtype == "list":
        ref = col if col in refs else refs[0]
        join, expr = _values("c", ref, 0)
        where = ["c.sensor = %s" % _lit(ref.partition(".")[0])]
        if row is not None:
            where.append("c.call_site = %s" % _lit(row))
        return ("SELECT DISTINCT %s\nFROM events_shown c%s\nWHERE %s\nORDER BY c.ts DESC LIMIT 500"
                % (_CELL_COLUMNS, join, " AND ".join(where)))
    if not rows:
        raise ValueError("a %s report needs rows" % rtype)
    row_join, row_expr = _values("r", rows, 1)
    if rtype == "table":
        picked = [col] if col in refs else refs
    elif rtype == "compare":
        picked = refs[:1]
    else:
        raise ValueError("unknown report type %s" % rtype)
    parts = []
    for ref in picked:
        col_join, col_expr = _values("c", ref, 2)
        where = ["r.run = c.run", "r.trace = c.trace", "r.sensor = %s" % _lit(rows.partition(".")[0]), "c.sensor = %s" % _lit(ref.partition(".")[0])]
        if row is not None:
            where.append("%s = %s" % (row_expr, _lit(row)))
        if rtype == "compare" and col is not None:
            where.append("%s = %s" % (col_expr, _lit(col)))
        parts.append("SELECT DISTINCT %s\nFROM events_shown r%s, events_shown c%s\nWHERE %s"
                     % (_CELL_COLUMNS, row_join, col_join, " AND ".join(where)))
    return "\nUNION\n".join(parts) + "\nORDER BY 1 DESC LIMIT 500"


# ---------------------------------------------------------------------------- search

# word:value narrows by a field, for example sensor:crypto-hash or action:blocked
SEARCH_FIELDS = {"sensor": "contains", "action": "equals", "origin": "equals", "app": "equals", "run": "equals",
                 "host": "equals", "trace": "number", "pid": "number", "route": "route"}
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
        elif SEARCH_FIELDS[field] == "route":
            # the request an event happened in came in at this route, as the http-route sensor saw it
            seen = "SELECT run, trace FROM events_raw WHERE sensor IN %s" % ROUTE_SENSORS_SQL
            cond = ("(run, trace) NOT IN (%s)" % seen if text == NO_REQUEST
                    else "(run, trace) IN (%s AND capture = %s)" % (seen, _lit(text)))
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
# the sensor that says which route a request came in at. It has been called get-routes and get-route, and the log still
# has events from the old names
ROUTE_SENSORS = ("http-route", "get-route", "get-routes")
ROUTE_SENSORS_SQL = "(%s)" % ", ".join("'%s'" % x for x in ROUTE_SENSORS)
# sensors whose capture is another route, under the names they had before they were http-forward and http-redirect too
JUMPS = ("http-forward", "http-redirect", "get-forward", "get-forwards", "get-redirect", "get-redirects")


def _short(name):
    """com.acme.ticketbook.Ticket.encrypt becomes Ticket.encrypt."""
    return ".".join(name.split(".")[-2:])


def _page_of(route):
    """/ticketbook/ssrf.jsp is compiled to ssrf_jsp."""
    last = (route or "").rsplit("/", 1)[-1]
    return last.replace(".", "_") if last else None


def graph_rows(db_path, route=None):
    """The events of the graph in the order they happened, request by request. The route is the first request the
    event happened in, as the http-route sensor saw it. Events of one request are together and in the agent's own
    order, which is the order the application caused them."""
    where = "WHERE sensor NOT IN %s AND stack IS NOT NULL" % ROUTE_SENSORS_SQL
    sql = """SELECT route, run, trace, sensor, action, capture, stack FROM (
               SELECT (SELECT r.capture FROM events_raw r WHERE r.run = e.run AND r.trace = e.trace AND r.sensor IN %s
                       ORDER BY r.pk LIMIT 1) AS route, e.run, e.trace, e.id, e.sensor, e.action, e.capture, e.stack
               FROM events e %s) %s ORDER BY run, trace, id""" % (ROUTE_SENSORS_SQL, where, "WHERE route = %s" % _lit(route) if route else "")
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
    describes the request, like who the user is, is left out unless details is set. Every node and edge says which
    lines use it, so what goes through a node can be told from what can merely be reached from it. One request that did
    A and then B and another that did B and then A make a loop between them, and following edges would join them."""
    nodes, edges = {}, {}
    line = [0]                 # the line being walked, a request that did the same things in the same order as others

    def node(kind, key, label, full=None):
        n = nodes.setdefault((kind, key), {"id": "%s:%s" % (kind, key), "kind": kind, "label": label, "full": full or key,
                                           "events": 0, "blocked": 0, "monitored": 0, "captures": {}, "lines": set()})
        n["lines"].add(line[0])
        return n

    def link(a, b, count):
        e = edges.setdefault((a["id"], b["id"]), {"from": a["id"], "to": b["id"], "events": 0, "lines": set()})
        e["events"] += count
        e["lines"].add(line[0])
        return e

    route_names = sorted(routes_seen)

    def walk(route, events, count):
        route = route or NO_REQUEST
        start = node("route", route, route)
        # the page the route names is compiled to a class, and every method of it, like the tag helpers Jasper
        # generates, is that page. The route already stands for it, so it isn't drawn again
        page = _page_of(route)
        start["events"] += count     # a route counts the requests that came in at it, the others count events
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
                nodes[("code", name)]["lines"].add(line[0])
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
    line_counts = {}
    for number, ((route, events), count) in enumerate(same.items()):
        line[0] = number
        line_counts[number] = count
        walk(route, events, count)

    out_nodes = sorted(nodes.values(), key=lambda n: (-n["events"], n["label"]))
    for n in out_nodes:
        n["captures"] = sorted(n["captures"].items(), key=lambda kv: -kv[1])[:25]
        n["lines"] = sorted(n["lines"])
    for e in edges.values():
        e["lines"] = sorted(e["lines"])
    return {"nodes": out_nodes, "edges": sorted(edges.values(), key=lambda e: -e["events"]),
            "routes": route_names, "truncated": truncated, "line_counts": line_counts}


def build_graphs(rows, routes_seen, app_prefixes=(), details=False, truncated=False):
    """One graph for each route, in alphabetical order, so each can be read and laid out on its own. A route is
    where a request came in, and its graph holds only what requests that came in there did."""
    by_route = {}
    for row in rows:
        by_route.setdefault(row[0] or NO_REQUEST, []).append(row)
    graphs = []
    for route, route_rows in by_route.items():
        g = build_graph(route_rows, routes_seen, app_prefixes, details, truncated)
        if not g["edges"]:
            continue   # nothing happened in it that the graph shows, like a stylesheet
        graphs.append({"route": route, "requests": sum(1 for _ in _requests(route_rows)),
                       "events": len(route_rows), "nodes": g["nodes"], "edges": g["edges"], "line_counts": g["line_counts"]})
    graphs.sort(key=lambda g: (g["route"] == NO_REQUEST, g["route"].lower()))
    return {"graphs": graphs, "routes": sorted(routes_seen), "truncated": truncated}


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


def get_hidden_jots(db_path):
    """The names of the JOTs whose observed events are left out, as a list."""
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT value FROM settings WHERE key = 'hidden_jots'").fetchone()
        return json.loads(row[0]) if row else []
    finally:
        db.close()


def set_hidden_jots(db, names):
    """Leave out the observed events of these JOTs, by name, or show everything again with an empty list."""
    names = sorted({str(n) for n in names})
    if len(names) > 1000 or any(len(n) > 200 for n in names):
        raise ValueError("too many or too long")
    if names:
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('hidden_jots', ?)", (json.dumps(names),))
    else:
        db.execute("DELETE FROM settings WHERE key = 'hidden_jots'")
    db.commit()


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
