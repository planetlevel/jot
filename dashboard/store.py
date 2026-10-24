"""SQLite storage for JOT events, a log tailer that fills it, and a safe read-only query runner."""

import copy
import difflib
import glob
import json
import os
import re
import shutil
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
  entry TEXT,           -- the entry point the event ran under, like com.acme.tools.Calc.add, NULL for an event outside every entry point
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

-- What every query and view reads. With no setting made, that is every event there is. A filter is a list of what is shown, kept as
-- the list of what is not, so nothing set means everything shows. The filters are independent, and an event shows when every one of them
-- lets it through. Reset removes them all.
--   since           the start time, in epoch milliseconds. This is how the dashboard is cleared, nothing is deleted.
--   hidden_actions  actions that are not shown, from observed, monitored and blocked.
--   hidden_origins  where an event came from that is not shown, from app, library, platform and none.
--   hidden_jots     the JOTs whose events are not shown, by name. A rule and its -active, -blocked and -monitored events are one JOT.
-- events_shown is what the reports read, and has the first three. A report names the sensors it needs, so hiding a JOT doesn't blank a
-- column of it, and events is events_shown with the hidden JOTs left out, which is what every other view reads.
CREATE VIEW IF NOT EXISTS events_shown AS
  SELECT * FROM events_raw
  WHERE ts >= COALESCE((SELECT CAST(value AS INTEGER) FROM settings WHERE key = 'since'), 0)
    AND COALESCE(action, 'observed') NOT IN
        (SELECT value FROM json_each(COALESCE((SELECT value FROM settings WHERE key = 'hidden_actions'), '[]')))
    AND COALESCE(origin, 'none') NOT IN
        (SELECT value FROM json_each(COALESCE((SELECT value FROM settings WHERE key = 'hidden_origins'), '[]')));

CREATE VIEW IF NOT EXISTS events AS
  SELECT * FROM events_shown
  WHERE (CASE WHEN sensor LIKE '%-active' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 7) WHEN sensor LIKE '%-blocked' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 8) WHEN sensor LIKE '%-monitored' THEN SUBSTR(sensor, 1, LENGTH(sensor) - 10) ELSE sensor END) NOT IN (SELECT value FROM json_each(COALESCE((SELECT value FROM settings WHERE key = 'hidden_jots'), '[]')));

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

-- The assistant's conversations. chat_api is what the model is sent, kept exactly as it came so a conversation can be continued, and
-- chat_items is what the page shows, in order. A proposal is a change the assistant has suggested, which nothing acts on until it is applied.
CREATE TABLE IF NOT EXISTS chats (
  id INTEGER PRIMARY KEY,
  title TEXT,
  created INTEGER,
  updated INTEGER
);

CREATE TABLE IF NOT EXISTS chat_api (
  chat INTEGER,
  n INTEGER,
  role TEXT,
  content TEXT,         -- JSON, the blocks of the message
  PRIMARY KEY (chat, n)
);

CREATE TABLE IF NOT EXISTS chat_items (
  chat INTEGER,
  n INTEGER,
  ts INTEGER,
  kind TEXT,            -- user, assistant, step, applied, error
  text TEXT,
  PRIMARY KEY (chat, n)
);

CREATE TABLE IF NOT EXISTS chat_proposals (
  id INTEGER PRIMARY KEY,
  chat INTEGER,
  item INTEGER,         -- the place in the conversation it was made
  kind TEXT,            -- setting, sensor, report, consolidation
  title TEXT,
  reason TEXT,
  payload TEXT,         -- JSON, what would be written
  status TEXT,          -- pending, applied, discarded
  result TEXT,          -- what happened when it was applied
  told INTEGER DEFAULT 0,
  created INTEGER
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

EVENT_COLUMNS = ("time", "ts", "run", "host", "pid", "app", "id", "trace", "entry", "thread", "thread_id", "sensor",
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
    # the filters of an older version, application only, blocked and monitored and JOT control events, do nothing now
    db.execute("DELETE FROM settings WHERE key IN (%s)" % ", ".join("?" * len(LEGACY_FILTER_SETTINGS)), LEGACY_FILTER_SETTINGS)
    have = {r[1] for r in db.execute("PRAGMA table_info(events_raw)")}
    for column in ("origin", "app_frame", "data", "entry"):
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


JOT_DIR = ".jot"
JOT_DIR_IGNORE = "# what JOT writes while it runs stays out of git, the configuration does not\n*\n!.gitignore\n!jot.yaml\n"
FRESH_CONFIG = "# The configuration of this project. The Assistant page can set it up, and this file is the one place it lives.\n"


def find_config(start=None):
    """The jots file of the project in the folder, .jot/jot.yaml first and then jot.yaml, or None. The agent looks in the same two places."""
    base = os.path.abspath(start or os.getcwd())
    for name in (os.path.join(JOT_DIR, "jot.yaml"), "jot.yaml"):
        found = os.path.join(base, name)
        if os.path.isfile(found):
            return found
    return None


def jot_dir(jots=None, start=None):
    """The .jot folder, where the events, the database and the other files that JOT writes go. It is the folder the jots file is in when
    that is a .jot, and a .jot next to it otherwise, and a .jot in the working folder when there is no jots file."""
    if jots:
        here = os.path.dirname(os.path.abspath(jots))
        return here if os.path.basename(here) == JOT_DIR else os.path.join(here, JOT_DIR)
    return os.path.join(os.path.abspath(start or os.getcwd()), JOT_DIR)


def make_jot_dir(path):
    """Makes the .jot folder, with a .gitignore that leaves only jot.yaml to be committed, unless it has one already."""
    os.makedirs(path, exist_ok=True)
    ignore = os.path.join(path, ".gitignore")
    if not os.path.exists(ignore):
        with open(ignore, "w") as f:
            f.write(JOT_DIR_IGNORE)
    return path


def reset_project(jots, folder, also=()):
    """Puts a project back to how it was before JOT, an empty configuration and nothing else. Everything inside the .jot folder is removed,
    the events, the database, the control file, the logs and the remembered command, and the jots file is written as a new project has it,
    with no sensors, reports, entry points or packages. A symbolic link is removed and never followed, so nothing outside .jot is touched.
    Files the configuration points at from elsewhere are the person's own and are left alone. Returns what was removed."""
    where = jot_dir(jots, folder)
    if os.path.basename(where) != JOT_DIR:
        raise SaveError("only a .jot folder can be reset, not %s" % where, 400)
    removed = []
    if os.path.isdir(where) and not os.path.islink(where):
        for entry in sorted(os.scandir(where), key=lambda e: e.name):
            if entry.is_dir(follow_symlinks=False):
                shutil.rmtree(entry.path)
            else:
                os.unlink(entry.path)
            removed.append(entry.name)
    for path in also:
        if path and os.path.isfile(path) and not os.path.islink(path):
            os.unlink(path)
            removed.append(os.path.basename(path))
    make_jot_dir(where)
    with open(jots, "w") as f:
        f.write(FRESH_CONFIG)
    return removed


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


JOTS_FILE_KEYS = ("jots", "control", "app", "ignore", "sensors", "reports")


def config_paths(path):
    """Everywhere the configuration is, starting with the jots file itself, which can hold sensors and reports, and then the files and
    directories it lists. A name is defined by the first place that defines it, so what the jots file says is used over what a file it lists
    says, which is how the agent reads them too."""
    jots, _, _ = read_jots_file(path)
    return [os.path.abspath(path)] + jots


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


# The places the application starts running, which the agent uses when the jots file has no app: entry: list. A JOT that writes no scopes
# of its own only applies while one of them is running, so it leaves out startup and background threads. A test reads AppScope.java so
# this can't drift from it.
DEFAULT_ENTRY = ("javax.servlet.Servlet.service", "jakarta.servlet.Servlet.service")


def entry_problems(entries):
    """What is wrong with a list of entry points, as a list of {"index", "message"}, index counting from 0, or None for the list as a
    whole. An entry is a method, written package.Class.method, or an annotation, written @package.Annotation, which is every method that
    carries it. Nothing wrong is []."""
    if not isinstance(entries, list):
        return [{"index": None, "message": "must be a list"}]
    problems, seen = [], set()
    for i, value in enumerate(entries):
        if not isinstance(value, str) or not value.strip():
            problems.append({"index": i, "message": "is empty, write a method like javax.servlet.Servlet.service or an annotation like @com.acme.Handler"})
            continue
        value = value.strip()
        problem = None
        if value.startswith("!"):
            problem = "can't start with !, an entry point is something to enter and not something to leave out"
        elif method_problem(value, annotation_ok=True):
            problem = method_problem(value, annotation_ok=True)
        elif value.endswith(".<init>"):
            problem = "is a constructor, which can't be an entry point of the application"
        elif value in seen:
            problem = "is listed twice"
        if problem:
            problems.append({"index": i, "message": problem})
        seen.add(value)
    return problems


def read_entry(path):
    """The entry points the jots file lists, as {"entry", "problems"}. entry is a list, [] when the file says there is no application scope,
    and None when it doesn't say, which is the default list. A list the agent couldn't use is None, with the problems."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    app = doc.get("app") if isinstance(doc, dict) else None
    if not isinstance(app, dict) or "entry" not in app:
        return {"entry": None, "problems": []}
    entry = app["entry"]
    if not isinstance(entry, list) or not all(isinstance(e, str) for e in entry):
        return {"entry": None, "problems": [{"index": None, "message": "app: entry: must be a list of methods, so the default list is used"}]}
    return {"entry": [e.strip() for e in entry], "problems": entry_problems([e.strip() for e in entry])}


_UNCHECKED = object()


def _list_text(indent, key, values):
    quote = lambda e: '"%s"' % e if e.startswith("@") else e
    if not values:
        return "%s%s: []\n" % (indent, key)
    return "%s%s:\n%s" % (indent, key, "".join("%s  - %s\n" % (indent, quote(e)) for e in values))


_entry_text = lambda indent, entries: _list_text(indent, "entry", entries)


def _read_list(before, parent, key):
    """The list a setting has in a parsed jots file, [] when it is empty, None when the file doesn't have it or it isn't a list of text."""
    where = before.get(parent) if parent else before
    if not isinstance(where, dict) or key not in where:
        return None
    value = where[key]
    return [v.strip() for v in value] if isinstance(value, list) and all(isinstance(v, str) for v in value) else None


def _write_list_setting(path, parent, key, values, original, check, noun):
    """Writes a list setting into the jots file, key at the top of it or under parent, a list or None for not having it, which takes the key
    out. Only that key is touched, and the rest of the file stays as written, comments and the other settings included, but a comment
    inside the old list is lost with it. original is the list the editor started from. If the file no longer says that, someone else
    changed it and nothing is written. check says what is wrong with a list, as {"index", "message"}. Returns the path written."""
    if values is not None:
        if not isinstance(values, list):
            raise SaveError("not saved, the %s must be a list" % noun)
        values = [v.strip() if isinstance(v, str) else v for v in values]
        problems = check(values)
        if problems:
            raise SaveError("not saved, %s %s %s" % (noun, problems[0]["index"] + 1 if problems[0]["index"] is not None else "list", problems[0]["message"]))
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    before = yaml.safe_load(text) or {}
    if not isinstance(before, dict):
        raise SaveError("not saved, %s isn't a jots file, which is a mapping" % os.path.basename(path))
    if original is not _UNCHECKED and original != _read_list(before, parent, key):
        raise SaveError("not saved, %s has changed since this was opened. Close it and open it again" % os.path.basename(path), 409)
    root = yaml.compose(text) if text.strip() else None
    container = root if isinstance(root, yaml.MappingNode) else None
    parent_key = None
    if parent and container is not None:
        container = None
        for k, v in root.value:
            if k.value == parent:
                parent_key, container = k, v
        if parent_key is not None and not (isinstance(container, yaml.MappingNode) and not container.flow_style and container.value):
            raise SaveError("not saved, %s: in %s isn't written as a block of settings, edit it by hand" % (parent, os.path.basename(path)))
    line_start = lambda i: text.rfind("\n", 0, i) + 1
    line_end = lambda i: (len(text) if text.find("\n", i) < 0 else text.find("\n", i) + 1)
    if container is None or (root is None and not text.strip()):
        # there is nowhere for it yet, so it goes at the end
        if values is None:
            return path
        body = _list_text("  " if parent else "", key, values)
        result = (text.rstrip("\n") + "\n" if text.strip() else "") + ("%s:\n%s" % (parent, body) if parent else body)
    else:
        first = container.value[0][0]
        indent = " " * first.start_mark.column
        found = next(((k, v) for k, v in container.value if k.value == key), None)
        if found:
            start, end = line_start(found[0].start_mark.index), line_end(_last_end(found[1]))
            if values is None and parent and len(container.value) == 1:
                start = line_start(parent_key.start_mark.index)     # the only setting under it, so the empty parent goes too
            result = text[:start] + ("" if values is None else _list_text(indent, key, values)) + text[end:]
        elif values is None:
            return path
        elif parent:
            at = line_start(first.start_mark.index)
            result = text[:at] + _list_text(indent, key, values) + text[at:]
        else:
            result = text.rstrip("\n") + "\n" + _list_text("", key, values)
    expected = copy.deepcopy(before)
    holder = expected
    if parent:
        if not isinstance(expected.get(parent), dict):
            if values is None:
                holder = None
            else:
                expected[parent] = {}
        holder = expected.get(parent) if isinstance(expected.get(parent), dict) else None
    if holder is not None:
        if values is None:
            holder.pop(key, None)
            if parent and not holder:
                expected.pop(parent, None)
        else:
            holder[key] = values
    if (yaml.safe_load(result) or {}) != expected:
        raise SaveError("not saved, putting this in the file would have changed something else in it")
    mode = os.stat(path).st_mode
    tmp = path + ".saving"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(result)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return path


def write_entry(path, entries, original=_UNCHECKED):
    """Writes the entry points into the jots file, a list, or None for the default, which takes the app: entry: key out."""
    return _write_list_setting(path, "app", "entry", entries, original, entry_problems, "entry point")


_PACKAGE = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")


def package_problems(packages):
    """What is wrong with a list of the application's packages, like com.acme, as {"index", "message"}. A package is dotted names."""
    if not isinstance(packages, list):
        return [{"index": None, "message": "must be a list"}]
    problems, seen = [], set()
    for i, value in enumerate(packages):
        if not isinstance(value, str) or not _PACKAGE.match(value.strip()):
            problems.append({"index": i, "message": "isn't a package, write it like com.acme"})
        elif value.strip() in seen:
            problems.append({"index": i, "message": "is listed twice"})
        if isinstance(value, str):
            seen.add(value.strip())
    return problems


def ignore_problems(entries):
    """What is wrong with the ignore list, as {"index", "message"}. An entry is a package, a class or a class and method, in dotted names,
    and it matches itself and everything inside it."""
    if not isinstance(entries, list):
        return [{"index": None, "message": "must be a list"}]
    problems, seen = [], set()
    for i, value in enumerate(entries):
        if not isinstance(value, str) or not _PACKAGE.match(value.strip()):
            problems.append({"index": i, "message": "isn't a package, a class or a method, write it like java.lang.ClassLoader"})
        elif value.strip() in seen:
            problems.append({"index": i, "message": "is listed twice"})
        if isinstance(value, str):
            seen.add(value.strip())
    return problems


def read_settings(path):
    """The list settings of the jots file as they are written, each a list, [] for an empty one, or None when the file doesn't say, which is the
    default: {"entry", "ignore", "packages"}."""
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh) or {}
    doc = doc if isinstance(doc, dict) else {}
    return {"entry": _read_list(doc, "app", "entry"), "ignore": _read_list(doc, None, "ignore"), "packages": _read_list(doc, "app", "packages")}


def write_ignore(path, entries, original=_UNCHECKED):
    """Writes the ignore list, the platform work that sensors leave out, or None for the default list."""
    return _write_list_setting(path, None, "ignore", entries, original, ignore_problems, "ignore entry")


def write_packages(path, packages, original=_UNCHECKED):
    """Writes app: packages:, the application's own code, or None for none."""
    return _write_list_setting(path, "app", "packages", packages, original, package_problems, "package")


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
                    _unknown_functions(expression, add)
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
            else:
                _unknown_functions(node, add)
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
    return _spans(text, "sensors")


def report_spans(text):
    """Where each report is written in a .jot file, the same way sensor_spans says it for sensors."""
    return _spans(text, "reports")


def _spans(text, list_key):
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return {}
    spans = {}
    if not isinstance(root, yaml.MappingNode):
        return spans
    for key, value in root.value:
        if key.value != list_key or not isinstance(value, yaml.SequenceNode):
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


def _item_head(text, start):
    """Where the list item whose mapping starts at index start begins, as (the index of the start of its first line, the text before the
    item's own text on that line, like "  - "), or None when it isn't written as a block list item. An item is usually written
    "- name: x", and it can also be a dash alone, or a dash and a comment, with the mapping on the lines after it."""
    line_start = text.rfind("\n", 0, start) + 1
    prefix = text[line_start:start]
    if re.match(r"^\s*-\s+$", prefix):
        return line_start, prefix
    if prefix.strip():
        return None
    at = line_start
    while at > 0:
        prev_start = text.rfind("\n", 0, at - 1) + 1
        line = text[prev_start:at - 1]
        found = re.match(r"^(\s*)-[ \t]*(#.*)?$", line)
        if found:
            return prev_start, found.group(1) + "- "
        if line.strip() and not line.lstrip().startswith("#"):
            return None
        at = prev_start
    return None


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
        if not ref or not rename:
            return ref
        return re.sub(r"(?<![\w.-])%s(?![\w-])" % re.escape(rename[0]), rename[1], str(ref))

    for r in (doc or {}).get("reports") or []:
        if isinstance(r, dict):
            rest = {k: v for k, v in r.items() if k not in ("rows", "cols", "value", "by")}
            out.append((rest, swap(r.get("rows")), [swap(c.strip()) for c in str(r.get("cols") or "").split(",") if c.strip()],
                        swap(r.get("value")), swap(r.get("by"))))
    return out


_FORBIDDEN_IN_EXPRESSIONS = re.compile(r"\bT\(|\bnew\s")

# What an expression can call as #name(...). The agent registers these in Expression and ExpressionFunctions, and a test reads both
# so this list can't drift from them. A name that isn't here is nothing, and the agent only says so in its log, so a typo like #match(
# would leave the field empty without a word.
EXPRESSION_FUNCTIONS = ("kind", "list", "luhn", "matches", "matching", "sort", "toLower", "toUpper")
_FUNCTION_CALL = re.compile(r"#([A-Za-z_]\w*)\s*\(")
_QUOTED = re.compile(r"'(?:[^']|'')*'|\"(?:[^\"]|\"\")*\"")


def _unknown_functions(node, add):
    """Says so for every #name( in an expression that is not a function the agent has. What is inside quotes is text, and a variable like
    #P0 followed by a method is not a function call, so neither counts."""
    if not isinstance(node, yaml.ScalarNode):
        return
    for name in dict.fromkeys(_FUNCTION_CALL.findall(_QUOTED.sub("''", node.value))):
        if name not in EXPRESSION_FUNCTIONS:
            add(node, "#%s() is not a function an expression can call. The functions are %s" % (name, ", ".join("#" + f for f in EXPRESSION_FUNCTIONS)))


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


REPORT_KEYS = ("name", "type", "rows", "cols", "value", "by")
REPORT_TYPES = ("list", "compare", "table")


def _reference_problem(ref, sensors):
    """Why sensor.field can't be read from the loaded JOTs, or None. A bare sensor name is allowed, it is everything captured."""
    sensor, dot, field = ref.partition(".")
    if sensor not in sensors:
        near = difflib.get_close_matches(sensor, list(sensors), n=1)
        return "%s is not a JOT that is defined%s" % (sensor, ", did you mean %s" % near[0] if near else "")
    if dot and field not in sensors[sensor]:
        have = ", ".join(sensors[sensor]) or "nothing"
        return "%s doesn't capture %s, its fields are %s" % (sensor, field, have)
    return None


def check_report_text(text, sensors, taken=()):
    """What is wrong with a report as written, as a list of {"line", "message"}, line counting from 1, like check_jot_text does for a
    JOT. sensors is {name: [fields]} of the JOTs that are defined, and a report can only read those. taken are report names that
    are used already. Nothing wrong is []."""
    if len(text or "") > 16 * 1024:
        return [{"line": 1, "message": "is too large to be one report"}]
    try:
        root = yaml.compose(text or "")
    except yaml.YAMLError as e:
        mark = getattr(e, "problem_mark", None)
        return [{"line": mark.line + 1 if mark else 1, "message": (getattr(e, "problem", None) or "isn't valid YAML").strip()}]
    if root is None:
        return [{"line": 1, "message": "is empty"}]
    if not isinstance(root, yaml.MappingNode):
        return [{"line": 1, "message": "must be a report, with a name, type and cols"}]
    problems = []

    def add(node, message):
        problems.append({"line": node.start_mark.line + 1, "message": message})

    keys = {}
    for key, value in root.value:
        name = key.value if isinstance(key, yaml.ScalarNode) else None
        if name not in REPORT_KEYS:
            add(key, "reports: is a list of reports in a file, write just the one report" if name == "reports"
                else "%s isn't something a report has. These are %s" % (name, ", ".join(REPORT_KEYS)))
        else:
            keys[name] = (key, value)

    def text_of(name):
        node = keys[name][1] if name in keys else None
        if node is None:
            return None
        if not isinstance(node, yaml.ScalarNode) or not node.value.strip() or node.tag.endswith(":null"):
            add(node, "%s must be text" % name)
            return None
        return node.value.strip()

    name = text_of("name")
    if "name" not in keys:
        add(root, "needs a name")
    elif name == "example":
        add(keys["name"][1], "example is not a name that is shown, choose another")
    elif name in set(taken):
        add(keys["name"][1], "the name %s is already used by another report" % name)
    rtype = (text_of("type") or "").lower()
    if "type" not in keys:
        add(root, "needs a type, one of %s" % ", ".join(REPORT_TYPES))
    elif rtype and rtype not in REPORT_TYPES:
        add(keys["type"][1], "type must be one of %s, not %s" % (", ".join(REPORT_TYPES), rtype))
        rtype = ""
    rows, cols, value, by = (text_of(k) for k in ("rows", "cols", "value", "by"))
    refs = [c.strip() for c in (cols or "").split(",") if c.strip()]
    if "cols" not in keys:
        add(root, "needs cols, the field the columns come from, like crypto-cipher.algorithm")
    elif not refs and cols is not None:
        add(keys["cols"][1], "cols has nothing in it")
    if rtype in ("compare", "table") and "rows" not in keys:
        add(root, "a %s report needs rows, the field the rows come from, like http-route.path" % rtype)
    if rtype == "list" and "rows" in keys:
        add(keys["rows"][0], "a list report has no rows, its rows are the code that called the method")
    if rtype in ("list", "compare") and len(refs) > 1:
        add(keys["cols"][1], "a %s report reads one column, only a table has several" % rtype)
    if rtype in ("list", "table"):
        for k in ("value", "by"):
            if k in keys:
                add(keys[k][0], "only a compare report has %s" % k)
    if "by" in keys and "value" not in keys and rtype == "compare":
        add(keys["by"][0], "by names who had each value, so it needs value")
    named = []
    for r in refs:
        try:
            named += [("cols", x) for x in column_refs(r)]
        except ValueError as e:
            add(keys["cols"][1], str(e))
    for k, ref in [("rows", rows)] + named + [("value", value), ("by", by)]:
        problem = _reference_problem(ref, sensors) if ref else None
        if problem:
            add(keys[k][1], problem)
    if rtype == "compare" and refs:
        for k, ref in (("value", value), ("by", by)):
            if ref and ref.partition(".")[0] != refs[0].partition(".")[0]:
                add(keys[k][1], "%s is a field of the cols sensor, %s" % (k, refs[0].partition(".")[0]))
    if not problems and rtype:
        try:
            report_sql(rtype, rows, cols, value, by)
        except ValueError as e:
            add(root, str(e))
    return problems


def check_report_draft(text, sensors, taken=()):
    """What is wrong with a report a model wrote, as messages. The checks of the editor, as lines of text."""
    return ["line %d %s" % (p["line"], p["message"]) for p in check_report_text(text, sensors, taken)]


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
    for path in jot_files(paths):
        with open(path, encoding="utf-8") as fh:
            names.update(sensor_spans(fh.read()))
    problems = check_draft(text, names)
    if problems:
        raise SaveError("not added, " + problems[0])
    return _add_entry(paths, file, text, "sensors")


def report_names(paths):
    """The names of the reports in the loaded files."""
    names = set()
    for path in jot_files(paths):
        names.update(str(r["name"]) for r in _read_jot(path).get("reports") or [] if isinstance(r, dict) and r.get("name"))
    return names


def add_report(paths, file, text, sensors):
    """Adds a report to the reports: list of a file, in the same way a JOT is added. sensors is {name: [fields]} of the loaded JOTs,
    which the report is checked against. Returns the path written."""
    problems = check_report_draft(text, sensors, report_names(paths))
    if problems:
        raise SaveError("not added, " + problems[0])
    return _add_entry(paths, file, text, "reports")


def _add_entry(paths, file, text, key):
    """Writes one already checked entry into the list called key, sensors or reports, of a loaded file, after the last one in it, and
    leaves everything else in the file as it was. Returns the path written."""
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
        result = key + ":\n" + "- " + new_text.replace("\n", "\n  ").rstrip(" ")
        if yaml.safe_load(result) != {key: [written]}:
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
        for k, value in root.value:
            if k.value == key and isinstance(value, yaml.SequenceNode) and value.value:
                items = value.value
    if items:
        last = items[-1]
        head = _item_head(text_before, last.start_mark.index)
        prefix = head[1] if head else ""
        if not head:
            raise SaveError("not added, the %s in %s aren't written as a block list, add it by hand" % (key, file))
        pad = " " * len(prefix)
        lines = new_text.rstrip("\n").split("\n")
        block = prefix + lines[0] + "".join("\n" + (pad + l if l.strip() else l) for l in lines[1:]) + "\n"
        end = _last_end(last)
        eol = text_before.find("\n", end)
        at = len(text_before) if eol < 0 else eol + 1
        lead = "" if eol >= 0 else "\n"
        result = text_before[:at] + lead + "\n" + block + text_before[at:]
    elif isinstance(root, yaml.MappingNode) and key in before:
        # an empty list, written as [] or with nothing after the key, which is what a new configuration has. It is filled in place.
        value = next((v for k, v in root.value if k.value == key), None)
        empty = (isinstance(value, yaml.SequenceNode) and not value.value) or (isinstance(value, yaml.ScalarNode) and value.tag.endswith(":null"))
        if not empty:
            raise SaveError("not added, the %s list in %s is written in a way that can't be added to here, add it by hand" % (key, file))
        body = "- " + new_text.rstrip("\n").replace("\n", "\n  ")
        result = text_before[:value.start_mark.index].rstrip(" \t") + "\n" + body + text_before[value.end_mark.index:]
    else:
        base = text_before if not text_before.strip() else text_before.rstrip("\n") + "\n\n"
        result = base + key + ":\n- " + new_text.replace("\n", "\n  ").rstrip(" ")
    after = yaml.safe_load(result) or {}
    if after.get(key) != (before.get(key) or []) + [written] or \
            {k: v for k, v in after.items() if k != key} != {k: v for k, v in before.items() if k != key}:
        raise SaveError("not added, putting this in %s would have changed something else in it" % file)
    mode = os.stat(path).st_mode
    tmp = path + ".saving"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(result)
    os.chmod(tmp, mode)
    os.replace(tmp, path)
    return path


def _list_items(text, key):
    """The items of the list called key at the top of a file as [(name, text)], the text being the item with the comments before it and
    moved to the left edge, so it can be put in another list. The first item takes what is between the key and itself, and what
    comes after the last item belongs to nothing and is left. Returns [] for a file with no such list or one that isn't YAML."""
    try:
        root = yaml.compose(text)
    except yaml.YAMLError:
        return []
    if not isinstance(root, yaml.MappingNode):
        return []
    for k, value in root.value:
        if k.value != key or not isinstance(value, yaml.SequenceNode) or not value.value:
            continue
        out, at = [], text.find("\n", k.end_mark.index) + 1
        for item in value.value:
            end = text.find("\n", _last_end(item))
            end = len(text) if end < 0 else end + 1
            column = item.start_mark.column
            dash = text[text.rfind("\n", 0, item.start_mark.index) + 1:item.start_mark.index]
            indent = len(dash) - len(dash.lstrip(" "))
            lines = text[at:end].split("\n")
            lines = [l[indent:] if l[:indent].strip() == "" else l for l in lines]
            name = next((v.value for kk, v in item.value if kk.value == "name" and isinstance(v, yaml.ScalarNode)), None) if isinstance(item, yaml.MappingNode) else None
            body = "\n".join(lines).rstrip("\n") + "\n"
            out.append((name, body))
            at = end
        return out
    return []


def _leading_comments(text):
    """The comment lines at the top of a file, before anything else, which say what the file is for."""
    out = []
    for line in text.split("\n"):
        if line.startswith("#"):
            out.append(line)
        elif (line.strip() == "" or line.strip() == "---") and not out:
            continue
        else:
            break
    return out


def _indented(block, indent):
    pad = " " * indent
    return "".join((pad + l if l.strip() else l) + "\n" for l in block.rstrip("\n").split("\n"))


def _append_list_items(text, key, block):
    """The text with block, a list as items at the left edge, added to the end of the list called key, which is made at the end of the
    file when there is none. The items are indented to line up with the list that is there."""
    root = yaml.compose(text) if text.strip() else None
    if isinstance(root, yaml.MappingNode):
        for k, value in root.value:
            if k.value == key:
                if not isinstance(value, yaml.SequenceNode) or value.flow_style or not value.value:
                    raise SaveError("not combined, %s: in the jots file isn't a list written one item to a line, combine it by hand" % key)
                last = value.value[-1]
                dash = text[text.rfind("\n", 0, last.start_mark.index) + 1:last.start_mark.index]
                end = text.find("\n", _last_end(last))
                at = len(text) if end < 0 else end + 1
                lead = "" if end >= 0 else "\n"
                return text[:at] + lead + "\n" + _indented(block, len(dash) - len(dash.lstrip(" "))) + text[at:]
    return (text.rstrip("\n") + "\n\n" if text.strip() else "") + key + ":\n" + block


def consolidate(path, out=None, keep=(), write=True):
    """Moves everything the jots file lists into the jots file itself, so the configuration is one file. The sensors, the rules and the
    reports of each listed file are added to the lists of the jots file, with the comments that were in the files, and the jots: list is taken
    out, or left with the entries named in keep, which are libraries that stay where they are. A name is defined by the first place that
    defines it, as the agent reads them, so a sensor or report a file defines that an earlier one already did is left out and said so.
    Nothing is written until the result has been read back and every sensor and report in it is exactly what was in its file. The files
    that were listed are not touched, and the jots file is copied to a .bak beside it when it is rewritten in place. With write false nothing
    is written, and the result is in the text of what is returned. Returns what was done."""
    path = os.path.abspath(path)
    out = os.path.abspath(out) if out else path
    base = os.path.dirname(path)
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    before = yaml.safe_load(text) or {}
    if not isinstance(before, dict):
        raise SaveError("not combined, %s isn't a jots file, which is a mapping" % os.path.basename(path))
    listed, _, _ = read_jots_file(path)
    kept_paths = {os.path.normpath(os.path.join(base, k)) for k in keep}
    merged_from = [p for p in listed if os.path.normpath(p) not in kept_paths]
    seen = {"sensors": set(sensor_spans(text)), "reports": {r.get("name") for r in before.get("reports") or [] if isinstance(r, dict)}}
    result, skipped, files, missing = text, [], [], []
    for entry in merged_from:
        if not os.path.exists(entry):
            missing.append(entry)
            continue
        for f in jot_files([entry]):
            with open(f, encoding="utf-8") as fh:
                source = fh.read()
            label = os.path.relpath(f, base)
            blocks = {}
            for key in ("sensors", "reports"):
                taken = []
                for name, body in _list_items(source, key):
                    if name in seen[key]:
                        skipped.append({"kind": key[:-1], "name": name, "file": label})
                        continue
                    seen[key].add(name)
                    taken.append(body)
                if taken:
                    blocks[key] = taken
            if not blocks:
                continue
            files.append(label)
            header = ["# ---- from %s ----" % label] + _leading_comments(source)
            for key, taken in blocks.items():
                comment = "\n".join(header) + "\n"
                result = _append_list_items(result, key, comment + "".join(taken))
    # the jots: list goes, or is left with what is kept
    root = yaml.compose(result)
    for k, value in root.value:
        if k.value == "jots":
            line_start = result.rfind("\n", 0, k.start_mark.index) + 1
            end = result.find("\n", _last_end(value))
            end = len(result) if end < 0 else end + 1
            kept = [e for e in keep]
            replacement = "jots:\n" + "".join("  - %s\n" % e for e in kept) if kept else ""
            result = result[:line_start] + replacement + result[end:]
            break
    # what is written is read back, and each sensor and report must be what its file had
    after = yaml.safe_load(result) or {}
    original = {"sensors": {}, "reports": {}}
    for key in original:
        for item in before.get(key) or []:
            if isinstance(item, dict) and item.get("name") not in original[key]:
                original[key][item.get("name")] = item
    for entry in merged_from:
        for f in jot_files([entry]) if os.path.exists(entry) else []:
            doc = _read_jot(f)
            for key in original:
                for item in doc.get(key) or []:
                    if isinstance(item, dict) and item.get("name") not in original[key]:
                        original[key][item.get("name")] = item
    for key in original:
        found = {item.get("name"): item for item in after.get(key) or [] if isinstance(item, dict)}
        if found != original[key]:
            raise SaveError("not combined, the %s in the result are not what was in the files, so nothing was written" % key)
    expected = {k: v for k, v in before.items() if k not in ("jots", "sensors", "reports")}
    if {k: v for k, v in after.items() if k not in ("jots", "sensors", "reports")} != expected or (after.get("jots") or []) != list(keep):
        raise SaveError("not combined, the rest of the jots file would have changed, so nothing was written")
    if not write:
        return {"out": out, "backup": None, "sensors": len(after.get("sensors") or []), "reports": len(after.get("reports") or []), "from": files,
                "skipped": skipped, "missing": missing, "kept": list(keep), "text": result}
    backup = None
    if out == path and result != text:
        backup = path + ".bak"
        shutil.copy2(path, backup)
    tmp = out + ".saving"
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(result)
    if os.path.exists(out):
        os.chmod(tmp, os.stat(out).st_mode)
    os.replace(tmp, out)
    return {"out": out, "backup": backup, "sensors": len(after.get("sensors") or []), "reports": len(after.get("reports") or []),
            "from": files, "skipped": skipped, "missing": missing, "kept": list(keep)}


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
        if not _item_head(text, span["start"]):
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


def save_report(paths, name, original, new_text, sensors, taken=()):
    """Writes the new text of one report into the .jot file that has it, leaving the rest of the file as it was, the way save_sensor
    does for a sensor. original is what the editor started from, and if the file no longer says that nothing is written. sensors is
    {name: [fields]} of the loaded JOTs and taken the names of the other reports, since a report can be renamed to a name that is free.
    Returns the path written."""
    new_text = (new_text or "").rstrip() + "\n"
    problems = check_report_text(new_text, sensors, [t for t in taken if t != name])
    if problems:
        raise SaveError("not saved, line %d %s" % (problems[0]["line"], problems[0]["message"]))
    written = yaml.safe_load(new_text)
    for path in jot_files(paths):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        span = report_spans(text).get(name)
        if not span:
            continue
        if (original or "").rstrip() != span["text"]:
            raise SaveError("not saved, %s has changed since this was opened. Close it and open it again" % os.path.basename(path), 409)
        if not _item_head(text, span["start"]):
            raise SaveError("not saved, this report isn't written as a block in the list, edit the file by hand")
        pad = " " * span["column"]
        lines = new_text.rstrip().split("\n")
        body = "\n".join([lines[0]] + [pad + l if l.strip() else l for l in lines[1:]])
        result = text[:span["start"]] + body + text[span["end"]:]
        before, after = yaml.safe_load(text) or {}, yaml.safe_load(result) or {}
        expected = [written if x.get("name") == name else x for x in before.get("reports") or []]
        if after.get("reports") != expected or {k: v for k, v in after.items() if k != "reports"} != {k: v for k, v in before.items() if k != "reports"}:
            raise SaveError("not saved, putting this in the file would have changed something else in it")
        mode = os.stat(path).st_mode
        tmp = path + ".saving"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(result)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        return path
    raise SaveError("not saved, no loaded file has a report called %s" % name, 404)


def delete_entry(paths, key, name, original):
    """Removes one sensor or report, key being sensors or reports, from the .jot file that has it, and leaves everything else in the file
    as it was, comments included. original is what the editor started from, and if the file no longer says that nothing is removed.
    A list left with nothing in it is written as []. Returns the path written."""
    spans = sensor_spans if key == "sensors" else report_spans
    for path in jot_files(paths):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        span = spans(text).get(name)
        if not span:
            continue
        if (original or "").rstrip() != span["text"]:
            raise SaveError("not deleted, %s has changed since this was opened. Close it and open it again" % os.path.basename(path), 409)
        head = _item_head(text, span["start"])
        if not head:
            raise SaveError("not deleted, this isn't written as a block in the list, edit the file by hand")
        line_start = head[0]
        end = text.find("\n", span["end"])
        end = len(text) if end < 0 else end + 1
        result = text[:line_start] + text[end:]
        before, after = yaml.safe_load(text) or {}, yaml.safe_load(result) or {}
        if not after.get(key):
            result = re.sub(r"^%s:[ \t]*(#.*)?$" % key, key + ": []", result, count=1, flags=re.M)
            after = yaml.safe_load(result) or {}
        expected = [x for x in before.get(key) or [] if not (isinstance(x, dict) and x.get("name") == name)]
        if (after.get(key) or []) != expected or {k: v for k, v in after.items() if k != key} != {k: v for k, v in before.items() if k != key}:
            raise SaveError("not deleted, taking this out of the file would have changed something else in it")
        mode = os.stat(path).st_mode
        tmp = path + ".saving"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(result)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
        return path
    raise SaveError("not deleted, no loaded file has a %s called %s" % (key[:-1], name), 404)


def reports_using(paths, sensor):
    """The names of the reports, in any loaded file, that read the sensor."""
    names = []
    for path in jot_files(paths):
        with open(path, encoding="utf-8") as fh:
            names += rename_in_reports(fh.read(), sensor, sensor)[1]
    return names


def report_definitions(paths):
    """{(file name, report name): the report as written in the file}, for the editor."""
    out = {}
    for path in jot_files(paths):
        try:
            with open(path, encoding="utf-8") as fh:
                spans = report_spans(fh.read())
        except OSError:
            continue
        for name, span in spans.items():
            out[(os.path.basename(path), name)] = span["text"]
    return out


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
            columns = []
            for c in str(r.get("cols") or "").split(","):
                try:
                    columns += column_refs(c.strip()) if c.strip() else []
                except ValueError as e:
                    _issue(db, "warning", "report %s has a column that isn't understood, %s" % (r["name"], e), source)
            used = ([r["rows"]] if r.get("rows") else []) + columns \
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


# A column of a table report can be an expression, written in Spring EL's style. #total(ai-model-call.input_tokens) adds up what the events of
# that sensor captured, once for each event, and #count, #average, #min and #max do what they say. They can be added, subtracted,
# multiplied and divided, so #total(a.x) / #count(a.x) is an average. The dashboard evaluates these itself, so only this much of Spring EL is understood.
REPORT_FUNCTIONS = {"total": "SUM(CAST(v AS REAL))", "count": "COUNT(DISTINCT pk)", "average": "AVG(CAST(v AS REAL))",
                    "min": "MIN(CAST(v AS REAL))", "max": "MAX(CAST(v AS REAL))"}
_REPORT_REF = re.compile(r"[a-z][a-z0-9-]*(?:\.[a-z][a-z0-9_]*)?$")


def is_expression(col):
    return str(col).lstrip().startswith("#")


def parse_report_expression(text):
    """An expression of a report column as (the tree, the calls in it as [(function, sensor.field)]). The tree is a number as
    ("num", text), a call as ("call", index), and ("bin", operator, left, right) or ("neg", tree). A ValueError says what is wrong."""
    tokens, i, calls = [], 0, []
    text = str(text)
    while i < len(text):
        if text[i].isspace():
            i += 1
            continue
        m = re.compile(r"\d+(?:\.\d+)?").match(text, i)
        if m:
            tokens.append(("num", m.group(0)))
        elif text[i] == "#":
            m = re.compile(r"#([A-Za-z]\w*)\s*\(\s*([^()]*?)\s*\)").match(text, i)
            if not m:
                raise ValueError("%s isn't a call, write it like #total(ai-model-call.input_tokens)" % text[i:i + 20].strip())
            name, ref = m.group(1), m.group(2)
            if name not in REPORT_FUNCTIONS:
                raise ValueError("#%s isn't something a report can call, these are %s" % (name, ", ".join("#" + f for f in REPORT_FUNCTIONS)))
            if not _REPORT_REF.match(ref):
                raise ValueError("#%s reads one sensor.field, like ai-model-call.input_tokens, not %s" % (name, ref or "nothing"))
            if "." not in ref and name != "count":
                raise ValueError("#%s needs a field, like %s.field" % (name, ref))
            calls.append((name, ref))
            tokens.append(("call", len(calls) - 1))
        elif text[i] in "+-*/()":
            m = re.compile(r".").match(text, i)
            tokens.append(("op", text[i]))
        else:
            raise ValueError("%s isn't understood in an expression" % text[i:i + 12].strip())
        i = m.end()
    pos = [0]

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else (None, None)

    def take():
        pos[0] += 1
        return tokens[pos[0] - 1]

    def factor():
        kind, value = peek()
        if kind == "num":
            take()
            return ("num", value)
        if kind == "call":
            take()
            return ("call", value)
        if (kind, value) == ("op", "-"):
            take()
            return ("neg", factor())
        if (kind, value) == ("op", "("):
            take()
            inner = expr()
            if peek() != ("op", ")"):
                raise ValueError("a ( has no closing )")
            take()
            return inner
        raise ValueError("an expression needs a number or a call like #total(a.x)" + (", not %s" % value if value else " at its end"))

    def term():
        left = factor()
        while peek() in (("op", "*"), ("op", "/")):
            left = ("bin", take()[1], left, factor())
        return left

    def expr():
        left = term()
        while peek() in (("op", "+"), ("op", "-")):
            left = ("bin", take()[1], left, term())
        return left

    if not tokens:
        raise ValueError("the expression is empty")
    tree = expr()
    if pos[0] < len(tokens):
        raise ValueError("%s doesn't belong after the expression" % tokens[pos[0]][1])
    if not calls:
        raise ValueError("an expression has to read something, like #total(ai-model-call.input_tokens)")
    return tree, calls


def column_refs(col):
    """The sensor.field a column reads. That is the column itself, or the fields of the calls in an expression."""
    return [ref for _, ref in parse_report_expression(col)[1]] if is_expression(col) else [col]


def _expression_sql(tree):
    kind = tree[0]
    if kind == "num":
        return tree[1]
    if kind == "call":
        return "f%d.x" % tree[1]
    if kind == "neg":
        return "(-%s)" % _expression_sql(tree[1])
    op, left, right = tree[1], _expression_sql(tree[2]), _expression_sql(tree[3])
    return "(%s * 1.0 / NULLIF(%s, 0))" % (left, right) if op == "/" else "(%s %s %s)" % (left, op, right)


def _relate(rows, sensor):
    """How a column's event is tied to the row's event, the same request, and for a column of the row's own sensor the very same event.
    Two events of a sensor in one request are two rows, and one must not read the other's values."""
    row_sensor = rows.partition(".")[0]
    return "r.run = c.run AND r.trace = c.trace AND r.sensor = %s%s" % (_lit(row_sensor), " AND r.pk = c.pk" if sensor == row_sensor else "")


def _expression_part(text, rows, row_join, row_expr):
    """The query for one expression column, as rows of (row, column, value). Each call is added up over the events of its sensor in the
    requests of each row, counting every event once, then the arithmetic is done on those."""
    tree, calls = parse_report_expression(text)
    sources = []
    for i, (fn, ref) in enumerate(calls):
        sensor, _, field = ref.partition(".")
        if field:
            join, expr = _values("c", ref, 2)
            have = "%s IS NOT NULL AND %s <> ''" % (expr, expr)
        else:
            join, expr, have = "", "1", "1"
        inner = ("SELECT DISTINCT %s AS rowv, c.pk AS pk, %s AS v FROM events_shown r%s, events_shown c%s WHERE %s AND c.sensor = %s AND %s"
                 % (row_expr, expr, row_join, join, _relate(rows, sensor), _lit(sensor), have))
        sources.append("(SELECT rowv, %s AS x FROM (%s) GROUP BY rowv) f%d" % (REPORT_FUNCTIONS[fn], inner, i))
    value = _expression_sql(tree)
    joined = sources[0] + "".join(" LEFT JOIN %s ON f0.rowv = f%d.rowv" % (src, i) for i, src in enumerate(sources[1:], 1))
    return ("SELECT f0.rowv AS %s, %s AS col, CASE WHEN %s = CAST(%s AS INTEGER) THEN CAST(%s AS INTEGER) ELSE ROUND(%s, 2) END AS value\n"
            "FROM %s WHERE f0.rowv IS NOT NULL" % (_ident(rows), _lit(text), value, value, value, value, joined))


def report_sql(rtype, rows, cols, value=None, by=None):
    """The query for a report, as rows of (row, column, value) which the dashboard turns into a grid. What it reads is
    written sensor.field. A row and a column are related when they were observed in the same request, which is the same
    run and trace. A table column can also be an expression like #total(ai-model-call.input_tokens)."""
    refs = [c.strip() for c in (cols or "").split(",") if c.strip()]
    if not refs:
        raise ValueError("a report needs cols")
    if rtype != "table" and any(is_expression(c) for c in refs):
        raise ValueError("only a table report can have an expression in cols")
    if rtype == "list":
        join, expr = _values("e", refs[0], 0)
        return ("SELECT DISTINCT e.call_site AS call_site, %s AS sensor, %s AS value\n"
                "FROM events_shown e%s WHERE e.sensor = %s AND e.call_site IS NOT NULL AND %s <> ''\n"
                "ORDER BY call_site" % (_lit(refs[0]), expr, join, _lit(refs[0].partition(".")[0]), expr))
    if not rows:
        raise ValueError("a %s report needs rows" % rtype)
    row_join, row_expr = _values("r", rows, 1)
    start = "FROM events_shown r%s, events_shown c" % row_join
    if rtype == "compare":
        relate = _relate(rows, refs[0].partition(".")[0])
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
        for ref in refs:
            if is_expression(ref):
                parts.append(_expression_part(ref, rows, row_join, row_expr))
                continue
            col_join, col_expr = _values("c", ref, 2)
            parts.append("SELECT DISTINCT %s AS %s, %s AS col, %s AS value\n%s%s WHERE %s AND c.sensor = %s"
                         % (row_expr, _ident(rows), _lit(ref), col_expr, start, col_join, _relate(rows, ref.partition(".")[0]), _lit(ref.partition(".")[0])))
        return "\nUNION\n".join(parts) + "\nORDER BY 1, 2"
    raise ValueError("unknown report type %s" % rtype)


_CELL_COLUMNS = ("c.pk AS pk, strftime('%Y-%m-%d %H:%M:%S', c.ts/1000, 'unixepoch', 'localtime') AS time, c.action AS action, "
                 "c.sensor AS sensor, c.call_site_name AS call_site, c.capture AS capture")


def sensor_report_sql(name, fields, rule=False):
    """The report every sensor has without anyone writing one, as the (row, col, value) the grid pivots. One row for each entry point
    and one column for each field the sensor captures, holding the values it captured under that entry point. The entry point is the
    route when a request has one and else the entry point the event ran under, like the graph. A sensor with no fields has one
    column, how many times it fired. A rule is read through the events it names, -active, -blocked and -monitored."""
    names = [name] + ([name + s for s in ("-active", "-blocked", "-monitored")] if rule else [])
    which = "e.sensor IN (%s)" % ", ".join(_lit(n) for n in names)
    route = ("COALESCE((SELECT %s FROM events_raw r WHERE r.run = e.run AND r.trace = e.trace AND r.sensor IN %s ORDER BY r.pk LIMIT 1), e.entry, %s)"
             % (route_of("r"), ROUTE_SENSORS_SQL, _lit(NO_ENTRY)))
    if not fields:
        return ("SELECT %s AS entry, 'events' AS \"column\", CAST(COUNT(*) AS TEXT) AS value\nFROM events_shown e\nWHERE %s\nGROUP BY 1"
                % (route, which))
    parts = []
    for n, field in enumerate(fields):
        join, value = _values("e", name + "." + field, n)
        parts.append("SELECT %s AS entry, %s AS \"column\", %s AS value\nFROM events_shown e%s\nWHERE %s AND %s IS NOT NULL AND %s <> ''"
                     % (route, _lit(field), value, join, which, value, value))
    return "SELECT DISTINCT entry, \"column\", value FROM (\n" + "\nUNION ALL\n".join(parts) + "\n)\nORDER BY 1, 2, 3"


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
        picked = [r for c in ([col] if col in refs else refs) for r in column_refs(c)]
    elif rtype == "compare":
        picked = refs[:1]
    else:
        raise ValueError("unknown report type %s" % rtype)
    parts = []
    for ref in picked:
        col_join, col_expr = _values("c", ref, 2)
        where = [_relate(rows, ref.partition(".")[0]), "c.sensor = %s" % _lit(ref.partition(".")[0])]
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
                 "host": "equals", "trace": "number", "pid": "number", "route": "route", "entry": "route"}
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
            # the request an event happened in came in at this route, as the http-route sensor saw it, or ran under this entry point
            seen = "SELECT run, trace FROM events_raw WHERE sensor IN %s" % ROUTE_SENSORS_SQL
            cond = ("((run, trace) NOT IN (%s) AND entry IS NULL)" % seen if text == NO_REQUEST
                    else "((run, trace) IN (%s AND %s = %s) OR entry = %s)" % (seen, route_of(), _lit(text), _lit(text)))
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
NO_ENTRY = "(outside every entry)"
# the sensor that says which route a request came in at, and the sensors whose capture is another route
ROUTE_SENSORS = ("http-route",)
ROUTE_SENSORS_SQL = "(%s)" % ", ".join("'%s'" % x for x in ROUTE_SENSORS)
JUMPS = ("http-forward", "http-redirect")


def route_of(alias=""):
    """SQL for the route an http-route event says. The sensor captures the path and the method, so its capture text reads
    path=/buy, method=GET and the route is the path field."""
    return "json_extract(%sdata, '$.path')" % (alias + "." if alias else "")


def method_of(alias=""):
    """SQL for the HTTP method an http-route event says, NULL for a route sensor that doesn't capture it."""
    return "json_extract(%sdata, '$.method')" % (alias + "." if alias else "")


def _short(name):
    """com.acme.ticketbook.Ticket.encrypt becomes Ticket.encrypt."""
    return ".".join(name.split(".")[-2:])


def _page_of(route):
    """/ticketbook/ssrf.jsp is compiled to ssrf_jsp."""
    last = (route or "").rsplit("/", 1)[-1]
    return last.replace(".", "_") if last else None


def graph_rows(db_path, route=None, method=None):
    """The events of the graph in the order they happened, request by request. The route is the first request the
    event happened in, as the http-route sensor saw it, and the method is the HTTP method that same event captured, None for a
    request that didn't say. Events of one request are together and in the agent's own order, which is the order the application
    caused them. Each row ends with the method. A method limits the rows to the requests that used it, and the route NO_REQUEST is
    the events that happened outside any request.

    There is a limit on how many events are used, since each carries its stack. It is shared out by route, so a busy route can't use up
    what the others need, and a route over its share is drawn from its newest requests. Nothing a route's sensors saw is lost to that.
    The newest request that each sensor was seen in, in each route, is always used in full, so every sensor of a route is in its
    graph. The result says whether any route was cut short."""
    # what the first route event of a request says, looked up by the request's trace, which is an index
    first = lambda what: ("(SELECT %s FROM events_raw r WHERE r.run = e.run AND r.trace = e.trace AND r.sensor IN %s ORDER BY r.pk LIMIT 1)"
                          % (what, ROUTE_SENSORS_SQL))
    where = []
    if route == NO_REQUEST:
        where.append("route IS NULL")
    elif route:
        where.append("route = %s" % _lit(route))
    if method:
        where.append("upper(COALESCE(method, '')) = %s" % _lit(method.upper()))
    if route and route != NO_REQUEST:
        share = GRAPH_ROW_LIMIT
    else:
        routes = run_query(db_path, "SELECT COUNT(DISTINCT %s) FROM events_raw WHERE sensor IN %s" % (route_of(), ROUTE_SENSORS_SQL))["rows"][0][0]
        share = max(GRAPH_MIN_ROUTE_ROWS, GRAPH_ROW_LIMIT // max(1, routes + 1))
    sql = """WITH ev AS (
           SELECT COALESCE(%s, e.entry) AS route, %s AS method, %s AS started, e.run AS run, e.trace AS trace, e.id AS id, e.sensor AS sensor,
                  e.action AS action, e.capture AS capture, e.stack AS stack
           FROM events e WHERE e.sensor NOT IN %s AND e.stack IS NOT NULL),
         chosen AS (SELECT * FROM ev %s)
         SELECT route, run, trace, sensor, action, capture, stack, method, total FROM (
           SELECT *, ROW_NUMBER() OVER (PARTITION BY route ORDER BY started DESC, run, trace, id) AS n,
                  COUNT(*) OVER (PARTITION BY route) AS total
           FROM chosen)
         WHERE n <= %d OR (run, trace) IN (
           SELECT run, trace FROM (SELECT run, trace, ROW_NUMBER() OVER (PARTITION BY route, sensor ORDER BY started DESC) AS newest FROM chosen)
           WHERE newest = 1)
         ORDER BY run, trace, id""" % (first(route_of("r")), first(method_of("r")), first("r.ts"), ROUTE_SENSORS_SQL,
                                       "WHERE " + " AND ".join(where) if where else "", share)
    found = run_query(db_path, sql, limit=GRAPH_ROW_LIMIT + GRAPH_COVERAGE_ROWS, timeout=GRAPH_TIMEOUT)
    cut = found["truncated"] or any(r[8] > share for r in found["rows"])
    return {"columns": found["columns"][:8], "rows": [r[:8] for r in found["rows"]], "truncated": cut, "ms": found["ms"]}


def graph_methods(db_path):
    """The HTTP methods the requests in the graph used, from what the http-route sensor captured, in the order they are colored
    GET, POST and then the others alphabetically. Empty when the sensor doesn't capture it."""
    rows = run_query(db_path, "SELECT DISTINCT upper(%s) FROM events_raw WHERE sensor IN %s AND ts >= %d AND %s IS NOT NULL" % (
        method_of(), ROUTE_SENSORS_SQL, get_since(db_path) or 0, method_of()), limit=50)["rows"]
    return sorted((r[0] for r in rows if r[0]), key=lambda m: (METHOD_ORDER.index(m) if m in METHOD_ORDER else len(METHOD_ORDER), m))


METHOD_ORDER = ("GET", "POST", "PUT", "DELETE", "PATCH")


GRAPH_ROW_LIMIT = 50000
# the least a route is given when there are many routes, and what is allowed on top of the limit for the newest request of each sensor
GRAPH_MIN_ROUTE_ROWS = 500
GRAPH_COVERAGE_ROWS = 20000
GRAPH_TIMEOUT = 30.0


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


def build_graph(rows, routes_seen, app_prefixes=(), details=False, truncated=False, methods_seen=(), entries=False):
    """Nodes and edges for the paths through the application. A request is one line. It starts at the route and goes down through the
    application methods that were running when each event happened, so the edges are who called whom. A box is a method, and the events
    that happened directly in it, the sensors it triggered, are its inner boxes in the order they were first seen. What a method calls
    is drawn after it, and what happens in a callee is that callee's own. Events that happened outside any application method are the
    route's own. A forward or a redirect also leads on to the route it names, which is an exit. Plumbing that only describes the
    request, like who the user is, is left out unless details is set. Every node, inner box and edge says which lines use it, so what
    goes through one can be told from what can merely be reached from it. Requests that used different HTTP methods are different lines
    even when they did the same things, and line_methods says which method each line used, so something can be told to belong to one
    method or to be common to several.

    A line starts at its entry point. For a request that is the route the http-route sensor saw. Otherwise it is the entry point method
    itself, like the tool of an agent, and the frames above that method are left out, since in a large application they are the same
    long chain for every line. When entries is set, what happened outside every entry point is drawn from the method that called it
    only, for the same reason."""
    nodes, edges = {}, {}
    line = [0]                 # the line being walked, a request that did the same things in the same order as others

    def node(kind, key, label, full=None):
        n = nodes.setdefault((kind, key), {"id": "%s:%s" % (kind, key), "kind": kind, "label": label, "full": full or key,
                                           "events": 0, "blocked": 0, "monitored": 0, "captures": [], "inner": {}, "lines": set()})
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
        # the route of a request is its path, and otherwise it is the method of the entry point, which has no slash
        by_entry = route != NO_REQUEST and "/" not in route
        start = node("route", route, _short(route) if by_entry else route, route)
        # the page the route names is compiled to a class, and every method of it, like the tag helpers Jasper
        # generates, is that page. The route already stands for it, so it isn't drawn again
        page = _page_of(route)
        start["events"] += count     # a route counts the requests that came in at it, the others count events
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
                if by_entry and route in names:
                    names = names[names.index(route) + 1:]
                elif entries and route == NO_REQUEST:
                    names = names[-1:]
            # down the call chain from the route, each method one level in, and the sensor is in the last of them
            site = start
            for name in names:
                callee = node("code", name, _short(name), name)
                callee["events"] += count
                link(site, callee, count)
                site = callee
            seen = site["inner"].setdefault(sensor, {"sensor": sensor, "events": 0, "blocked": 0, "monitored": 0, "captures": {}, "lines": set()})
            seen["lines"].add(line[0])
            seen["events"] += count
            if action in ("blocked", "monitored"):
                seen[action] += count
                site[action] += count
            seen["captures"][capture or ""] = seen["captures"].get(capture or "", 0) + count
            if sensor in JUMPS and capture:
                target = capture.strip()
                match = next((r for r in route_names if r == target or r.endswith("/" + target.lstrip("/"))), None)
                exit_node = node("exit", match or target.lstrip("/"), match or target.lstrip("/"))
                exit_node["events"] += count
                link(site, exit_node, count)

    # requests that did the same things in the same order are drawn once, and counted
    same = {}
    for group in _requests(rows):
        method = (group[0][7] or "").upper() or None if len(group[0]) > 7 else None
        key = (group[0][0], method, tuple((r[3], r[4], r[5], r[6]) for r in group))
        same[key] = same.get(key, 0) + 1
    line_counts, line_methods = {}, {}
    for number, ((route, method, events), count) in enumerate(same.items()):
        line[0] = number
        line_counts[number] = count
        line_methods[number] = method
        walk(route, events, count)

    out_nodes = sorted(nodes.values(), key=lambda n: (-n["events"], n["label"]))
    for n in out_nodes:
        n["inner"] = [dict(i, captures=sorted(i["captures"].items(), key=lambda kv: -kv[1])[:25], lines=sorted(i["lines"])) for i in n["inner"].values()]
        n["lines"] = sorted(n["lines"])
    for e in edges.values():
        e["lines"] = sorted(e["lines"])
    return {"nodes": out_nodes, "edges": sorted(edges.values(), key=lambda e: -e["events"]),
            "routes": route_names, "methods": list(methods_seen), "truncated": truncated,
            "line_counts": line_counts, "line_methods": line_methods}


def empty_graph(route, requests):
    """The graph of an entry that no sensor fired in, which is its box and how many requests came in at it."""
    by_entry = route != NO_REQUEST and "/" not in route
    node = {"id": "route:" + route, "kind": "route", "label": _short(route) if by_entry else route, "full": route, "events": requests, "blocked": 0,
            "monitored": 0, "captures": [], "inner": [], "lines": [0]}
    return {"route": route, "requests": requests, "events": 0, "nodes": [node], "edges": [], "line_counts": {0: requests}, "line_methods": {}, "all_requests": requests}


def build_graphs(rows, routes_seen, app_prefixes=(), details=False, truncated=False, methods_seen=(), all_requests=None, entries=False):
    """One graph for each route, in alphabetical order, so each can be read and laid out on its own. A route is
    where a request came in, and its graph holds only what requests that came in there did. all_requests is how many requests there
    were at each route, which is more than its graph has when the route was too busy to draw every one of them."""
    by_route = {}
    for row in rows:
        by_route.setdefault(row[0] or NO_REQUEST, []).append(row)
    graphs = []
    for route, route_rows in by_route.items():
        g = build_graph(route_rows, routes_seen, app_prefixes, details, truncated, methods_seen, entries)
        if not g["edges"] and not any(n["inner"] for n in g["nodes"]):
            continue   # nothing happened in it that the graph shows, like a stylesheet. A sensor that fired in the route itself is something
        graphs.append({"route": route, "requests": sum(1 for _ in _requests(route_rows)),
                       "events": len(route_rows), "nodes": g["nodes"], "edges": g["edges"], "line_counts": g["line_counts"],
                       "line_methods": g["line_methods"]})
        graphs[-1]["all_requests"] = max(graphs[-1]["requests"], (all_requests or {}).get(route, 0))
    graphs.sort(key=lambda g: (g["route"] == NO_REQUEST, g["route"].lower()))
    return {"graphs": graphs, "routes": sorted(routes_seen), "methods": list(methods_seen), "truncated": truncated}


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


def get_hidden_jots(db_path):
    """The names of the JOTs whose events are left out, as a list."""
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT value FROM settings WHERE key = 'hidden_jots'").fetchone()
        return json.loads(row[0]) if row else []
    finally:
        db.close()


def set_hidden_jots(db, names):
    """Leave out every event of these JOTs, by name, or show everything again with an empty list."""
    names = sorted({str(n) for n in names})
    if len(names) > 1000 or any(len(n) > 200 for n in names):
        raise ValueError("too many or too long")
    if names:
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('hidden_jots', ?)", (json.dumps(names),))
    else:
        db.execute("DELETE FROM settings WHERE key = 'hidden_jots'")
    db.commit()


ACTIONS = ("observed", "monitored", "blocked")
ORIGINS = ("app", "library", "platform", "none")
FILTER_SETTINGS = ("since", "hidden_actions", "hidden_origins", "hidden_jots")
# settings of the filters there were before they were all lists of what is shown. They do nothing now, and are removed
LEGACY_FILTER_SETTINGS = ("app_only", "filter_blocked", "filter_monitored", "show_jot_control")


def reset_filters(db, keep=()):
    """Take every filter off, so every event shows. The start time, the actions and the origins that are shown and the hidden JOTs are the
    filters there are, and with none of them set the views read the whole log. Nothing is deleted. keep names settings to leave as they are."""
    drop = [k for k in FILTER_SETTINGS + LEGACY_FILTER_SETTINGS if k not in keep]
    db.execute("DELETE FROM settings WHERE key IN (%s)" % ", ".join("?" * len(drop)), drop)
    db.commit()


def _get_shown(db_path, key, everything):
    db = sqlite3.connect(db_path)
    try:
        row = db.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        hidden = set(json.loads(row[0])) if row else set()
        return [v for v in everything if v not in hidden]
    finally:
        db.close()


def _set_shown(db, key, shown, everything):
    if not isinstance(shown, (list, tuple)) or any(v not in everything for v in shown):
        raise ValueError("what is shown must be a list of %s" % ", ".join(everything))
    hidden = [v for v in everything if v not in shown]
    if hidden:
        db.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)", (key, json.dumps(hidden)))
    else:
        db.execute("DELETE FROM settings WHERE key = ?", (key,))
    db.commit()


def get_shown_actions(db_path):
    """The actions that are shown, from observed, monitored and blocked, in that order. All of them unless some have been hidden."""
    return _get_shown(db_path, "hidden_actions", ACTIONS)


def set_shown_actions(db, shown):
    """Show these actions and no others. All of them shows every event again."""
    _set_shown(db, "hidden_actions", shown, ACTIONS)


def get_shown_origins(db_path):
    """The places events came from that are shown, from app, library, platform and none, in that order. All of them unless some are hidden."""
    return _get_shown(db_path, "hidden_origins", ORIGINS)


def set_shown_origins(db, shown):
    """Show events from these places and no others. All of them shows every event again."""
    _set_shown(db, "hidden_origins", shown, ORIGINS)
