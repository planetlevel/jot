"""The assistant, an ongoing conversation with the model about how to configure JOT for a project.

The model can look at the configuration and at the names of what the application has been seen doing, and with a project folder it can look at the
project's code. What it can change, it can only propose. A proposal is a card in the conversation that the person applies or discards, and applying
it goes through the same checked writers as the editors, so the model never writes a file. What is sent to the model is definitions, names and the
files it asks for in the folder, never what the application captured.

A turn runs in a thread, and the page asks for what is new, so a model that takes a minute and a dozen tool calls shows its progress as it goes.
"""

import json
import os
import sys
import threading
import time

import llm
import store

MAX_STEPS = 30                 # model calls in one turn, so a model that keeps asking for things can't go on forever
MAX_TOOL_RESULT = 60000        # characters of one tool's answer that are sent back
TITLE = 60

INTRO = """You are the assistant of the JOT dashboard. You help a person configure JOT for their Java application, in one ongoing conversation.

JOT puts sensors and rules in a running Java application without changing its code. A sensor records what happens at the methods it watches,
a rule can also block or report a call, and a report tabulates what the sensors recorded. The dashboard shows what was recorded.

All the configuration is one file, the jots file, which has these parts.
  app: entry     the methods or annotations that mark the application as running, like javax.servlet.Servlet.service or @com.acme.Handler. A JOT
                 with no scopes of its own applies only while one of them is running, so it leaves out startup and background threads. Without
                 a list the two servlet service methods are used, and an empty list means no application scope, so JOTs apply everywhere.
  app: packages  the application's own code, like com.acme, which the dashboard uses to tell it from libraries.
  ignore         platform work that sensors leave out, like class loading and page compiling. A package, a class or a class and method.
  sensors        the sensors and rules.
  reports        the reports.
  jots           files and directories that stay separate, like libraries of rules shared by projects. Not yours to change.
  control        the Monitor and Protect state, which the dashboard writes while the application runs. Not yours to change.

What you can do
- Look at what is there with get_configuration, and at a sensor's full definition with get_sensor.
- Look at what the application has been seen doing with get_observed, which gives the names of methods and of the application's packages, and how
  many events each sensor has. You never see what was captured, only names.
- When the person has set a project folder you can also use project_overview and find_entry_candidates for a first look, and list_files, read_file and
  search_files to go further. Use them to find how the application starts running. Files that can hold credentials are never readable. Read what you need and no more, a few files that decide the question are better than many.
- Propose changes with propose_setting, propose_sensor, propose_report, propose_delete, propose_consolidation and propose_restart. The person sees each as a card and nothing changes
  until they press Apply, so you never change anything yourself. Say you have proposed it, not that you have done it. A proposal that has problems
  is not shown, you are told what they are, and you should mend it and propose again.

How to work
- Start from what is there. Look at the configuration before you propose, so you don't repeat a name or a setting that exists.
- To scan a project, look for what starts the application running, like servlets and filters, Spring controllers and handler annotations such as
  @RestController, @GetMapping and @RequestMapping, JAX-RS resources with @Path, message listeners, schedulers and main methods, and for the packages
  that hold the application's own code. Propose the narrowest entry points that cover how requests or work arrive, and explain in a sentence why
  each is there. The packages go in app: packages, and the platform work worth leaving out goes in ignore.
- Setting up a new project. When the dashboard says the configuration is empty and a project folder is set, run a setup. Call
  project_overview and find_entry_candidates, read the few files that decide the question, then propose together the entry points and the
  application's packages (propose_setting), and the ignore list if the platform work is noisy. Then call list_catalog and choose the sensors, rules and
  reports that fit what the project uses, like its database, file, command and crypto calls, leaving out what it doesn't use. Offer them in
  one propose_from_catalog card, or several by area, and say in a sentence why each group is there. When a request needs sensors and a report,
  put them in one propose_from_catalog card, which adds the sensors first, and never ask the person to apply one before you propose the other. Adapt a definition with get_catalog_item
  and propose_sensor only when the catalog's doesn't fit. Do the setup in a few steps and tell the
  person what comes next at the end of each. When the configuration already has things in it, change only what the person asks for.
- Propose one thing at a time when the choices are the person's, and several together when they belong together, like the entry points and the
  packages of a new project.
- Ask one short question when you can't tell what the person wants. Don't ask for things you can look up with a tool.
- Keep replies short and plain. Say what you found, what you propose and why, and what they might do next.
- Sensors and rules are named, described and written as the rules below say. Reports can only read fields that a sensor captures.
- A sensor only records when a method it watches is called. Before you propose one, check that the method is one the application calls, from get_observed
  and the code you have read. When the data the person wants lives behind an object, like a database's metadata, don't watch the method that
  owns it, since the application may never call it. Pick a method it does call, like a statement's or a connection's, and walk to the data from
  #OBJ, #P0 or #RET, as the rules below say. If no method the application calls can get to it, say so, and never propose a sensor that can't fire.
- Whenever you propose or adapt a sensor, go through the three places its captures can start from, and ask what each could tell the person. #OBJ is
  the object the method is called on, the parameters #P0, #P1 and so on are what it was given, and #RET is what it returned. Each is an object with
  getters of its own, so walk into them, the way a query's ResultSet has its columns, tables and types, the statement it came from has its timeout
  and row limit, and the connection behind that has its database, user, schema and transaction settings. Don't stop at the first useful fact. Capture
  the ones a person looking at the application would want, and when they come from different objects propose a sensor for each group and say in a
  sentence what it gives. Use what you know of the library's API, and keep to cheap getters that change nothing.
"""

OUTRO = """
Everything above about JOTs and reports is how to write them. In this conversation you do not answer by calling a draft tool. You write a JOT or a
report by calling propose_sensor or propose_report with its YAML, and the person sees it as a card.
"""

# the tools. Each answer is JSON, and the model is told in the description what it gets back
TOOLS = [
    {"name": "get_configuration",
     "description": "The configuration as the jots file has it now. The file's name and whether it can be changed, the entry points, the ignore list and the "
                    "application's packages (null means the file doesn't say, which is the default), every sensor and rule with its name, description, the "
                    "methods it watches and the fields it captures, the reports, and anything wrong with the files.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_sensor",
     "description": "The full definition of one sensor or rule, as YAML, which you need to propose a change to it.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "get_observed",
     "description": "What the application has been seen doing, by name only. The methods that sensors saw called with how many events, the packages of the "
                    "application's own frames in those events, and how many events each sensor has recorded. Never what was captured.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "propose_setting",
     "description": "Propose a change to one of the list settings of the jots file. setting is entry (the application's entry points, methods like "
                    "javax.servlet.Servlet.service or annotations like @com.acme.Handler), ignore (packages, classes or methods whose work sensors leave "
                    "out) or packages (the application's own packages, like com.acme). values is the whole new list, which replaces the old one, or null "
                    "to take the setting out so the default is used. The person sees a card and applies it.",
     "input_schema": {"type": "object", "properties": {
         "setting": {"type": "string", "enum": ["entry", "ignore", "packages"]},
         "values": {"type": ["array", "null"], "items": {"type": "string"}},
         "reason": {"type": "string", "description": "one or two sentences on why, which the person reads on the card"}},
         "required": ["setting", "values", "reason"]}},
    {"name": "propose_sensor",
     "description": "Propose a new sensor or rule, or a change to an existing one. yaml is one JOT as a YAML mapping, as the rules say, with no sensors: list. "
                    "To change an existing one give its current name in replaces, and yaml is the whole new definition, which may rename it.",
     "input_schema": {"type": "object", "properties": {
         "yaml": {"type": "string"}, "replaces": {"type": "string"}, "reason": {"type": "string"}}, "required": ["yaml", "reason"]}},
    {"name": "propose_delete",
     "description": "Propose removing one sensor, rule or report from its file. The person sees a card and nothing is removed until they apply it. Before "
                    "proposing to remove a sensor, look at get_configuration for the reports that read it, which stop working without it, and propose "
                    "changing or removing those too, so the person can apply them together.",
     "input_schema": {"type": "object", "properties": {"kind": {"type": "string", "enum": ["sensor", "report"]}, "name": {"type": "string"},
                                                       "reason": {"type": "string"}}, "required": ["kind", "name", "reason"]}},
    {"name": "propose_restart",
     "description": "Propose restarting the application, which the agent needs for a new or changed sensor or setting to take effect. The person sees a card and "
                    "nothing is restarted until they apply it. It restarts with the command the person last started the application with from the Run page, "
                    "you never give a command. If the console doesn't know how the application starts you are told, and should ask the person to start it "
                    "once from the Run page.",
     "input_schema": {"type": "object", "properties": {"reason": {"type": "string"}}, "required": ["reason"]}},
    {"name": "propose_report",
     "description": "Propose a new report, or a change to an existing one. To change one give its current name in replaces, and yaml is the whole new "
                    "definition, which may rename it. yaml is one report as a YAML mapping, as the rules say, reading only fields that sensors capture. If it reads "
                    "catalog sensors that the configuration doesn't have yet, they are added in the same card. For sensors you wrote yourself, use "
                    "propose_from_catalog with sensors and reports together.",
     "input_schema": {"type": "object", "properties": {"yaml": {"type": "string"}, "replaces": {"type": "string"}, "reason": {"type": "string"}},
                      "required": ["yaml", "reason"]}},
    {"name": "list_catalog",
     "description": "The catalog of generic sensors, rules and reports that come with JOT, each with its name, kind, area, description, what it watches "
                    "and captures, and for a report the sensors it needs. This is where to start when setting up a project, then choose what fits "
                    "what you found in its code, a sensor for SQL only if the project uses a database, and so on.",
     "input_schema": {"type": "object", "properties": {}}},
    {"name": "get_catalog_item",
     "description": "The full definition of one catalog sensor, rule or report as written, which you can adapt before proposing it with propose_sensor "
                    "or propose_report.",
     "input_schema": {"type": "object", "properties": {"name": {"type": "string"}}, "required": ["name"]}},
    {"name": "propose_from_catalog",
     "description": "Propose several changes in one card, which is how to set something up in one step. names are catalog sensors, rules and reports "
                    "copied as they are. sensors are new sensors you wrote, and reports are new reports you wrote, each one YAML as the rules say. "
                    "The sensors are added first, so a report may read the fields of any sensor in the same card, and every report is checked as if "
                    "they were there. Rules are copied with protect: false, so they only report until the person turns them on. Anything the "
                    "configuration already has is left out. Use this whenever a request needs both sensors and a report.",
     "input_schema": {"type": "object", "properties": {"names": {"type": "array", "items": {"type": "string"}},
                                                       "sensors": {"type": "array", "items": {"type": "string"}},
                                                       "reports": {"type": "array", "items": {"type": "string"}}, "reason": {"type": "string"}},
                      "required": ["reason"]}},
    {"name": "propose_consolidation",
     "description": "Propose moving the sensors, rules and reports of every file the jots file lists into the jots file itself, so the configuration is one "
                    "file. keep names entries of its jots: list to leave as separate files, like a library shared by several projects.",
     "input_schema": {"type": "object", "properties": {"keep": {"type": "array", "items": {"type": "string"}}, "reason": {"type": "string"}}, "required": ["reason"]}},
]

STEPS = {"list_catalog": "Looked through the catalog", "get_catalog_item": "Looked at a catalog item", "get_configuration": "Looked at the configuration", "get_sensor": "Looked at a sensor", "get_observed": "Looked at what the application has been seen doing"}


def system_prompt():
    """What the model is told. It includes how to write a JOT and a report, which drafting uses too, without that way of answering."""
    jot = llm.JOT_SYSTEM.split("Always answer by calling the draft tool")[0].strip()
    report = llm.REPORT_SYSTEM.split("Always answer by calling the draft tool")[0].strip()
    return INTRO + "\n# How to write a JOT\n\n" + jot + "\n\n# How to write a report\n\n" + report + "\n" + OUTRO


class Assistant:
    def __init__(self, app, post=None, project=None):
        self.app = app
        self.post = post or llm._post
        self.project = project           # looks at the project's files, see scanner.py, or None
        self.lock = threading.Lock()
        self.running = {}                # chat id to its thread and its flag for stopping
        self.tools = {"get_configuration": self._get_configuration, "get_sensor": self._get_sensor, "get_observed": self._get_observed,
                      "propose_setting": self._propose_setting, "propose_sensor": self._propose_sensor,
                      "propose_report": self._propose_report, "propose_delete": self._propose_delete, "propose_restart": self._propose_restart, "propose_consolidation": self._propose_consolidation,
                      "list_catalog": self._list_catalog, "get_catalog_item": self._get_catalog_item, "propose_from_catalog": self._propose_from_catalog}

    # ------------------------------------------------------------------ storage

    def _db(self):
        return store.connect(self.app.db_path)

    def _one(self, sql, args=()):
        db = self._db()
        try:
            return db.execute(sql, args).fetchone()
        finally:
            db.close()

    def _all(self, sql, args=()):
        db = self._db()
        try:
            return db.execute(sql, args).fetchall()
        finally:
            db.close()

    def _write(self, sql, args=()):
        db = self._db()
        try:
            cur = db.execute(sql, args)
            db.commit()
            return cur.lastrowid
        finally:
            db.close()

    def _item(self, chat, kind, text):
        """Adds to what the page shows, and returns the place it has in the conversation."""
        db = self._db()
        try:
            n = (db.execute("SELECT COALESCE(MAX(n), 0) FROM chat_items WHERE chat = ?", (chat,)).fetchone()[0]) + 1
            db.execute("INSERT INTO chat_items (chat, n, ts, kind, text) VALUES (?,?,?,?,?)", (chat, n, int(time.time() * 1000), kind, text))
            db.execute("UPDATE chats SET updated = ? WHERE id = ?", (int(time.time() * 1000), chat))
            db.commit()
            return n
        finally:
            db.close()

    def _api(self, chat, role, content):
        db = self._db()
        try:
            n = (db.execute("SELECT COALESCE(MAX(n), 0) FROM chat_api WHERE chat = ?", (chat,)).fetchone()[0]) + 1
            db.execute("INSERT INTO chat_api (chat, n, role, content) VALUES (?,?,?,?)", (chat, n, role, json.dumps(content)))
            db.commit()
        finally:
            db.close()

    def _messages(self, chat):
        return [{"role": role, "content": json.loads(content)} for role, content in
                self._all("SELECT role, content FROM chat_api WHERE chat = ? ORDER BY n", (chat,))]

    # ------------------------------------------------------------------ the conversations

    def chats(self):
        return [{"id": i, "title": t or "New conversation", "updated": u, "running": i in self.running}
                for i, t, u in self._all("SELECT id, title, updated FROM chats ORDER BY updated DESC, id DESC")]

    def new_chat(self):
        now = int(time.time() * 1000)
        return self._write("INSERT INTO chats (title, created, updated) VALUES (NULL, ?, ?)", (now, now))

    def view(self, chat, after=0):
        """What the page shows of a conversation, the items after the one it has, every proposal with how it stands, and whether a turn is running."""
        found = self._one("SELECT id, title FROM chats WHERE id = ?", (chat,))
        if not found:
            raise LookupError("no conversation %s" % chat)
        items = [{"n": n, "ts": ts, "kind": kind, "text": text}
                 for n, ts, kind, text in self._all("SELECT n, ts, kind, text FROM chat_items WHERE chat = ? AND n > ? ORDER BY n", (chat, int(after or 0)))]
        proposals = [self._proposal_view(row) for row in self._all(
            "SELECT id, item, kind, title, reason, payload, status, result FROM chat_proposals WHERE chat = ? ORDER BY id", (chat,))]
        return {"chat": chat, "title": found[1] or "New conversation", "items": items, "proposals": proposals, "running": chat in self.running,
                "configured": llm.configured(), "model": llm.model() if llm.configured() else None, "editable": self._editable(),
                "folder": self.project.root if self.project is not None else None, "can_scan": bool(self.project is not None and self.project.local),
                "empty": self._empty()}

    def _proposal_view(self, row):
        pid, item, kind, title, reason, payload, status, result = row
        return {"id": pid, "item": item, "kind": kind, "title": title, "reason": reason, "payload": json.loads(payload), "status": status, "result": result}

    def _empty(self):
        """True when nothing is configured yet, so the person is setting up and not changing."""
        try:
            if self.app.jots()["sensors"]:
                return False
            settings = store.read_settings(self.app.jots_file) if self.app.jots_file and os.path.exists(self.app.jots_file) else {}
            return not any(settings.get(k) for k in ("entry", "packages", "ignore"))
        except (OSError, ValueError, LookupError):
            return True

    def _folder_from(self, text):
        """If all the person said is where their project is, sets the folder, and says what happened. Nothing else is done with the words."""
        word = text.strip()
        if " " in word or "\n" in word:
            return None
        if word.startswith(("http://", "https://", "git@", "ssh://")):
            return "I can't fetch a repository for you. Clone it with git, then give me the folder it is in, like ~/git/%s." % (
                word.rstrip("/").rsplit("/", 1)[-1].replace(".git", "") or "project")
        if word.startswith(("/", "~")):
            if self.project is None:
                return None
            try:
                root = self.project.set_root(word)
            except ValueError as e:
                return "I can't use that folder, %s." % e
            return "I can look at %s now. Say what you would like, or choose Set up this project." % root
        return None

    def _editable(self):
        return bool(self.app.editable and self.app.jots_file)

    def send(self, chat, text):
        """Adds what the person said and starts the assistant on it. One turn runs at a time in a conversation."""
        text = (text or "").strip()
        if not text:
            raise store.QueryError("say what you would like to do")
        if len(text) > 8000:
            raise store.QueryError("that is too long, a few paragraphs are enough")
        if not self._one("SELECT id FROM chats WHERE id = ?", (chat,)):
            raise LookupError("no conversation %s" % chat)
        with self.lock:
            if chat in self.running:
                raise store.QueryError("the assistant is still working on the last message")
            if self.project is not None:
                self.project.begin()
            self._item(chat, "user", text)
            said = self._folder_from(text)
            if said:
                self._item(chat, "assistant", said)
                self._write("UPDATE chats SET title = COALESCE(title, ?) WHERE id = ?", ("Project folder", chat))
                return self.view(chat, 0)
            self._write("UPDATE chats SET title = COALESCE(title, ?) WHERE id = ?", (text.replace("\n", " ")[:TITLE], chat))
            self._api(chat, "user", [{"type": "text", "text": self._context(chat) + "\n\n" + text}])
            stop = threading.Event()
            thread = threading.Thread(target=self._run, args=(chat, stop), daemon=True, name="assistant-%s" % chat)
            self.running[chat] = {"thread": thread, "stop": stop}
            thread.start()
        return self.view(chat, 0)

    def stop(self, chat):
        with self.lock:
            run = self.running.get(chat)
            if run:
                run["stop"].set()
        return self.view(chat, 0)

    def wait(self, chat, timeout=30):
        """For tests, waits until a conversation's turn has finished."""
        run = self.running.get(chat)
        if run:
            run["thread"].join(timeout)

    def _context(self, chat):
        """What the dashboard says before the person's words, which they didn't type. Where the configuration is, and what happened to the
        proposals since the last message, since the model can't see the page."""
        lines = ["[From the dashboard, not typed by the person]"]
        lines.append("Jots file: %s, %s" % (os.path.basename(self.app.jots_file) if self.app.jots_file else "none",
                                            "changes can be applied" if self._editable() else "changes can't be applied here"))
        if self.project is not None:
            lines.append("Project folder: %s" % (self.project.root or "not set"))
            lines.append("Configuration: %s" % ("empty, this is a new setup" if self._empty() else "has sensors or settings in it"))
        news = self._all("SELECT id, kind, title, status FROM chat_proposals WHERE chat = ? AND status <> 'pending' AND told = 0 ORDER BY id", (chat,))
        for pid, _, title, status in news:
            lines.append("Proposal %d, %s, was %s by the person." % (pid, title, status))
        if news:
            self._write("UPDATE chat_proposals SET told = 1 WHERE chat = ? AND status <> 'pending' AND told = 0", (chat,))
        return "\n".join(lines)

    # ------------------------------------------------------------------ a turn

    def _run(self, chat, stop):
        try:
            for _ in range(MAX_STEPS):
                if stop.is_set():
                    self._item(chat, "step", "Stopped")
                    return
                body = {"model": llm.model(), "max_tokens": llm.MAX_TOKENS,
                        "system": [{"type": "text", "text": system_prompt(), "cache_control": {"type": "ephemeral"}}],
                        "messages": self._messages(chat), "tools": self._tools()}
                data = self.post(body, 300)
                blocks = data.get("content") or []
                self._api(chat, "assistant", blocks)
                for block in blocks:
                    if block.get("type") == "text" and (block.get("text") or "").strip():
                        self._item(chat, "assistant", block["text"].strip())
                reason = data.get("stop_reason")
                if reason == "max_tokens":
                    self._item(chat, "error", "The model ran out of room before it finished. Ask for something smaller, or say continue.")
                    return
                if reason == "refusal":
                    self._item(chat, "error", "The model declined to answer that.")
                    return
                uses = [b for b in blocks if b.get("type") == "tool_use"]
                if reason != "tool_use" or not uses:
                    return
                results = []
                for use in uses:
                    out = self._execute(chat, use)
                    text = json.dumps(out)
                    if len(text) > MAX_TOOL_RESULT:
                        text = json.dumps({"error": "the answer was too long to send, ask for less"})
                    results.append({"type": "tool_result", "tool_use_id": use["id"], "content": text, **({"is_error": True} if "error" in out else {})})
                self._api(chat, "user", results)
            self._item(chat, "error", "The assistant stopped after %d steps in one turn. Say continue to go on." % MAX_STEPS)
        except llm.LLMError as e:
            self._item(chat, "error", str(e))
        except Exception as e:   # the thread must not die without saying so
            print("[dashboard] assistant error:", repr(e), file=sys.stderr)
            self._item(chat, "error", "Something went wrong in the dashboard, %s" % type(e).__name__)
        finally:
            with self.lock:
                self.running.pop(chat, None)

    def _tools(self):
        extra = self.project.tools() if self.project is not None else []
        return TOOLS + extra

    def _execute(self, chat, use):
        name, args = use.get("name"), use.get("input") or {}
        function = self.tools.get(name) or (self.project.functions().get(name) if self.project is not None else None)
        if function is None:
            return {"error": "there is no tool called %s" % name}
        try:
            out = function(chat, **args) if name.startswith("propose") else function(**args)
        except TypeError as e:
            return {"error": "the arguments of %s are wrong, %s" % (name, e)}
        except (store.QueryError, ValueError, LookupError, OSError) as e:
            if self.project is not None and name in self.project.functions():
                self._item(chat, "step", self.project.describe(name, args, {"error": str(e)}))
            return {"error": str(e)}
        if name in STEPS:
            self._item(chat, "step", STEPS[name] + ("" if name != "get_sensor" else ", " + str(args.get("name"))))
        elif self.project is not None and name in self.project.functions():
            self._item(chat, "step", self.project.describe(name, args, out))
        return out

    # ------------------------------------------------------------------ looking

    def _get_configuration(self):
        jots = self.app.jots()
        settings = store.read_settings(self.app.jots_file) if self.app.jots_file else {"entry": None, "ignore": None, "packages": None}
        return {
            "jots_file": os.path.basename(self.app.jots_file) if self.app.jots_file else None,
            "can_be_changed": self._editable(),
            "entry": settings["entry"], "default_entry": list(store.DEFAULT_ENTRY),
            "ignore": settings["ignore"], "packages": settings["packages"],
            "sensors": [{"name": s["name"], "kind": s["kind"], "description": s["description"], "file": s["file"],
                         "methods": s["methods"][:6], "fields": list(s["captures"]), "events": s["events"]} for s in jots["sensors"]],
            "reports": [{"name": r["name"], "type": r["type"], "rows": r["rows"], "cols": r["cols"], "value": r["value"], "by": r["by"], "file": r["file"],
                         "yaml": r["definition"]} for r in jots["reports"]],
            "read_by": {s["name"]: s["used_by"] for s in jots["sensors"] if s["used_by"]},
            "files": [{"name": f["name"], "sensors": f["sensors"], "rules": f["rules"], "reports": f["reports"]} for f in jots["files"]],
            "problems": [i["text"] for i in jots["issues"]],
        }

    def _get_sensor(self, name):
        for s in self.app.jots()["sensors"]:
            if s["name"] == name:
                return {"name": name, "file": s["file"], "yaml": s["definition"]}
        raise LookupError("there is no sensor or rule called %s" % name)

    def _get_observed(self):
        methods = store.run_query(self.app.db_path, """
            SELECT method_name, COUNT(*) AS n FROM events_raw WHERE method_name IS NOT NULL AND sensor NOT LIKE 'jot-%'
            GROUP BY method_name ORDER BY n DESC LIMIT 60""")["rows"]
        sensors = store.run_query(self.app.db_path, """
            SELECT sensor, COUNT(*) AS n FROM events_raw WHERE sensor NOT LIKE 'jot-%' GROUP BY sensor ORDER BY n DESC LIMIT 60""")["rows"]
        frames = store.run_query(self.app.db_path, "SELECT app_frame, COUNT(*) FROM events_raw WHERE app_frame IS NOT NULL GROUP BY app_frame ORDER BY 2 DESC LIMIT 500")["rows"]
        packages = {}
        for frame, n in frames:
            name = (frame or "").split("(")[0]
            parts = name.split(".")
            package = ".".join(parts[:-2][:3]) if len(parts) > 2 else ""
            if package:
                packages[package] = packages.get(package, 0) + n
        return {"methods": [{"method": m, "events": n} for m, n in methods],
                "application_packages": [{"package": p, "events": n} for p, n in sorted(packages.items(), key=lambda kv: -kv[1])[:30]],
                "sensors": [{"sensor": s, "events": n} for s, n in sensors]}

    # ------------------------------------------------------------------ proposing

    def _record(self, chat, kind, title, reason, payload):
        """Keeps a proposal and puts its card in the conversation, and returns what the model is told."""
        item = self._item(chat, "proposal", "")
        pid = self._write("INSERT INTO chat_proposals (chat, item, kind, title, reason, payload, status, created) VALUES (?,?,?,?,?,?, 'pending', ?)",
                          (chat, item, kind, title, (reason or "").strip(), json.dumps(payload), int(time.time() * 1000)))
        self._write("UPDATE chat_items SET text = ? WHERE chat = ? AND n = ?", (str(pid), chat, item))
        return {"ok": True, "proposal": pid, "note": "The person sees it as a card, and nothing changes until they apply it."}

    def _problems(self, chat, what, problems):
        self._item(chat, "step", "A proposal of %s had problems and was not shown, %s" % (what, problems[0] if problems else ""))
        return {"ok": False, "problems": problems, "note": "Mend these and propose again. Nothing was shown to the person."}

    def _propose_setting(self, chat, setting, values, reason=""):
        check = {"entry": store.entry_problems, "ignore": store.ignore_problems, "packages": store.package_problems}.get(setting)
        if check is None:
            return {"error": "setting must be entry, ignore or packages"}
        if values is not None:
            values = [v.strip() if isinstance(v, str) else v for v in values] if isinstance(values, list) else values
            problems = check(values)
            if problems:
                return self._problems(chat, setting, ["%s %s" % ("entry %d" % (p["index"] + 1) if p["index"] is not None else "the list", p["message"]) for p in problems])
        before = store.read_settings(self.app.jots_file)[setting] if self.app.jots_file else None
        label = {"entry": "entry points", "ignore": "the ignore list", "packages": "the application's packages"}[setting]
        return self._record(chat, "setting", "Change " + label if values is not None else "Use the default for " + label, reason,
                            {"setting": setting, "label": label, "values": values, "before": before})

    def _names(self):
        return {s["name"] for s in self.app.sensors()}

    def _propose_sensor(self, chat, yaml, reason="", replaces=None):
        text = store.stage_rule((yaml or "").strip("\n"))
        taken = self._names()
        original = None
        if replaces:
            found = next((s for s in self.app.jots()["sensors"] if s["name"] == replaces), None)
            if not found:
                return self._problems(chat, "a sensor", ["there is no sensor or rule called %s to replace" % replaces])
            taken.discard(replaces)
            original = found["definition"]
        problems = store.check_draft(text, taken)
        if problems:
            return self._problems(chat, "a sensor", problems)
        import yaml as pyyaml
        doc = pyyaml.safe_load(text) or {}
        title = ("Change " if replaces else "Add ") + ("the rule " if "block-when" in doc else "the sensor ") + str(doc.get("name"))
        return self._record(chat, "sensor", title, reason, {"yaml": text, "replaces": replaces, "original": original, "rule": "block-when" in doc})

    def _propose_delete(self, chat, kind, name, reason=""):
        if kind == "sensor":
            found = next((s for s in self.app.jots()["sensors"] if s["name"] == name), None)
            used = found["used_by"] if found else []
        elif kind == "report":
            found = next((r for r in self.app.jots()["reports"] if r["name"] == name), None)
            used = []
        else:
            return {"error": "kind must be sensor or report"}
        if not found:
            return self._problems(chat, "a removal", ["there is no %s called %s" % (kind, name)])
        return self._record(chat, "delete", "Remove the %s %s" % (kind, name), reason,
                            {"kind": kind, "name": name, "original": found["definition"], "used_by": used, "file": found["file"]})

    def _propose_restart(self, chat, reason="", **_ignored):
        # the command is never an input, so anything the model adds is dropped
        run = self.app.launcher
        if not run:
            return self._problems(chat, "a restart", ["the application can't be started or stopped from here"])
        if not run.command:
            return self._problems(chat, "a restart", ["the console doesn't know how this application starts. Ask the person to start it once from the Run page, "
                                                      "and then it can be restarted"])
        return self._record(chat, "restart", "Restart the application", reason, {"command": run.command})

    def _propose_report(self, chat, yaml, reason="", replaces=None):
        text = (yaml or "").strip("\n")
        fields = self.app.sensor_fields()
        taken = self.app.report_names()
        original = None
        if replaces:
            found = next((r for r in self.app.jots()["reports"] if r["name"] == replaces), None)
            if not found:
                return self._problems(chat, "a report", ["there is no report called %s to replace" % replaces])
            taken = [n for n in taken if n != replaces]
            original = found["definition"]
            problems = store.check_report_draft(text, fields, taken)
            if problems:
                return self._problems(chat, "a report", problems)
            import yaml as pyyaml
            doc = pyyaml.safe_load(text) or {}
            return self._record(chat, "report", "Change the report " + str(doc.get("name")), reason, {"yaml": text, "replaces": replaces, "original": original})
        problems = store.check_report_draft(text, fields, taken)
        if problems:
            # a report that reads sensors the configuration doesn't have yet, which the catalog does, comes with them in the same card
            wanted = self._catalog_sensors_for(text, fields)
            if wanted:
                return self._propose_bundle(chat, names=wanted, reports=[text], reason=reason)
            return self._problems(chat, "a report", problems)
        import yaml as pyyaml
        doc = pyyaml.safe_load(text) or {}
        return self._record(chat, "report", "Add the report " + str(doc.get("name")), reason, {"yaml": text})

    def _catalog_sensors_for(self, text, fields):
        """The catalog sensors that the report reads and the configuration doesn't have, when adding them would make the report valid, else []."""
        catalog = self.app.catalog
        if not catalog.available():
            return []
        extra = {r["name"]: r.get("fields", []) for r in catalog.items() if r["kind"] != "report" and r["name"] not in fields}
        if not extra or store.check_report_draft(text, dict(fields, **extra), self.app.report_names()):
            return []
        import re
        return [n for n in extra if re.search(r"(?<![\w-])%s\.\w" % re.escape(n), text)]

    def _list_catalog(self):
        catalog = self.app.catalog
        if not catalog.available():
            return {"error": "there is no catalog here, write the sensors yourself as the rules say"}
        mine = self._names()
        return {"items": [dict(row, in_configuration=row["name"] in mine) for row in catalog.listing()]}

    def _get_catalog_item(self, name):
        found = self.app.catalog.get(name)
        if not found:
            return {"error": "there is nothing called %s in the catalog" % name}
        return {"name": name, "kind": found["kind"], "needs_sensors": found["needs"], "yaml": found["text"]}

    def _propose_from_catalog(self, chat, names=None, reason="", sensors=None, reports=None):
        return self._propose_bundle(chat, names=names, sensors=sensors, reports=reports, reason=reason)

    def _propose_bundle(self, chat, names=None, sensors=None, reports=None, reason=""):
        """One card that adds sensors, rules and reports together. The sensors are added first, so the reports can read what they capture, and
        every report is checked as if they were already there. names are catalog items, sensors and reports are YAML written by the model."""
        import yaml as pyyaml
        catalog = self.app.catalog
        wanted = list(dict.fromkeys(names or []))
        if not wanted and not sensors and not reports:
            return self._problems(chat, "the changes", ["name at least one catalog item, or give a sensor or a report"])
        unknown = [n for n in wanted if not catalog.get(n)]
        if unknown:
            return self._problems(chat, "the changes", ["not in the catalog, %s" % ", ".join(unknown)])
        have = self._names()
        have_reports = set(self.app.report_names())
        fields = dict(self.app.sensor_fields())
        picked = [catalog.get(n) for n in wanted]
        new_sensors = [(r["name"], store.stage_rule(r["text"].strip("\n")), r["kind"] == "rule", list(r.get("fields", []))) for r in picked
                       if r["kind"] != "report" and r["name"] not in have]
        new_reports = [(r["name"], r["text"].strip("\n"), False) for r in picked if r["kind"] == "report" and r["name"] not in have_reports]
        left_out = [r["name"] for r in picked if r["name"] in have or r["name"] in have_reports]
        problems, taken = [], set(have)
        for name, text, _, _ in new_sensors:
            problems += ["%s, %s" % (name, p) for p in store.check_draft(text, taken)]
            taken.add(name)
        for text in sensors or []:
            text = store.stage_rule((text or "").strip("\n"))
            found = store.check_draft(text, taken)
            if found:
                problems += found
                continue
            doc = pyyaml.safe_load(text) or {}
            taken.add(doc.get("name"))
            new_sensors.append((doc.get("name"), text, "block-when" in doc, list((doc.get("captures") or {}).keys())))
        for name, text, rule, captured in new_sensors:
            fields[name] = captured
        taken_reports = set(have_reports) | {n for n, *_ in new_reports}
        custom = []
        for text in reports or []:
            text = (text or "").strip("\n")
            found = store.check_report_draft(text, fields, taken_reports)
            if found:
                problems += found
                continue
            doc = pyyaml.safe_load(text) or {}
            taken_reports.add(doc.get("name"))
            new_reports.append((doc.get("name"), text, True))
            custom.append(text)
        for name, text, is_custom in new_reports:
            if not is_custom:
                missing = [n for n in (catalog.get(name) or {}).get("needs", []) if n not in fields]
                if missing:
                    problems.append("the report %s reads %s, which the configuration doesn't have, add them to names or leave the report out" % (name, ", ".join(missing)))
        if problems:
            return self._problems(chat, "the changes", problems)
        if not new_sensors and not new_reports:
            return {"ok": False, "problems": ["the configuration already has all of those"], "note": "Nothing was shown to the person."}
        rules = [n for n, _, rule, _ in new_sensors if rule]
        plain = [n for n, _, rule, _ in new_sensors if not rule]
        parts = ["%d sensors" % len(plain) if plain else None, "%d rules" % len(rules) if rules else None, "%d reports" % len(new_reports) if new_reports else None]
        title = "Add %s" % ", ".join(p for p in parts if p) + (" from the catalog" if wanted and not sensors and not reports else "")
        return self._record(chat, "catalog", title, reason, {"sensors": [t for _, t, _, _ in new_sensors], "reports": [t for _, t, _ in new_reports],
                                                          "names": [n for n, *_ in new_sensors], "rules": rules, "report_names": [n for n, *_ in new_reports],
                                                          "left_out": left_out, "custom": custom})

    def _propose_consolidation(self, chat, reason="", keep=None):
        if not self.app.jots_file:
            return {"error": "the dashboard was not started with a jots file, so there is nothing to combine"}
        try:
            done = store.consolidate(self.app.jots_file, keep=list(keep or []), write=False)
        except store.SaveError as e:
            return self._problems(chat, "combining the files", [str(e)])
        if not done["from"]:
            return self._problems(chat, "combining the files", ["there is nothing to combine, no file is listed in jots: that has sensors or reports"])
        summary = {k: done[k] for k in ("sensors", "reports", "from", "skipped", "missing", "kept")}
        return self._record(chat, "consolidation", "Combine the files into %s" % os.path.basename(self.app.jots_file), reason, {"keep": list(keep or []), "summary": summary})

    # ------------------------------------------------------------------ applying

    def resolve(self, pid, action, file=None):
        """Applies a proposal or discards it. Applying uses the same checked writers as the editors, so it can be refused, like when the file
        changed since the proposal was made. Returns the proposal as it now stands."""
        row = self._one("SELECT id, item, kind, title, reason, payload, status, result, chat FROM chat_proposals WHERE id = ?", (int(pid),))
        if not row:
            raise LookupError("no proposal %s" % pid)
        chat = row[8]
        if row[6] != "pending":
            raise store.QueryError("that proposal was already %s" % row[6])
        payload = json.loads(row[5])
        if action == "discard":
            self._write("UPDATE chat_proposals SET status = 'discarded' WHERE id = ?", (row[0],))
            self._item(chat, "step", "Discarded, %s" % row[3])
            return self._proposal_view(self._one("SELECT id, item, kind, title, reason, payload, status, result FROM chat_proposals WHERE id = ?", (row[0],)))
        if action != "apply":
            raise store.QueryError("an action is apply or discard")
        result = self._apply(row[2], payload, file)
        self._write("UPDATE chat_proposals SET status = 'applied', result = ? WHERE id = ?", (result, row[0]))
        self._item(chat, "applied", "%s. %s" % (row[3], result))
        return self._proposal_view(self._one("SELECT id, item, kind, title, reason, payload, status, result FROM chat_proposals WHERE id = ?", (row[0],)))

    def _main(self):
        return os.path.basename(self.app.jots_file) if self.app.jots_file else None

    def _apply(self, kind, payload, file):
        app = self.app
        agent = "The agent reads it when the application starts."
        if kind == "setting":
            done = app.save_setting(payload["setting"], payload["values"], payload["before"])
            return "Written to %s. %s" % (done["saved"], agent)
        if kind == "sensor":
            if payload.get("replaces"):
                done = app.save_jot(payload["replaces"], payload.get("original"), payload["yaml"])
                return "Saved to %s. %s" % (done["saved"], agent)
            done = app.add_jot(file or self._main() or "", payload["yaml"])
            return "Added to %s. %s" % (done["file"], agent)
        if kind == "delete":
            done = (app.delete_jot if payload["kind"] == "sensor" else app.delete_report)(payload["name"], payload["original"])
            return "Removed from %s. %s" % (done["deleted"], agent if payload["kind"] == "sensor" else "")
        if kind == "restart":
            done = app.restart_application()
            return "Restarted with %s. Events appear when it handles a request." % done["command"]
        if kind == "report":
            if payload.get("replaces"):
                done = app.save_report(payload["replaces"], payload.get("original"), payload["yaml"])
                return "Saved to %s." % done["saved"]
            done = app.add_report(file or self._main() or "", payload["yaml"])
            return "Added to %s, and the Reports page has it." % done["file"]
        if kind == "catalog":
            target = file or self._main() or ""
            added = 0
            try:
                for text in payload["sensors"]:
                    app.add_jot(target, text)
                    added += 1
                for text in payload["reports"]:
                    app.add_report(target, text)
                    added += 1
            except store.SaveError as e:
                raise store.SaveError("%s. %d of %d were added first." % (e, added, len(payload["sensors"]) + len(payload["reports"])), getattr(e, "status", 400))
            return "Added %d to %s. %s" % (added, os.path.basename(target) or "the configuration", agent)
        if kind == "consolidation":
            if not app.editable:
                raise store.SaveError("saving is off, the dashboard is open to other machines", 403)
            done = store.consolidate(app.jots_file, keep=payload.get("keep") or [])
            app.reload_jots(force=True)
            note = " %d left out because an earlier file defined them." % len(done["skipped"]) if done["skipped"] else ""
            return "Everything is in %s now, %d sensors and rules and %d reports, and the old one is in %s.%s" % (
                os.path.basename(done["out"]), done["sensors"], done["reports"], os.path.basename(done["backup"] or ""), note)
        raise store.QueryError("unknown kind of proposal %s" % kind)
