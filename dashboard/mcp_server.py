#!/usr/bin/env python3
"""An MCP server that lets an LLM agent work with a running JOT application, through the dashboard.

The triangle is the agent sends events to the dashboard, the dashboard keeps a model of them, and the LLM asks the dashboard questions
and changes the sensors through it. The dashboard writes the sensor into a .jot file and the agent, which follows its files, puts the
sensor on the running application within a few seconds. Nothing here talks to the agent, and nothing here writes a file itself.

    claude mcp add jot -- python3 /path/to/jot/dashboard/mcp_server.py

It speaks MCP over stdio, one JSON message to a line, and needs only the standard library. JOT_DASHBOARD says where the dashboard is
(http://127.0.0.1:8765) and JOT_CATALOG where the catalog is, by default the catalog folder of this repository.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import catalog as catalog_module   # noqa: E402

PROTOCOL = "2024-11-05"
MAX_TEXT = 40000      # characters of one answer, so a big graph doesn't fill the model's context
CONFIRM_SECONDS = 10  # how long to wait for the agent to say it has put a sensor on or taken it off


class ToolError(Exception):
    """What went wrong, said to the model."""


class Dashboard:
    """The dashboard's HTTP API. The header is the one the dashboard asks of every write."""

    def __init__(self, base):
        self.base = base.rstrip("/")

    def _send(self, req):
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read() or b"{}")
        except urllib.error.HTTPError as e:
            try:
                said = json.loads(e.read()).get("error")
            except ValueError:
                said = None
            raise ToolError(said or "the dashboard answered %d" % e.code)
        except (urllib.error.URLError, OSError) as e:
            raise ToolError("the dashboard at %s can't be reached (%s). Start it with the jot command in the application's folder" % (self.base, e))

    def get(self, path):
        return self._send(urllib.request.Request(self.base + path))

    def post(self, path, body):
        return self._send(urllib.request.Request(self.base + path, data=json.dumps(body).encode(), method="POST",
                                                 headers={"Content-Type": "application/json", "X-JOT-Dashboard": "1"}))

    def sql(self, sql, limit=None):
        return self.post("/api/sql", {"sql": sql, "limit": limit})


def _quote(text):
    return "'" + str(text).replace("'", "''") + "'"


class Tools:
    def __init__(self, dashboard, catalog, wait=time.sleep, now=time.time, confirm_seconds=CONFIRM_SECONDS):
        self.dash = dashboard
        self.catalog = catalog
        self.wait = wait
        self.now = now
        self.confirm_seconds = confirm_seconds

    # --- looking ---

    def jot_overview(self, **_):
        """The sensors and rules now defined, how often each has fired, and what looks wrong."""
        jots = self.dash.get("/api/jots")
        status = self.dash.get("/api/status")
        return {
            "events": status.get("events"), "last_event_ts": status.get("last_ts"), "editable": jots.get("editable"),
            "files": jots.get("files"),
            "sensors": [{k: s.get(k) for k in ("name", "kind", "mode", "description", "methods", "scopes", "captures", "file", "events", "last_hour")}
                        for s in jots.get("sensors", [])],
            "reports": [r["name"] for r in jots.get("reports", [])],
            "issues": jots.get("issues", [])}

    def search_catalog(self, query=None, area=None, **_):
        """Sensors, rules and reports that come with JOT. With neither a query nor an area it lists the areas."""
        if not self.catalog.available():
            raise ToolError("no catalog was found, set JOT_CATALOG to the catalog folder")
        if query:
            return {"matches": self.catalog.search(query)}
        if area:
            return {"items": self.catalog.listing(area)}
        return {"areas": self.catalog.areas()}

    def catalog_item(self, name, **_):
        """One catalog item, with its definition as written, ready to give to add_sensor."""
        item = self.catalog.get(name)
        if not item:
            raise ToolError("the catalog has nothing called %s" % name)
        return {"name": item["name"], "kind": item["kind"], "area": item["area"], "note": item.get("note"), "yaml": item["text"]}

    def query_events(self, sql, limit=None, **_):
        """A read-only SQL question about what the sensors saw. The events view has the columns sensor, action, capture, data (JSON,
        read with json_extract), method_name, call_site_name, entry, trace, ts and time."""
        return self.dash.sql(sql, limit)

    def recent_events(self, after=None, **_):
        return self.dash.get("/api/recent" + ("?after=%d" % int(after) if after is not None else ""))

    def get_graph(self, route=None, **_):
        """The paths through the application, from each route through the methods the sensors saw."""
        from urllib.parse import quote
        return self.dash.get("/api/graph" + ("?route=" + quote(route) if route else ""))

    # --- changing ---

    def check_sensor(self, yaml, **_):
        """What is wrong with a sensor as written, before it is added. An empty list means nothing."""
        return self.dash.post("/api/jots/check", {"text": yaml})

    def add_sensor(self, yaml, file=None, **_):
        """Writes a sensor into a .jot file. The agent follows its files, so the sensor is on the running application within a few
        seconds, and the answer says whether the agent confirmed it."""
        problems = self.dash.post("/api/jots/check", {"text": yaml}).get("problems") or []
        if problems:
            raise ToolError("not added, line %s %s" % (problems[0].get("line"), problems[0].get("message")))
        jots = self.dash.get("/api/jots")
        if not jots.get("editable"):
            raise ToolError("the dashboard is not allowed to save, it is open to other machines")
        if not file:
            main = [f["name"] for f in jots.get("files", []) if f.get("main")]
            if not main:
                raise ToolError("there is no jots file to add to, give a file")
            file = main[0]
        mark = self._last_pk()
        added = self.dash.post("/api/jots/add", {"file": file, "text": yaml})
        return dict(added, agent=self._confirm(added["added"], "loaded", mark))

    def remove_sensor(self, name, **_):
        """Takes a sensor or rule out of its file. Reports that read it are left as they are, and the answer lists them."""
        found = [s for s in self.dash.get("/api/jots").get("sensors", []) if s["name"] == name]
        if not found:
            raise ToolError("no sensor is called %s" % name)
        mark = self._last_pk()
        removed = self.dash.post("/api/jots/delete", {"name": name, "original": found[0]["definition"]})
        return dict(removed, agent=self._confirm(name, "unloaded", mark))

    # --- the agent's side of it ---

    def _last_pk(self):
        rows = self.dash.sql("SELECT COALESCE(MAX(pk), 0) FROM events_raw", 1).get("rows") or [[0]]
        return rows[0][0]

    def _confirm(self, name, verb, mark):
        """Waits for the agent to say it has the change, which it does in a jot-config event after it reads the file again. Said plainly
        when it doesn't, since that is the case the model has to know about, usually because the application isn't running."""
        want = "%s=%s" % (verb, name)
        end = self.now() + self.confirm_seconds
        while True:
            rows = self.dash.sql("SELECT 1 FROM events_raw WHERE pk > %d AND sensor = 'jot-config' AND capture = %s LIMIT 1" % (int(mark), _quote(want)), 1)
            if rows.get("rows"):
                return "confirmed, the agent says %s" % want
            if self.now() >= end:
                return ("not confirmed within %d seconds. The file is changed. If the application is running with JOT, check overview issues, "
                        "the agent leaves out a sensor it can't make and says why" % self.confirm_seconds)
            self.wait(1)


def _props(spec, required=()):
    return {"type": "object", "properties": {k: {"type": t, "description": d} for k, (t, d) in spec.items()}, "required": list(required)}


TOOL_LIST = [
    ("jot_overview", "The sensors and rules that are defined, how many times each has fired, the files they live in and anything that looks wrong. Start here.",
     _props({})),
    ("search_catalog", "Find sensors, rules and reports that come with JOT, by words such as a library or method. Give an area to list one area, or nothing to list the areas.",
     _props({"query": ("string", "words that appear in the name, description or methods"), "area": ("string", "an area such as sql or web")})),
    ("catalog_item", "One catalog item with its definition as written, to adapt and pass to add_sensor.",
     _props({"name": ("string", "the item's name")}, ["name"])),
    ("query_events", "Run a read-only SQL query over the events the sensors recorded, newest data first when you order by ts. Use it to count, group and compare. "
                     "Read a captured field with json_extract(data, '$.field').",
     _props({"sql": ("string", "a SELECT over the events view"), "limit": ("integer", "most rows to return")}, ["sql"])),
    ("recent_events", "The newest events. Pass after, a pk from an earlier answer, to get only what is newer.",
     _props({"after": ("integer", "only events with a larger pk")})),
    ("get_graph", "The paths through the application, from each route through the methods the sensors saw. Give a route to look at one.",
     _props({"route": ("string", "a route such as /ticketbook/idor/1/read/query")})),
    ("check_sensor", "Check a sensor's YAML before adding it. Returns a list of problems, empty when it is fine.",
     _props({"yaml": ("string", "one sensor as a YAML mapping, with no sensors: list")}, ["yaml"])),
    ("add_sensor", "Add a sensor to the running application. It is written to a .jot file and the agent puts it on within a few seconds, with no restart. "
                   "A sensor only records when the code it watches runs, so trigger the behavior, then query_events. Remove it with remove_sensor when you are done.",
     _props({"yaml": ("string", "one sensor as a YAML mapping, with no sensors: list"), "file": ("string", "the file to add it to, by default the main jots file")}, ["yaml"])),
    ("remove_sensor", "Take a sensor or rule out of the running application.",
     _props({"name": ("string", "the sensor's name")}, ["name"])),
]


def handle(tools, message):
    """The answer to one JSON-RPC message, or None for a notification."""
    method, ident, params = message.get("method"), message.get("id"), message.get("params") or {}
    if ident is None:
        return None
    try:
        if method == "initialize":
            result = {"protocolVersion": PROTOCOL, "capabilities": {"tools": {}}, "serverInfo": {"name": "jot", "version": "1"},
                      "instructions": "Use jot_overview first. To answer a question about the running application, add the narrowest sensor that could "
                                      "show it, trigger the behavior, read the events, and remove the sensor when you are done."}
        elif method == "ping":
            result = {}
        elif method == "tools/list":
            result = {"tools": [{"name": n, "description": d, "inputSchema": s} for n, d, s in TOOL_LIST]}
        elif method == "tools/call":
            name = params.get("name")
            if name not in {n for n, _, _ in TOOL_LIST}:
                return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32602, "message": "unknown tool %s" % name}}
            try:
                out = getattr(tools, name)(**(params.get("arguments") or {}))
                text, error = json.dumps(out, indent=1, default=str), False
            except ToolError as e:
                text, error = str(e), True
            except TypeError as e:
                text, error = "bad arguments, %s" % e, True
            if len(text) > MAX_TEXT:
                text = text[:MAX_TEXT] + "\n... cut, ask for less"
            result = {"content": [{"type": "text", "text": text}], "isError": error}
        else:
            return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32601, "message": "unknown method %s" % method}}
    except Exception as e:   # one bad request must not end the server
        return {"jsonrpc": "2.0", "id": ident, "error": {"code": -32603, "message": str(e)}}
    return {"jsonrpc": "2.0", "id": ident, "result": result}


def main():
    base = os.environ.get("JOT_DASHBOARD", "http://127.0.0.1:8765")
    path = os.environ.get("JOT_CATALOG") or os.path.join(os.path.dirname(HERE), "catalog")
    tools = Tools(Dashboard(base), catalog_module.Catalog(path))
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except ValueError:
            continue
        reply = handle(tools, message)
        if reply is not None:
            sys.stdout.write(json.dumps(reply) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
