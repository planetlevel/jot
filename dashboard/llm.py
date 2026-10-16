"""Turns a question into a SQL query over the JOT event store, using the Claude API.

What is sent to the model is the table definitions, the sensor names and descriptions, the question,
and the SQL of earlier questions. It is never sent event data. Captured values can hold secrets, and
the query runs locally, so the answer comes back to the browser without the data leaving this machine.
"""

import json
import os
import ssl
import urllib.error
import urllib.request

API_URL = "https://api.anthropic.com/v1/messages"
DEFAULT_MODEL = "claude-sonnet-5-5"

SYSTEM = """You turn questions about a running Java application into SQLite queries.

The application is watched by JOT, which instruments Java methods with sensors. Each time a sensor
fires it records one row in the events table. A sensor is a rule like "record the algorithm passed to
Cipher.getInstance" or "block ProcessBuilder when called from a vulnerable method". The sensors
table describes each one. The events table is all you can query, plus sensors for what they mean.

Rules for the SQL
- SQLite dialect. One read-only SELECT (a WITH clause is fine). Never write, attach or pragma.
- Events are related when they have the same run and the same trace. For example, "which routes use
  which ciphers" joins the events of the route sensor to the events of the cipher sensor ON
  a.run = b.run AND a.trace = b.trace.
- Use sensor names exactly as listed in the sensors table. Filter on them with sensor = '...'.
- action is 'observed' (the sensor recorded something), 'blocked' (the sensor stopped the call, an
  attack or violation was prevented) or 'monitored' (it would have blocked, but only watched).
- Prefer method_name and call_site_name for grouping, they have no line numbers. Use call_site when
  the line number matters. The stack column is a JSON array, use json_each(stack) to search it.
- Times. ts is epoch milliseconds. Show times in the viewer's local time, as
  datetime(ts/1000, 'unixepoch', 'localtime'). A relative window such as the last hour is
  ts > (strftime('%s','now') - 3600) * 1000. Bucket with
  strftime('%Y-%m-%d %H:%M', ts/1000, 'unixepoch', 'localtime').
- When a question lists individual events, rather than counts or groups, include pk as the first column. The
  dashboard hides it and uses it to open the event when a row is clicked.
- Give columns short readable aliases. Add ORDER BY, and LIMIT when a question asks for the top few.
- You can't see the data, only the tables. Never ask the user for values such as role names, route names
  or user names. Write the query so it works for whatever values are there.
- Use LIKE and lower() for text matches the user phrases loosely.

Grids (crosstabs)
- SQLite can't turn data values into columns, so don't try. For any matrix or crosstab, such as "routes as
  rows and roles as columns with an X where detected", return one row per cell with three columns, in
  this order, a row label, a column label and optionally a value. Use SELECT DISTINCT. Set chart to "grid".
  The dashboard builds the columns from the values it finds. A cell shows the value, or X when there is no
  value column. Example for routes by role, relating events from the same request
    SELECT DISTINCT r.capture AS route, c.capture AS role
    FROM events r JOIN events c ON r.run = c.run AND r.trace = c.trace
    WHERE r.sensor = 'get-routes' AND c.sensor = 'get-role' ORDER BY 1, 2
- The reports section lists the reports the user defined in their .jot files, which they may ask you to
  recreate or adapt. The types are
    list     rows are the code that called the instrumented method (call_site), one column for the sensor
             in cols, cells hold what it captured
    compare  rows are the captures of the rows sensor, columns come from the captures of the cols sensor,
             related when they share a run and trace. A capture written name:value gives the column
             name and the cell value, and a capture without a colon gives just the name with an X
    table    rows are the captures of the rows sensor, one column per sensor in cols, cells hold what
             that sensor captured, related by run and trace

Always answer by calling the report tool.
- title is a short heading for the result.
- chart is "grid" for a matrix as described above, "bar" when the result is a label column followed by
  a count or number, "line" when it is a time bucket column followed by a number, and otherwise "table".
- explanation is one or two plain sentences saying what the query shows and any assumption you made.
- If the question can't be answered from these tables, leave sql empty and say why in explanation.
"""

TOOL = {
    "name": "report",
    "description": "Return the query that answers the question.",
    "input_schema": {
        "type": "object",
        "properties": {
            "title": {"type": "string"},
            "sql": {"type": "string", "description": "One SQLite SELECT, or empty if it can't be answered"},
            "chart": {"type": "string", "enum": ["table", "bar", "line", "grid"]},
            "explanation": {"type": "string"},
        },
        "required": ["title", "sql", "chart", "explanation"],
    },
}


class LLMError(Exception):
    pass


def configured():
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


def tls_context():
    """The TLS settings for calling the model. Certificates and host names are fully checked.
    Python 3.13 added a stricter rule that rejects many company inspection proxy CAs, so that one
    flag is relaxed. JOT_DASHBOARD_CA_BUNDLE names a CA file to trust, for a proxy whose CA isn't
    already known to Python."""
    ctx = ssl.create_default_context(cafile=os.environ.get("JOT_DASHBOARD_CA_BUNDLE") or None)
    ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    return ctx


def api_url():
    return os.environ.get("JOT_DASHBOARD_API_URL", API_URL)


def model():
    return os.environ.get("JOT_DASHBOARD_MODEL", DEFAULT_MODEL)


def build_prompt(question, schema, sensors, history=(), error=None, reports=()):
    """The user message. Sensors is a list of dicts with name, description, methods, scopes, blocks."""
    lines = ["Tables", schema, "", "Sensors"]
    if sensors:
        for s in sensors:
            line = "- %s" % s["name"]
            if s.get("description"):
                line += ": " + s["description"]
            if s.get("methods"):
                line += " (watches %s)" % ", ".join(s["methods"])
            if s.get("scopes"):
                line += " (only inside %s)" % ", ".join(s["scopes"])
            if s.get("blocks"):
                line += " (blocks, message: %s)" % s["blocks"]
            lines.append(line)
    else:
        lines.append("(no sensor definitions were loaded, use the sensor values in the events table)")
    if reports:
        lines += ["", "Reports defined in the .jot files"]
        for r in reports:
            lines.append("- %s (%s, rows %s, cols %s)" % (r["name"], r["type"], r.get("rows_sensor") or "none", r.get("cols")))
    if history:
        lines += ["", "Earlier in this conversation, oldest first"]
        for h in history[-5:]:
            lines.append("Q: %s" % h.get("question", ""))
            if h.get("sql"):
                lines.append("SQL: %s" % h["sql"])
    lines += ["", "Question: %s" % question]
    if error:
        lines += ["", "Your previous SQL failed with this error. Fix it.", error]
    return "\n".join(lines)


def generate(question, schema, sensors, history=(), error=None, timeout=60, reports=()):
    """Ask the model. Returns {"title", "sql", "chart", "explanation"}."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise LLMError("ANTHROPIC_API_KEY is not set, so natural language questions are turned off. "
                       "You can still write SQL yourself.")
    body = {
        "model": model(),
        "max_tokens": 1500,
        "system": SYSTEM,
        "messages": [{"role": "user", "content": build_prompt(question, schema, sensors, history, error, reports)}],
        "tools": [TOOL],
    }
    req = urllib.request.Request(api_url(), data=json.dumps(body).encode(), method="POST", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as resp:
            data = json.load(resp)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.load(e).get("error", {}).get("message", "")
        except Exception:
            pass
        raise LLMError("the model API returned %d. %s" % (e.code, detail))
    except (urllib.error.URLError, TimeoutError) as e:
        raise LLMError("could not reach the model API: %s" % e)

    for block in data.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "report":
            out = block.get("input") or {}
            return {
                "title": str(out.get("title") or question)[:200],
                "sql": str(out.get("sql") or "").strip(),
                "chart": out.get("chart") if out.get("chart") in ("table", "bar", "line", "grid") else "table",
                "explanation": str(out.get("explanation") or ""),
            }
    raise LLMError("the model did not return a query")
