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
    SELECT DISTINCT json_extract(r.data, '$.path') AS route, json_extract(c.data, '$.role') AS role,
           json_extract(c.data, '$.allowed') AS value
    FROM events r JOIN events c ON r.run = c.run AND r.trace = c.trace
    WHERE r.sensor = 'http-route' AND c.sensor = 'auth-role-check' ORDER BY 1, 2
  (a sensor captures named fields, and the events table keeps them in data as JSON. Read one with
  json_extract(data, '$.field'). A field that is a list is a JSON array, use json_each(data, '$.field') for one row per item.
  The sensors list names each sensor's fields. capture is the same values as one line of text)
- The reports section lists the reports the user defined in their .jot files, which they may ask you to
  recreate or adapt. The types are
    list     rows are the code that called the instrumented method (call_site), one column for the sensor
             in cols, cells hold what it captured
    compare  rows are the values of the rows field, columns are the values of the cols field, and cells hold
             the value field, or an x, related when they share a run and trace. With by, a fourth column of who had
             each value, which the grid shows like true (UserB), naming them for true and not for false
    table    rows are the values of the rows field, one column per field in cols, cells hold that field,
             related by run and trace
  Rows, cols and value are written sensor.field, like http-route.path.

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
            if s.get("fields"):
                line += " (fields %s)" % ", ".join(s["fields"])
            if s.get("blocks"):
                line += " (a rule, blocks every call)" if s["blocks"] == "true" else " (a rule, blocks when: %s)" % s["blocks"]
            lines.append(line)
    else:
        lines.append("(no sensor definitions were loaded, use the sensor values in the events table)")
    if reports:
        lines += ["", "Reports defined in the .jot files"]
        for r in reports:
            lines.append("- %s (%s, rows %s, cols %s%s)" % (r["name"], r["type"], r.get("rows_sensor") or "none", r.get("cols"),
                                                          (", value %s" % r["value"] if r.get("value") else "") + (", by %s" % r["by"] if r.get("by") else "")))
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


def _post(body, timeout):
    """Calls the model API and returns its answer. Raises LLMError with a reason that makes sense to the user."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key:
        raise LLMError("ANTHROPIC_API_KEY is not set, so natural language questions are turned off. "
                       "You can still write SQL yourself.")
    req = urllib.request.Request(api_url(), data=json.dumps(body).encode(), method="POST", headers={
        "x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=tls_context()) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = json.load(e).get("error", {}).get("message", "")
        except Exception:
            pass
        raise LLMError("the model API returned %d. %s" % (e.code, detail))
    except (urllib.error.URLError, TimeoutError) as e:
        raise LLMError("could not reach the model API: %s" % e)


def generate(question, schema, sensors, history=(), error=None, timeout=60, reports=()):
    """Ask the model. Returns {"title", "sql", "chart", "explanation"}."""
    body = {
        "model": model(),
        "max_tokens": 1500,
        "system": SYSTEM,
        "messages": [{"role": "user", "content": build_prompt(question, schema, sensors, history, error, reports)}],
        "tools": [TOOL],
    }
    data = _post(body, timeout)

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


# ------------------------------------------------------------------ drafting a JOT

JOT_SYSTEM = r"""You write JOTs for JOT, a Java agent that watches methods of a running application. A JOT is a sensor, which
records what it sees, or a rule, which also blocks or reports a call. You write one JOT as YAML, for what the user asks.

The YAML is one mapping, with no sensors: list around it. These are all the keys it can have, and nothing else is allowed.

  name          required. Lower case words joined with -, domain first, like crypto-cipher, http-cookie-set, sql-statement,
                file-path, net-url, native-process. A rule is named for what it guards, a sensor for what it records.
  description   what the JOT identifies, written to start with Identifies, like "Identifies starting a native process" or
                "Identifies a cookie being set and whether it is Secure and HttpOnly". Never start with Records or Detects. It is
                also the message of a rule, so it says what was found, in words that are as true when the call is blocked as when it
                is only reported.
  methods       required. The methods to watch, each written package.Class.method, with <init> for a constructor, like
                java.io.FileOutputStream.<init> or java.security.MessageDigest.getInstance. That is the whole syntax. Never write
                static, public, a parameter list or a return type, they are not part of the name, and static and instance methods
                are matched the same way. Every overload of the method is watched. @package.Annotation is also allowed, it means
                every method that carries that annotation. Servlet methods are written twice, once with javax and once with jakarta,
                like javax.servlet.http.HttpServletResponse.addCookie and jakarta.servlet.http.HttpServletResponse.addCookie.
  scopes        usually leave this out. A JOT with no scopes applies only while the application is running, which the jots file
                defines once, so it already ignores startup and background threads. Write scopes only to limit a JOT to the code
                around one library method, like a CVE rule inside the vulnerable method, and scopes: [] to apply everywhere. A JOT
                with scopes also reports once that its scope was active.
  excludes      optional. Classes to ignore.
  captures      what to record, as a mapping of a field name to an expression in the Spring expression language. A field name is
                lower case words joined with _, like path or remote_ip. The expressions use these variables.
                #P0 #P1 and so on are the arguments, #ARGS all of them, #OBJ the object the method is called on, #RET the
                return value, #CALLER the calling method, #STACK the stack. Record each thing as its own field, a name and a
                result as name and value, a host and a port as host and port, and add facts the method can tell, like
                exists: "#P0.exists()". A number or a boolean stays one, and a list becomes a list of its items.
                #RET only exists after the method returns, so a rule should not use it, it would block too late.
                Never capture secrets. Record lengths, names and algorithms, not keys, passwords or tokens. Never use T( or new
                in an expression.
  matchers      optional. A mapping of a captured field to a list of regular expressions that the text of that field is searched
                with. It is a search and not a full match, so write ^ and $ only to anchor to the text. A leading ! excludes.
                (?i) makes it case insensitive. Every field that has matchers has to pass for the call to be recorded, and for a
                list field the items that match are kept.
  block-when    makes it a rule. true blocks every call that gets that far, or an expression over the same variables that is
                true when the call is bad, like '#P0 < 2048'. Without it the JOT only records.
  protect       false for a rule that only reports until the person turns it on. Always write protect: false in a new rule.
  enabled, debug   true or false, almost never needed.

What a capture looks like to a matcher
- A String, number, boolean, character, enum, File, Path, URI or URL is recorded as its plain text, a File as its path, and
  a matcher looks at that text.
- Any other object is recorded as {class the.Name:its text}, so a matcher anchored with $ would not match it. Call a method for
  what you want instead, like #P0.getName(), or #P0.toString().
- A method with overloads can take different types in the same position, like File, Path or String as #P0. Write the capture so
  it works for all of them, and think about which overloads the application is likely to call.

Choosing the methods
- A watched method that calls another watched method is reported twice. Watch the lowest-level method that every path goes through.
  Files.write and Files.newBufferedWriter both call Files.newOutputStream, and FileWriter calls the FileOutputStream constructor, so
  to see files being written, watch java.io.FileOutputStream.<init> and java.nio.file.Files.newOutputStream and nothing above them.
- Do not invent methods. Use ones you are sure exist in the JDK or in the library the person named, or that appear in the list
  of methods already seen in their application. If you are not sure, say so in the explanation and use the closest one you do know.
- Do not repeat a name that is already in use.

Writing the YAML
- Write a value plain when you can. Quote it when it starts with #, !, *, [, {, a quote or a dash, or contains a colon followed
  by a space. A capture that starts with # always needs quotes, and so does a matcher that starts with !.
- Quote with double quotes, like "#P0" and "!null". Use single quotes only when the value itself contains a double quote or a
  backslash, like '#P0 == 1 ? "encrypt" : "other"' and '!\.class', because in single quotes a backslash stays a backslash.
- A rule needs a description and a block-when. A sensor needs at least one capture, written as field: expression.

Examples that were run against a real application and did what they say

name: file-log-write
description: Identifies a log file being opened for writing
methods:
- java.io.FileOutputStream.<init>
- java.nio.file.Files.newOutputStream
captures:
  path: "#P0.toString()"
matchers:
  path:
  - (?i)\.log(\.\d+)?$

name: http-cookie-set
description: Identifies a cookie being set and whether it is Secure and HttpOnly
methods:
- javax.servlet.http.HttpServletResponse.addCookie
- jakarta.servlet.http.HttpServletResponse.addCookie
captures:
  name: "#P0.getName()"
  secure: "#P0.getSecure()"
  http_only: "#P0.isHttpOnly()"

name: native-process
description: Identifies starting a native process
methods:
- java.lang.ProcessBuilder.<init>
captures:
  command: "#ARGS"
block-when: true
protect: false

Always answer by calling the draft tool. The explanation is two to four plain sentences saying what the JOT watches, what it
records or blocks, and any assumption you made or thing the person should check, such as an argument number or an overload.
If the request can't be done with a JOT, leave yaml empty and say why in the explanation.
"""

JOT_TOOL = {
    "name": "draft",
    "description": "Return the JOT that does what was asked.",
    "input_schema": {
        "type": "object",
        "properties": {
            "yaml": {"type": "string", "description": "One JOT as a YAML mapping, with no sensors: list, or empty if it can't be done"},
            "explanation": {"type": "string"},
        },
        "required": ["yaml", "explanation"],
    },
}


def build_jot_prompt(request, sensors, methods, history=(), problems=None):
    """The user message for drafting a JOT. sensors are the ones already defined, methods are the instrumented methods seen in the
    application's own log, by name only. No captured values and no event data are sent."""
    lines = ["JOTs already defined, so don't repeat a name"]
    if sensors:
        for s in sensors:
            line = "- %s" % s["name"]
            if s.get("description"):
                line += ": " + s["description"]
            if s.get("methods"):
                line += " (watches %s)" % ", ".join(s["methods"][:4])
            lines.append(line)
    else:
        lines.append("(none)")
    if methods:
        lines += ["", "Methods the application has been seen calling that a JOT watches", ", ".join(methods)]
    if history:
        lines += ["", "Earlier in this conversation, oldest first"]
        for h in history[-3:]:
            lines.append("Request: %s" % h.get("request", ""))
            if h.get("yaml"):
                lines.append("Your draft:\n%s" % h["yaml"])
    lines += ["", "Request: %s" % request]
    if problems:
        lines += ["", "Your draft has these problems. Fix them and answer again.", *["- " + p for p in problems]]
    return "\n".join(lines)


def draft_jot(request, sensors, methods, history=(), problems=None, timeout=90):
    """Ask the model for a JOT. Returns {"yaml", "explanation"}."""
    body = {
        "model": model(),
        "max_tokens": 1800,
        "system": JOT_SYSTEM,
        "messages": [{"role": "user", "content": build_jot_prompt(request, sensors, methods, history, problems)}],
        "tools": [JOT_TOOL],
    }
    data = _post(body, timeout)
    for block in data.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == "draft":
            out = block.get("input") or {}
            return {"yaml": str(out.get("yaml") or "").strip("\n"), "explanation": str(out.get("explanation") or "")}
    raise LLMError("the model did not return a JOT")
