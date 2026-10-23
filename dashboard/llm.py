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


# The model thinks before it answers, and what it thinks counts against max_tokens. A limit that is only as big as the answer lets a hard
# request spend it all thinking and stop before the answer is written, so there is room for both. A request that finishes early costs
# only what it used.
MAX_TOKENS = 16000


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


def _answer(data, tool, what):
    """What the model passed to the tool, or an LLMError that says why there is nothing. A reply that ran out of room has a tool call
    that stops part way, which is nothing, and one the model declined has none."""
    stop = data.get("stop_reason")
    if stop == "max_tokens":
        raise LLMError("the model ran out of room before it finished the %s, so nothing was made. Try a shorter or simpler request" % what)
    if stop == "refusal":
        raise LLMError("the model declined to write the %s" % what)
    for block in data.get("content", []):
        if block.get("type") == "tool_use" and block.get("name") == tool:
            return block.get("input") or {}
    raise LLMError("the model did not return a %s" % what)


def _drafted(out, what):
    """A draft as {"yaml", "explanation"}. A draft with neither is not an answer, and the page would show an empty message, so it is an error."""
    text = str(out.get("yaml") or "").strip("\n")
    explanation = str(out.get("explanation") or "")
    if not text and not explanation:
        raise LLMError("the model sent back an empty %s, try asking again" % what)
    return {"yaml": text, "explanation": explanation}


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


def generate(question, schema, sensors, history=(), error=None, timeout=180, reports=()):
    """Ask the model. Returns {"title", "sql", "chart", "explanation"}."""
    body = {
        "model": model(),
        "max_tokens": MAX_TOKENS,
        "system": SYSTEM,
        "messages": [{"role": "user", "content": build_prompt(question, schema, sensors, history, error, reports)}],
        "tools": [TOOL],
    }
    out = _answer(_post(body, timeout), "report", "query")
    return {
        "title": str(out.get("title") or question)[:200],
        "sql": str(out.get("sql") or "").strip(),
        "chart": out.get("chart") if out.get("chart") in ("table", "bar", "line", "grid") else "table",
        "explanation": str(out.get("explanation") or ""),
    }


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
                An expression can call these functions, which take a String, an array, a list or null alike. Use them in place of T(.
                  #matches(x, "regex")   true when x, or any item of it, has a match for the pattern anywhere in it, like a matcher.
                  #matching(x, "regex")  the items of x that have a match, as they are.
                  #list(x)               x as a list. An array has to go through this before .?[...] and .![name] give a list,
                                         since selecting from an array or projecting it gives an array, which is recorded as text.
                                         A request's cookies are #list(#P0.cookies), and null for none is an empty list.
                  #luhn(x)               true when x, or any item of it, is a card number, 13 to 19 digits with the right check digit.
                  #kind(x)               what sort of sensitive value x is, or null. ssn for a social security number, card for a card
                                         number that passes the check, jwt for a web token and token for 32 or more letters and digits,
                                         like a session id or an api key. For several items it is the first that has a kind.
                  #toLower(x) #toUpper(x)  change the case of a String.
                A capture that is a list with nothing in it records nothing at all, not even what the other captures found. That is how a
                JOT stays quiet for a request with nothing to report. It also means a JOT that should report either of two lists, like
                parameters or cookies, has to be two JOTs, since each stays quiet when its own list is empty.
  matchers      optional. A mapping of a captured field to a list of regular expressions that the text of that field is searched
                with. It is a search and not a full match, so write ^ and $ only to anchor to the text. A leading ! excludes.
                (?i) makes it case insensitive. Every field that has matchers has to pass for the call to be recorded, and for a
                list field the items that match are kept.
  block-when    makes it a rule. true blocks every call that gets that far, or an expression over the same variables that is
                true when the call is bad, like '#P0 < 2048'. Without it the JOT only records.
  protect       false for a rule that only reports until the person turns it on. Always write protect: false in a new rule.
  enabled, debug   true or false, almost never needed.

Reaching data the watched method doesn't hand you
- A JOT only records when a method it watches is called, so watch a method the application does call and walk to the data from there. Never
  watch a method only because it is where the data lives. The application may never call it, like DatabaseMetaData.getTables in an
  application that never asks for metadata, and the JOT would stay silent for ever. Look at the methods already seen in the application first.
- The expression is Spring expression language, so it can walk from #OBJ, #P0 and so on, and #RET, calling a method or reading a property at each
  step. On a java.sql.Statement method, #OBJ.getConnection().getMetaData().getDatabaseProductName() is the database the query ran against. On
  java.sql.Connection.prepareStatement, #OBJ.getMetaData().getURL() is the database URL. Use ?. at a step that can be null, like
  #RET?.getName(). Prefer the methods a JDK interface defines, like getConnection and getMetaData, over a driver's own classes, which may not
  be public.
- Start from the object closest to what is wanted. #OBJ is what the method was called on, #P0 and #P1 are what it was given, and #RET is what it
  returned, which only exists after the method returns. Watching a method that returns the thing, like Connection.getMetaData, is another way,
  but only when the application calls it.
- Look at what every object in reach can tell, not just the first one. The return value is an object with facts of its own. executeQuery returns a
  ResultSet, and #RET.getMetaData() has getColumnCount(), getColumnLabel(i), getTableName(i) and getColumnTypeName(i), and #RET.getType() and
  #RET.getFetchSize() say how it can be read. The statement is #OBJ, with getQueryTimeout() and getMaxRows(), and behind it #OBJ.getConnection() has
  getAutoCommit(), getTransactionIsolation(), isReadOnly(), getSchema() and getMetaData().getDatabaseProductName(). The same goes for any call, an
  HTTP request has headers and a session, a file has a size, and a cipher has an algorithm and a key length. When different facts come from different
  objects, write more than one sensor on the same method, one for each, and say what each of them gives.
- The expression language has no loop over a number, so to record a fact for each column, write the positions you could want, keep those that are
  there, and project them, like {1,2,3,4,5,6,7,8}.?[#this <= #RET.getMetaData().getColumnCount()].![#RET.getMetaData().getColumnLabel(#this)]. That
  gives the names of the first eight columns, and only the ones the result has. #RET and the other variables can be used inside the brackets.
- An expression runs on the application's thread every time the watched method is called, so walk only through cheap getters that change
  nothing and ask nothing of a database or a stream. getDatabaseProductName, getURL and getUserName are fine. getTables, getColumns,
  ResultSet.next, reading a stream and using up an Enumeration are not, they cost a query or change what the application sees next.
- An expression that fails, because a step is null or the library doesn't support it, records nothing for that field and the other fields are
  still recorded. The agent's log says why. After proposing a sensor that walks, say which field to look at and ask the person to check that it
  is filled once the method has been called.

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

name: sql-database
description: Identifies a prepared statement and the database it is for
methods:
- java.sql.Connection.prepareStatement
captures:
  sql: "#P0"
  database: "#OBJ.getMetaData().getDatabaseProductName()"
  url: "#OBJ.getMetaData().getURL()"

name: sql-result
description: Identifies the shape of what a query returned, its columns and where they came from
methods:
- java.sql.Statement.executeQuery
captures:
  sql: "#P0"
  column_count: "#RET.getMetaData().getColumnCount()"
  columns: "{1,2,3,4,5,6,7,8}.?[#this <= #RET.getMetaData().getColumnCount()].![#RET.getMetaData().getColumnLabel(#this)]"
  first_table: "#RET.getMetaData().getTableName(1)"

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


def draft_jot(request, sensors, methods, history=(), problems=None, timeout=180):
    """Ask the model for a JOT. Returns {"yaml", "explanation"}."""
    body = {
        "model": model(),
        "max_tokens": MAX_TOKENS,
        "system": JOT_SYSTEM,
        "messages": [{"role": "user", "content": build_jot_prompt(request, sensors, methods, history, problems)}],
        "tools": [JOT_TOOL],
    }
    return _drafted(_answer(_post(body, timeout), "draft", "JOT"), "JOT")


# ------------------------------------------------------------------ drafting a report

REPORT_SYSTEM = r"""You write reports for the JOT dashboard. JOTs are sensors and rules that record what happens in a running Java
application. A report tabulates what they recorded. You write one report as YAML, for what the user asks, using only the JOTs
and captured fields you are given.

The YAML is one mapping, with no reports: list around it. These are all the keys it can have, and nothing else is allowed.

  name    required. Words for a person to read, like "Encryption Usage" or "Routes by role". Never repeat a name that is already used.
  type    required. list, compare or table, described below.
  rows    what the rows are, written sensor.field, like http-route.path. Required for compare and table, not used by list.
  cols    required. What the columns are, written sensor.field. One reference for list and compare, and for table one or more
          separated by commas, like cols: "http-cookie-set.name, http-cookie-set.secure".
  value   compare only, optional. The field that fills the cells, written sensor.field, of the same sensor as cols.
  by      compare only, optional, and only together with value. A field of the same sensor as cols that names who had each value, so
          a cell shows like true (UserB).

What a reference is. sensor.field is a field the sensor captures, and only the fields listed for that sensor in the JOTs you
were given exist. Never invent a sensor or a field. A bare sensor name means everything it captured as one line, which is a
last resort when no single field is what the person means.

The types
  list     One row for each piece of code that called the instrumented method, shown as the call site. One column, the field in
           cols. Cells hold the values of that field. Use it for "where is X used and what with", like where ciphers are used and
           which algorithm. Only the cols sensor matters.
  compare  Rows are the values of the rows field, columns are the values of the cols field. A cell holds the value field, or an x
           when there is no value. Use it for a matrix, like routes against roles. The rows sensor and the cols sensor have to
           be seen in the same request, so choose two sensors that run in the same request. The usual rows are an http-route
           sensor's path.
  table    Rows are the values of the rows field, with one column for each field in cols, from sensors seen in the same request
           as the rows. Use it for several facts about each row, like each route with its cookies and their flags.
           A column of a table can instead be a total. #total(sensor.field) adds up the field over every event, and #count(sensor),
           #count(sensor.field), #average(sensor.field), #min(sensor.field) and #max(sensor.field) do what they say. They can be
           added, subtracted, multiplied and divided with parentheses, like #total(a.x) / #count(a), and mixed with plain columns.
           Always quote cols when it has one, because # starts a comment in YAML, like
           cols: "#count(ai-model-call), #total(ai-model-call.input_tokens), ai-model-call.finish_reason".
           Use them for how many and how much, like tokens by model. Only a table can have them, and nothing else of Spring EL works.

Choosing
- Prefer the type that answers the question most directly. Where is something used is a list, who can do what is a compare,
  everything about each thing is a table.
- When the person names a field or a sensor, use exactly that. When they describe something, choose from the fields you were given
  by name and description.
- Write a reference as plain text. Quote the value when it contains a comma or a colon.
- If what is asked for needs data that no listed JOT captures, do not stretch to the closest field. Leave yaml empty, say what is
  missing and which JOT would capture it, so the person can make it with New JOT first.

Examples that were run against a real application and did what they say

name: Encryption Usage
type: list
cols: crypto-cipher.algorithm

name: Route role checks
type: compare
rows: http-route.path
cols: auth-role-check.role
value: auth-role-check.allowed

name: Route cookies
type: table
rows: http-route.path
cols: "http-cookie-set.name, http-cookie-set.secure, http-cookie-set.http_only"

Always answer by calling the draft tool. The explanation is two to four plain sentences saying what the report shows, which JOTs and
fields it reads, and any assumption you made or thing the person should check, such as sensors that must be seen in the same request.
"""

REPORT_TOOL = {
    "name": "draft",
    "description": "Return the report that shows what was asked.",
    "input_schema": {
        "type": "object",
        "properties": {
            "yaml": {"type": "string", "description": "One report as a YAML mapping, with no reports: list, or empty if it can't be done"},
            "explanation": {"type": "string"},
        },
        "required": ["yaml", "explanation"],
    },
}


def build_report_prompt(request, sensors, reports, history=(), problems=None):
    """The user message for drafting a report. sensors are the JOTs that are defined, each with the fields it captures, and reports
    are the names of the reports that exist. Only definitions are sent, no captured values and no event data."""
    lines = ["JOTs you can use, and the fields each captures"]
    if sensors:
        for s in sensors:
            line = "- %s" % s["name"]
            if s.get("description"):
                line += ": " + s["description"]
            line += " (fields %s)" % (", ".join(s["fields"]) if s.get("fields") else "none, only a bare name works")
            lines.append(line)
    else:
        lines.append("(none are defined)")
    lines += ["", "Report names already used", ", ".join(reports) if reports else "(none)"]
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


def draft_report(request, sensors, reports, history=(), problems=None, timeout=180):
    """Ask the model for a report. Returns {"yaml", "explanation"}."""
    body = {
        "model": model(),
        "max_tokens": MAX_TOKENS,
        "system": REPORT_SYSTEM,
        "messages": [{"role": "user", "content": build_report_prompt(request, sensors, reports, history, problems)}],
        "tools": [REPORT_TOOL],
    }
    return _drafted(_answer(_post(body, timeout), "draft", "report"), "report")
