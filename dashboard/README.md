# JOT Dashboard

A small web app that follows JOT's JSON event logs into SQLite and lets you ask questions about them,
in plain English or SQL. Answers are tables and charts, and they can update live as events arrive or be
run later against the history.

## Quick start

Run your application with JOT writing JSON events.

    java -Djot.output=json -Djot.output.file=/var/log/jot/app.jsonl -javaagent:jot.jar=jots/ -jar app.jar

Then start the dashboard and open http://localhost:8765.

    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=...        # only needed for natural language questions
    python3 server.py --log /var/log/jot/app.jsonl --jot ../src/main/resources

Instead of exporting the key you can keep it in `dashboard/.env`, which git ignores and the server reads at
startup. Copy `.env.example`, fill it in, and run `chmod 600 .env`. A variable set in your shell wins over the file.

Without a key the dashboard still works. The preset views and the SQL box don't use a model.

| Option | Description |
|--------|-------------|
| `--log` | JSON event log to follow. May be a glob such as `'logs/*.jsonl'`, and may be given more than once. Default `jot-events.jsonl` |
| `--jot` | A `.jot` file or a directory of them. The sensor names and descriptions help the model understand your questions. May be given more than once |
| `--db` | SQLite file that holds the events. Default `jot-dashboard.db`. Delete it to start fresh |
| `--app` | A package of your application, like `com.acme`. May be given more than once. See App events only below |
| `--since` | Show only events from this time on. `now`, or a date and time like `2026-10-16T09:30`. Nothing is deleted |
| `--control` | Control file agents poll, to switch rules between monitor and block. See below |
| `--port`, `--host` | Where to listen. Default `127.0.0.1:8765`. See the note on access below |

Environment variables are `ANTHROPIC_API_KEY`, `JOT_DASHBOARD_MODEL` (default `claude-sonnet-5-5`) and
`JOT_DASHBOARD_API_URL` if requests have to go through a gateway. If your network inspects TLS and the
model call fails with a certificate error, set `JOT_DASHBOARD_CA_BUNDLE` to the path of your company's CA file.

## Asking questions

Type a question like "which call sites triggered blocked events today?" or "how many cipher events per
minute?". The dashboard shows the result, a one line explanation, and the SQL that produced it, which you
can edit and run again. A question you have asked appears as a button, and clicking it re-runs its saved SQL
without asking the model again.

Turn on **Live** and the current result refreshes every few seconds, along with the event feed on the right.
Turn it off and the view stays put while you look at it.

Events from several applications can share one dashboard. Each event records its host, process and
application, and events with the same `run` and `trace` came from the same request.

## The path graph

The **Graph** tab draws every path the application took, built from the events of each request. A path starts at
the route of the request on the left, goes through the application methods that were running, and ends at what a
sensor saw, like a cipher, a query, a file or a blocked call. A forward or a redirect goes on to the route it names,
shown at the far right as an exit. Lines get wider with the number of events, and a node shows its count.

Click a node to follow its paths, everything that does not lead to or from it fades. The panel beside the graph shows
what the node captured, where it comes from and where it leads, and **Show these events** opens them in a search.
A picked node has its own address, like `#graph/effect%3Aget-ciphers`. The Route box shows the paths of one route.

Only your application's code is drawn, as set by `--app`, so the JDK, the server and libraries don't clutter it. Sensors
that only describe the request, like who the user was, are left out unless you tick **Include request details**. The
graph follows Clear and App events only, and it redraws by itself when new events arrive. The stack of an event is cut
at `jot.output.stack` frames, 25 by default, so an older event may be missing the outer methods. TicketBook records 500.

## Searching and refreshing

The search box under the question box finds individual events, newest first, and each row opens in the event viewer.
Every word has to match somewhere in the event, in its capture, message, sensor, call site or stack, so `rsa`
finds anything with RSA in it and `hash jar` needs both. Put quotes around a phrase, and a leading `-` leaves out
what follows, like `-jasper`. A `field:value` narrows to one field. The fields are `sensor` (contains), `action`,
`origin`, `app`, `run` and `host` (exact), and `trace` and `pid` (a number). For example `sensor:get-hashes action:observed -jasper`.
The search honors Clear and App events only, and says how many more matches the filter left out.

**Refresh** fetches the latest events now, and the time beside it says when the page last fetched. With
**Refresh every 3 seconds** ticked, which is the default, the current view and the counts are fetched every 3 seconds.
With it unticked only the counts update, every 6 seconds, and the view waits for the button.

## Clearing

The **Clear** button on the Events page hides everything recorded so far, so the views, charts, reports, rule counts
and questions only reflect what happens from that moment on. **Show all** brings it back. The stats line says when
you cleared and how many earlier events are hidden.

Nothing is deleted. Clearing sets a start time that is kept in the database, so it survives a restart and applies to
everyone looking at this dashboard. Internally the table of events is called `events_raw`, and `events`, which every query
reads, is a view over it that applies the start time. An older database is converted the first time the dashboard
starts on it, and keeps all its events. Start with `--since now` to begin clear, or delete the database file to start
completely fresh, after which it is rebuilt from the whole log.

## App events only

The JDK and the application server do plenty on their own, like checking the signature of a jar they load, and
JOT's sensors see all of it. The **App events only** box, on by default, leaves those out. An observed event stays
when any frame of its stack is code from your application, even with libraries in between. So a hash made by
`hsqldb` on behalf of `com.acme.Ticket` stays, and the same hash made while Tomcat starts up doesn't.

Each event is tagged as it is stored, so the filter is cheap and the model and the SQL box can use it too.

| Column | Meaning |
|--------|---------|
| `origin` | `app` when a frame is application code, `library` when the stack has libraries but nothing of yours, `platform` when it is all JDK and server, `none` when the event has no stack |
| `app_frame` | The innermost frame of the application, like `com.acme.Ticket.encrypt(Ticket.java:125)` |

Which code is yours comes from `--app`, for example `--app com.acme --app org.apache.jsp` (Tomcat compiles a page to
`org.apache.jsp`, which is your code). Without it, anything that isn't the JDK or the server counts as yours, and
nothing is tagged `library`. A servlet's `service` method counts as the application, since the container calls it
on the application's behalf, which keeps the route and user sensors. Blocked and reported events are never left out.
The stats line says how many events are left out, and unticking the box brings them back. Nothing is deleted.
If you change `--app` the stored events are tagged again at the next start.

## What the model sees

The model is sent the table definitions, the sensor names and descriptions, your question, and the SQL of
your last few questions. It is never sent event rows or captured values. The SQL runs on this machine and
the results go straight to your browser. This matters because captures can contain secrets, tokens and
customer data. If a query fails, the database's error message goes back to the model so it can fix the SQL,
and that message has no data in it.

## Safety of the queries

The model's SQL is untrusted. Every query, whether it came from the model or from you, runs on a
connection that SQLite itself restricts to reading. Writes, `ATTACH`, `PRAGMA` and extension loading are
refused by the database, not by checking the text. Queries are stopped after five seconds and return at most
1000 rows.

Captured values come from your application's inputs and may be attacker controlled. The page only ever
displays them as text.

## Switching rules between monitor and block

Start the dashboard with `--control /path/to/control.json` and `JOT_DASHBOARD_ADMIN_TOKEN` set, and start each
application with `-Djot.control=/path/to/control.json`. The Enforcement panel then lists every rule, meaning every
sensor that has an `exception`, with a Monitor and a Block button, a master switch that makes all rules report only,
and how many violations each saw in the last hour. It also shows which changes agents have confirmed applying, taken
from the `jot-control` events in their logs.

Agents pull this. The dashboard writes the file and the agent reads it once a second. Nothing connects to an agent and
agents accept no connections. The agent and the dashboard must share the file, so this suits one machine or a shared
volume. Because anyone who can change the file can switch protection off, changes need the admin token (typed into the
page, never stored), five wrong tokens lock changes for a minute, the file is replaced atomically, and every change is
logged with before and after in `<control file>.audit`. Without the token variable the panel is read only.

The panel shows what the file says. An agent started with `-Djot.enforce=false` ignores it.

## Access

The server has no login. It listens on localhost and rejects requests whose Host header is something else,
and it rejects posts that didn't come from its own page, which protects against other websites in your
browser reaching it. If you listen on another address, anyone who can reach the port can read every event,
so only do that on a network you trust.

## Data model

Two tables are exposed to queries. `events` has one row per event with the fields documented in the JOT
README, plus `method_name` and `call_site_name`, which are the method and caller without module or line
numbers. `sensors` has the name, description and methods of each sensor loaded from your `.jot` files.
Open the SQL box on any result and try `SELECT * FROM events LIMIT 5`.

Reports translate naturally into queries over `events`. For example the JOT "compare" report is a join of two
sensors' events on `run` and `trace`.

## Tests

    python3 -m unittest discover -s tests
