# JOT Dashboard

A small web app that follows JOT's JSON event logs into SQLite and lets you ask questions about them,
in plain English or SQL. Answers are tables and charts, and they can update live as events arrive or be
run later against the history.

## Quick start

Run your application with JOT writing JSON events.

    java -Djot.output=json -Djot.output.file=/var/log/jot/app.jsonl -javaagent:jot.jar=jots.yaml -jar app.jar

Then start the dashboard and open http://localhost:8765.

    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=...        # only needed for natural language questions
    python3 server.py --log /var/log/jot/app.jsonl --jots ../demo/ticketbook/jots.yaml

Instead of exporting the key you can keep it in `dashboard/.env`, which git ignores and the server reads at
startup. Copy `.env.example`, fill it in, and run `chmod 600 .env`. A variable set in your shell wins over the file.

Without a key the dashboard still works. The preset views and the SQL box don't use a model.

| Option | Description |
|--------|-------------|
| `--log` | JSON event log to follow. May be a glob such as `'logs/*.jsonl'`, and may be given more than once. Default `jot-events.jsonl` |
| `--jots` | The jots file that lists the JOTs and the control file. Start each agent with `-javaagent:jot.jar=<this path>`, so the agent and the dashboard use the same definitions |
| `--db` | SQLite file that holds the events. Default `jot-dashboard.db`. Delete it to start fresh |
| `--app` | A package of your application, like `com.acme`. May be given more than once, and adds to `app: packages:` in the jots file. See App events only below |
| `--since` | Show only events from this time on. `now`, or a date and time like `2026-10-16T09:30`. Nothing is deleted |
| `--port`, `--host` | Where to listen. Default `127.0.0.1:8765`. `--allow-remote` is needed for any other host, see the note on access below |

Environment variables are `ANTHROPIC_API_KEY`, `JOT_DASHBOARD_MODEL` (default `claude-sonnet-5-5`) and
`JOT_DASHBOARD_API_URL` if requests have to go through a gateway. If your network inspects TLS and the
model call fails with a certificate error, set `JOT_DASHBOARD_CA_BUNDLE` to the path of your company's CA file.

## Asking questions

Type a question like "which call sites triggered blocked events today?" or "how many cipher events per
minute?". The dashboard shows the result, a one line explanation, and the SQL that produced it, which you
can edit and run again. A question you have asked appears as a button, and clicking it re-runs its saved SQL
without asking the model again.

A sensor captures named fields, and each event keeps them in its `data` column as JSON. In SQL read one with
`json_extract(data, '$.path')`, and use `json_each(data, '$.names')` for a field that is a list. The `capture` column
is the same values as one line of text. The event drawer shows each field by name.

The current result refreshes every 3 seconds on its own, along with the event feed on the right. A result whose SQL you have open
to edit is left alone until you close it.

Events from several applications can share one dashboard. Each event records its host, process and
application, and events with the same `run` and `trace` came from the same request.

## The path graph

The **Graph** tab draws every path the application took, built from the events of each request. A path starts at
the route of the request on the left, goes through the application methods that were running, and ends at what a
sensor saw, like a cipher, a query, a file or a blocked call. A forward or a redirect goes on to the route it names,
shown at the far right as an exit. Lines get wider with the number of events, and a node shows its count.

Click a node to follow its paths, everything that does not lead to or from it fades. The panel beside the graph shows
what the node captured, where it comes from and where it leads, and **Show these events** opens them in a search.
A picked node has its own address, like `#graph/effect%3Acrypto-cipher`. The Route box shows the paths of one route.

Only your application's code is drawn, as set by `app: packages:` in the jots file, so the JDK, the server and libraries don't clutter it. Sensors
that only describe the request, like who the user was, are left out unless you tick **Include request details**. The
graph follows Clear and App events only, and it redraws by itself when new events arrive. The stack of an event is cut
at `jot.output.stack` frames, 25 by default, so an older event may be missing the outer methods. TicketBook records 500.

**Blocked** and **Monitored** in the toolbar limit the page to events where a rule blocked a call, or where a rule reported that it would have and let the call go ahead. Tick one, or both to see both. With neither ticked everything shows. They apply to the views, the search and the counts, and they are off until you tick them.

**JOT control events** shows the events the agent writes when a rule is switched between monitor and protect. They are left out by default. The Protection panel still lists the latest changes whatever this is set to.

## Searching

The search box under the question box finds individual events, newest first, and each row opens in the event viewer.
Every word has to match somewhere in the event, in its capture, message, sensor, call site or stack, so `rsa`
finds anything with RSA in it and `hash jar` needs both. Put quotes around a phrase, and a leading `-` leaves out
what follows, like `-jasper`. A `field:value` narrows to one field. The fields are `sensor` (contains), `action`,
`origin`, `app`, `run` and `host` (exact), `route` (the route the request came in at, exact), and `trace` and `pid` (a number). For example `sensor:crypto-hash action:observed -jasper`.
The search honors Clear, App events only, Blocked and Monitored, and says how many more matches the filter left out.

The page fetches the latest events and counts every 3 seconds, and there is nothing to switch on or press for it.

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

Calls made by class loading and page compiling are left out by the agent, using the `ignore:` list in the jots file, and the dashboard
uses the same list for events that an older agent didn't leave out. Which code is yours comes from `app: packages:` in the jots file, for example `com.acme` and `org.apache.jsp` (Tomcat compiles a page to
`org.apache.jsp`, which is your code). Without it, anything that isn't the JDK or the server counts as yours, and
nothing is tagged `library`. A servlet's `service` method counts as the application, since the container calls it
on the application's behalf, which keeps the route and user sensors. Blocked and reported events are never left out.
The stats line says how many events are left out, and unticking the box brings them back. Nothing is deleted.
If you change the app packages the stored events are tagged again at the next start.

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

Name the control file in the jots file (`control: control.yaml`), start the dashboard with `--jots`, and start each application with `-javaagent:jot.jar=<the same jots file>`. The Protection panel then has a master Monitor and Protect switch that makes all rules report only,
and says so when no agent has confirmed picking up the settings, which it knows from the `jot-control` events in their logs.

The JOTs tab is one list with a line for every sensor and rule. Every sensor and rule has an enabled switch on its left. A sensor that isn't enabled
records nothing and a rule that isn't enabled neither blocks nor reports. The switch writes `enabled` under the sensor's
name in the control file, and puts it back to what the .jot file says when you switch it to that. A rule, meaning a sensor that has a `block-when`, also has
a slider on its right between Monitor and Protect for that rule alone. Reports are on their own tab.

The panel that opens over a JOT or an event has Previous and Next buttons that go through the list it was opened from,
so the list doesn't have to be closed and reopened. The left and right arrow keys do the same.

Agents pull this. The dashboard writes the file and the agent reads it once a second. Nothing connects to an agent and
agents accept no connections. The agent and the dashboard must share the file, so this suits one machine or a shared
volume. Because anyone who can change the file can switch protection off, there is no login because the dashboard is for local use by a developer. The file is replaced atomically, and every
change is logged with before and after in `<control file>.audit`.

The panel shows what the file says. An agent started with `-Djot.protect=false` ignores the file, and the agent reports that
at startup in `jot-config` events, so the panel shows it as locked to monitor and disables the switches. The same events
say which JOTs the agent loaded, and a rule the agent didn't load is marked as such.

## Drafting a JOT

New JOT, on the JOTs tab, opens a chat. Say what you want a JOT to watch or stop, like "block any request that creates an RSA
key under 2048 bits", and the model drafts one, with a few sentences about what it watches and what to check. The draft
opens in the same editor as an existing sensor, so you can read it, change it and see its problems as you type. You can ask for
changes afterward, like "make it only report", and the draft is sent along so it changes and doesn't start again.

A draft is never saved by itself. Add to file puts it after the last JOT in the file you pick, or in a new file in the first
directory of the jots file, and leaves everything else in the file as it was. A rule always starts with `protect: false`, so it
only reports until you switch it on. Before you see a draft the dashboard checks it the way the editor does, and also that it is one
JOT, that its name is free, that a sensor records something, that a rule has a description, and that no expression uses `T(` or
`new`. A draft with a problem goes back to the model with it, up to two more times, and one that is still wrong comes back with
its problems shown so you can fix it. Under the draft is a note saying which of the methods it watches have been seen in your log,
and which haven't, since a model can get a name wrong.

It needs `ANTHROPIC_API_KEY`, like the question box, and is off without it. A request sends the model your text, the names and
descriptions of the JOTs, and the names of the methods the application's JOTs were seen watching, by count. It never sends what was
captured. Adding to a file needs the dashboard to be able to write files, so it is off with `--allow-remote`. The model can get the
logic wrong, an argument number for one, even when the YAML is fine, so read a draft before you add it.

## Editing a sensor

A sensor's drawer on the JOTs page shows it as it is written in its file, comments included, in an editor. What you type is
checked as you type, with the problems marked on their lines. Save, or Ctrl or Cmd S, writes the new text into the `.jot`
file that has the sensor and changes nothing else in that file, so the comments and the other sensors in a bundle stay as they
were. The agent reads its `.jot` files when the application starts, so a saved change applies at the next restart.
The name can be changed, to one that no sensor has, and every report that uses the old name in its `rows` or `cols`, in
any loaded file, is changed to the new one, with the comments and layout around it left as written. The drawer says which
reports changed, and if the control file still has a setting for the old name. A save is refused, and nothing is written, if the text has a problem, if the new name is taken, or if the
file changed since the drawer was opened. Saving is switched off when the dashboard is started with `--allow-remote`.

## Access

The server has no login, so it only answers this machine. It listens on localhost, refuses any connection that
doesn't come from the loopback address, rejects requests whose Host header is something else, and rejects posts
that didn't come from its own page, which protects against other websites in your browser reaching it. A
`--host` that isn't localhost is refused unless `--allow-remote` is also given. With it, anyone who can reach
the port can read every event and switch rules, so only do that on a network you trust.

## Data model

Two tables are exposed to queries. `events` has one row per event with the fields documented in the JOT
README, plus `method_name` and `call_site_name`, which are the method and caller without module or line
numbers. `sensors` has the name, description and methods of each sensor loaded from your `.jot` files.
Open the SQL box on any result and try `SELECT * FROM events LIMIT 5`.

Reports translate naturally into queries over `events`. For example the JOT "compare" report is a join of two
sensors' events on `run` and `trace`.

## Tests

    python3 -m unittest discover -s tests
