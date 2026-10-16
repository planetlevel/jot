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
| `--port`, `--host` | Where to listen. Default `127.0.0.1:8765`. See the note on access below |

Environment variables are `ANTHROPIC_API_KEY`, `JOT_DASHBOARD_MODEL` (default `claude-sonnet-5-5`) and
`JOT_DASHBOARD_API_URL` if requests have to go through a gateway.

## Asking questions

Type a question like "which call sites triggered blocked events today?" or "how many cipher events per
minute?". The dashboard shows the result, a one line explanation, and the SQL that produced it, which you
can edit and run again. A question you have asked appears as a button, and clicking it re-runs its saved SQL
without asking the model again.

Turn on **Live** and the current result refreshes every few seconds, along with the event feed on the right.
Turn it off and the view stays put while you look at it.

Events from several applications can share one dashboard. Each event records its host, process and
application, and events with the same `run` and `trace` came from the same request.

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
