# JOT Dashboard

A small web app that follows JOT's JSON event logs into SQLite and lets you ask questions about them,
in plain English or SQL. Answers are tables and charts, and they can update live as events arrive or be
run later against the history.

## Quick start

Run your application with JOT writing JSON events.

    java -Djot.output=json -Djot.output.file=/var/log/jot/app.jsonl -javaagent:jot.jar=jot.yaml -jar app.jar

Then start the dashboard and open http://localhost:8765.

    pip install -r requirements.txt
    export ANTHROPIC_API_KEY=...        # only needed for natural language questions
    python3 server.py --log /var/log/jot/app.jsonl --jots ../demo/ticketbook/.jot/jot.yaml

Instead of exporting the key you can keep it in `dashboard/.env`, which git ignores and the server reads at
startup. Copy `.env.example`, fill it in, and run `chmod 600 .env`. A variable set in your shell wins over the file.

Without a key the dashboard still works. The preset views and the SQL box don't use a model.

| Option | Description |
|--------|-------------|
| `--log` | JSON event log to follow. May be a glob such as `'logs/*.jsonl'`, and may be given more than once. Default `.jot/events.jsonl` |
| `--jots` | The jots file that lists the JOTs and the control file. Start each agent with `-javaagent:jot.jar=<this path>`, so the agent and the dashboard use the same definitions |
| `--db` | SQLite file that holds the events. Default `.jot/dashboard.db`. Delete it to start fresh |
| `--app` | A package of your application, like `com.acme`. May be given more than once, and adds to `app: packages:` in the jots file. See Where an event came from below |
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
the entry of the request on the left, goes through the application methods that were running, and ends at what a
sensor saw, like a cipher, a query, a file or a blocked call. A forward or a redirect goes on to the entry it names,
shown as an exit right after it. Lines get wider with the number of events, and a node shows its count.

The picture is a main line with branches. The main line, drawn along one row with its lines a little stronger, is what most requests of that
entry did, box after box. A branch leaves it at the box it follows and sits one column on from there, on a row above or below, and carries on
along that row, so a box is never pushed further right than the path that led to it. Where a branch joins the main line again, its line reaches
across. Paths that few requests took are left out so the common ones can be read. Up to ten requests everything is drawn, then a path needs two
requests, and from twenty a tenth of them. A rare path is not left out when it is the only way to something. Every kind of thing a sensor saw is
drawn, with its commonest path if all of them are rare, and everything a rule blocked or reported keeps every path to it, so the one request in a
hundred that read a file is never the one that is hidden. The summary says how many paths were hidden, and **Show rare paths** draws them.

A graph is drawn from the events of each request, and there is a limit on how many are used, shared out among the entries so a busy entry can't
use up what the others need. An entry over its share is drawn from its newest requests, and its box says how many of how many, like `27/280`, and
the summary says how many entries are drawn that way. Whatever an entry's sensors saw is still in its graph, since the newest request that
each sensor was seen in is always used in full. **Lay out top to bottom** turns the same picture so the main line is a column, which suits a narrow window.

Click a node to follow its paths, everything that does not lead to or from it fades. The panel beside the graph shows
what the node captured, where it comes from and where it leads, and **Show these events** opens them in a search.
A picked node has its own address, like `#graph/effect%3Acrypto-cipher`. The Entry box shows the paths of one entry.

**Entry points.** Whatever the application declares as an entry point in `app: entry:` is where a line starts, a request or not. The agent stamps every event with the
outermost entry point it ran under, and a line with no `http-route` starts at that method instead, like `MathTools.calculate` for the tool of an agent. The code above the entry point is
left out, so in a large application the graph is not a long chain of the same callers. What happened outside every entry point, like the call to a model between two tools,
is in the `(outside a request)` graph, drawn from the method that called it only.

**GET and POST.** The `http-route` JOT captures the HTTP method beside the path, and the graph reads both. An entry that is a request is the path alone, so GET and
POST of `/buy` are one graph, and each request is its own line by method. What only one method reaches is colored for it, GET green and POST purple, on the box's left edge and on
the lines into it, and what both reach is blue, so a POST that skips a check the GET goes through stands out. The legend names the colors,
the panel and the hover box say which methods reach a node, and the Method box shows one method's paths alone, as does clicking a method in the legend. An entry's box has a bar along its bottom showing how its requests split by method. Sensor boxes are neutral, so green is only ever GET, and only a rule that reported or blocked is colored by outcome. Nothing is colored until more than one
method has been seen. A route JOT that doesn't capture `method` still draws, just without colors. The dashboard reads the path from the `path` field, so a
route JOT has to capture it by that name, as the ones that ship do.

Only your application's code is drawn, as set by `app: packages:` in the jots file, so the JDK, the server and libraries don't clutter it. Sensors
that only describe the request, like who the user was, are left out unless you tick **Include request details**. The
graph follows the filters, and it redraws by itself when new events arrive. The stack of an event is cut
at `jot.output.stack` frames, 25 by default, so an older event may be missing the outer methods. TicketBook records 500.

## Filters

The **Filters** button on the Events and Graph pages opens a drawer. Every filter in it is a list of what is shown, so a ticked box is something you see and unticking it stops showing it. Everything starts ticked, so a fresh dashboard shows every event. The filters are independent, and an event shows when every one of them lets it through.

- **Time** is how far back to show, all of it or the last 15 minutes, hour or day. Once chosen it reads *Since* and the time. Clear on the toolbar is the same filter, set to now.
- **Outcome** is Observed, Reported only and Blocked. Reported only is what a rule would have blocked and let through.
- **Source** is where an event came from. Application means a frame of its stack is your code, Libraries means the stack has libraries your application uses and none of its own, JDK and server means only the JDK or the application server, and No stack is an event with none, like the agent's own.
- **JOTs** has a box for every JOT, with the agent's own events as a JOT too. A rule and its `-active`, `-blocked` and `-monitored` events are one JOT. All and None work on the ones the search box has narrowed the list to.

Each choice shows how many events it covers since the time you chose, whatever else is hidden, so you can see what ticking it would add. **Show everything** in the drawer, and **Show all** next to the Filters button, take every filter off in one press, Time included. The button shows how many things are hidden. The filters apply to the events, the graph, the views, the search and the counts, and nothing is deleted. A JOT you hide stays in the reports, which each name the sensors they need, so a column never vanishes because its sensor was hidden. Time, Outcome and Source do apply to the reports.

You can hide a JOT without opening the drawer. Point at a kind of event in the graph and press **H**, or use the **Hide** button in the graph's detail panel or an event's drawer. A message offers Undo for a few seconds. A box for a rule that blocked something can't be hidden that way.

The filters you set last until the dashboard is restarted, except the time. Clear is kept across a restart, and `--since` sets it at a start.

## Events behind a report

A report's grid is clickable. A cell opens the events that put its values there, a row label opens all the events of that row and a
column heading all the events of that column. They open on the Events page, newest first, and a row of them opens its event like any other.
The events are those of the column's sensor, from the requests the report relates to that row, so the cell for `/buy` and `RoleA` is the
role check of RoleA that happened in a `/buy` request. Reports built from your question rather than from a `.jot` file aren't clickable.

## Searching

The search box under the question box finds individual events, newest first, and each row opens in the event viewer.
Every word has to match somewhere in the event, in its capture, message, sensor, call site or stack, so `rsa`
finds anything with RSA in it and `hash jar` needs both. Put quotes around a phrase, and a leading `-` leaves out
what follows, like `-jasper`. A `field:value` narrows to one field. The fields are `sensor` (contains), `action`,
`origin`, `app`, `run` and `host` (exact), `entry` (the entry point or the route the request came in at, exact, and `route` means the same), and `trace` and `pid` (a number). For example `sensor:crypto-hash action:observed -jasper`.
The search honors the filters, and says how many more matches they left out.

The page fetches the latest events and counts every 3 seconds, and there is nothing to switch on or press for it.

## Clearing

The **Clear** button next to Filters hides everything recorded so far, so the views, charts, reports, rule counts
and questions only reflect what happens from that moment on. **Show all** brings it back, along with every other filter.
The stats line says when you cleared and how many earlier events are hidden. Clear is the Time filter set to now.

Nothing is deleted. Clearing sets a start time that is kept in the database, so it survives a restart, and applies to
everyone looking at this dashboard. Internally the table of events is called `events_raw`, and `events`, which every query
reads, is a view over it that applies the filters. An older database is converted the first time the dashboard
starts on it, and keeps all its events. Start with `--since now` to begin clear, or delete the database file to start
completely fresh, after which it is rebuilt from the whole log.

## Where an event came from

The JDK and the application server do plenty on their own, like checking the signature of a jar they load, and
JOT's sensors see all of it. The **Source** filter lets you leave that out. An event counts as the application's
when any frame of its stack is code from your application, even with libraries in between. So a hash made by
`hsqldb` on behalf of `com.acme.Ticket` is the application's, and the same hash made while Tomcat starts up is the platform's.

Each event is tagged as it is stored, so the filter is cheap and the model and the SQL box can use it too.

| Column | Meaning |
|--------|---------|
| `origin` | `app` when a frame is application code, `library` when the stack has libraries but nothing of yours, `platform` when it is all JDK and server, `none` when the event has no stack |
| `app_frame` | The innermost frame of the application, like `com.acme.Ticket.encrypt(Ticket.java:125)` |

Calls made by class loading and page compiling are left out by the agent, using the `ignore:` list in the jots file, and the dashboard
uses the same list for events that an older agent didn't leave out. Which code is yours comes from `app: packages:` in the jots file, for example `com.acme` and `org.apache.jsp` (Tomcat compiles a page to
`org.apache.jsp`, which is your code). Without it, anything that isn't the JDK or the server counts as yours, and
nothing is tagged `library`. A servlet's `service` method counts as the application, since the container calls it
on the application's behalf, which keeps the route and user sensors.
The stats line says how many events the filters leave out. If you change the app packages the stored events are tagged again at the next start.

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

**From a method.** You can also start from a method you can already see. Click a box for the application's own code in the graph and press
**Make this a sensor**, or hover a frame in an event's stack and press **Make a sensor**, which also works for library and JDK frames. The
editor opens with a JOT for that method, named for its class and method, with its arguments and result as captures. Change the captures to
what you want, then Add to file. It needs no API key, since nothing is sent to a model, and a static initializer can't be watched, so it has no button.

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

## Drafting a report

New report, on the Reports tab, works the same way as New JOT. Say what you want to see, like "which entry points use which ciphers" or
"every cookie and whether it is Secure", and the model drafts a report in the `reports:` format from the JOTs you have defined. It can
only read fields that a JOT captures, and before you see a draft the dashboard checks that every `sensor.field` it uses exists, that the
type has what it needs (a compare has rows, a list does not), that value and by come from the same JOT as cols, and that the name is
free. A draft with a problem goes back to the model with it, up to two more times. If what you ask for needs data no JOT captures, the
model says which JOT is missing so you can make it with New JOT first.

The draft opens in the editor, which suggests as you type. A new line offers the keys a report has, `type:` offers list, compare and
table, and `rows:`, `cols:`, `value:` and `by:` offer every `sensor.field` of your JOTs, with value and by narrowed to the JOT that cols
reads. Press Ctrl and Space to ask for suggestions. Add to file puts the report after the last one in the file you pick, or in a new file,
leaves the rest of the file as it was, and runs the new report. If a JOT it reads has recorded nothing yet, a note says the report
is empty until the application runs that code.

The model is sent your text, the names and descriptions of the JOTs, their field names and the names of existing reports. It is never sent
captured values or events. It needs `ANTHROPIC_API_KEY` and a dashboard that can write files, like drafting a JOT.

**Totals in reports.** A column of a table report can be an expression in Spring EL's style, which adds up what sensors captured instead of listing it. `#total(ai-model-call.input_tokens)`
adds the field over the events of each row, counting every event once, and `#count(ai-model-call)`, `#average`, `#min` and `#max` do what they say. They can be added, subtracted, multiplied
and divided, like `#total(ai-model-call.input_tokens) / #count(ai-model-call)`, and mixed with plain columns. Quote `cols` when it has one, since `#` starts a comment in YAML.
The dashboard evaluates these itself, so it understands only this part of Spring EL, and the column heading is the expression as written. A cell opens the events it adds up.
A plain column of the row's own sensor shows the values of that event only, not those of other events that happened in the same request.

## Running your application

The Run page starts your application with the agent attached, so nothing needs adding to the command. A console with nothing in it yet opens there.

It suggests the command that probably starts the project, from a `run.sh`, a Spring Boot Maven or Gradle build, or the newest jar that was built. Edit it or type your own, then press Start. The console runs the command in the project folder with `JAVA_TOOL_OPTIONS` set to load the agent and the project's `jot.yaml`, shows what the application prints, and moves to the Events page when the first event arrives. Stop ends the application and anything its script started. The command is remembered in `.jot/run.json`.

The agent jar is found from `JOT_AGENT_JAR`, then `~/.jot/jot.jar`, then the newest `target/jot-*.jar` beside the dashboard. A path with a space is quoted for the JVM.

An application that was started some other way, and is writing this project's events, shows on the Run page as running outside the console, with a Stop it button that asks twice. The console only offers that for a live Java process on this machine that was started before its last event, which rules out another program that was given the same process number. It sends the process an ordinary end request and says if it is still running a few seconds later.

Start over, at the bottom of the Run page, puts the project back to how it was before JOT, for demos. It shows what it will delete, the events, sensors, reports and entry points, the Assistant conversations, the protection settings and the logs, and after you confirm it removes everything inside `.jot` and writes `jot.yaml` as a new project has it. The application is stopped first, whether the console started it or it is running some other way and still writing events, and if it doesn't end the reset deletes nothing. Sensor files the configuration points at from outside `.jot` are yours and stay, and the page lists them. A symbolic link inside `.jot` is removed and never followed, and your application's own files are never touched. It can't be undone.

The Assistant can propose a restart, for after a sensor or setting changes, since the agent reads them when the application starts. It shows as a card, and Apply stops the application and starts it again with the command you last used on the Run page. The command is never the Assistant's to give. Until you have started the application once from the Run page the console doesn't know the command, and the Assistant says so.

When the configuration changes while an application is running, a banner appears on every page saying it needs a restart, since the agent reads the configuration when the application starts. Restart now stops it and starts it again with the command you last used on the Run page, and when the console doesn't know that command yet the banner takes you to the Run page instead. It counts an application started some other way too, and it clears once the new process has started after the change. The protection settings don't trigger it, the agents read those while they run.

Only a command typed or confirmed at the console is ever run, never one from the Assistant, the configuration or an event. A console that other machines can reach has no Run page. Switching projects or ending the console stops the application it started. Windows isn't supported yet.

A build tool such as Maven also loads the agent in its own JVM, because the option reaches every JVM the command starts, so a `mvn` command can show a few events from the build itself.

## Switching projects

The project menu at the left of the header shows the project that is open. Type the folder of another project, or choose one from the recent list, and the console switches to it without being restarted. It looks for `.jot/jot.yaml` in the folder, then `jot.yaml`, and uses that project's own database and events, which are in its `.jot` folder too. The Assistant's project folder follows along. A folder with no `jot.yaml` asks before anything is written, and Make it creates `.jot/jot.yaml` there for the Assistant to fill. The recent list is kept in `~/.jot/recent.json`, or under `JOT_HOME`. Switching is off when the dashboard is started with `--allow-remote`.

## The assistant

The Assistant page is one conversation for the whole of configuration. It starts by asking where your project is. Paste a folder path in the chat or the Project folder field (a repository URL has to be cloned first, the dashboard doesn't fetch code). With nothing configured yet it offers Set up this project, which looks through the code for how the application starts running, then proposes the entry points, the application's packages and sensors that fit what the project uses. Afterwards the same conversation changes the configuration, like adding a sensor or a report or combining files into one.

It can only propose. Each proposal is a card with Apply and Discard, and nothing changes until you press Apply. Every file it reads shows as a step in the conversation. It stays inside the folder, follows no link out of it, skips built and fetched folders like `target` and `node_modules`, and never reads files that can hold credentials, such as `.env` files, keys, keystores and `credentials` files. The folder tools are off when the dashboard is started with `--allow-remote`.

What the model sees from the assistant is the configuration, the names of methods and packages the agent has seen, and the project files it asks to read. It never sees captured values. Get IT and security approval before pointing it at customer or proprietary code, since file contents go to the model provider.

## One configuration file

All of a project's configuration can be one file, the jots file, which the dashboard is started with and the agent is given. Besides `app:`, `ignore:` and
`control:` it holds the `sensors:` and the `reports:`, so the JOTs page, New JOT, New report and Entry points all write into it, and Add to file offers
it first. A project that has many `.jot` files can list them under `jots:`, and `python3 consolidate.py jot.yaml` moves their sensors, rules and reports
into the jots file, with their comments, after checking that the result defines exactly what they did. The Monitor and Protect state stays in its
own control file, since the dashboard writes it on every switch and the agent reads it every second.

## Entry points

The **Entry points** section of the JOTs page lists the places the application starts running, which are the `app: entry:` list of the jots file.
A JOT that writes no scopes of its own applies only while one of them is running, so it leaves out startup and background threads. Each is a method,
like `javax.servlet.Servlet.service`, or an annotation like `@com.acme.Handler`, which is every method that carries it. Without a list in the file the
two servlet `service` methods are used, which the section shows as the default, and an empty list means there is no application scope, so JOTs apply
everywhere.

Change an entry in place, remove one with its button, or type a new one and press Add. A mistake is said on its row as it is typed, and Save stays
off until there are none. **Use the default** takes the list out of the file, and **Revert** goes back to what the file says. Save writes only the `entry:`
key of `app:`, so the rest of the file stays as written, comments included, though a comment inside the old list goes with it, and it refuses if the file changed
since the section was opened. The agent reads the file when the application starts, so a running one keeps the list it had. Like saving a JOT, it needs
the dashboard to be started with `--jots` and to be able to write files, so it is read only with `--allow-remote`.

## Editing a sensor or a report

Clicking a sensor, rule or report shows its result under the list. A sensor needs no report written for it. Its result has one row for each entry point where it ran, using the route when a request has one, and one column for each thing it captured, with what it captured there in each cell. A sensor that captures nothing has one column that counts how often it ran. The **Edit** button at the end of the row, or in the result's heading, opens the drawer with the definition. The address is `#jots/name` for the result and `#jots/name/edit` for the drawer, and `#reports/name` and `#reports/name/edit` for a report.

Both drawers have a **Delete** button. It asks for a second click, then removes only that sensor or report from its file and leaves the rest as written, comments included. A list left empty is written as `[]`. Reports that still read a deleted sensor are left alone and named afterward, and the page flags them as reading a sensor that isn't defined.

Deleting a sensor that reports read warns first. The drawer names the reports, which would show as using a sensor that isn't defined, and offers **Delete anyway**, **Ask the Assistant to clean up** or Cancel. The Assistant is sent a message naming the sensor and its reports, and proposes a change or a removal for each report and then the removal of the sensor, as cards you apply yourself. It can now propose changing an existing report and removing a sensor or report, which it couldn't before.

A report is edited the same way as a sensor. Its text is checked as you type, against the sensors that are defined, and saving writes only that report into its file. It can be renamed to a name no other report has. The rest of this section says how a sensor is saved, and a report is the same except that no other file refers to a report by name.

A sensor's drawer shows it as it is written in its file, comments included, in an editor. What you type is
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
