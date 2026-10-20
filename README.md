# Java Observability Toolkit (JOT)

The Java Observability Toolkit (JOT) is a platform for making any Java application observable
without writing any code or even recompiling. The platform consists of...

- a library that you can add to your applications
- a set of JOTs that you can enable to make different aspects of your application observable.

You can create JOTs quickly and easily without any coding. JOTs can make
just about anything in a running Java application observable. Here are
a few examples of what you might use it for... but the only limit is your
creativity.

- You're stuck troubleshooting a production issue and you don't have enough
logs or the ability to debug.  With a simple JOT rule you can get the data
you need quickly and easily.

- You want to monitor something that's only accessible deep inside an app
and you don't have a way to expose it to your tools.

- You want to prevent abuse of powerful methods by attackers, but they're in libraries
that you don't control.

JOTs goal is to provide maximum instrumentation power without compromising simplicity.

Let us know the cool things you do with JOT! And consider contributing them back
to the project so that others can share in your awesomeness. The easiest way to contribute
is to create a pull request. If you're sharing a JOT, add it to the projects' "contrib"
directory... and please include a comment detailing what it's intended to be used for.


## A Simple JOT

Define your sensors and reports in yaml and save it in a .jot file. Sensors define what data
to capture and "reports" tell the dashboard how to tabulate it. 

    sensors:
    - name: "crypto-cipher"
      description: "Identifies encryption ciphers"
      methods:
      - "javax.crypto.Cipher.getInstance"
      captures:
        algorithm: "#P0"
    
    reports:
    - name: "Encryption Usage"
      type: "list"
      cols: "crypto-cipher.algorithm"

## Getting Started with JOT

Basically all you have to do is add JOT to the JVM
- Download the latest jot.jar from https://github.com/planetlevel/jot/tags
- Grab the ciphers.jot file from https://github.com/planetlevel/jot/blob/master/src/main/resources/ciphers.jot
- Launch your app with "java -javaagent:jot.jar=ciphers.jot -Djot.output=json"

Then you just use your application normally and let JOT gather data for you. The agent writes nothing
to your application's output, the events go to `jot-events.jsonl`. Start the dashboard on that file and its
Reports page has a table of exactly where encryption is used and what algorithm is specified.

    Encryption Usage         crypto-cipher-request.algorithm
    -----------------------  --------------------------------
    com.acme.ticketbook.Ticket.encrypt(Ticket.java:125)          DES
    org.apache.jsp.accessA_jsp._jspService(accessA_jsp.java:212) AES
    org.apache.jsp.accessA_jsp._jspService(accessA_jsp.java:213) PBEWithMD5AndTripleDES
    org.apache.jsp.accessB_jsp._jspService(accessB_jsp.java:212) DES
    org.apache.jsp.accessC_jsp._jspService(accessC_jsp.java:212) DES/CBC/PKCS5Padding

## Events and Output
JOT reports what its sensors observe, and what they block, as events. Each event has a sensor name,
an action (`observed`, `monitored` or `blocked`), the captured values, the calling method and, for blocks,
the stack. Events are delivered on a background thread, so your application never waits on output. Nothing is written
unless you choose an output below. This is what `-Djot.output=console` prints.

    [JOT] 2026-10-15T19:27:07.301Z BLOCKED cve-log4shell-no-exec [[touch, pwned.txt]]
          CVE-2021-44228 microsandbox blocked process execution
          at java.base/java.lang.ProcessBuilder.<init>(ProcessBuilder.java:228)

Choose where events go with system properties.

| Property | Default | Description |
|----------|---------|-------------|
| `jot.output` | none | Comma separated list of `json` (one JSON object per line, in a file) and `console` (stderr). With none, the agent writes nothing anywhere |
| `jot.output.file` | `jot-events.jsonl` | File for the `json` output |
| `jot.events` | `all` | `all`, or `violations` to only report monitored and blocked events |
| `jot.queue.size` | `10000` | Events to buffer. If the queue fills up, new events are dropped and counted. |
| `jot.protect` | `true` | `false` makes every rule only report, see below |
| `jot.retransform` | `true` | Also instruments classes the JVM had already loaded when JOT started. `false` turns it off, see below |
| `jot.control` | none | Control file the agent polls to switch rules between monitor and block while running, see below |
| `jot.output.stack` | `25` | Stack frames to include in each `json` event. `0` leaves the stack out. |
| `jot.app` | main class | Application name written to each `json` event |
| `jot.host` | host name | Host name written to each `json` event |

The `json` output is meant for loading into a database. Each line is a flat object with everything known
about the event.

| Field | Description |
|-------|-------------|
| `v` | Format version, currently `1` |
| `time`, `ts` | When it happened, as ISO 8601 and as epoch milliseconds |
| `run`, `host`, `pid`, `app` | Which JVM it came from. `run` is a random id for each start of the JVM |
| `id` | Event number, unique within a `run` |
| `trace` | Events with the same `trace` and `run` came from the same request, or from the same thread outside a request |
| `thread`, `thread_id` | The thread that triggered it |
| `sensor`, `action` | The sensor name, and `observed`, `monitored` or `blocked` |
| `data` | What the sensor captured, as an object of its named fields, like `{"algorithm":"AES","bits":128}`. A number or a boolean stays one and a list is a list |
| `capture`, `message` | The same values as one line of text, and for monitored and blocked events the rule's message, its description and condition |
| `method` | The instrumented method that was called |
| `call_site` | The code that called it |
| `stack` | The stack from the instrumented method up to `jot.output.stack` frames |

## Dashboard
The `dashboard` directory has a web app that loads the `json` event log into SQLite and answers questions
about it in plain English, as live or historical tables and charts. See [dashboard/README.md](dashboard/README.md).

## Observe, Monitor and Block
A sensor with no `block-when` observes. It records what it sees and the call carries on. This is how you build an
inventory such as routes, ciphers or roles, and it is what the reports use.

A sensor with a `block-when` is a rule. Its `block-when` says when the call is bad, `true` for every call that gets
that far or an expression over the same variables as a capture, like `#P0 < 2048`. The rule's `description` is its
message. Every JOT's description says what it identifies and starts with "Identifies", like "Identifies starting a native
process", which reads the same whether the rule is blocking or only reporting. When the condition is an expression the
message is the description and then the condition, like "Identifies a key shorter than 2048 bits being generated: #P0 < 2048".
Whether the rule stops the call depends on whether it protects.

| Rule has a `block-when` | Protects | Event | Call stopped |
|---|---|---|---|
| no | not applicable | `observed` | no |
| yes | no | `monitored` | no |
| yes | yes | `blocked` | yes |

An expression that can't be read, or that fails when it runs, counts as false, so a mistake in a condition never blocks
anything. A setting the agent doesn't know, including the old `exception`, is logged and ignored, so a rule that still
says `exception` only observes until it says `block-when`.

By default rules protect. To try a rule without risking your application, report only. A `monitored` event
carries the same message, captures and stack as a `blocked` one would, so you can see everything the rule would
have stopped and check it for false positives before turning it on.

    # one rule only reports, the others still block
    - name: "cve-log4shell-no-exec"
      description: "Creates a microsandbox around CVE-2021-44228"
      block-when: true
      protect: false

    # every rule only reports
    java -Djot.protect=false -javaagent:jot.jar=jots.yaml -jar app.jar

`jot.protect=false` is a master switch. A rule can turn its own protection off with `protect: false`, but it can't
turn it back on when the master switch is off.

Any sensor or rule can be switched off with `enabled: false`. It records nothing, and a rule neither blocks nor reports.
A sensor that doesn't say is enabled.

    - name: "crypto-cipher"
      enabled: false

### Switching while the application runs
Start the agent with `-Djot.control=/etc/jot/control.yaml` and it reads that file once a second. This is how the
dashboard switches rules between monitor and block. The agent only ever reads the file. It opens no port and accepts
no connections, so nothing can reach into it.

    v: 1
    protect: true
    sensors:
      cve-log4shell-no-exec:
        protect: false
      crypto-cipher:
        enabled: false

`protect` is the master switch, and when it is false every rule only reports. Under `sensors`, each name has the
settings for that sensor or rule. Its `protect` is `false` to report only and `true` to block, and it takes priority over
the rule's own `protect:` in its .jot file. Its `enabled` is `false` to switch it off and `true` to switch on one that the
.jot file wrote with `enabled: false`. A setting that isn't listed goes back to its .jot setting, and a rule keeps its
`protect` setting while it is off. `-Djot.protect=false` can't be overridden by the file. Any other setting under a sensor makes the file
invalid, so a typo like `enable:` is caught, not ignored. So does a top-level `rules` map, which older versions used and
which is no longer read.

The agent fails safe. A file that is missing, unreadable, over 64 KB or invalid changes nothing, and the last good
settings stay in force. Each change is logged as an event from the sensor `jot-control`. Because anyone who can write
this file can switch protection off, keep it writable only by the account that manages JOT. The agent warns at startup if
group or other users can write it.

## Servlet Applications
JOT works with both `javax` (Tomcat 9 and earlier) and `jakarta` (Tomcat 10 and later) applications. Jakarta EE 9
renamed packages such as `servlet`, `el`, `websocket`, `persistence`, `mail`, `jms` and `validation` from `javax.*` to
`jakarta.*`. A sensor watches only the names it lists, so a sensor for servlets lists both spellings and one .jot file
works on either server. A name that isn't in the application is simply never seen.

    methods:
    - "javax.servlet.Servlet.service"
    - "jakarta.servlet.Servlet.service"

The same goes for scopes. Packages that belong to the JDK, such as `javax.crypto`, `javax.naming` and `javax.sql`, were not
renamed, so they are listed once. A negative scope such as `!javax.servlet.Servlet.service` applies to the name it lists
and nothing else.

The `demo/ticketbook` directory runs a sample servlet application under Tomcat 11 with JOT attached, for use with
the dashboard. See `demo/ticketbook/run.sh`.

## Classes the JVM loaded before JOT
JOT instruments a class when it is loaded. A few classes in the JDK are loaded before any agent starts, among them
`java.io.File`, `java.security.MessageDigest` and `java.net.Socket`. To reach those, JOT also transforms classes that are
already loaded, which the JVM calls retransforming. It only rewrites the classes a sensor targets, but it has to look at
every loaded class, so it adds a delay at startup, about a tenth of a second for a small program and more for an
application server with thousands of classes.

It is on by default. Start the JVM with `-Djot.retransform=false` to turn it off, and sensors on those early classes then
never fire. `demo/retransform/run.sh` shows both behaviours.

## Advanced Options
Set `-Djot.verbose=true` to report instrumentation errors. By default JOT suppresses them so that
a problem in a JOT can never break your application, which also means a rule that fails to apply
fails silently. Turn verbose on while writing or debugging JOTs.

You might find using the JAVA_TOOL_OPTIONS environment variable useful.
Like "export JAVA_TOOL_OPTIONS="-javaagent:jot.jar=jots.yaml". Then
no matter how Java eventually gets launched, it will use JOT.

The agent argument is a jots file, a small YAML file that lists the .jot files and directories to load.
Directories are searched recursively, so organize your JOTs however you like.

    jots:
    - ciphers.jot
    - rules                    # directories are searched recursively
    control: jot-control.yaml
    app:
      entry:                   # where your application starts running, a JOT with no scopes applies only inside these
      - javax.servlet.Servlet.service
      - "@dev.langchain4j.agent.tool.Tool"
      packages:                # your application's own code, used only by the dashboard
      - com.acme
    ignore:                    # calls made inside these are left out of what sensors report
    - java.lang.ClassLoader
    - org.apache.jasper.compiler

The `app` entry points are the application as a scope. A JOT that doesn't write `scopes:` of its own applies only while one of
them is running on the thread, so it leaves out startup, background threads and anything else that isn't your application at work.
An entry is a method, or an annotation, written `"@the.Annotation"`, which is every method that carries it and every method of a
class that does, so a framework's tool, listener or scheduled-job annotation can mark the places your code is called. A JOT that
writes `scopes:` uses those instead, and `scopes: []` means anywhere, for a JOT that should see startup too. Without an entry list
the servlet `service` methods are used, and `entry: []` leaves no application scope, so every JOT applies everywhere. The scope
follows the thread, so work a request hands to another thread isn't covered. The application scope is not mentioned in the
events, a JOT with its own scopes still says once that its scope is active. See demo/app-scope.

The `ignore` list is for the platform doing work nothing in your application asked for. Loading a class makes the JVM
open jars and check signatures, and compiling a page reads and parses its source, and in a servlet container both
happen in the middle of requests. A sensor that observes leaves out a call when the way from it out to one of these is
nothing but JDK and server code. Your code and your libraries still count when they are closer in, a class initializer
for one, and so does work you asked for, like a page fetching an https address. An entry is a package, a class or a class
and method, and matches itself and everything inside it. Without an `ignore` list the standard class loaders, the Tomcat
class loader, the page compiler and the Eclipse compiler are used, and `ignore: []` leaves out nothing. Rules are not
affected, they see everything. The dashboard reads the same list.

Relative paths are relative to the jots file. The dashboard reads the same file with "--jots", so the agent
and the dashboard always use the same definitions. See demo/ticketbook/jots.yaml. If two JOTs define a sensor
with the same name, the first one loaded wins, so list your own first to override a standard one.

Lastly, every JOT can have "captures." Each capture is a named field and an expression that says
what data to collect from the methods you specified in the JOT. The simple
expressions are things like:
	#P0 - the first parameter
	#P1 - the second parameter
	#ARGS - all the parameters concatenated in a String
	#OBJ - the object the method is being called on
	#RET - the return from the method
	
Every call produces one event, with each field by name in its `data`. A host and a port are two fields,
and a fact the method can tell, like whether a file exists, is one more. Expressions are Spring Expression Language (SpEL), so you can call methods
on those basic objects, compare stuff, and do operations. This helps
you observe exactly what you want. See below for all the details of writing your own sensors.

## Logging with JOT

The agent runs inside your application, so it is built to be invisible. It writes nothing to the application's console and nothing to
the JVM's `java.util.logging`, and it takes nothing from either. Its mistakes, like a sensor that is written wrong, reach you as events
in the event log, which the dashboard shows under the JOTs page. A rule that stops a call still throws its exception, since stopping the call is its job.

To see what the agent itself is doing, ask for its log file.

| Property | Default | Description |
|----------|---------|-------------|
| `jot.log` | none | A file the agent appends its own messages to. Without it nothing is written |
| `jot.log.level` | `info` | `severe`, `warning`, `info`, `fine` or `finest`. `fine` lists every method it instruments |
| `jot.verbose` | `false` | Also writes the errors the instrumentation hit, which are otherwise suppressed, to that log |

	java -javaagent:jot.jar=jots.yaml -Djot.log=/tmp/jot-agent.log -Djot.log.level=fine

## Creating Your Own JOT Sensors

Sensors are how you define the data you want to gather. You can also use
sensors to perform limited actions within an application.
    
    # The name of this sensor, which can be referenced by reports
    - name: "crypto-cipher"
    
	  # Use this to describe what this sensor does. Try to provide enough
	  # detail so that anyone would understand what it's about.
	  description: "Identifies what the sensor is for, starting with the word Identifies"
	
	  # A list of methods to gather data from. To avoid potential performance issues,
	  # avoid putting sensors in methods that are extremely frequently used,
	  # like StringBuffer.append() or File.<init>.
	  methods: 
	  - "a.b.c.Class.method"
	  - "d.e.f.Class.method"
	  - "@a.b.c.Annotation"                  # every method carrying this annotation, see below
	  # A method is package.Class.method, and <init> is a constructor. Never static, a parameter list or a return type, they
	  # are not part of the name, and every overload of a static or instance method is matched. A JOT that has a mistake in
	  # it is not loaded and the agent says so.
	  
	  # Scopes allow you to limit when a sensor will fire. With none, a sensor applies while the application is running,
	  # see app: entry: in the jots file. scopes: [] means anywhere.
	  # A sensor will fire if it is invoked while "inside" one of the scopes. That is,
	  # when any of these methods is on the stack.
	  # You can define negative scopes using !scope, so that this sensor will only fire outside the scope
	  # A scope is written like a method, package.Class.method, with no static or other modifiers. It can't be an annotation.
	  # A JOT with scopes also says that its scope is active, once, the first time one of them is entered. It is an event
	  # named for the JOT and -active, like cve-2021-44228-active, with the scope method as what it saw. It is sent once
	  # in the life of the JVM, not once for each call or each request, so it only answers whether the code the scope
	  # names ever runs. For a CVE rule that is whether the CVE is active in the application.
	  scopes: 
	  - "a.b.c.Class.method"                 # matches only if inside method
	  - "!a.b.c.Class.method"                # matches only if NOT inside method
	  - "a.b.c.Class.<init>"                 # matches if inside a constructor
	  
	  # Excludes allow you to prevent data from being gathered from any
	  # classes that starts with any of these patterns or are "isAssignableFrom" these classes
	  # FIXME: currently you must put .all after each classname
	  excludes:  
	  - "javax.el.MapELResolver.all"         
	  - "org.foo.package.all"
	  
	  # Captures are the workhorse of JOT and are written in Spring Expression Language (SpEL)
	  # You may reference data from the method currently running.
	  # Options are OBJ, P1..P10, ARGS, RET, STACK, and ANNOTATION for methods selected by an annotation.
	  # These objects are whatever type they happen
	  # to be, and you can invoke any existing methods on those objects. Note that STACK is a StackFrame[]
	  # See https://blog.abelotech.com/posts/useful-things-spring-expression-language-spel/
	  # Each capture is a field name, in lower case words joined with _, and an expression.
	  # A String stays one, a number or boolean keeps its type, and a list becomes a list of its items.
	  captures:
	    upper: "#RET?.toUpperCase()"         # call toUpperCase if #RET is not null (note ?. operator)
	    name: "#P0"                          # for methods that take a name and return a value
	    value: "#RET"
	    path: "#OBJ.getCanonicalPath()"
	    exists: "#OBJ.exists()"              # a fact about the file, which stays a boolean
	    status: "#RET ? 'yes' : 'no'"        # use the ternary operator
	  
	  # Matchers allow you to filter the data that was captured with a set of regular expressions.
	  # Each one names a captured field and lists the patterns that field's text is searched with.
	  # A field with no matchers always passes, and every field that has some must pass for the call to be recorded.
	  # Positive matchers pass if any of them match. Negative matchers (starting with !) pass if none of them match.
	  # For a field that is a list, the items that pass are kept and the field fails if none do.
	  matchers:
	    name:
	    - "^\\w*$"                           # matches anything with word characters start to finish
	    - "!^\\[foo"                         # matches anything that doesn't start with foo
	    value:
	    - "!null"                            # hide empty results from output
	  
	  # block-when makes this a rule, which can change the behavior of an application.
	  # true blocks every call where the captures are recorded and the matchers pass. An expression, like #P0 < 2048,
	  # blocks only when it is true, and it can use the same variables as a capture. If the mode is monitor it
	  # only reports. JOT throws a SensorException whose message is the description, then the condition.
	  # Note that generally you don't want to use #RET in a capture if you're blocking,
	  # because it will throw at the end of the method, which is probably too late.
	  block-when: true
	
	  # Debug mode will generate extra logging for this rule only
	  debug: "false"
	
  

## Methods Selected by Annotation

A method can be written as an annotation, with an @ in front, and then it matches every method carrying that
annotation, wherever it is, with no need to know the classes. It also matches every method of a class that carries
the annotation. If both have it, the method's own annotation is the one you read.

    sensors:
    - name: "who-may-call-what"
      description: "Identifies the roles a method requires, each time it is called"
      methods:
      - "@javax.annotation.security.RolesAllowed"
      captures:
        method: "#CALLER"
        roles: "#ANNOTATION.value"

Inside a capture, `#ANNOTATION` holds the annotation's attributes. Read one as `#ANNOTATION.roles` or
`#ANNOTATION['roles']`. Strings and numbers are themselves, an array is a list, a class is its name, an enum is its
name, and an attribute left at its default has the default. A capture that gives a list is a list in the event,
so a method that needs two roles has both in `roles`, and a matcher keeps the ones that match.

A rule can use the same capture and a matcher to stop a call based on what the annotation says.

    - name: "no-auditors"
      methods:
      - "@javax.annotation.security.RolesAllowed"
      captures:
        roles: "#ANNOTATION.value"
      description: "Identifies an auditor calling a method that auditors may not call"
      matchers:
        roles:
        - "auditor"
      block-when: true

A few things to know. An annotation is matched by the name it is written with, so list both spellings for an annotation that Jakarta EE renamed.
The annotation must be kept at runtime, so annotations with source retention, like Lombok's, can't be used. Only the
annotation on the method or its class counts, not an annotation that is itself annotated with it, and annotations
inherited from a superclass or interface are not looked at. An annotation can't be a scope, and it doesn't select
constructors.

## Reports

A `reports:` section in a .jot file defines tables for the dashboard. The agent does not read it or print anything for it, the dashboard
reads the same files, builds each report from the recorded events and shows it on the Reports page. Paths through the application, which
used to be a report type, are the dashboard's Graph page.

       # Title of this report that will be displayed above the results
       - name: "example"

         # What a report reads is written sensor.field, the field of a sensor's captures, like http-route.path.
         # A bare sensor name is everything it captured as one line.
         #
         # Types of reports
         # 1. list
         #       ROWS: the code that called the instrumented method
         #       COLS: one column named after the field in "cols"
         #       DATA: values of that field
         # 2. compare
         #       ROWS: values of the field in "rows"
         #       COLS: one column for each value of the field in "cols"
         #       DATA: the field in "value", which has to be of the same sensor as "cols", or an x
         # 3. table
         #       ROWS: values of the field in "rows"
         #       COLS: one column per field in "cols"
         #       DATA: values of those fields
         type: "compare"

         # A field to be used to populate row headers (compare and table)
         rows: "http-route.path"

         # A field, or a comma separated list of fields, to be used to populate columns
         cols: "auth-role-check.role"

         # compare only, the field that fills the cells
         value: "auth-role-check.allowed"

A row and a column are related when both were observed during the same request, in either order. Outside of a servlet request,
events are related when they happen on the same thread. A report uses the events the dashboard is showing, so Clear and the other
filters apply, but hiding a JOT does not, since a report names the sensors it needs.

## Building from Source

Should be as simple as cloning this repo and building with maven

         $ git clone https://github.com/planetlevel/jot.git
         $ cd jot
         $ mvn install
        
Then you can use the jot-x.x.jar in the target directory.

Contributions are welcome.  See the bugtracker to find issues to work on if you want to make JOT better.







## TO DO LIST
        
        - Solve problem of sensors inside JOT scope
          1) don't instrument JOT classes -- anything using shading
          2) use global scope to check anywhere you're inside a sensor call
        
        - Create separate JOT log file instead of using java.util.logging
        
        - New rules
          1) which routes are non-idempotent?
        
        - Sensors
          # future features - maybe think about reporting?
          # enabled: "false"
          # sample: "1000" # report every 1000 times? time frequency?
          # counter: "?"   # report 10 mins?
          # scope: include a capture and regex to say whether to start scope (if service.P0.getParameter=foobar)
          # exec: run this code.  before? after? during?
        
        - Reports 
          # possible additions to cols -- caller, stack[n], trace#

        - Query Language
          # investigate using query language instead of yaml jots.
          # Perhaps two types of "queries" -- one to create sensors, another to pull reports.
          
          #    SELECT #P0.toUpperCase()
               FROM java.lang.Runtime.getRuntime.exec
               WITHIN javax.servlet.Servlet.service
               WHERE pattern

          #    SELECT [capture, capture]
               FROM [method, method]
               EXCLUDE [class, class]
               WITHIN [scope, scope]
               WHERE [pattern, pattern]
               THROWS [msg]

          #   SELECT #P0 FROM javax.crypto.Cipher.getInstance

          #   SELECT #P0 FROM javax.crypto.Cipher.getInstance
              WHERE "DES|DESEDE"
              THROWS "Weak encryption algorithm detected"



