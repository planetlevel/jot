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
to capture and "reports" tell JOT how to track the data over time. 

    sensors:
    - name: "get-ciphers"
      description: "Identifies encryption ciphers"
      methods:
      - "javax.crypto.Cipher.getInstance"
      captures:
      - "#P0"
    
    reports:
    - name: "Encryption Usage"
      type: "list"
      cols: "get-ciphers"  

## Getting Started with JOT

Basically all you have to do is add JOT to the JVM
- Download the latest jot.jar from https://github.com/planetlevel/jot/tags
- Grab the ciphers.jot file from https://github.com/planetlevel/jot/blob/master/src/main/resources/ciphers.jot
- Launch your app with "java -javaagent:jot.jar=ciphers.jot"

Then you just use your application normally and let JOT gather data for you.
JOT will make a nice table capturing exactly where encryption is used and
what algorithm is specified.

    Encryption Algorithms                                        get-ciphers            
    ------------------------------------------------------------ ---------------------- 
    com.acme.ticketbook.Ticket.encrypt(Ticket.java:125)          DES                    
    org.apache.jsp.accessA_jsp._jspService(accessA_jsp.java:212) AES                    
    org.apache.jsp.accessA_jsp._jspService(accessA_jsp.java:213) PBEWithMD5AndTripleDES 
    org.apache.jsp.accessB_jsp._jspService(accessB_jsp.java:212) DES                    
    org.apache.jsp.accessC_jsp._jspService(accessC_jsp.java:212) DES/CBC/PKCS5Padding   

## Events and Output
JOT reports what its sensors observe, and what they block, as events. Each event has a sensor name,
an action (`observed`, `monitored` or `blocked`), the captured values, the calling method and, for blocks,
the stack. Events are delivered on a background thread, so your application never waits on output.

    [JOT] 2026-10-15T19:27:07.301Z BLOCKED cve-log4shell-no-exec [[touch, pwned.txt]]
          CVE-2021-44228 microsandbox blocked process execution
          at java.base/java.lang.ProcessBuilder.<init>(ProcessBuilder.java:228)

Choose where events go with system properties.

| Property | Default | Description |
|----------|---------|-------------|
| `jot.output` | `console` | Comma separated list of `console` (stderr) and `json` (one JSON object per line) |
| `jot.output.file` | `jot-events.jsonl` | File for the `json` output |
| `jot.events` | `all` | `all`, or `violations` to only report monitored and blocked events |
| `jot.queue.size` | `10000` | Events to buffer. If the queue fills up, new events are dropped and counted. |
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
| `capture`, `message` | What the sensor captured, and for blocks the sensor's exception message |
| `method` | The instrumented method that was called |
| `call_site` | The code that called it |
| `stack` | The stack from the instrumented method up to `jot.output.stack` frames |

## Dashboard
The `dashboard` directory has a web app that loads the `json` event log into SQLite and answers questions
about it in plain English, as live or historical tables and charts. See [dashboard/README.md](dashboard/README.md).

## Advanced Options
Set `-Djot.verbose=true` to report instrumentation errors. By default JOT suppresses them so that
a problem in a JOT can never break your application, which also means a rule that fails to apply
fails silently. Turn verbose on while writing or debugging JOTs.

You might find using the JAVA_TOOL_OPTIONS environment variable useful.
Like "export JAVA_TOOL_OPTIONS="-javaagent:jot.jar=ciphers.jot". Then
no matter how Java eventually gets launched, it will use JOT.

If you want to use multiple JOTs at the same time, you can either put them all into one
big .jot file, or you can put multiple .jot files in a directory and use
"-javaagent:jot.jar=directory"

Lastly, every JOT can have multiple "captures." A capture is a way to specify
what data you want to collect from the methods you specified in the JOT.  The simple
captures are things like:
	#P0 - the first parameter
	#P1 - the second parameter
	#ARGS - all the parameters concatenated in a String
	#OBJ - the object the method is being called on
	#RET - the return from the method
	
Captures are actually Spring Expression Language (SpEL) expressions, so you can call methods
on those basic objects, compare stuff, and do operations. This helps
you observe exactly what you want. See below for all the details of writing your own sensors.

## Logging with JOT

JOT uses FluentLogger which takes configuration from `java.util.logging` and can be configured by the JVM with `-Djava.util.logging.config.file`

This sample config will log JOT to stdout as well as to /tmp/jot.log

	handlers = java.util.logging.ConsoleHandler, java.util.logging.FileHandler
	
	java.util.logging.ConsoleHandler.level = ALL
	java.util.logging.ConsoleHandler.formatter = java.util.logging.SimpleFormatter
	java.util.logging.SimpleFormatter.format = %1$tF %1$tT %4$-7s [%2$s] - %5$s %n
	
	java.util.logging.FileHandler.level=ALL
	java.util.logging.FileHandler.pattern=/tmp/jot.log
	java.util.logging.FileHandler.formatter=java.util.logging.SimpleFormatter
	java.util.logging.FileHandler.append=true

using:

	java -javaagent:jot.jar=ciphers.jot -Djava.util.logging.config.file=/root/jul.properties


## Creating Your Own JOT Sensors

Sensors are how you define the data you want to gather. You can also use
sensors to perform limited actions within an application.
    
    # The name of this sensor, which can be referenced by reports
    - name: "get-ciphers"
    
	  # Use this to describe what this sensor does. Try to provide enough
	  # detail so that anyone would understand what it's about.
	  description: "What does sensor do?"
	
	  # A list of methods to gather data from. To avoid potential performance issues,
	  # avoid putting sensors in methods that are extremely frequently used,
	  # like StringBuffer.append() or File.<init>.
	  methods: 
	  - "a.b.c.Class.method"
	  - "d.e.f.Class.method"
	  
	  # Scopes allow you to limit when a sensor will fire.
	  # A sensor will fire if it is invoked while "inside" one of the scopes. That is,
	  # when any of these methods is on the stack.
	  # You can define negative scopes using !scope, so that this sensor will only fire outside the scope
	  # For static methods you need to prefix the method with "static"
	  scopes: 
	  - "a.b.c.Class.method"                 # matches only if inside method
	  - "!a.b.c.Class.method"                # matches only if NOT inside method
	  - "static a.b.c.Class.method"          # matches if inside static method
	  
	  # Excludes allow you to prevent data from being gathered from any
	  # classes that starts with any of these patterns or are "isAssignableFrom" these classes
	  # FIXME: currently you must put .all after each classname
	  excludes:  
	  - "javax.el.MapELResolver.all"         
	  - "org.foo.package.all"
	  
	  # Captures are the workhorse of JOT and are written in Spring Expression Language (SpEL)
	  # You may reference data from the method currently running.
	  # Options are OBJ, P1..P10, ARGS, RET, STACK. These objects are whatever type they happen
	  # to be, and you can invoke any existing methods on those objects. Note that STACK is a StackFrame[]
	  # See https://blog.abelotech.com/posts/useful-things-spring-expression-language-spel/
	  captures: 
	  - "#RET?.toUpperCase()"                # call toUpperCase if #RET is not null (note ?. operator)
	  - "\"\"+#P0+\":\"+#RET"                # for methods that take a name and return a value
	  - "#OBJ.getCanonicalPath() + \" \" + #OBJ.exists() ? [EXISTS] : [DOES NOT EXIST]"   # use ternary operator
	  - "\"\"+#P0+\":\"+(#RET ? \"Y\" : \"N\")"          # for methods that return boolean
	  
	  # Matchers allow you to filter the data that was captured with a set of regular expressions.
	  # If there are no matchers then all captures will report data.
	  # Positive matchers only fire if the data matches the pattern. You'll get a result if any positive matchers match.
	  # Negative matchers (starting with !) only fire if the data does not match the pattern. You'll get a result if no negative matchers match.
	  # If you mix positive and negative, you'll get a result if any positive captures match and no negative matchers match.
	  matchers:
	  - "^\\w*$"                             # matches anything with word characters start to finish
	  - "!^\\[foo"                           # matches anything that doesn't start with foo
	  - "!null"                              # hide empty results from output
	  
	  # Exceptions are a way to change the behavior of an application.
	  # If the sensor fires (capture occurs and matchers fire) then JOT will
	  # throw a SensorException.
	  # The message should be appropriate for end user, JOT will log all the relevant details.
	  # Note that generally you don't want to use #RET in your capture if you're throwing an exception,
	  # because it will throw at the end of the method, which is probably too late.
	  exception: "Message"
	
	  # Debug mode will generate extra logging for this rule only
	  debug: "false"
	
  

## Creating Your Own JOT Reports

Reports summarize the events JOT's sensors produce. A report receives every event as it happens,
keeps a bounded table in memory, and prints it to stderr when the JVM shuts down. Reports are
independent of the event output, so they work the same with `jot.output=console`, `json`, or neither.

       # Title of this report that will be displayed above the results
       - name: "example"

         # Types of reports
         # 1. list
         #       ROWS: the code that called the instrumented method
         #       COLS: one column named after the sensor in "cols"
         #       DATA: values captured by that sensor
         # 2. compare
         #       ROWS: values captured by the sensor in "rows"
         #       COLS: names taken from the "cols" sensor's captures, written as name:value
         #       DATA: the value part of those captures
         # 3. table
         #       ROWS: values captured by the sensor in "rows"
         #       COLS: one column per sensor in "cols"
         #       DATA: values captured by those sensors
         # 4. graph - not a table. Prints a GraphViz DOT graph of what happened inside each route.
         #       rows: the sensor that identifies the route
         #       cols: optional, sensors such as forwards that start a new route node
         type: "table"

         # A sensor to be used to populate row headers (compare, table and graph)
         rows: "get-routes"

         # A sensor, or a comma separated list of sensors, to be used to populate columns
         cols: "get-users"

compare, table and graph relate a row to a column when both were observed during the same request,
in either order. Outside of a servlet request, events are related when they happen on the same thread.

A table holds at most 1000 rows and 20 values per cell. Anything beyond that is counted and a note is
printed under the table. A graph holds at most 2000 nodes.

The old `series` report type is gone. Its job, a record of every event with its caller, is what the
event log does. Use `-Djot.output=json` to keep one. A `series` report in a .jot file is skipped
with a warning.

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



