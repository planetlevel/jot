# TicketBook demo

TicketBook is a deliberately vulnerable Jakarta EE application. This directory runs it under Tomcat 11 with JOT
attached, so you can watch what it does, see what a rule would stop, and then stop it.

    demo/ticketbook/run.sh                 # MODE=protect, the default. The rules block
    MODE=monitor demo/ticketbook/run.sh    # the rules only report, the attacks still work

Then browse http://localhost:8080/ticketbook. Tomcat 11 is downloaded on first use and checked against Apache's SHA-512.
You need Java 17 or newer, Maven and Python 3. The application is in `webapp/`, see "The application" below.

## Using the demo

1. Start the application with `run.sh`, as above. Use `MODE=monitor` to watch an attack succeed and see what a rule would have stopped.
2. In a second terminal start the dashboard from this folder, with `../../bin/jot`, and open http://127.0.0.1:8765. It opens on the Assistant page.
3. Use the application, and try the pages under "Try it" below.
4. Look at what happened. Events lists every event, Graph draws the path from each route to what the sensors saw, Reports tabulates it, and Sensors lists the sensors and rules.
5. Switch rules between monitor and protect on the Sensors page, or with the toggle in the header, with no restart.

Start over resets `.jot/jot.yaml` to an empty configuration and deletes the events. That removes the demo's sensors, rules and reports, and `git checkout .jot/jot.yaml` brings them back.

## The JOTs

`.jot/jot.yaml` is all the configuration, in one file, and both the agent (`-javaagent:jot.jar`, which finds it) and the dashboard
(`--jots`) read it, so they can't disagree. Everything in it is loaded in both modes. `MODE` only decides whether the
rules report or block, and that state is the control file, which the dashboard writes while the app runs. Add your own sensors, rules and
reports to the file, or list other files or directories under `jots:`.

| Where in `.jot/jot.yaml` | What |
|---|---|
| `app:` and `ignore:` | the entry points, the application's own packages, and the platform work that sensors leave out |
| `sensors:`, the first part | sensors that only record what they see, such as routes, users, roles, ciphers, hashes, queries, files and sockets |
| `sensors:`, the second part | the rules, which block or report |
| `reports:` | the original reports, such as the Access Control Matrix and Encryption Algorithms |
| `sensors:`, the last part | the CVE microsandboxes, one rule for each vulnerable library in the app, written out in the file like the others |

The rules are `native-process` (a web request must not start a process), `object-deserialization`, `native-library`
(a web request must not load native code), `jvm-exit` (a web request must not end the JVM),
`expression` (an expression being evaluated must not start a process or open a socket) and
`expression-suspicious` (looks for attack text in an expression, and is easier to get around than the sandbox).

`native-process` is the broad rule and `expression` the narrow one. Both match an expression injection
that starts a process, and the broad one fires first, so the sandbox rule only shows up when the broad rule is switched
off. To show the microsandbox on its own, start without `native-process`.

## Switching while it runs

The agent polls a control file, so the dashboard can flip the rules without a restart. Nothing connects to the agent.

    cd demo/ticketbook && ../../bin/jot

The header has a Monitor and Protect toggle, and the Sensors tab has an enabled switch and a Monitor and Protect switch for each rule. `run.sh` starts each run
with no control file, so a setting from an earlier session can't change what the run does. `MODE=monitor` only sets the state a run starts in, and the toggle changes it while the app runs.

## Try it

Expression injection on `el.jsp`. Put this into the input box, and look for the file it creates.

    ${Runtime.getRuntime().exec("touch /tmp/el-pwned")}

In monitor the file appears. With the rules protecting the page fails and no file is created. `cmd.jsp` is an
operating system command injection, and `xss.jsp` and `flow.jsp` show other bad patterns.

## Object access, IDOR and BOLA

`idor.jsp` is an exercise in reaching a booking that belongs to another user. Sign in as UserA to UserE, and each level hands you the id
of your own bookings in a different disguise. Level 1 is the plain id, as an int, an 8 digit ticket number or a reference like
`TB-1001`. Level 2 is an id the server reshapes (a prefix, a substring, two halves joined, an offset, reversed digits, case and spaces).
Level 3 is an id inside a carrier (base64, hex, a JWT that is never verified, JSON in a header, cookie or body). Every level can be
reached by the query string, a form field, a path segment, the `X-Ticket-Id` header, the `ticket` cookie or a JSON body, at
`/idor/{level}/{operation}/{channel}`. The operations are `read` and `update`, which answer with the booking, and `close`, `delete` and
`mail`, which answer only "Action complete" unless the settings say otherwise. That is the blind case, and `outbox.jsp` shows what really
happened, including mail that went to an address you chose. It also lists every booking with its owner, as the instructor view.

The settings pick Vulnerable, a fix that checks the signed-in name, or a fix that checks the `SecurityContext` kept in the session when
you sign in. That context holds a user id, which reads and updates check, and an opaque access id, which `close`, `delete` and `mail` check.
Nothing in the request can change either one. Reset puts the bookings and the outbox back.

## The application

`webapp/` is the TicketBook web application, already converted to `jakarta.servlet` for Tomcat 11. It is deliberately
vulnerable. It has expression injection, cross-site scripting, XXE, command injection, path and parameter problems and
weak access control, so that there is something for JOT to observe and stop. Run it only on a machine you control and
never expose it to a network.

- **Build.** The Java source is in `src/main/java` and the libraries are listed in `pom.xml`. `./build.sh` compiles the
  classes for Java 17 and Jakarta EE 11, fetches the libraries, converts them from `javax` to `jakarta` with Tomcat's
  migration tool, and puts both in `webapp/WEB-INF`. Neither is committed, and `run.sh` runs `build.sh` when `WEB-INF/lib`
  is empty. Stop Tomcat before rebuilding, replacing a jar under a running JVM can crash it. The JSPs and
  `css/ticketbook.css` are edited in place.
- **Old libraries.** `pom.xml` pins about 47 third-party jars, many of them old versions with known vulnerabilities, such as
  commons-collections 3.2, xalan 2.7.0, log4j 1.2 and spring-security 3.0.5. Dependency scanners will flag them, and they
  are not to be reused in a real application. They are deliberately not upgraded, each CVE microsandbox and page goes with
  one of them. They keep their own licenses, which differ from this repository's and include at least one LGPL library
  (xom), so check each jar before redistributing it.
- **Demo secrets.** `WEB-INF/classes/esapi/ESAPI.properties` contains an ESAPI master key and salt, and the demo users in
  `conf/tomcat-users.xml` all have the password `test`. They protect nothing real.
- **Look.** `css/ticketbook.css` gives it a dark theme over Bootstrap 3, and `menu.jsp` builds the sidebar and highlights the
  current page.
