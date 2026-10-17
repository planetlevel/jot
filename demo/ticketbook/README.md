# TicketBook demo

TicketBook is a deliberately vulnerable Jakarta EE application. This directory runs it under Tomcat 11 with JOT
attached, so you can watch what it does, see what a rule would stop, and then stop it.

    demo/ticketbook/run.sh                 # MODE=monitor, the default. The rules only report, the attacks still work
    MODE=protect demo/ticketbook/run.sh    # the rules block

Then browse http://localhost:8080/ticketbook. The script prints the dashboard command to use. Tomcat 11 is downloaded
on first use and checked against Apache's SHA-512. The application is in `webapp/`, see "The application" below.

## The JOTs

`jots.yaml` lists the JOTs, and both the agent (`-javaagent:jot.jar=jots.yaml`) and the dashboard
(`--jots`) read it, so they can't disagree. Directories are searched recursively, and everything listed is loaded in both modes. `MODE` only decides whether the
rules report or block. Add your own rules by adding a path to that file.

| Where | What |
|---|---|
| `jots/observe.jot` | 18 sensors that only record what they see, such as routes, users, roles, ciphers, hashes, queries, files and sockets |
| `jots/reports.jot` | the original reports, such as the Access Control Matrix and Encryption Algorithms |
| `rules/protect.jot` | 4 rules |
| `../../cves/` | the CVE microsandboxes, one per vulnerable library in the app |

The rules are `block-native-process` (a web request must not start a process), `block-deserialization`,
`sandbox-expressions` (an expression being evaluated must not start a process or open a socket) and
`block-nasty-expressions` (looks for attack text in an expression, and is easier to get around than the sandbox).

`block-native-process` is the broad rule and `sandbox-expressions` the narrow one. Both match an expression injection
that starts a process, and the broad one fires first, so the sandbox rule only shows up when the broad rule is switched
off. To show the microsandbox on its own, start without `block-native-process`.

## Switching while it runs

The agent polls a control file, so the dashboard can flip the rules without a restart. Nothing connects to the agent.

    python3 dashboard/server.py --log jot-events.jsonl \
        --jots demo/ticketbook/jots.yaml

The header has a Monitor and Protect toggle, and the Protection panel has a switch per rule. `run.sh` starts each run
with no control file, so a setting from an earlier session can't change what the run does. `MODE=monitor` is fixed for the
life of the process and can't be switched to protect from the dashboard.

## Try it

Expression injection on `el.jsp`. Put this into the input box, and look for the file it creates.

    ${Runtime.getRuntime().exec("touch /tmp/el-pwned")}

In monitor the file appears. With the rules protecting the page fails and no file is created. `cmd.jsp` is an
operating system command injection, and `xss.jsp` and `flow.jsp` show other bad patterns.

## The application

`webapp/` is the TicketBook web application, already converted to `jakarta.servlet` for Tomcat 11. It is deliberately
vulnerable. It has expression injection, cross-site scripting, XXE, command injection, path and parameter problems and
weak access control, so that there is something for JOT to observe and stop. Run it only on a machine you control and
never expose it to a network.

- **No Java source.** The repository has the JSPs, the stylesheet and the compiled classes (`WEB-INF/classes`), but not the
  Java source for those classes. The JSPs and `css/ticketbook.css` can be edited. The classes can only be replaced.
- **Old libraries.** `WEB-INF/lib` holds about 15 MB of third-party jars, many of them old versions with known
  vulnerabilities, such as commons-collections 3.2, xalan 2.7.0, log4j 1.2 and spring-security 3.0.5. Dependency
  scanners will flag them, and they are not to be reused in a real application. They keep their own licenses, which
  differ from this repository's and include at least one LGPL library (xom), so check each jar before redistributing it.
- **Demo secrets.** `WEB-INF/classes/esapi/ESAPI.properties` contains an ESAPI master key and salt, and the demo users in
  `conf/tomcat-users.xml` all have the password `test`. They protect nothing real.
- **Look.** `css/ticketbook.css` gives it a dark theme over Bootstrap 3, and `menu.jsp` builds the sidebar and highlights the
  current page.
