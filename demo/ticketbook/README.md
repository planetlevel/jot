# TicketBook demo

TicketBook is a deliberately vulnerable Jakarta EE application. This directory runs it under Tomcat 11 with JOT
attached, so you can watch what it does, see what a rule would stop, and then stop it.

    demo/ticketbook/run.sh                 # MODE=observe, the default
    MODE=enforce demo/ticketbook/run.sh    # the rules block
    MODE=monitor demo/ticketbook/run.sh    # the rules only report, the attacks still work

Then browse http://localhost:8080/ticketbook. The script prints the dashboard command to use. Tomcat 11 is downloaded
on first use and checked against Apache's SHA-512. The application itself, `webapp/`, is not part of the repository.

## The policy

| Where | What |
|---|---|
| `jots/observe.jot` | 18 sensors that only record what they see, such as routes, users, roles, ciphers, hashes, queries, files and sockets |
| `jots/reports.jot` | the original reports, such as the Access Control Matrix and Encryption Algorithms |
| `rules/enforce.jot` | 4 rules. They are added in monitor and enforce modes |

The rules are `block-native-process` (a web request must not start a process), `block-deserialization`,
`sandbox-expressions` (an expression being evaluated must not start a process or open a socket) and
`block-nasty-expressions` (looks for attack text in an expression, and starts staged as report only so you can promote it
to block from the dashboard).

`block-native-process` is the broad rule and `sandbox-expressions` the narrow one. Both match an expression injection
that starts a process, and the broad one fires first, so the sandbox rule only shows up when the broad rule is switched
off. To show the microsandbox on its own, start without `block-native-process`.

## Switching while it runs

The agent polls a control file, so the dashboard can flip the rules without a restart. Nothing connects to the agent.

    JOT_DASHBOARD_ADMIN_TOKEN=<choose one> python3 dashboard/server.py --log jot-events.jsonl \
        --jot demo/ticketbook/jots --jot demo/ticketbook/rules --control jot-control.json

The header has an Observe and Block toggle, and the Enforcement panel has a switch per rule. `run.sh` starts each run
with no control file, so a setting from an earlier session can't change what the run does. `MODE=monitor` is fixed for the
life of the process and can't be switched to block from the dashboard.

## Try it

Expression injection on `el.jsp`. Put this into the input box, and look for the file it creates.

    ${Runtime.getRuntime().exec("touch /tmp/el-pwned")}

In observe the file appears. With the rules enforcing the page fails and no file is created. `cmd.jsp` is an
operating system command injection, and `xss.jsp` and `flow.jsp` show other bad patterns.
