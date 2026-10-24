# JOT Investigation Agent, Architecture

Status is a proposal. Nothing in this document is built yet, except the pieces named under "What already exists".

## Purpose

The goal is an agent that can answer almost any question about a running Java application. Examples include "are there any IDORs", "which code paths touch the payments table", "what does this service call outside the company", "is this cache header policy applied everywhere", and "why is checkout slow". The question does not have to be about security.

The agent works the way a person would. It reads the code, decides what to watch, runs the application and pushes traffic through it, studies what happened, and decides what to try next. It stops when it can give an answer it can defend.

## Design in one paragraph

The design has three nouns, one loop and one choke point. The nouns are the question, the experiment and the evidence. The loop is plan, apply, restart, stimulate, collect, digest and update. The choke point is the gate, which every action that changes or exercises the application must pass through. All memory lives in a single case file, so the agent can be stopped, resumed, audited and replayed.

## The three nouns

**Question.** What the person asked, plus a definition of done. "Sure" has to mean something, so every question ends in one of three states. *Confirmed* means there is evidence of the thing. *Refuted for the tested scope* means it was looked for and not found, with coverage stated. *Inconclusive* means the budget ran out or the application could not be driven far enough, with the reason stated. Some questions also need a policy to test against, for example who is allowed to see which record. The agent derives a candidate policy from the code and asks the person to confirm it before it treats any difference as a finding.

**Experiment.** One turn of the loop. It has a hypothesis, the instruments needed to observe it (sensors and rules), a stimulus (the requests or actions to run), a prediction for each possible outcome, and a budget. Writing the predictions before running anything is what keeps the digest honest.

**Evidence.** A fact with a source. Runtime evidence is an event, a response or a trace joined to a request. Code evidence is a citation to a file and line. Every claim in the final answer must point at evidence, and evidence records whether it was only read from the source or also seen running.

## Components

```
   person <-cards-> PLANNER --> ORCHESTRATOR --> GATE --> INSTRUMENTER --> RUNTIME
                      ^  ^                                      ^
                      |  +--------- CODE ANALYST ---------------+
                      |            (application model)
                   ANALYST <-- COLLECTOR <-- DRIVER
                      
        every component reads and writes the CASE FILE
```

### Case file

A SQLite database per investigation, kept with the project. It holds the question and its definition of done, the policy under test, the hypotheses, the experiments with their results, the evidence, the coverage map, the budgets, the audit log, the baseline configuration, and the model settings. It is the only memory. A transcript is not memory, because it grows without bound and cannot be queried. The planner is given a summary built from the case file at the start of each loop, never the whole history.

### Code analyst

This is step one of the loop and it runs again after every digest. It turns the question into facts about the code, and it builds an application model that the other components share.

The model holds entry points and routes, controllers, the call graph, where data enters and where it ends up, the data model and any ownership columns, the places that check identity or role, the libraries and server and what they can do, and configuration such as OpenAPI files.

It works in three layers that check each other. The first is a code map, a cheap structural index of classes, methods, annotations, routes and calls, cached by file timestamp. The second is question-directed reading, where the model uses the map to pull only the slices that matter to the question and reads those. The third is runtime evidence. Events carry stack traces with file and line, so a surprising event points straight back at the code that caused it. When what the code says and what the run shows disagree, the analyst is called again on that spot.

Each fact it records has a citation and a status of read or observed. It also hands the instrumenter a list of sensor candidates, checked against methods the application actually calls, and hands the driver the endpoints and parameters it found.

### Planner

The planner decides what to ask next. It is the existing Assistant engine, generalized from "propose a configuration" to "propose an experiment". It reads the case summary, calls the code analyst when it needs facts, and emits an experiment. It never touches the application directly. Everything it wants done goes through the orchestrator.

### Orchestrator

A persisted state machine that walks one experiment through plan, apply, restart, preflight, stimulate, collect, digest and update. Each state is written to the case file before it runs, so a crash or a stop resumes where it left off. The orchestrator also enforces the loop's stopping rules, which are the question reaching a final state, the budget running out, or a loop that makes no progress for several rounds.

### Gate

The single choke point. Anything that changes the application, restarts it, sends traffic or removes a sensor must pass through the gate. It enforces a scope lock so traffic only goes to the declared base URL, budgets for request count, rate and time, a list of allowed verbs, an acknowledgment that the target is a throwaway environment before any write is sent, and an audit log of every decision. It has three modes. In approve-each mode the person confirms every experiment. In auto-with-gates mode the agent proceeds on its own while inside the limits and stops at the first limit. In full-auto mode only the scope lock and the budgets apply. Having one choke point means safety is reviewed in one place.

### Instrumenter

Turns the experiment's instruments into a configuration change. Every sensor it adds is tagged with the investigation id, so removal at the end is exact and the baseline configuration comes back unchanged. It builds on the catalog and on the Assistant's existing config tools, and a model-written sensor goes through the same validation as one the person writes.

### Runtime

Restarts the application so the new configuration takes effect. This is the existing Run controller plus a reset step for application state, such as reseeding a test database or clearing sessions. Restart cost is real, so the planner is encouraged to batch several hypotheses into one experiment rather than restart for each.

### Driver

Produces the stimulus. For anything with real client-side code it is a Playwright worker in its own subprocess, with one isolated browser context per persona. A persona holds a login and its saved storage state, so "alice and bob" are two contexts that never share cookies. The driver records the requests the page itself makes, which is how it learns about calls a crawler would never find, and it can send direct API requests from the context where the page's own origin rules would get in the way. A simple HTTP exerciser covers plain APIs without a browser. Every request carries a trace id header. Saved login state is a live session, so it is stored outside the project with owner-only permissions, is never shown to the model, and is deleted when the person starts over.

### Collector

Gathers what the run produced and joins it by trace id, so each request, its response and the events it caused sit together. Events that happen on other threads still attach to the right request through the trace id, which needs a small agent change to propagate the id to downstream events.

### Analyst

Reads the joined evidence against the predictions. Deterministic analyzers do the checks that should not depend on a model's mood, such as "the same record came back for two different users" or "this value reached a sink unchanged". The model handles the open-ended reading, such as what an unexpected event means. The analyst updates hypotheses, coverage and the question state, and writes the digest the planner will see next.

### Playbooks

Playbooks are data files, like the catalog. A playbook for a question type gives the planner a starting plan and the analyzers that apply. An IDOR playbook, for example, lists how to find object identifiers in parameters and paths, which personas to create, the swap-and-compare stimulus, and the analyzer that compares responses and data touched. A new kind of investigation is a new playbook, not new code. A question with no playbook still works, with the planner building the plan from the code analyst's facts.

## The loop

1. Examine the code. The code analyst answers what the question needs from the source, and adds or updates facts and hypotheses.
2. Create the entry points and sensors. The planner writes the experiment and the instrumenter turns it into configuration, through the gate.
3. Restart. The runtime applies the configuration and resets state, and a preflight confirms the application is up and the new sensors are loaded.
4. Run and fuzz. The driver sends the stimulus, through the gate, as each persona.
5. Digest. The collector joins the evidence and the analyst reads it against the predictions.
6. Update and plan. The case file is updated, the question state is checked, and either the loop ends or the planner writes the next experiment.

## The final answer

The answer always carries the question state, the evidence behind it, a coverage statement that says what was and was not exercised, a reproduction a person can run, and a list of what the agent changed and reverted. A refutation without coverage is not an answer. "No IDOR found" is reported as "no IDOR found across these 14 endpoints and 3 personas, and these 6 endpoints were not reachable."

## What already exists

Much of the base is already in the dashboard. The Assistant engine and its tool loop become the planner. The scanner and library discovery (`list_libraries`, `search_libraries`, `describe_class`) become the first layer of the code analyst. The catalog and the config tools become the instrumenter's source material. The Run controller becomes the runtime. Event queries and the stack traces in events give the collector and the runtime half of the analyst their data.

## What has to be built

In rough order, these are the case file and orchestrator, the gate, the experiment format and the Assistant's change to emit experiments, the Driver with Playwright personas, the trace id propagation in the agent, the code map for the code analyst, the deterministic analyzers, and the first two or three playbooks. The IDOR playbook is the best first target because it needs every part of the loop.

## Risks and open decisions

Sending captured values to a model is a decision the person makes per project. It is recorded in the case file as an explicit setting, with sensitive kinds masked unless the person turns that off. It is acceptable for this feature only because the person chose it, and it should stay off by default everywhere else in JOT.

The agent exercises a live application, so the default is a localhost target and a gate that asks before any write. Nothing the model produces is ever run as a shell command. Only commands the person types or confirms are run.

Because this sends code structure and possibly data to a model API, and ships a browser automation dependency, it needs a review by IT and security before it is deployed anywhere beyond local use.

The loop is only as good as its evaluation. The ticketbook application has known flaws and should become the first test set, with the agent scored on whether it finds the known problems, whether it invents ones that are not there, and whether its coverage statements are true.

Open decisions are whether the Playwright install happens at first use after a consent prompt (the current recommendation) or without asking, whether state reset is a user-supplied command or something JOT infers, and how far the code map should go before it needs a real parser.
