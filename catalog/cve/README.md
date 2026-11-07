# Known vulnerabilities

Known vulnerabilities. Each rule is a sandbox for one CVE in one library, named for it, like `cve-2021-44228`. Inside the vulnerable code the library keeps working, but what an attack does with it is flagged or blocked.
A rule only matters when the application uses a vulnerable version, which the note above each rule says, so search this area by the library's name and don't copy all of it.

## How a rule is written

A CVE rule uses two lists, and they mean different things.

`scopes` lists the methods or call sites of the CVE, which is the vulnerable code itself, like `org.apache.logging.log4j.core.lookup.JndiLookup.lookup`. The rule only applies while one of them is running, so the rest of the library, and the rest of the application, is left alone.

`methods` lists the harmful capabilities to flag or block, like starting a process, evaluating a script, compiling code or looking up a remote object over JNDI. Inside the scope, a call to any of them is what the rule reports or stops.

    - name: cve-2021-44228
      description: Identifies an attack on CVE-2021-44228, when its vulnerable code does something an exploit needs, like starting a process or running a script
      methods:                      # the harmful capabilities
      - java.lang.Runtime.exec
      - javax.script.ScriptEngine.eval
      scopes:                       # the CVE's own methods
      - org.apache.logging.log4j.core.lookup.JndiLookup.lookup
      captures:
        args: "#ARGS"
      block-when: true

Put the library and its vulnerable versions in the comment above the rule, as the existing files do, because that is what the Assistant reads to decide whether a rule applies. A rule is copied with `protect: false`, so it only reports until you turn it on. The agent reports once that a scope was entered, as `cve-...-active`, which is how to tell that a CVE is active in an application.

## Adding more

The files are made from the shield data in the vulnpoint repo, which says where each CVE lives and what its code must not do there.

    tools/vulnpoint2jot.py CVE-2021-44228 CVE-2019-12384 -o catalog/cve     # needs ../vulnpoint, on its main branch
    tools/vulnpoint2jot.py --all -o /tmp/all-cves                            # every CVE vulnpoint has an active policy for, 109 of them
