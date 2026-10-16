# CVE microsandboxes

Each file is the sandbox for one CVE, and each rule is named for it, like `cve-2021-44228`. Inside the vulnerable code
the library keeps working, but what an attack does with it, like starting a process or evaluating a script, is blocked.

These files are generated, don't edit them. The source of truth is the shield data in the vulnpoint repo, which says
where each CVE lives and what its code must not do there.

    tools/vulnpoint2jot.py CVE-2021-44228 CVE-2021-39144 -o cves     # needs ../vulnpoint
    tools/vulnpoint2jot.py --all -o /tmp/all-cves                    # every CVE vulnpoint has a policy for

Run an application with a rule by pointing the agent at the file, or at this folder for all of them.

    java -javaagent:jot.jar=cves/CVE-2021-44228.jot -jar app.jar
    java -Djot.enforce=false -javaagent:jot.jar=cves/ -jar app.jar     # report what would be blocked, stop nothing
