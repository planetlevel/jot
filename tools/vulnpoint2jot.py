#!/usr/bin/env python3
"""Writes .jot files from the CVE shield data in the vulnpoint repo.

vulnpoint is the source of truth for where a CVE lives and what its code must not do there.
  shields/java/CVE-*.json   one file per CVE. Each shield names the scope methods, which are where the
                            vulnerable code runs, and the capabilities that are disallowed inside them
  vulnpoint/callgraph/java/capabilities-policy.json, or resources/capabilities.json in older checkouts
                            the catalog that says which JDK and library methods perform each capability

A shield with disallowed capabilities becomes one JOT rule. Inside the scope methods, calling any method that
performs one of those capabilities throws, so the library keeps working, but what an attack does with it
doesn't. For example JNDI lookups stay allowed in Log4j, and starting a process from inside JndiLookup.lookup
does not. The rule is named for the shield, like cve-2021-44228.

vulnpoint can fail to tie an active policy to its shield, for example when the policy names a method the shield
doesn't list, and the shield then says nothing is disallowed. So the active policy in data/policies is read as well,
and its methods are added to the scope.

A rule says when the vulnerable code runs, without anything more in the file. The agent reports that the scope of a JOT
is active, once, as cve-...-active, and that is how to tell whether a CVE is active in an application. A shield with no
disallowed capabilities and no policy has nothing to sandbox. With --observe it becomes a sensor on the vulnerable
methods instead.

    tools/vulnpoint2jot.py CVE-2021-44228 CVE-2019-12384 -o cves
    tools/vulnpoint2jot.py --all -o /tmp/all-cves
    tools/vulnpoint2jot.py CVE-2022-42889 --deny process,scripting     # a policy vulnpoint doesn't have yet
"""

import argparse
import glob
import json
import os
import re
import sys

from unquote_jot import needs_quotes

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VULNPOINT = os.path.join(HERE, "..", "..", "vulnpoint")

# methods that can't take advice. They are native or private to the JDK, and the public method that calls them is
# in the catalog too, so nothing is lost by leaving them out
SKIP = ("java.lang.ProcessImpl.forkAndExec", "java.lang.ProcessImpl.start")


def q(text):
    """A YAML value, plain when it reads back as the same text and a double quoted string when it needs to be. JSON
    strings are valid YAML."""
    return text if not needs_quotes(text) else json.dumps(text, ensure_ascii=False)


# where the Java sink mappings are. Newer vulnpoint keeps them with the call graph code, and resources/capabilities.json
# is only the vocabulary. Older vulnpoint has the sinks in resources/capabilities.json.
CATALOGS = (os.path.join("vulnpoint", "callgraph", "java", "capabilities-policy.json"),
            os.path.join("resources", "capabilities.json"))
METHOD = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*\.(<init>|<clinit>|[A-Za-z_$][\w$]*)$")


def load_catalog(vulnpoint):
    """capability -> the methods that perform it. Refuses a file that isn't that, so a change in vulnpoint's layout
    stops the generator and does not turn into rules full of nonsense."""
    for relative in CATALOGS:
        path = os.path.join(vulnpoint, relative)
        if not os.path.exists(path):
            continue
        with open(path) as f:
            catalog = json.load(f).get("capabilities", {})
        # a key like comment_reflection is a note in the file, not a capability
        catalog = {k: v for k, v in catalog.items() if not k.startswith(("comment_", "_"))}
        bad = [k for k, v in catalog.items() if not (isinstance(v, list) and all(isinstance(m, str) and METHOD.match(m) for m in v))]
        if len(bad) == len(catalog):
            continue          # this one is only the vocabulary, the sinks are in the next
        if bad:
            sys.exit("%s has entries that are not lists of methods, %s" % (relative, ", ".join(bad[:5])))
        return catalog
    sys.exit("no capability catalog with sink methods in %s, looked for %s" % (vulnpoint, " and ".join(CATALOGS)))


def load_policy(vulnpoint, cve):
    """The active policy entries for a CVE, as (entry method, capabilities). An entry that denies nothing, or one
    that isn't active, is left out."""
    # the file is named for the CVE, and newer vulnpoint adds the language, like CVE-2021-44228_java.json
    folder = os.path.join(vulnpoint, "data", "policies")
    path = next((p for p in (os.path.join(folder, cve + suffix + ".json") for suffix in ("_java", "")) if os.path.exists(p)), None)
    if not path:
        return []
    with open(path) as f:
        policy = json.load(f)
    if policy.get("status") != "active":
        return []
    return [(m["entry_method"], sorted(m["policy"]["deny"])) for m in policy.get("methods", []) if m["policy"].get("deny")]


def sinks_for(capabilities, catalog):
    found = []
    for cap in capabilities:
        for method in catalog.get(cap, []):
            if method not in SKIP and method not in found:
                found.append(method)
    return found


def jot_method(method):
    """vulnpoint names a constructor after its class, like Foo.Foo. JOT writes it as Foo.<init>."""
    cls, _, name = method.rpartition(".")
    return cls + ".<init>" if name == cls.rsplit(".", 1)[-1].rsplit("$", 1)[-1] else method


def lines(items, indent="  "):
    return "".join("%s- %s\n" % (indent, q(i)) for i in items)


def scope_groups(shield, policy, deny):
    """The scope methods that disallow something, grouped by what they disallow, as {capabilities: [methods]}.
    These come from the shield. A policy entry whose method the shield doesn't list is added as well, which is the
    case when vulnpoint couldn't match the policy to the shield and left the shield monitor only."""
    groups, seen = {}, set()
    for m in shield["scope_methods"]:
        if m["disallowed_capabilities"]:
            groups.setdefault(tuple(sorted(m["disallowed_capabilities"])), []).append(m["method"])
            seen.add(m["method"])
    unmatched = [(method, caps) for method, caps in policy if method not in seen]
    for method, caps in unmatched:
        groups.setdefault(tuple(caps), []).append(method)
    return groups, bool(unmatched)


def rule(shield, catalog, deny, observe, policy=()):
    """The text of the sensors for one shield, or None when it has nothing to sandbox and observe wasn't asked for.
    A shield whose methods disallow different things gives one sensor for each, named id, id-2, id-3."""
    base = shield["id"].lower()
    library = shield["target_library"]
    scope_methods = shield["scope_methods"]
    groups, from_policy = scope_groups(shield, policy, deny)
    overridden = False
    if not groups and deny:
        groups, overridden = {tuple(sorted(deny)): [m["method"] for m in scope_methods]}, True
    behavior = shield.get("max_supported_behavior", "MONITOR")
    header = "# %s %s\n# %s %s\n" % (shield["cve"], shield.get("title") or "", library["package_coordinates"],
                                     library.get("display_version_range") or "")
    texts = []
    for n, (caps, methods) in enumerate(groups.items(), 1):
        sinks = sinks_for(caps, catalog)
        if not sinks:
            continue
        name = base if n == 1 else "%s-%d" % (base, n)
        text = header if not texts else ""
        if overridden:
            text += "# vulnpoint has no policy for this CVE, so the disallowed capabilities were given with --deny\n"
        if from_policy and not overridden:
            text += "# scope from the vulnpoint policy, its shield doesn't list this method\n"
        text += "- name: %s\n" % q(name)
        short = sorted({jot_method(m).rsplit(".", 2)[-2] + "." + jot_method(m).rsplit(".", 1)[-1] for m in methods})
        text += "  description: %s\n" % q("%s microsandbox. Inside %s, these are not allowed: %s" % (
            shield["cve"], ", ".join(short), ", ".join(caps)))
        text += "  methods:\n" + lines(sinks)
        text += "  scopes:\n" + lines(jot_method(m) for m in methods)
        text += "  captures:\n  - \"#ARGS\"\n"
        text += "  block-when: true\n"
        if (behavior != "BLOCK" and not from_policy) or overridden:
            text += "  protect: false\n"   # reports what it would have blocked until someone turns it on
        texts.append(text)
    if texts:
        return "\n".join(texts)
    if observe:
        # nothing to sandbox, so only a sensor on the methods that make up the vulnerable code. It records the word reached
        # and not the arguments, which can be anything, a whole request body for a JSON library.
        text = header + "- name: %s\n" % q(base)
        text += "  description: %s\n" % q("%s. The vulnerable code was reached" % shield["cve"])
        text += "  methods:\n" + lines(jot_method(m["method"]) for m in scope_methods)
        text += "  captures:\n  - %s\n" % q("'reached'")
        return text
    return None


def convert(path, catalog, deny, observe, vulnpoint=None):
    with open(path) as f:
        data = json.load(f)
    policy = load_policy(vulnpoint, os.path.basename(path)[:-5]) if vulnpoint else []
    # a policy can only be tied to a shield by its method, so with several shields it is added to none of them
    given = policy if len(data["shields"]) == 1 else []
    texts = [t for t in (rule(s, catalog, deny, observe, given) for s in data["shields"]) if t]
    return "sensors:\n" + "\n".join(texts) if texts else None


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("cves", nargs="*", help="CVE ids, like CVE-2021-44228")
    p.add_argument("--all", action="store_true", help="every CVE in vulnpoint")
    p.add_argument("--vulnpoint", default=DEFAULT_VULNPOINT, help="the vulnpoint checkout, default ../vulnpoint")
    p.add_argument("-o", "--out", default="cves", help="where to write the .jot files")
    p.add_argument("--observe", action="store_true", help="also write a sensor for shields that have nothing to sandbox")
    p.add_argument("--deny", default="", help="capabilities to disallow for a shield that has none, comma separated")
    args = p.parse_args()

    if not os.path.isdir(os.path.join(args.vulnpoint, "data", "policies")) or \
            not glob.glob(os.path.join(args.vulnpoint, "data", "policies", "CVE-*.json")):
        sys.exit("no policies in %s/data/policies, is --vulnpoint a vulnpoint checkout?" % args.vulnpoint)
    catalog = load_catalog(args.vulnpoint)
    deny = [c for c in args.deny.split(",") if c]
    unknown = [c for c in deny if c not in catalog]
    if unknown:
        sys.exit("unknown capability %s, the catalog has %s" % (", ".join(unknown), ", ".join(sorted(catalog))))
    folder = os.path.join(args.vulnpoint, "shields", "java")
    paths = sorted(glob.glob(os.path.join(folder, "CVE-*.json"))) if args.all else \
        [os.path.join(folder, c.upper() + ".json") for c in args.cves]
    if not paths:
        p.error("give CVE ids or --all")
    os.makedirs(args.out, exist_ok=True)
    written = skipped = 0
    for path in paths:
        if not os.path.exists(path):
            print("no shield for %s" % os.path.basename(path)[:-5], file=sys.stderr)
            skipped += 1
            continue
        text = convert(path, catalog, deny, args.observe, args.vulnpoint)
        if text is None:
            skipped += 1
            continue
        target = os.path.join(args.out, os.path.basename(path)[:-5] + ".jot")
        with open(target, "w") as f:
            f.write(text)
        written += 1
    print("wrote %d files to %s, %d CVEs had nothing to write" % (written, args.out, skipped))


if __name__ == "__main__":
    main()
