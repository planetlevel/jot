#!/usr/bin/env python3
"""Writes .jot files from the CVE shield data in the vulnpoint repo.

vulnpoint is the source of truth for where a CVE lives and what its code must not do there.
  shields/java/CVE-*.json   one file per CVE. Each shield names the scope methods, which are where the
                            vulnerable code runs, and the capabilities that are disallowed inside them
  resources/capabilities.json
                            the catalog that says which JDK and library methods perform each capability

A shield with disallowed capabilities becomes one JOT rule. Inside the scope methods, calling any method that
performs one of those capabilities throws, so the library keeps working, but what an attack does with it
doesn't. For example JNDI lookups stay allowed in Log4j, and starting a process from inside JndiLookup.lookup
does not. The rule is named for the shield, like cve-2021-44228.

A shield with no disallowed capabilities has nothing to sandbox. With --observe it becomes a sensor with no
exception, which records that the vulnerable code was reached.

    tools/vulnpoint2jot.py CVE-2021-44228 CVE-2021-39144 -o cves
    tools/vulnpoint2jot.py --all -o /tmp/all-cves
    tools/vulnpoint2jot.py CVE-2022-42889 --deny process,scripting     # a policy vulnpoint doesn't have yet
"""

import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_VULNPOINT = os.path.join(HERE, "..", "..", "vulnpoint")

# methods that can't take advice. They are native or private to the JDK, and the public method that calls them is
# in the catalog too, so nothing is lost by leaving them out
SKIP = ("java.lang.ProcessImpl.forkAndExec", "java.lang.ProcessImpl.start")


def q(text):
    """A YAML double quoted string. JSON strings are valid YAML."""
    return json.dumps(text, ensure_ascii=False)


def load_catalog(vulnpoint):
    with open(os.path.join(vulnpoint, "resources", "capabilities.json")) as f:
        catalog = json.load(f)["capabilities"]
    # a key like comment_reflection is a note in the file, not a capability
    return {k: v for k, v in catalog.items() if not k.startswith("comment_")}


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


def rule(shield, catalog, deny, observe):
    """The text of one sensor, or None when the shield has nothing to sandbox and observe wasn't asked for."""
    name = shield["id"].lower()
    library = shield["target_library"]
    scope_methods = shield["scope_methods"]
    with_caps = [m for m in scope_methods if m["disallowed_capabilities"]]
    caps = sorted({c for m in with_caps for c in m["disallowed_capabilities"]})
    overridden = False
    if not caps and deny:
        caps, with_caps, overridden = sorted(deny), scope_methods, True
    behavior = shield.get("max_supported_behavior", "MONITOR")

    header = "# %s %s\n# %s %s\n" % (shield["cve"], shield.get("title") or "", library["package_coordinates"],
                                     library.get("display_version_range") or "")
    if caps:
        sinks = sinks_for(caps, catalog)
        if not sinks:
            return None
        text = header
        if overridden:
            text += "# vulnpoint has no policy for this CVE, so the disallowed capabilities were given with --deny\n"
        text += "- name: %s\n" % q(name)
        text += "  description: %s\n" % q("%s microsandbox. Inside %s, these are not allowed: %s" % (
            shield["cve"], ", ".join(sorted({m["method"].rsplit(".", 2)[-2] + "." + m["method"].rsplit(".", 1)[-1] for m in with_caps})),
            ", ".join(caps)))
        text += "  methods:\n" + lines(sinks)
        text += "  scopes:\n" + lines(jot_method(m["method"]) for m in with_caps)
        text += "  captures:\n  - \"#ARGS\"\n"
        text += "  exception: %s\n" % q("%s microsandbox blocked %s" % (shield["cve"], " and ".join(caps) if len(caps) < 3 else ", ".join(caps)))
        if behavior != "BLOCK" or overridden:
            text += "  enforce: false\n"   # reports what it would have blocked until someone turns it on
        return text
    if observe:
        text = header + "- name: %s\n" % q(name)
        text += "  description: %s\n" % q("%s. The vulnerable code was reached" % shield["cve"])
        text += "  methods:\n" + lines(jot_method(m["method"]) for m in scope_methods)
        text += "  captures:\n  - \"#ARGS\"\n"
        return text
    return None


def convert(path, catalog, deny, observe):
    with open(path) as f:
        data = json.load(f)
    texts = [t for t in (rule(s, catalog, deny, observe) for s in data["shields"]) if t]
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
        text = convert(path, catalog, deny, args.observe)
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
