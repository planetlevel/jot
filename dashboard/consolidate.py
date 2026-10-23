#!/usr/bin/env python3
"""Combines a jots file and the files it lists into one jots file, so all the configuration is in one place.

    python3 consolidate.py demo/ticketbook/.jot/jot.yaml --keep ../../cves

The sensors, rules and reports of every listed file are added to the jots file, with the comments that were in the files. --keep names an
entry of the jots: list that stays a separate file or directory, like a library shared by several projects. The listed files are not
touched, and the jots file is copied to jot.yaml.bak first when it is rewritten in place. Nothing is written until the result has been read
back and every sensor and report in it is exactly what was in its file. --dry-run says what would happen and writes nothing.
"""

import argparse
import sys

import store


def main(argv=None):
    p = argparse.ArgumentParser(description="Combine a jots file and the files it lists into one file")
    p.add_argument("jots", help="the jots file")
    p.add_argument("--out", help="write the result here instead of over the jots file. Keep it in the same directory, relative paths in it are relative to it")
    p.add_argument("--keep", action="append", default=[], metavar="ENTRY", help="an entry of the jots: list to leave as it is, repeat for more")
    p.add_argument("--dry-run", action="store_true", help="say what would be done and write nothing")
    args = p.parse_args(argv)
    try:
        done = store.consolidate(args.jots, args.out, args.keep, write=not args.dry_run)
    except (store.SaveError, OSError, ValueError) as e:
        print("consolidate:", e, file=sys.stderr)
        return 1
    print("%s %d sensors and rules and %d reports%s" % ("Would write" if args.dry_run else "Wrote", done["sensors"], done["reports"], " to " + done["out"]))
    if done["from"]:
        print("  combined from", ", ".join(done["from"]))
    else:
        print("  there was nothing to combine")
    if done["kept"]:
        print("  left as they are, listed in jots:", ", ".join(done["kept"]))
    for x in done["skipped"]:
        print("  left out %s %s of %s, since it was defined earlier" % (x["kind"], x["name"], x["file"]))
    for x in done["missing"]:
        print("  not found, so not combined:", x)
    if done["backup"]:
        print("  the jots file before is in", done["backup"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
