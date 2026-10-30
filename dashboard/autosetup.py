"""Fills in what the jots file doesn't say yet when the console starts, from a look at the project's source.

It fills the gaps and never changes a setting the file already has, so a person's or the Assistant's choices stay as they were. What it can
fill is the entry points, the application's packages, and one sensor, http-route, that names the route of each request. Nothing is read
outside the project folder, and a folder that has no Java in it is left alone.
"""

import os
import re

import scanner
import store

ROUTE_SENSOR = """name: http-route
description: Identifies the route a request came in at
methods:
- javax.servlet.Servlet.service
- jakarta.servlet.Servlet.service
captures:
  path: "#P0.getRequestURI()"
  method: "#P0.getMethod()"
"""

SOURCE = (".java", ".kt", ".scala", ".groovy")
MAX_FILES = 5000
MAX_PACKAGES = 3
_CLASS = re.compile(r"^\s*(?:public\s+)?(?:final\s+|abstract\s+)*(?:class|interface|enum)\s+(\w+)", re.M)
_MAIN = re.compile(scanner.SIGNALS[11][0])
_SERVLET_KINDS = {"a servlet class", "a servlet annotation", "a servlet filter", "a Spring controller", "a Spring request mapping",
                  "a JAX-RS resource", "a framework route", "a Struts action"}
_SCHEDULED = "@org.springframework.scheduling.annotation.Scheduled"


def _walk(folder):
    seen = 0
    for base, dirs, files in os.walk(folder):
        dirs[:] = sorted(d for d in dirs if d not in scanner.SKIP_DIRS and d not in scanner.SECRET_DIRS and not d.startswith("."))
        for name in sorted(files):
            seen += 1
            if seen > MAX_FILES:
                return
            yield os.path.join(base, name)


def _in_tests(path):
    return (os.sep + "test" + os.sep) in path or (os.sep + "tests" + os.sep) in path


def detect(folder):
    """What the project's source says, as {"entry": [...], "packages": [...], "servlet": bool}. Empty lists when it says nothing."""
    packages, mains, kinds = {}, [], set()
    web = False
    for path in _walk(folder):
        if os.path.basename(path) == "web.xml" or path.endswith((".jsp", ".jspx")):
            web = True
        if not path.endswith(SOURCE) or _in_tests(path):
            continue
        try:
            if os.path.getsize(path) > scanner.MAX_SEARCH_BYTES:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        package = scanner._PACKAGE.search(text[:3000])
        if package:
            prefix = ".".join(package.group(1).split(".")[:2])
            packages[prefix] = packages.get(prefix, 0) + 1
        for rx, kind in scanner._SIGNALS:
            if rx.search(text):
                kinds.add(kind)
        if package and path.endswith(".java") and _MAIN.search(text):
            owner = _CLASS.search(text)
            if owner:
                mains.append("%s.%s.main" % (package.group(1), owner.group(1)))
    entry = []
    servlet = web or bool(kinds & _SERVLET_KINDS)
    if servlet:
        entry += list(store.DEFAULT_ENTRY)
    if "a Spring scheduled task" in kinds:
        entry.append(_SCHEDULED)
    if not servlet:
        entry += mains[:3]
    top = [p for p, _ in sorted(packages.items(), key=lambda kv: (-kv[1], kv[0])) if not p.startswith(("java.", "javax.", "jakarta."))]
    return {"entry": entry, "packages": [p for p in top[:MAX_PACKAGES] if store.package_problems([p]) == []], "servlet": servlet}


def _has_sensor(jots_file, name):
    for path in store.config_paths(jots_file):
        for found in store.jot_files([path]):
            try:
                with open(found, encoding="utf-8") as fh:
                    if name in store.sensor_spans(fh.read()):
                        return True
            except OSError:
                continue
    return False


def run(jots_file, folder, say=print):
    """Fills the entry points, packages and route sensor the jots file doesn't have. Returns what was added, as a list of words for the
    startup message. A problem is said and skipped, since the console should start whatever happens here."""
    added = []
    try:
        settings = store.read_settings(jots_file)
        found = detect(folder)
        if settings["entry"] is None and found["entry"]:
            store.write_entry(jots_file, found["entry"], None)
            added.append("%d entry points" % len(found["entry"]))
        if settings["packages"] is None and found["packages"]:
            store.write_packages(jots_file, found["packages"], None)
            added.append("packages " + ", ".join(found["packages"]))
        if found["servlet"] and not _has_sensor(jots_file, "http-route"):
            store.add_sensor([jots_file], os.path.basename(jots_file), ROUTE_SENSOR)
            added.append("the http-route sensor")
    except (OSError, ValueError, store.SaveError, store.QueryError) as e:
        say("  couldn't fill in the project settings, %s" % e)
    if added:
        say("  filled in %s in %s" % (", ".join(added), os.path.relpath(jots_file)))
    return added
