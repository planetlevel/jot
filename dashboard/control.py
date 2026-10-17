"""Switches JOT rules between monitor and protect by writing the control file that agents read.

The agent polls the file, once a second. Nothing here connects to an agent, and agents never accept
connections. The risk is that whoever can write this file can switch protection off, so every change is logged, and the file is replaced atomically so an agent never reads half of it.
"""

import json
import os
import tempfile
import threading
import time

import yaml


class ControlError(Exception):
    pass


class ControlStore:
    def __init__(self, path, audit_path=None):
        self.path = path
        self.audit_path = audit_path or path + ".audit"
        self._lock = threading.Lock()

    def read(self):
        """The settings in the file. A missing or unreadable file means the defaults."""
        state = {"protect": True, "rules": {}, "updated": None, "by": None, "exists": False}
        try:
            with open(self.path) as f:
                doc = yaml.safe_load(f)
        except (OSError, ValueError, yaml.YAMLError):
            return state
        if not isinstance(doc, dict):
            return state
        state["exists"] = True
        if isinstance(doc.get("protect"), bool):
            state["protect"] = doc["protect"]
        if isinstance(doc.get("rules"), dict):
            state["rules"] = {k: v for k, v in doc["rules"].items() if isinstance(v, bool)}
        state["updated"] = doc.get("updated")
        state["by"] = doc.get("by")
        return state

    def write(self, master=None, rules=None, known_rules=(), who="dashboard"):
        """Change settings. master is True or False, or None to leave it. rules maps a rule name to True (block),
        False (monitor) or None (back to the .jot setting). Only names in known_rules are accepted."""
        if master is not None and not isinstance(master, bool):
            raise ControlError("master must be true or false")
        if rules is not None and not isinstance(rules, dict):
            raise ControlError("rules must be an object")
        for name, value in (rules or {}).items():
            if name not in known_rules:
                raise ControlError("%s is not a rule. Rules are sensors that have an exception" % name)
            if value is not None and not isinstance(value, bool):
                raise ControlError("rule %s must be true, false or null" % name)

        with self._lock:
            current = self.read()
            before = {"protect": current["protect"], "rules": dict(current["rules"])}
            protect = current["protect"] if master is None else master
            merged = dict(current["rules"])
            for name, value in (rules or {}).items():
                if value is None:
                    merged.pop(name, None)
                else:
                    merged[name] = value
            doc = {"v": 1, "protect": protect, "rules": merged,
                   "updated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "by": who}
            self._atomic_write(doc)
            self._audit(who, before, {"protect": protect, "rules": merged})
        return self.read()

    def _atomic_write(self, doc):
        directory = os.path.dirname(os.path.abspath(self.path)) or "."
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".control-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                yaml.safe_dump(doc, f, sort_keys=False, default_flow_style=False)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, 0o644)       # agents may read it, only this user may write it
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def _audit(self, who, before, after):
        entry = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "by": who, "before": before, "after": after}
        with open(self.audit_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
