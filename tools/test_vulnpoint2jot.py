import json
import os
import sys
import tempfile
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vulnpoint2jot as v

CATALOG = {"process": ["java.lang.ProcessBuilder.start", "java.lang.Runtime.exec", "java.lang.ProcessImpl.forkAndExec"],
           "jndi": ["javax.naming.Context.lookup"], "scripting": ["javax.script.ScriptEngine.eval"]}


def shield(id="CVE-2021-44228", behavior="BLOCK", scopes=None):
    return {"id": id, "cve": id[:14], "title": "Remote code injection in Log4j", "max_supported_behavior": behavior,
            "target_library": {"package_coordinates": "org.apache.logging.log4j:log4j-core", "display_version_range": ">= 2.13.0, < 2.15.0"},
            "scope_methods": scopes if scopes is not None else [
                {"method": "org.apache.logging.log4j.core.lookup.JndiLookup.lookup", "disallowed_capabilities": ["process", "scripting"]},
                {"method": "org.apache.logging.log4j.core.net.JndiManager.lookup", "disallowed_capabilities": []}]}


def parsed(text):
    return yaml.safe_load(text)["sensors"]


class Vulnpoint2JotTests(unittest.TestCase):
    def test_a_shield_with_capabilities_becomes_a_rule_named_for_the_cve(self):
        (s,) = parsed("sensors:\n" + v.rule(shield(), CATALOG, [], False))
        self.assertEqual("cve-2021-44228", s["name"])
        self.assertEqual(["org.apache.logging.log4j.core.lookup.JndiLookup.lookup"], s["scopes"],
                         "only the scope methods that disallow something, the other one only says where the code lives")
        self.assertIn("java.lang.ProcessBuilder.start", s["methods"])
        self.assertIn("javax.script.ScriptEngine.eval", s["methods"])
        self.assertNotIn("javax.naming.Context.lookup", s["methods"], "jndi was not disallowed, so it stays allowed")
        self.assertIn("CVE-2021-44228", s["exception"])
        self.assertNotIn("enforce", s)

    def test_sinks_that_cannot_take_advice_are_left_out(self):
        (s,) = parsed("sensors:\n" + v.rule(shield(), CATALOG, [], False))
        self.assertNotIn("java.lang.ProcessImpl.forkAndExec", s["methods"])

    def test_a_shield_that_may_only_monitor_does_not_enforce(self):
        (s,) = parsed("sensors:\n" + v.rule(shield(behavior="MONITOR"), CATALOG, [], False))
        self.assertIs(False, s["enforce"])

    def test_a_shield_with_nothing_to_sandbox_is_skipped_or_observed(self):
        empty = shield(scopes=[{"method": "a.B.c", "disallowed_capabilities": []}])
        self.assertIsNone(v.rule(empty, CATALOG, [], False))
        (s,) = parsed("sensors:\n" + v.rule(empty, CATALOG, [], True))
        self.assertEqual((["a.B.c"], None), (s["methods"], s.get("exception")))

    def test_deny_gives_a_shield_without_a_policy_capabilities_and_says_so_and_only_reports(self):
        empty = shield(scopes=[{"method": "a.B.c", "disallowed_capabilities": []}])
        text = v.rule(empty, CATALOG, ["process"], False)
        (s,) = parsed("sensors:\n" + text)
        self.assertEqual(["a.B.c"], s["scopes"])
        self.assertIs(False, s["enforce"])
        self.assertIn("--deny", text)

    def test_a_constructor_is_written_the_way_jot_does(self):
        self.assertEqual("org.x.Foo.<init>", v.jot_method("org.x.Foo.Foo"))
        self.assertEqual("org.x.Outer$Inner.<init>", v.jot_method("org.x.Outer$Inner.Inner"))
        self.assertEqual("org.x.Foo.run", v.jot_method("org.x.Foo.run"))

    def test_quotes_in_a_title_do_not_break_the_file(self):
        s = shield()
        s["title"] = 'A "quoted" title: with, punctuation # and more'
        (rule,) = parsed("sensors:\n" + v.rule(s, CATALOG, [], False))
        self.assertEqual("cve-2021-44228", rule["name"])

    def test_a_cve_with_several_libraries_keeps_each_id(self):
        a, b = shield("CVE-2026-1111-spring5"), shield("CVE-2026-1111-spring6")
        rules = parsed("sensors:\n" + "\n".join(v.rule(x, CATALOG, [], False) for x in (a, b)))
        self.assertEqual(["cve-2026-1111-spring5", "cve-2026-1111-spring6"], [r["name"] for r in rules])

    def test_files_are_written_from_a_vulnpoint_checkout(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "shields", "java"))
            os.makedirs(os.path.join(root, "resources"))
            json.dump({"capabilities": {**CATALOG, "comment_x": ["ignored"]}}, open(os.path.join(root, "resources", "capabilities.json"), "w"))
            json.dump({"language": "JAVA", "shields": [shield()]}, open(os.path.join(root, "shields", "java", "CVE-2021-44228.json"), "w"))
            out = os.path.join(root, "out")
            sys.argv = ["x", "CVE-2021-44228", "--vulnpoint", root, "-o", out]
            v.main()
            self.assertEqual("cve-2021-44228", parsed(open(os.path.join(out, "CVE-2021-44228.jot")).read())[0]["name"])
            self.assertNotIn("comment_x", v.load_catalog(root))


if __name__ == "__main__":
    unittest.main()
