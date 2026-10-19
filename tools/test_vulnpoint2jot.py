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


def rules_of(text):
    """Just the rules of a file, the sensors that block."""
    return [s for s in parsed(text) if "block-when" in s]


class Vulnpoint2JotTests(unittest.TestCase):
    def test_a_rule_has_no_separate_sensor_because_the_agent_reports_its_scope_being_active(self):
        names = [s["name"] for s in parsed("sensors:\n" + v.rule(shield(), CATALOG, [], False))]
        self.assertEqual(["cve-2021-44228"], names)

    def test_a_shield_with_capabilities_becomes_a_rule_named_for_the_cve(self):
        (s,) = rules_of("sensors:\n" + v.rule(shield(), CATALOG, [], False))
        self.assertEqual("cve-2021-44228", s["name"])
        self.assertEqual(["org.apache.logging.log4j.core.lookup.JndiLookup.lookup"], s["scopes"],
                         "only the scope methods that disallow something, the other one only says where the code lives")
        self.assertIn("java.lang.ProcessBuilder.start", s["methods"])
        self.assertIn("javax.script.ScriptEngine.eval", s["methods"])
        self.assertNotIn("javax.naming.Context.lookup", s["methods"], "jndi was not disallowed, so it stays allowed")
        self.assertIn("CVE-2021-44228", s["description"])
        self.assertIs(True, s["block-when"], "a rule that blocks every call that gets that far")
        self.assertNotIn("exception", s)
        self.assertNotIn("protect", s)

    def test_sinks_that_cannot_take_advice_are_left_out(self):
        (s,) = rules_of("sensors:\n" + v.rule(shield(), CATALOG, [], False))
        self.assertNotIn("java.lang.ProcessImpl.forkAndExec", s["methods"])

    def test_a_shield_that_may_only_monitor_does_not_protect(self):
        (s,) = rules_of("sensors:\n" + v.rule(shield(behavior="MONITOR"), CATALOG, [], False))
        self.assertIs(False, s["protect"])

    def test_a_shield_with_nothing_to_sandbox_is_skipped_or_observed(self):
        empty = shield(scopes=[{"method": "a.B.c", "disallowed_capabilities": []}])
        self.assertIsNone(v.rule(empty, CATALOG, [], False))
        (s,) = parsed("sensors:\n" + v.rule(empty, CATALOG, [], True))
        self.assertEqual(("cve-2021-44228", ["a.B.c"], ["'reached'"], None), (s["name"], s["methods"], s["captures"], s.get("block-when")),
                         "a sensor that records the word reached and nothing of the arguments")

    def test_deny_gives_a_shield_without_a_policy_capabilities_and_says_so_and_only_reports(self):
        empty = shield(scopes=[{"method": "a.B.c", "disallowed_capabilities": []}])
        text = v.rule(empty, CATALOG, ["process"], False)
        (s,) = rules_of("sensors:\n" + text)
        self.assertEqual(["a.B.c"], s["scopes"])
        self.assertIs(False, s["protect"])
        self.assertIn("--deny", text)

    def test_a_constructor_is_written_the_way_jot_does(self):
        self.assertEqual("org.x.Foo.<init>", v.jot_method("org.x.Foo.Foo"))
        self.assertEqual("org.x.Outer$Inner.<init>", v.jot_method("org.x.Outer$Inner.Inner"))
        self.assertEqual("org.x.Foo.run", v.jot_method("org.x.Foo.run"))

    def test_quotes_in_a_title_do_not_break_the_file(self):
        s = shield()
        s["title"] = 'A "quoted" title: with, punctuation # and more'
        (rule,) = rules_of("sensors:\n" + v.rule(s, CATALOG, [], False))
        self.assertEqual("cve-2021-44228", rule["name"])

    def test_a_cve_with_several_libraries_keeps_each_id(self):
        a, b = shield("CVE-2026-1111-spring5"), shield("CVE-2026-1111-spring6")
        rules = rules_of("sensors:\n" + "\n".join(v.rule(x, CATALOG, [], False) for x in (a, b)))
        self.assertEqual(["cve-2026-1111-spring5", "cve-2026-1111-spring6"], [r["name"] for r in rules])

    def test_an_active_policy_the_shield_did_not_pick_up_is_added_to_the_scope(self):
        monitor_only = shield("CVE-2014-0114", "MONITOR", [{"method": "a.PropertyUtilsBean.reset", "disallowed_capabilities": []}])
        policy = [("a.BeanUtilsBean.setProperty", ["jndi", "process"])]
        text = v.rule(monitor_only, CATALOG, [], False, policy)
        (s,) = rules_of("sensors:\n" + text)
        self.assertEqual(["a.BeanUtilsBean.setProperty"], s["scopes"])
        self.assertIn("javax.naming.Context.lookup", s["methods"])
        self.assertNotIn("protect", s, "the policy is active, so it blocks")
        self.assertIn("vulnpoint policy", text)

    def test_a_policy_for_a_method_the_shield_already_has_is_not_added_twice(self):
        policy = [("org.apache.logging.log4j.core.lookup.JndiLookup.lookup", ["process", "scripting"])]
        (s,) = rules_of("sensors:\n" + v.rule(shield(), CATALOG, [], False, policy))
        self.assertEqual(1, len(s["scopes"]))

    def test_methods_that_disallow_different_things_get_a_sensor_each(self):
        two = shield(scopes=[{"method": "a.B.one", "disallowed_capabilities": ["process"]},
                             {"method": "a.B.two", "disallowed_capabilities": ["jndi"]}])
        rules = rules_of("sensors:\n" + v.rule(two, CATALOG, [], False))
        self.assertEqual(["cve-2021-44228", "cve-2021-44228-2"], [r["name"] for r in rules])
        self.assertEqual([["a.B.one"], ["a.B.two"]], [r["scopes"] for r in rules])
        self.assertNotIn("javax.naming.Context.lookup", rules[0]["methods"])

    def test_policies_are_read_only_when_active_and_only_when_they_deny_something(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "data", "policies"))
            def write(cve, status, deny):
                with open(os.path.join(root, "data", "policies", cve + ".json"), "w") as f:
                    json.dump({"cve_id": cve, "status": status, "methods": [{"entry_method": "a.B.c", "policy": {"deny": deny}}]}, f)
            write("CVE-1", "active", ["process", "jndi"])
            write("CVE-2", "unblockable", ["process"])
            write("CVE-3", "active", [])
            self.assertEqual([("a.B.c", ["jndi", "process"])], v.load_policy(root, "CVE-1"))
            self.assertEqual([], v.load_policy(root, "CVE-2"))
            self.assertEqual([], v.load_policy(root, "CVE-3"))
            self.assertEqual([], v.load_policy(root, "CVE-4"))
            os.rename(os.path.join(root, "data", "policies", "CVE-1.json"), os.path.join(root, "data", "policies", "CVE-1_java.json"))
            self.assertEqual([("a.B.c", ["jndi", "process"])], v.load_policy(root, "CVE-1"), "the newer name has the language in it")

    def test_the_catalog_comes_from_the_call_graph_folder_when_resources_is_only_the_vocabulary(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "resources"))
            os.makedirs(os.path.join(root, "vulnpoint", "callgraph", "java"))
            with open(os.path.join(root, "resources", "capabilities.json"), "w") as f:
                json.dump({"capabilities": {"process": {"description": "starts a process", "supported_languages": ["java"]}}}, f)
            with open(os.path.join(root, "vulnpoint", "callgraph", "java", "capabilities-policy.json"), "w") as f:
                json.dump({"capabilities": CATALOG}, f)
            self.assertEqual(["java.lang.ProcessBuilder.start", "java.lang.Runtime.exec", "java.lang.ProcessImpl.forkAndExec"],
                             v.load_catalog(root)["process"])

    def test_a_catalog_that_is_only_descriptions_stops_the_generator_and_does_not_write_nonsense(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "resources"))
            with open(os.path.join(root, "resources", "capabilities.json"), "w") as f:
                json.dump({"capabilities": {"process": {"description": "starts a process", "supported_languages": ["java"]}}}, f)
            with self.assertRaises(SystemExit) as stop:
                v.load_catalog(root)
            self.assertIn("no capability catalog with sink methods", str(stop.exception))

    def test_constructors_are_valid_sinks(self):
        for sink in ("java.io.FileOutputStream.<init>", "a.Outer$Inner.run", "java.lang.Runtime.exec"):
            self.assertRegex(sink, v.METHOD)
        for bad in ("description", "a.b c", "", "java.lang."):
            self.assertNotRegex(bad, v.METHOD)

    def test_a_catalog_with_some_entries_that_are_not_methods_is_refused(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "resources"))
            with open(os.path.join(root, "resources", "capabilities.json"), "w") as f:
                json.dump({"capabilities": {"process": ["java.lang.Runtime.exec"], "jndi": {"description": "x"}}}, f)
            with self.assertRaises(SystemExit) as stop:
                v.load_catalog(root)
            self.assertIn("jndi", str(stop.exception))

    def test_files_are_written_from_a_vulnpoint_checkout(self):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, "shields", "java"))
            os.makedirs(os.path.join(root, "resources"))
            os.makedirs(os.path.join(root, "data", "policies"))
            json.dump({"cve_id": "CVE-2021-44228", "status": "active", "methods": []}, open(os.path.join(root, "data", "policies", "CVE-2021-44228_java.json"), "w"))
            json.dump({"capabilities": {**CATALOG, "comment_x": ["ignored"]}}, open(os.path.join(root, "resources", "capabilities.json"), "w"))
            json.dump({"language": "JAVA", "shields": [shield()]}, open(os.path.join(root, "shields", "java", "CVE-2021-44228.json"), "w"))
            out = os.path.join(root, "out")
            sys.argv = ["x", "CVE-2021-44228", "--vulnpoint", root, "-o", out]
            v.main()
            self.assertEqual("cve-2021-44228", parsed(open(os.path.join(out, "CVE-2021-44228.jot")).read())[0]["name"])
            self.assertNotIn("comment_x", v.load_catalog(root))


if __name__ == "__main__":
    unittest.main()
