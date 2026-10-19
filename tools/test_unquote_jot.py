import os
import subprocess
import sys
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unquote_jot import needs_quotes, unquote  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class UnquoteTests(unittest.TestCase):
    def test_quotes_stay_where_plain_text_would_read_as_something_else(self):
        for value in ("#P0", "!null", "yes", "No", "123", "1.5", "null", "~", "", " padded", "a: b", "a #b", "- x", "[x]", "{x}",
                      "*star", "&anchor", "@at", "`tick", "%pct", "2026-10-18", "0x1F", "true", "on"):
            self.assertTrue(needs_quotes(value), repr(value))

    def test_quotes_go_where_plain_text_reads_the_same(self):
        for value in ("get-route", "javax.servlet.Servlet.service", "java.lang.ProcessBuilder.<init>", r"\.class", "a, b (c)",
                      "Blocks attempts to start native processes", "it's fine", 'say "hi"', "static java.util.UUID.<init>", "#P0.getRequestURI()".replace("#", "x")):
            self.assertFalse(needs_quotes(value), repr(value))

    def test_only_the_quotes_change_and_comments_and_layout_stay(self):
        text = '''---
# a bundle
sensors:

# first
- name: "one"   # trailing comment
  description: 'It''s "fine"'
  methods:
  - "a.b.C.m"
  captures:
  - "#P0"
  - '!null'
  matchers:
  - "\\\\.class"
  - "yes"
  flow: ["a", "b"]
'''
        result, count = unquote(text)
        self.assertEqual(yaml.safe_load(text), yaml.safe_load(result))
        self.assertEqual(4, count)
        self.assertIn("- name: one   # trailing comment", result)
        self.assertIn("  description: It's \"fine\"", result)
        self.assertIn("  - a.b.C.m", result)
        self.assertIn('  - "#P0"', result)
        self.assertIn("  - '!null'", result)
        self.assertIn("  - \\.class", result)
        self.assertIn('  - "yes"', result)
        self.assertIn('flow: ["a", "b"]', result, "a list written inline is left as it is")
        self.assertEqual(result, unquote(result)[0], "running it again changes nothing")

    def test_text_that_is_not_yaml_is_left_alone(self):
        self.assertEqual(("a: [b", 0), unquote("a: [b"))

    def test_every_jot_in_the_repo_is_already_free_of_unneeded_quotes(self):
        files = subprocess.check_output(["git", "ls-files", "*.jot"], cwd=ROOT, text=True).split()
        self.assertGreater(len(files), 20)
        for path in files:
            with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
                text = fh.read()
            self.assertEqual(0, unquote(text)[1], path)


if __name__ == "__main__":
    unittest.main()
