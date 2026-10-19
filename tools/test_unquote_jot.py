import os
import subprocess
import sys
import unittest

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from unquote_jot import needs_quotes, quote, unquote  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")


class UnquoteTests(unittest.TestCase):
    def test_quotes_stay_where_plain_text_would_read_as_something_else(self):
        for value in ("#P0", "!null", "yes", "No", "123", "1.5", "null", "~", "", " padded", "a: b", "a #b", "- x", "[x]", "{x}",
                      "*star", "&anchor", "@at", "`tick", "%pct", "2026-10-18", "0x1F", "true", "on"):
            self.assertTrue(needs_quotes(value), repr(value))

    def test_quotes_go_where_plain_text_reads_the_same(self):
        for value in ("http-route", "javax.servlet.Servlet.service", "java.lang.ProcessBuilder.<init>", r"\.class", "a, b (c)",
                      "Blocks attempts to start native processes", "it's fine", 'say "hi"', "static java.util.UUID.<init>", "#P0.getRequestURI()".replace("#", "x")):
            self.assertFalse(needs_quotes(value), repr(value))

    def test_the_convention_is_plain_then_double_quotes_then_single_when_there_is_a_double_quote_or_a_backslash(self):
        for value, written in (("get-routes", "get-routes"), ("#P0", '"#P0"'), ("!null", '"!null"'), ("yes", '"yes"'), ("a: b", '"a: b"'),
                               ("(?i)\\.log$", "(?i)\\.log$"), ('#P0 + ": " + #RET', "'#P0 + \": \" + #RET'"),
                               ("!\\.class", "'!\\.class'"), ("#P0.equals('x')", '"#P0.equals(\'x\')"'),
                               ("#P0 + \"it's\"", "'#P0 + \"it''s\"'")):
            self.assertEqual(written, quote(value), value)
            self.assertEqual(value, yaml.safe_load("- " + written)[0], "and it reads back as the same text")

    def test_every_value_is_written_by_the_convention_and_comments_and_layout_stay(self):
        text = '''---
# a bundle
sensors:

# first
- name: "one"   # trailing comment
  description: 'It''s "fine"'
  methods:
  - "a.b.C.m"
  captures:
  - '#P0'
  - "!null"
  matchers:
  - "\\\\.class"
  - "yes"
  - '(?i)\\.log$'
  - "#P0 + \\": \\" + #RET"
  flow: ["a", "b"]
'''
        result, count = unquote(text)
        self.assertEqual(yaml.safe_load(text), yaml.safe_load(result))
        self.assertIn("- name: one   # trailing comment", result)
        self.assertIn("  description: It's \"fine\"", result, "quotes inside don't make a value need them, only how it starts does")
        self.assertIn("  - a.b.C.m", result)
        self.assertIn('  - "#P0"', result, "single quotes with nothing inside that needs them become double")
        self.assertIn('  - "!null"', result)
        self.assertIn("  - \\.class", result, "plain, the backslash needs no quoting there")
        self.assertIn('  - "yes"', result)
        self.assertIn("  - (?i)\\.log$", result, "plain, nothing about it needs quotes")
        self.assertIn("  - '#P0 + \": \" + #RET'", result, "double quotes inside become single quotes")
        self.assertIn('flow: ["a", "b"]', result, "a list written inline is left as it is")
        self.assertEqual(result, unquote(result)[0], "running it again changes nothing")
        self.assertEqual(0, unquote(result)[1])

    def test_text_that_is_not_yaml_is_left_alone(self):
        self.assertEqual(("a: [b", 0), unquote("a: [b"))

    def test_every_jot_in_the_repo_is_written_by_the_convention(self):
        files = subprocess.check_output(["git", "ls-files", "*.jot"], cwd=ROOT, text=True).split()
        self.assertGreater(len(files), 20)
        for path in files:
            with open(os.path.join(ROOT, path), encoding="utf-8") as fh:
                text = fh.read()
            self.assertEqual(0, unquote(text)[1], path)


if __name__ == "__main__":
    unittest.main()
