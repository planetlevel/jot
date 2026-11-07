"""The MCP server, against a stand-in for the dashboard. Run from the dashboard folder with python3 tests/test_mcp.py."""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
import mcp_server   # noqa: E402


class FakeDashboard:
    """Answers like the dashboard, and says what was posted. A jot-config event shows up once a sensor is written, when agent is True."""

    def __init__(self, agent=True, problems=None, editable=True):
        self.agent, self.problems, self.editable = agent, problems or [], editable
        self.posted, self.events = [], []

    def get(self, path):
        if path == "/api/jots":
            return {"editable": self.editable, "files": [{"name": "jot.yaml", "main": True}],
                    "sensors": [{"name": "old", "definition": "name: old"}], "reports": [], "issues": []}
        return {}

    def post(self, path, body):
        self.posted.append((path, body))
        if path == "/api/jots/check":
            return {"problems": self.problems}
        if path == "/api/jots/add":
            if self.agent:
                self.events.append("loaded=new")
            return {"added": "new", "file": body["file"]}
        if path == "/api/jots/delete":
            if self.agent:
                self.events.append("unloaded=" + body["name"])
            return {"deleted": "jot.yaml", "name": body["name"]}
        return {}

    def sql(self, sql, limit=None):
        if "MAX(pk)" in sql:
            return {"rows": [[0]]}
        return {"rows": [[1]] if any(("'%s'" % e) in sql for e in self.events) else []}


class NoCatalog:
    def available(self):
        return False


def tools_for(dash, **kw):
    clock = [0]
    return mcp_server.Tools(dash, NoCatalog(), wait=lambda s: clock.__setitem__(0, clock[0] + s), now=lambda: clock[0], confirm_seconds=3, **kw)


class ProtocolTests(unittest.TestCase):
    def test_lists_the_tools_and_ignores_notifications(self):
        t = tools_for(FakeDashboard())
        self.assertIsNone(mcp_server.handle(t, {"jsonrpc": "2.0", "method": "notifications/initialized"}))
        names = [x["name"] for x in mcp_server.handle(t, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})["result"]["tools"]]
        self.assertIn("add_sensor", names)
        self.assertIn("query_events", names)

    def test_a_tool_that_fails_answers_as_an_error_the_model_can_read(self):
        t = tools_for(FakeDashboard(problems=[{"line": 2, "message": "has no methods"}]))
        r = mcp_server.handle(t, {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "add_sensor", "arguments": {"yaml": "name: x"}}})
        self.assertTrue(r["result"]["isError"])
        self.assertIn("has no methods", r["result"]["content"][0]["text"])

    def test_unknown_tool_and_bad_arguments(self):
        t = tools_for(FakeDashboard())
        self.assertIn("error", mcp_server.handle(t, {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "nope"}}))
        r = mcp_server.handle(t, {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "remove_sensor", "arguments": {}}})
        self.assertTrue(r["result"]["isError"])


class ChangeTests(unittest.TestCase):
    def test_add_goes_to_the_main_file_and_waits_for_the_agent(self):
        d = FakeDashboard()
        out = tools_for(d).add_sensor("name: new")
        self.assertEqual("jot.yaml", out["file"])
        self.assertTrue(out["agent"].startswith("confirmed"))

    def test_add_says_so_when_the_agent_does_not_confirm(self):
        out = tools_for(FakeDashboard(agent=False)).add_sensor("name: new")
        self.assertTrue(out["agent"].startswith("not confirmed"))

    def test_add_refuses_when_saving_is_off(self):
        with self.assertRaises(mcp_server.ToolError):
            tools_for(FakeDashboard(editable=False)).add_sensor("name: new")

    def test_remove_sends_the_definition_the_dashboard_checks_against(self):
        d = FakeDashboard()
        out = tools_for(d).remove_sensor("old")
        self.assertEqual({"name": "old", "original": "name: old"}, d.posted[-1][1])
        self.assertTrue(out["agent"].startswith("confirmed"))
        with self.assertRaises(mcp_server.ToolError):
            tools_for(d).remove_sensor("missing")

    def test_answers_are_json(self):
        t = tools_for(FakeDashboard())
        json.dumps(t.check_sensor("name: x"))


if __name__ == "__main__":
    unittest.main()
