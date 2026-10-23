#!/usr/bin/env python3
r"""Writes the values of .jot files the one way they are written. A value is plain when it can be, which is when it reads back
as the same text. Otherwise it is in double quotes, unless it contains a double quote or a backslash, and then it is in single
quotes, where both are just themselves, so a regular expression keeps its backslashes and an expression keeps its strings.
That makes "#P0" and "!null" double quoted, '!\.class' and '#P0 + ": " + #RET' single quoted, and the rest, like (?i)\.log$, plain.
Everything else is left as written, comments and layout included. Every file is parsed before and after and left alone if the
two aren't the same.

    python3 tools/unquote_jot.py cves/*.jot demo/ticketbook/.jot/jot.yaml

needs_quotes and quote are also what the CVE generator uses, so regenerated files come out the same way.
"""
import re
import sys

import yaml

# what YAML 1.1 and 1.2 may read as something other than text. Anything like these keeps its quotes
_NOT_TEXT = re.compile(r"^(y|n|yes|no|true|false|on|off|null|~|[-+]?[\d._]+([eE][-+]?\d+)?|0[xob][\da-fA-F_]+|[-+]?\.(inf|nan)"
                       r"|\d{4}-\d\d?-\d\d?.*|[-+]?\d+(:\d+)+(\.\d*)?)$", re.IGNORECASE)


def needs_quotes(value):
    """True if value, written plain as a list item or after a key, wouldn't read back as exactly this text."""
    if not value or value != value.strip() or "\n" in value or "\t" in value or _NOT_TEXT.match(value):
        return True
    try:
        return yaml.safe_load("- " + value) != [value] or yaml.safe_load("k: " + value) != {"k": value}
    except yaml.YAMLError:
        return True


def quote(value):
    """The value as it is written in a .jot file, plain if it can be and otherwise quoted by the convention in the top of this file."""
    if not needs_quotes(value):
        return value
    if '"' not in value and "\\" not in value and value.isprintable():
        return '"' + value + '"'
    return "'" + value.replace("'", "''") + "'"


def _scalars(node, in_flow=False):
    """The quoted scalars of a document that are written in block style, which can be written plain."""
    if isinstance(node, yaml.ScalarNode):
        if node.style in ('"', "'") and not in_flow:
            yield node
    elif isinstance(node, yaml.SequenceNode):
        for item in node.value:
            yield from _scalars(item, in_flow or bool(node.flow_style))
    elif isinstance(node, yaml.MappingNode):
        for key, value in node.value:
            yield from _scalars(key, in_flow or bool(node.flow_style))
            yield from _scalars(value, in_flow or bool(node.flow_style))


def unquote(text):
    """The text with every quoted value written by the convention, and how many were changed. The text itself if anything would
    read differently."""
    try:
        root = yaml.compose(text)
        before = yaml.safe_load(text)
    except yaml.YAMLError:
        return text, 0
    if root is None:
        return text, 0
    edits = []
    for node in _scalars(root):
        raw = text[node.start_mark.index:node.end_mark.index]
        if "\n" in raw or "\n" in node.value or "\t" in node.value:
            continue
        written = quote(node.value)
        if written != raw:
            edits.append((node.start_mark.index, node.end_mark.index, written))
    result = text
    for start, end, value in sorted(edits, reverse=True):
        result = result[:start] + value + result[end:]
    try:
        if yaml.safe_load(result) != before:
            return text, 0
    except yaml.YAMLError:
        return text, 0
    return result, len(edits)


def main(paths):
    total = 0
    for path in paths:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
        result, count = unquote(text)
        if count:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(result)
        print("%4d  %s" % (count, path))
        total += count
    print("%4d  quotes removed" % total)


if __name__ == "__main__":
    main(sys.argv[1:])
