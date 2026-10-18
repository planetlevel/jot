#!/usr/bin/env python3
"""Takes the quotes off values in .jot files that don't need them, leaving everything else as written, comments and
layout included. A value keeps its quotes if written plain it would read as something else, like "#P0", "!null", "yes" or
"a: b". Every file is parsed before and after and left alone if the two aren't the same.

    python3 tools/unquote_jot.py cves/*.jot demo/ticketbook/jots/*.jot

needs_quotes is also what the CVE generator uses, so regenerated files come out the same way.
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
    """The text with unneeded quotes removed, and how many were. The text itself if anything would read differently."""
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
        if "\n" in raw or needs_quotes(node.value):
            continue
        edits.append((node.start_mark.index, node.end_mark.index, node.value))
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
