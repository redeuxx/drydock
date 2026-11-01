"""docs/threat-model.md: every threat names tests, and every named test exists."""

import ast
import re
from pathlib import Path

ROOT = Path(__file__).parent.parent
THREAT_RE = re.compile(r"^### (T\d+)\. ", re.MULTILINE)
TEST_RE = re.compile(r"`(tests/test_\w+\.py)::(test_\w+)`")
REFERENCE_RE = re.compile(r"`tests/[^`]*`")


def test_every_threat_names_tests_that_exist() -> None:
    text = (ROOT / "docs" / "threat-model.md").read_text(encoding="utf-8")
    # The threats section runs from its heading to the next second-level heading.
    section = text.split("\n## Threats\n", 1)[1].split("\n## ", 1)[0]
    headings = re.findall(r"^###.*$", section, re.MULTILINE)
    assert all(THREAT_RE.match(h) for h in headings), headings
    parts = THREAT_RE.split(section)[1:]
    threats = dict(zip(parts[::2], parts[1::2], strict=True))
    assert list(threats) == [f"T{n}" for n in range(1, len(threats) + 1)]
    malformed = len(REFERENCE_RE.findall(section)) - len(TEST_RE.findall(section))
    assert malformed == 0, "a test reference that is not tests/test_x.py::test_y"
    defined: dict[str, set[str]] = {}
    for threat, body in threats.items():
        named = TEST_RE.findall(body)
        assert named, f"{threat} names no test"
        for path, name in named:
            if path not in defined:
                tree = ast.parse((ROOT / path).read_text(encoding="utf-8"))
                defined[path] = {
                    node.name
                    for node in tree.body
                    if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
                }
            assert name in defined[path], f"{threat}: {path}::{name} does not exist"
