import json
from vibefort.secrets import parse_betterleaks_output


def test_parse_betterleaks_output_with_findings():
    raw = json.dumps([{
        "RuleID": "aws-access-key",
        "Description": "AWS Access Key",
        "File": "config.py",
        "StartLine": 14,
        "Match": "AKIAIOSFODNN7EXAMPLE",
    }])
    findings = parse_betterleaks_output(raw)
    assert len(findings) == 1
    assert findings[0]["file"] == "config.py"
    assert findings[0]["line"] == 14
    assert findings[0]["rule"] == "aws-access-key"


def test_parse_betterleaks_output_empty():
    assert parse_betterleaks_output("[]") == []


def test_parse_betterleaks_output_no_output():
    assert parse_betterleaks_output("") == []
