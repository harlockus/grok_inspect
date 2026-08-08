from grok_inspect.agent.grok import _parse_json_object


def test_parse_fenced_json():
    text = (
        'Here you go:\n{"executive_summary": "ok", "threat_narrative": "n", '
        '"prioritized_findings": [], "likely_attacker_goals": [], '
        '"remediation_plan": [], "questions_for_operator": [], "confidence": 0.5}'
    )
    d = _parse_json_object(text)
    assert d["executive_summary"] == "ok"
