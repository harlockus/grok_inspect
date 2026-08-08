"""HTML report generation — fixed template, autoescaped."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from grok_inspect.models import ScanResult

_TEMPLATE_NAME = "brief.html.j2"


def to_html(result: ScanResult) -> str:
    tpl_dir = Path(__file__).resolve().parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(tpl_dir)),
        autoescape=select_autoescape(enabled_extensions=("html", "xml", "j2")),
        # No user-controlled template includes
        auto_reload=False,
    )
    # Fixed template name only — never accept path from user input
    template = env.get_template(_TEMPLATE_NAME)
    return template.render(result=result)
