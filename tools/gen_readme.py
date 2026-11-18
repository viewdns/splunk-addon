"""Renders package/README.md from docs/README.template.md and the action registry (dev tool, not shipped).

Run after changing lookups:  .venv/bin/python tools/gen_readme.py
"""
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
table = subprocess.check_output([sys.executable, os.path.join(ROOT, "tools", "gen_action_docs.py")], text=True).strip()
template = open(os.path.join(ROOT, "docs", "README.template.md"), encoding="utf-8").read()
assert "{{ACTIONS_TABLE}}" in template
with open(os.path.join(ROOT, "package", "README.md"), "w", encoding="utf-8") as handle:
    handle.write(template.replace("{{ACTIONS_TABLE}}", table))
print("wrote package/README.md")
