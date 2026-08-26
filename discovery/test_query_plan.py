import json
from collections import Counter
from pathlib import Path
from discovery.query_plan import build_query_plan, QUERY_FAMILIES
from scamscan import load_config

cfg = load_config(Path(__file__).parents[1] / "config.json")
budgets = cfg["search"]["query_family_budgets"]
plan = build_query_plan(cfg["brand"], budgets,
    [{"summary": "Call +254712345678, paybill 123456 or @mpesa_help"}],
    cfg["search"]["free_hosting_domains"])
assert plan
assert all(q.query_family in QUERY_FAMILIES for q in plan)
counts = Counter(q.query_family for q in plan)
assert all(counts[f] <= budgets[f] for f in QUERY_FAMILIES)
assert set(QUERY_FAMILIES) == set(counts)
assert any("254712345678" in q.query for q in plan)
assert counts["platform_specific"] <= budgets["platform_specific"]
assert len({q.query for q in plan}) == len(plan)
print(f"PASS: {len(plan)} queries across {len(counts)} independently budgeted families")
