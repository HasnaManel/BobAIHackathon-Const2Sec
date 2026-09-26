import json
with open("docs/SUBAGENT_FINDINGS.json", encoding="utf-8") as f:
    data = json.load(f)
print(f"JSON valid: {len(data)} findings")
for item in data:
    print(f"  {item['id']:10s} [{item['severity']:8s}] {item['agent']}")
