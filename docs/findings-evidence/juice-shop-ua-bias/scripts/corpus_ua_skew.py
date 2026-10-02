import json, collections
c = collections.defaultdict(lambda: [0, 0])
with open("training/data_clean/unified.jsonl") as f:
    for line in f:
        r = json.loads(line); c[r['label']][0] += 1
        if len(r.get('userAgent') or '') > 40: c[r['label']][1] += 1
for k, (n, l) in c.items(): print(f"{k:15} n={n:7} UA>40: {l/n*100:5.1f}%")
