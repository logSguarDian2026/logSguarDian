import sqlite3, re, collections, sys
db = sqlite3.connect(sys.argv[1] if len(sys.argv) > 1 else "events-monitor-pass.db")
db.row_factory = sqlite3.Row
rows = db.execute("select method,path,user_agent,verdict,predicted_class from detection_events").fetchall()
def norm(p):
    p = re.sub(r'/\d+(?=/|$)', '/:id', p)
    return re.sub(r'/track-order/.*', '/track-order/:id', p)
agg = collections.defaultdict(lambda: {'n': 0, 'block': 0, 'classes': collections.Counter()})
tot = collections.defaultdict(lambda: [0, 0])
for r in rows:
    ua = 'browser' if r['user_agent'].startswith('Mozilla') else 'curl'
    a = agg[(r['method'], norm(r['path']), ua)]
    a['n'] += 1; tot[ua][0] += 1
    if r['verdict'] == 'block':
        a['block'] += 1; tot[ua][1] += 1; a['classes'][r['predicted_class']] += 1
for k, a in sorted(agg.items(), key=lambda kv: (-kv[1]['block'] / kv[1]['n'], kv[0])):
    print(f"{k[0]+' '+k[1]:50}{k[2]:8}{a['n']:4}{a['block']:5} {a['block']/a['n']*100:5.1f}%  {dict(a['classes']) or ''}")
for ua, (n, b) in tot.items(): print(f"TOTAL {ua}: {b}/{n} ({b/n*100:.1f}%)")
